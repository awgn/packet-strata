use ahash::RandomState;
use clap::Parser;
use hashlink::LinkedHashMap;
use packet_strata::tracker::{Timestamped, Tracker, flow_key::{FlowKeyV4, FlowKeyV6}, vni::VniMapper};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::{fs::File};
use std::path::PathBuf;
use tracing::{error, info};

use crate::packet_metadata::TimestampNsec;

mod packet_metadata;
mod process;
mod stats;

#[derive(Parser, Debug)]
#[command(name = "pcap-reader")]
#[command(about = "PCAP reader and packet analyzer", long_about = None)]
struct Args {
    /// Path to the PCAP file to read
    #[arg(short, long, value_name = "FILE")]
    pcap: PathBuf,

    /// dump packet contents
    #[arg(short, long)]
    dump_packet: bool,

    /// Parse full packet, instead of using iterator
    #[arg(short, long)]
    full_parse: bool,

    /// track flows and VNI (tunnels)
    #[arg(long, requires ="full_parse")]
    flow_tracker: bool,

    /// print statistics at the end
    #[arg(short, long)]
    stats: bool,
}

fn main() {
    // Initialize tracing subscriber for logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let stats = stats::Stats::default();
    let mut flow_tracker = FlowTracker::new();

    // Read and process PCAP file
    info!("Reading PCAP file: {:?}", args.pcap);
    if let Err(e) = process_pcap(&args.pcap, &args, &stats, &mut flow_tracker) {
        error!("Failed to process PCAP file: {}", e);
        std::process::exit(1);
    }
    if args.stats {
        println!("{stats}");
    }

    if args.flow_tracker {
        println!("--- Flow Tracker Stats ---");
        println!("IPv4 Flows: {}", flow_tracker.v4.len());
        println!("IPv6 Flows: {}", flow_tracker.v6.len());
        println!("VNI mapping: {}", flow_tracker.vni_mapper.len());
    }

    info!("PCAP processing completed!");
}

struct Flow {
    timestamp: TimestampNsec,
    counter: u64,
}

impl Timestamped for Flow {
    type Timestamp = TimestampNsec;
    #[inline]
    fn timestamp(&self) -> &Self::Timestamp {
        &self.timestamp
    }

    #[inline]
    fn set_timestamp(&mut self, ts: Self::Timestamp) {
        self.timestamp = ts;
    }
}

struct FlowTracker {
    v4: Tracker<FlowKeyV4, Flow>,
    v6: Tracker<FlowKeyV6, Flow>,
    vni_mapper: VniMapper,
}

impl FlowTracker {
    fn new() -> Self {
        Self {
            v4: Tracker::with_capacity(100000),
            v6: Tracker::with_capacity(100000),
            vni_mapper: VniMapper::new(),
        }
    }
}

/// Process PCAP file packet by packet
fn process_pcap(pcap_path: &PathBuf, args: &Args, stats: &stats::Stats, flow_tracker: &mut FlowTracker) -> Result<(), String> {
    // Create thread-local stats for high-performance counting
    let mut local_stats = stats::LocalStats::new();

    // Read the PCAP file

    let file = File::open(pcap_path).unwrap();

    let mut packet_count = 0;
    let mut bytes_count = 0;

    let start = std::time::Instant::now();
    let link_type = &mut None;

    // Try to create a PCAPNG reader first
    match PcapNGReader::new(65536, file) {
        Ok(mut reader) => {
            info!("Detected PCAPNG format");
            loop {
                match reader.next() {
                    Ok((offset, block)) => {
                        match block {
                            PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                                packet_count += 1;
                                bytes_count += epb.caplen as u64;
                                process::process_packet(
                                    packet_count,
                                    link_type,
                                    &epb,
                                    &mut local_stats,
                                    stats,
                                    flow_tracker,
                                    args,
                                );
                            }
                            PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                                packet_count += 1;
                                bytes_count += spb.origlen as u64;
                                process::process_packet(
                                    packet_count,
                                    link_type,
                                    &spb,
                                    &mut local_stats,
                                    stats,
                                    flow_tracker,
                                    args,
                                );
                            }
                            PcapBlockOwned::NG(Block::SectionHeader(_shb)) => {
                                info!("PCAPNG Section Header found");
                            }
                            PcapBlockOwned::NG(Block::InterfaceDescription(_idb)) => {
                                info!("PCAPNG Interface Description found");
                            }
                            _ => {
                                // Other block types (interface statistics, etc.)
                            }
                        }
                        reader.consume(offset);
                    }
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete(_)) => {
                        reader.refill().unwrap();
                    }
                    Err(e) => {
                        return Err(format!("Error reading PCAPNG: {:?}", e));
                    }
                }
            }
        }
        Err(_) => {
            let file = File::open(pcap_path).unwrap();

            // Try legacy PCAP format
            let mut reader = LegacyPcapReader::new(65536, file)
                .map_err(|e| format!("Failed to create PCAP reader: {:?}", e))?;

            loop {
                match reader.next() {
                    Ok((offset, block)) => {
                        match block {
                            PcapBlockOwned::Legacy(packet) => {
                                packet_count += 1;
                                bytes_count += packet.caplen as u64;
                                process::process_packet(
                                    packet_count,
                                    link_type,
                                    &packet,
                                    &mut local_stats,
                                    stats,
                                    flow_tracker,
                                    args,
                                );
                            }
                            PcapBlockOwned::LegacyHeader(_header) => {
                                info!("Legacy PCAP header found");
                            }
                            _ => {}
                        }
                        reader.consume(offset);
                    }
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete(_)) => {
                        reader.refill().unwrap();
                    }
                    Err(e) => {
                        return Err(format!("Error reading PCAP: {:?}", e));
                    }
                }
            }
        }
    }

    // Final flush of local stats
    local_stats.flush(stats);

    info!(
        "Total packets processed: {}, {:.3}M pkt/sec, {:.3} Gbps",
        packet_count,
        (packet_count as f64 / start.elapsed().as_secs_f64()) / 1_000_000.0,
        (bytes_count as f64 * 8.0) / (start.elapsed().as_secs_f64() * 1_000_000_000.0)
    );
    Ok(())
}
