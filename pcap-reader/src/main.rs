use clap::Parser;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;
use std::path::PathBuf;
use tracing::{error, info};

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

    // Read and process PCAP file
    info!("Reading PCAP file: {:?}", args.pcap);
    if let Err(e) = process_pcap(&args.pcap, &args, &stats) {
        error!("Failed to process PCAP file: {}", e);
        std::process::exit(1);
    }
    if args.stats {
        println!("{stats}");
    }
    info!("PCAP processing completed!");
}

/// Process PCAP file packet by packet
fn process_pcap(pcap_path: &PathBuf, args: &Args, stats: &stats::Stats) -> Result<(), String> {
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
                                    args.dump_packet,
                                    args.full_parse,
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
                                    args.dump_packet,
                                    args.full_parse,
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
                                    args.dump_packet,
                                    args.full_parse,
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
