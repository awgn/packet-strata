# Packet Strata

A high-performance packet parsing library and PCAP reader for Rust.

## Workspace Structure

This repository is organized as a Cargo workspace containing:

- **`packet-strata-lib/`** - Core packet parsing library
  - Zero-copy packet parsing
  - Support for multiple protocols (Ethernet, IPv4/IPv6, TCP, UDP, tunnels, etc.)
  - Iterator-based and full-packet parsing modes

- **`pcap-reader/`** - Command-line PCAP file analyzer
  - Reads PCAP and PCAPNG files
  - Provides detailed packet statistics
  - High-performance packet processing

## Building

Build the library (default):

```bash
cargo build --release
```

Build the entire workspace (library + pcap-reader):

```bash
cargo build --release --workspace
```

Build only the library:

```bash
cargo build --release -p packet-strata
```

Build only the pcap-reader:

```bash
cargo build --release -p pcap-reader
```

## Usage

### Using the Library

Add to your `Cargo.toml`:

```toml
[dependencies]
packet-strata = "0.1" 
```

**Note**: When adding `packet-strata` as a dependency, only the library will be built. The `pcap-reader` binary is excluded from default builds and won't be compiled unless explicitly requested with `cargo build --workspace` or `cargo build -p pcap-reader`.

### Using the PCAP Reader

```bash
# Basic usage
cargo run -p pcap-reader -- -p path/to/file.pcap

# With statistics
cargo run -p pcap-reader -- -p path/to/file.pcap --stats

# Dump packet contents
cargo run -p pcap-reader -- -p path/to/file.pcap --dump-packet

# Use full packet parsing (instead of iterator mode)
cargo run -p pcap-reader -- -p path/to/file.pcap --full-parse
```

Or after building:

```bash
./target/release/pcap-reader --help
```

## Features

### Supported Protocols

**Link Layer:**
- Ethernet
- Linux Cooked Capture (SLL/SLLv2)
- Null/Loopback

**Network Layer:**
- IPv4
- IPv6
- ARP
- MPLS

**Transport Layer:**
- TCP
- UDP
- SCTP
- ICMP/ICMPv6

**Tunnel Protocols:**
- VXLAN
- Geneve
- GRE/NVGRE
- MPLS
- Teredo
- GTPv1/GTPv2
- L2TPv2/L2TPv3
- PBB
- STT
- PPTP
- IP-in-IP (IPIP, SIT, IP4in6, IP6Tnl)

## License

MIT

## Author

Nicola Bonelli <nicola.bonelli@larthia.com>
