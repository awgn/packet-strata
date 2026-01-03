#[derive(Hash, Eq, PartialEq, Debug, Copy, Clone)]
pub struct FlowKeyV4 {
    pub teid: u32, // New field (Tunnel Endpoint ID)
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKeyV4 {
    pub fn new_from_ethernet(payload: &[u8], len: usize) -> Option<Self> {
        // 1. Absolute minimum length check (Ethernet header min = 14 bytes)
        if len < 14 || payload.len() < len {
            return None;
        }

        // Start checking EtherType at offset 12
        let mut cur_offset = 12;

        // Read the current EtherType
        let mut eth_type = u16::from_be_bytes([payload[cur_offset], payload[cur_offset + 1]]);

        // 2. VLAN PARSING LOOP (Supports Nested VLAN / QinQ)
        // 0x8100 = Customer VLAN (802.1Q), 0x88A8 = Service VLAN (802.1ad)
        while eth_type == 0x8100 || eth_type == 0x88A8 {
            // A VLAN tag is 4 bytes long (2 TPID + 2 TCI).
            // We need to skip them to reach the next EtherType.
            cur_offset += 4;

            // Bounds check: We need at least 2 bytes to read the next EtherType
            if cur_offset + 2 > len {
                return None;
            }

            // Read the next EtherType (could be another VLAN or the real protocol)
            eth_type = u16::from_be_bytes([payload[cur_offset], payload[cur_offset + 1]]);
        }

        // 3. IPV4 CHECK
        // If after the VLAN chain we don't find IPv4 (0x0800), we exit.
        if eth_type != 0x0800 {
            return None;
        }

        // The IPv4 header starts AFTER the last EtherType (2 bytes)
        let ip_offset = cur_offset + 2;

        // Check: do we have enough data for the minimum IPv4 header (20 bytes)?
        if ip_offset + 20 > len {
            return None;
        }

        // 4. IPV4 PARSING
        let ver_ihl = payload[ip_offset];

        // Version must be 4
        if (ver_ihl >> 4) != 4 {
            return None;
        }

        // IHL is in 32-bit words. (x 4 to get bytes)
        let ip_header_len = ((ver_ihl & 0x0F) as usize) * 4;

        // Minimum IHL is 5 words (20 bytes)
        if ip_header_len < 20 {
            return None;
        }

        let protocol = payload[ip_offset + 9];

        // Bounds check for the entire IP header (needed to read src/dst IPs safely)
        if ip_offset + 20 > len {
            return None;
        }

        // src IP offset: 12, dst IP offset: 16 (relative to ip_offset)
        let src_ip_slice = &payload[ip_offset + 12..ip_offset + 16];
        let dst_ip_slice = &payload[ip_offset + 16..ip_offset + 20];

        // Safe conversion (we know slices are length 4)
        let src_ip: [u8; 4] = src_ip_slice.try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = dst_ip_slice.try_into().unwrap_or([0; 4]);

        // 5. TRANSPORT PARSING
        let trans_offset = ip_offset + ip_header_len;

        // Minimum 4 bytes needed to read ports (src 2b + dst 2b)
        if trans_offset + 4 > len {
            return None;
        }

        let (src_port, dst_port) = match protocol {
            6 | 17 => {
                // TCP (6) or UDP (17)
                let sp = u16::from_be_bytes([payload[trans_offset], payload[trans_offset + 1]]);
                let dp = u16::from_be_bytes([payload[trans_offset + 2], payload[trans_offset + 3]]);
                (sp, dp)
            }
            _ => return None, // Protocol not tracked
        };

        // 6. CANONICALIZATION
        // Sort IPs and ports to ensure bidirectional flows map to the same key
        let (c_src_ip, c_dst_ip, c_src_port, c_dst_port) =
            if src_ip > dst_ip || (src_ip == dst_ip && src_port > dst_port) {
                (dst_ip, src_ip, dst_port, src_port)
            } else {
                (src_ip, dst_ip, src_port, dst_port)
            };

        Some(Self {
            teid: 0, // Placeholder as requested
            src_ip: c_src_ip,
            dst_ip: c_dst_ip,
            src_port: c_src_port,
            dst_port: c_dst_port,
            protocol,
        })
    }
}
