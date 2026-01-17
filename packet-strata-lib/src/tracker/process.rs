use crate::{metadata::PacketMetadata, packet::Packet};

/// A trait for types that can process a packet and update their state.
///
/// This is primarily used by `Flow` to update statistics (counters, timestamps)
/// and protocol-specific state machines (like TCP) upon receiving a new packet.
pub trait Process {
    /// Update the state based on the provided packet metadata and content.
    fn process<Meta: PacketMetadata>(&mut self, meta: &Meta, pkt: &Packet<'_>);
}

impl Process for () {
    fn process<Meta: PacketMetadata>(&mut self, _meta: &Meta, _pkt: &Packet<'_>) {}
}
