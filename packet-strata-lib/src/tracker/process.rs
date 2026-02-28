use crate::{
    metadata::PacketMetadata,
    packet::Packet,
    tracker::{direction::PacketDirection, flow::FlowBase},
};

/// A trait for types that can process a packet and update their state.
///
/// This is primarily used by `Flow` to update statistics (counters, timestamps)
/// and protocol-specific state machines (like TCP) upon receiving a new packet.
pub trait Process {
    /// Update the state based on the provided packet metadata and content.
    ///
    /// # Arguments
    ///
    /// * `meta` - Packet metadata (timestamp, length, etc.)
    /// * `pkt` - The parsed packet
    /// * `dir` - Direction of the packet relative to the flow
    /// * `core` - Mutable reference to the flow's core statistics and metadata
    fn process<Meta: PacketMetadata, T>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        dir: PacketDirection,
        base: &mut FlowBase<T>,
    );
}

impl Process for () {
    #[inline(always)]
    fn process<Meta: PacketMetadata, T>(
        &mut self,
        _meta: &Meta,
        _pkt: &Packet<'_>,
        _dir: PacketDirection,
        _base: &mut FlowBase<T>,
    ) {
    }
}
