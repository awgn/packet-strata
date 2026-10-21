use crate::{
    metadata::PacketMetadata,
    packet::Packet,
    tracker::{direction::PacketDirection, flow::FlowBase},
};

/// A trait for custom per-flow data (`D` in `Flow<T, D>`) that processes a packet
/// during Phase 2 (after `Flow::update` has updated L3/L4 flow state and counters).
///
/// If the custom DPI / analyzer determines that the flow orientation should be swapped,
/// it can call `base.flip_direction()`.
pub trait Process {
    /// Update custom state based on the provided packet metadata and content.
    ///
    /// # Arguments
    ///
    /// * `meta` - Packet metadata (timestamp, length, etc.)
    /// * `pkt` - The parsed packet
    /// * `dir` - Direction of the packet relative to the flow (computed in Phase 1)
    /// * `base` - Mutable reference to the flow's core statistics and metadata
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
