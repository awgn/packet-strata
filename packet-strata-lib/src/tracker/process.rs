//! Custom per-flow packet processing trait (Phase 2 DPI integration)
//!
//! This module defines the [`Process`] trait, which allows users of `packet-strata`
//! to attach custom state `D` (such as an L7 Deep Packet Inspection engine,
//! application protocol classifier, or custom telemetry collector) to each [`Flow`](crate::tracker::flow::Flow).
//!
//! # Execution Order
//!
//! Whenever [`Flow::update`](crate::tracker::flow::Flow::update) or
//! [`Tracker::track_packet`](crate::tracker::Tracker::track_packet) is called:
//! 1. **Phase 1 (`packet-strata`)** computes the packet's [`PacketDirection`], updates
//!    `FlowTiming`, `FlowMetrics`, `IpState`, and `TcpState`.
//! 2. **Phase 2 (`D::process`)** is invoked with the packet, its computed `dir`, and
//!    a mutable reference to [`FlowBase`].
//! 3. If the custom analyzer determines that the flow orientation was inverted, it can
//!    call [`base.flip_direction()`](crate::tracker::flow::FlowBase::flip_direction) to
//!    swap the flow tuple, MAC addresses, IP/TCP state, and all accumulated counters in-place.
//!
//! # Example
//!
//! ```
//! use packet_strata::metadata::PacketMetadata;
//! use packet_strata::packet::Packet;
//! use packet_strata::tracker::direction::PacketDirection;
//! use packet_strata::tracker::flow::FlowBase;
//! use packet_strata::tracker::process::Process;
//! use packet_strata::tracker::tuple::Tuple;
//!
//! #[derive(Default, Debug)]
//! pub struct PayloadCounter {
//!     pub client_chunks: u32,
//!     pub server_chunks: u32,
//! }
//!
//! impl Process for PayloadCounter {
//!     fn process<Meta: PacketMetadata, T: Tuple>(
//!         &mut self,
//!         _meta: &Meta,
//!         pkt: &Packet<'_>,
//!         dir: PacketDirection,
//!         base: &mut FlowBase<T>,
//!     ) {
//!         if !pkt.data().is_empty() {
//!             match dir {
//!                 PacketDirection::Upwards => self.client_chunks += 1,
//!                 PacketDirection::Downwards => self.server_chunks += 1,
//!             }
//!             if pkt.data().starts_with(b"GET ") && dir != PacketDirection::Upwards {
//!                 base.flip_direction();
//!                 std::mem::swap(&mut self.client_chunks, &mut self.server_chunks);
//!             }
//!         }
//!     }
//! }
//! ```

use crate::{
    metadata::PacketMetadata,
    packet::Packet,
    tracker::{direction::PacketDirection, flow::FlowBase, tuple::Tuple},
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
    fn process<Meta: PacketMetadata, T: Tuple>(
        &mut self,
        meta: &Meta,
        pkt: &Packet<'_>,
        dir: PacketDirection,
        base: &mut FlowBase<T>,
    );
}

impl Process for () {
    #[inline(always)]
    fn process<Meta: PacketMetadata, T: Tuple>(
        &mut self,
        _meta: &Meta,
        _pkt: &Packet<'_>,
        _dir: PacketDirection,
        _base: &mut FlowBase<T>,
    ) {
    }
}
