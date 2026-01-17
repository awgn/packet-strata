use crate::{metadata::PacketMetadata, packet::Packet};

pub trait Process {
    fn process<Meta: PacketMetadata>(&mut self, meta: &Meta, pkt: &Packet<'_>);
}

impl Process for () {
    fn process<Meta: PacketMetadata>(&mut self, _meta: &Meta, _pkt: &Packet<'_>) {}
}
