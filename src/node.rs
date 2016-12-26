// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mix node cryptographic operations

use std::collections::HashMap;


/// This trait is used to detect mix packet replay attacks. A unique
/// tag for each packet is remembered and if ever seen again implies a
/// replay attack. Note that we can flush our cache upon mix node key
/// rotation, which must happen fairly often.
pub trait PacketReplayCheck {

    /// returns true if we've seen a given tag before
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn check(&self, tag: [u8; 32]) -> bool;

    /// record a tag in our cache so that future calls with `check`
    /// will return true for that tag
    fn set(&mut self, tag: [u8; 32]);

    /// flush our cache of tags
    fn flush(&mut self);
}

/// VolatileReplayHashMap is used to detect replay attacks
/// with a volatile cache, a HashMap. No disk persistence is used here.
pub struct VolatileReplayHashMap {
    map: HashMap<[u8; 32], bool>,
}

impl VolatileReplayHashMap {
    /// return a new VolatileReplayHashMap struct
    pub fn new() -> VolatileReplayHashMap {
        VolatileReplayHashMap{
            map: HashMap::new(),            
        }
    }
}

impl PacketReplayCheck for VolatileReplayHashMap {

    /// return true if the given tag is present in our HashMap
    ///
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn check(&self, tag: [u8; 32]) -> bool {
        match self.map.get(&tag) {
            Some(result) => return true,
            None => return false,
        }
    }

    /// remember the given tag in our HashMap
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn set(&mut self, tag: [u8; 32]) {
        self.map.insert(tag, true);
    }

    /// clear the HashMap
    fn flush(&mut self) {
        self.map.clear();
    }
}

/// SphinxPacket represents a decoded sphinx mix packet
pub struct SphinxPacket {
    /// the blinded key element
    pub alpha: Vec<u8>,
    /// encrypted and padded routing information
    pub beta: Vec<u8>,
    /// HMAC of the routing information
    pub gamma: Vec<u8>,
    /// message body encrypted with Lioness
    pub delta: Vec<u8>,
}

pub struct UnwrappedMessage {}

pub struct SphinxNodeState {
    private_key: [u8; 32],
    public_key: [u8; 32],
    id: [u8; 16],
}

pub struct SphinxNode {}

impl SphinxNode {
    pub fn new() -> SphinxNode {
        SphinxNode{}
    }

    pub fn unwrap(packet: &SphinxPacket) -> UnwrappedMessage {
        UnwrappedMessage{}
    }
}