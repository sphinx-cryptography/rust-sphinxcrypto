// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mix node cryptographic operations

use std::collections::HashMap;
pub use crypto_primitives::{GroupCurve25519, SphinxDigest};


/// This trait is used to detect mix packet replay attacks. A unique
/// tag for each packet is remembered and if ever seen again implies a
/// replay attack. Note that we can flush our cache upon mix node key
/// rotation, which must happen fairly often.
pub trait PacketReplayCache {
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

impl PacketReplayCache for VolatileReplayHashMap {
    /// return true if the given tag is present in our HashMap
    ///
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn check(&self, tag: [u8; 32]) -> bool {
        match self.map.get(&tag) {
            Some(_) => return true,
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

/// Errors that can be produced while unwrapping sphinx packets
#[derive(Debug)]
pub enum SphinxPacketError {
    ReplayAttack,
    InvalidHMAC,
    InvalidMessageType,
    InvalidClientHop,
    InvalidProcessHop,
}

/// UnwrappedPacketType represents one of three possible
/// types of results
pub enum UnwrappedPacketType {
    Client,
    Process,
    NextHop,
}

/// UnwrappedPacket is the result of a mix node unwrapping a Sphinx packet.
/// This of course results in yet another SphinxPacket, our `packet` member.
pub struct UnwrappedPacket {
    /// type of unwrapped-packet
    pub result_type: UnwrappedPacketType,
    /// next hop mix ID
    pub next_mix_id: [u8; 16],
    /// client ID
    pub client_id: [u8; 16],
    /// message ID
    pub message_id: [u8; 16],
    /// sphinx packet
    pub packet: SphinxPacket,
}

/// sphinx mix node key material state.
/// mix nodes only need their private key
/// to perform packet unwrapping. However
/// this private key is of course destroyed
/// during key rotation.
pub trait SphinxMixState {
    fn get_private_key(self) -> [u8; 32];
}

/// this struct represents the Sphinx mix node's current
/// key material state and node identification.
pub struct VolatileMixState {
    /// node identification
    pub id: [u8; 16],
    /// public key
    pub public_key: [u8; 32],
    /// private key
    pub private_key: [u8; 32],
}

impl SphinxMixState for VolatileMixState {
    /// return the private key
    fn get_private_key(self) -> [u8; 32] {
        self.private_key
    }
}

/// unwrap a single layer of sphinx mix packet encryption
/// and returns a Result of either UnwrappedPacket or SphinxPacketError
///
/// # Arguments
///
/// * `state` - an implementation of the SphinxMixState trait
/// * `replay_cache` - an implementation of the PacketReplayCache trait
/// * `packet` - a reference to a SphinxPacket
///
/// # Errors
/// * `SphinxPacketError::ReplayAttack` - indicates a replay attack when a packet tag was found in the `replay_cache`
/// * `SphinxPacketError::InvalidHMAC` - computed HMAC doesn't match the gamma element
/// * `SphinxPacketError::InvalidMessageType` - prefix-free encoding error, invalid message type
/// * `SphinxPacketError::InvalidClientHop` - invalid client hop
/// * `SphinxPacketError::InvalidProcessHop` - invalid process hop
pub fn sphinx_packet_unwrap<S,C>(state: S, replay_cache: C, packet: SphinxPacket) -> Result<UnwrappedPacket, SphinxPacketError>
    where S: SphinxMixState,
          C: PacketReplayCache
{
    // derive shared secret from alpha using our private key
    let group = GroupCurve25519::new();
    let mut alpha_array = [0u8; 32];
    for (place, element) in alpha_array.iter_mut().zip(packet.alpha.iter()) {
        *place = *element;
    }
    let private_key = state.get_private_key();
    let shared_secret = group.exp_on(&alpha_array, private_key.as_ref());

    // derive HMAC key from shared secret
    let mut digest = SphinxDigest::new();
    let hmac_key = digest.derive_hmac_key(shared_secret.as_ref());

    // generate HMAC and check it against gamma
    let mac = digest.hmac(&hmac_key, &packet.beta);
    if packet.gamma != mac {
        return Err(SphinxPacketError::InvalidHMAC)
    }

    // check prefix hash against our replay cache
    let tag = digest.hash_replay(&shared_secret);
    if replay_cache.check(tag) {
        return Err(SphinxPacketError::ReplayAttack)
    }

    // TODO unwrap sphinx packet

    // XXX fix me
    let client_id: [u8; 16] = [0; 16];
    let next_mix_id: [u8; 16] = [0; 16];
    let message_id: [u8; 16] = [0; 16];
    let p = UnwrappedPacket{
        result_type: UnwrappedPacketType::NextHop,
        next_mix_id: next_mix_id,
        client_id: client_id,
        message_id: message_id,
        packet: packet,
    };
    Ok(p)
}
