// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mix node cryptographic operations

extern crate lioness;

use std::collections::HashMap;
pub use crypto_primitives::{GroupCurve25519, SphinxDigest,
                            SphinxLionessBlockCipher, SphinxStreamCipher, CURVE25519_SIZE};
use self::lioness::xor;
use std::error::Error;
use std::fmt;

/// The "security bits" expressed as bytes that Sphinx mix packet crypto provides,
/// curve25519 uses a 256 bit key and provides 128 bits of security. Therefor the
/// Sphinx digest and cipher stream functions are keyed with the 128 bits of security.
pub const SECURITY_PARAMETER: usize = 16;
/// The maximum number of hops a Sphinx packet may contain.
pub const MAX_HOPS: usize = 5;
const BETA_CIPHER_SIZE: usize = CURVE25519_SIZE + (2 * MAX_HOPS - 1) + (3 * SECURITY_PARAMETER);
/// The size of the Sphinx packet body
pub const PAYLOAD_SIZE: usize = 1024;
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
#[derive(Default)]
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
    InvalidMessage,
    InvalidClientHop,
    InvalidProcessHop,
}

/// UnwrappedPacketType represents one of three possible
/// types of results
#[derive(PartialEq)]
pub enum UnwrappedPacketType {
    ClientHop,
    ProcessHop,
    MixHop,
}

#[derive(Debug)]
pub enum PrefixFreeDecodeError {
    ZeroInputError,
    InvalidInputError,
}

impl fmt::Display for PrefixFreeDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::PrefixFreeDecodeError::*;
        match *self {
            InvalidInputError => write!(f, "Invalid prefix free decoding value."),
            ZeroInputError => write!(f, "Invalid input, zero size."),
        }
    }
}

impl Error for PrefixFreeDecodeError {
    fn description(&self) -> &str {
        "I'm a prefix-free decoding error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::PrefixFreeDecodeError::*;
        match *self {
            InvalidInputError => None,
            ZeroInputError => None,
        }
    }
}

pub struct PrefixFreeDecodedMessage {
    message_type: UnwrappedPacketType,
    value: Vec<u8>,
    remainder: Vec<u8>,
}

pub fn prefix_free_decode(s: &[u8]) -> Result<PrefixFreeDecodedMessage, PrefixFreeDecodeError> {
    let empty = Vec::new();
    if s.len() == 0 {
        return Err(PrefixFreeDecodeError::ZeroInputError)
    }
    if s[0] == 0x00 {
        return Ok(PrefixFreeDecodedMessage{
            message_type: UnwrappedPacketType::ProcessHop,
            value: empty,
            remainder: s[1..].as_ref().to_vec(),
        })
    } else if s[0] == 0xff {
        return Ok(PrefixFreeDecodedMessage{
            message_type: UnwrappedPacketType::MixHop,
            value: s[0..SECURITY_PARAMETER].as_ref().to_vec(),
            remainder: s[SECURITY_PARAMETER..].as_ref().to_vec(),
        })
    } else if s[0] < 128 {
        return Ok(PrefixFreeDecodedMessage{
            message_type: UnwrappedPacketType::ClientHop,
            value: s[1..s[0] as usize +1].as_ref().to_vec(),
            remainder: s[s[0] as usize +1..].as_ref().to_vec(),
        })
    }
    return Err(PrefixFreeDecodeError::InvalidInputError)
}


/// UnwrappedPacket is the result of a mix node unwrapping a Sphinx packet.
/// This of course results in yet another SphinxPacket, our `packet` member.
pub struct UnwrappedPacket {
    /// type of unwrapped-packet
    pub result_type: UnwrappedPacketType,
    /// next hop mix ID
    pub next_mix_id: Option<[u8; 16]>,
    /// client ID
    pub client_id: Option<[u8; 16]>,
    /// message ID
    pub message_id: Option<[u8; 16]>,
    /// sphinx packet
    pub packet: SphinxPacket,
}

impl Default for UnwrappedPacket {
    fn default() -> UnwrappedPacket {
        UnwrappedPacket{
            result_type: UnwrappedPacketType::MixHop,
            next_mix_id: None,
            client_id: None,
            message_id: None,
            packet: SphinxPacket{
                alpha: vec![],
                beta: vec![],
                gamma: vec![],
                delta: vec![],
            },
        }
    }
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
///
/// * `SphinxPacketError::ReplayAttack` - indicates a replay attack when a packet tag was found in the `replay_cache`
/// * `SphinxPacketError::InvalidHMAC` - computed HMAC doesn't match the gamma element
/// * `SphinxPacketError::InvalidMessage` - prefix-free encoding error, invalid message type
/// * `SphinxPacketError::InvalidClientHop` - invalid client hop
/// * `SphinxPacketError::InvalidProcessHop` - invalid process hop
///
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
    let hmac_key = digest.derive_hmac_key(&shared_secret);

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

    // unwrap body, lioness decrypt block
    let mut block_cipher = SphinxLionessBlockCipher::new();
    let block_cipher_key = block_cipher.derive_key(&shared_secret);
    let mut block = packet.delta.clone();
    block_cipher.decrypt(block_cipher_key, block.as_mut_slice());

    // unwrap beta
    let stream_key = digest.derive_stream_cipher_key(&shared_secret);
    let stream_cipher = SphinxStreamCipher::new();
    let stream = stream_cipher.generate_stream(stream_key, BETA_CIPHER_SIZE);
    let mut unwrapped_beta = &mut [0u8; BETA_CIPHER_SIZE];
    let padding = [0u8; 2*SECURITY_PARAMETER];
    let mut beta_copy = packet.beta;
    beta_copy.extend(padding.as_ref());
    xor(&stream, beta_copy.as_ref(), unwrapped_beta);

    let beta_message: PrefixFreeDecodedMessage;
    match prefix_free_decode(unwrapped_beta) {
        Ok(m) => beta_message = m,
        Err(_) => return Err(SphinxPacketError::InvalidMessage),
    }
    if beta_message.message_type == UnwrappedPacketType::MixHop {
        let blinding_factor = digest.hash_blinding(array_ref!(&packet.alpha, 0, CURVE25519_SIZE), &shared_secret);
        let alpha = group.exp_on(array_ref!(packet.alpha, 0, CURVE25519_SIZE), &blinding_factor);
        let gamma = array_ref!(unwrapped_beta, SECURITY_PARAMETER, SECURITY_PARAMETER*2);
        let beta = array_ref!(unwrapped_beta, SECURITY_PARAMETER*2, BETA_CIPHER_SIZE);
        assert!(beta.len() > 0);
        let new_packet = SphinxPacket {
            alpha: alpha.to_vec(),
            beta: beta.to_vec(),
            gamma: gamma.to_vec(),
            delta: block.to_vec(),
        };
        let mix_id = array_ref!(beta_message.value, 0, SECURITY_PARAMETER);
        let p = UnwrappedPacket{
            result_type: UnwrappedPacketType::MixHop,
            next_mix_id: Some(*mix_id),
            packet: new_packet,
            ..Default::default()
        };
        return Ok(p);
    }
    if beta_message.message_type == UnwrappedPacketType::ClientHop {
        if beta_message.remainder.len() < SECURITY_PARAMETER {
            return Err(SphinxPacketError::InvalidClientHop)
        }
        let new_packet = SphinxPacket {
            delta: block.to_vec(),
            ..Default::default()
        };
        let client_id = array_ref!(beta_message.value, 0, SECURITY_PARAMETER);
        let message_id = array_ref!(beta_message.remainder, 0, SECURITY_PARAMETER);
        let p = UnwrappedPacket{
            result_type: UnwrappedPacketType::ClientHop,
            client_id: Some(*client_id),
            message_id: Some(*message_id),
            packet: new_packet,
            ..Default::default()
        };
        return Ok(p);
    }
    if beta_message.message_type == UnwrappedPacketType::ProcessHop {
        let zeros = [0u8; SECURITY_PARAMETER];
        let body_head = array_ref!(block.as_slice(), 0, SECURITY_PARAMETER);
        let body_tail = array_ref!(block.as_slice(), SECURITY_PARAMETER, PAYLOAD_SIZE-SECURITY_PARAMETER);
        if zeros != *body_head {
            return Err(SphinxPacketError::InvalidProcessHop)
        }
        let body_message: PrefixFreeDecodedMessage;
        match prefix_free_decode(body_tail) {
            Ok(m) => body_message = m,
            Err(_) => return Err(SphinxPacketError::InvalidProcessHop),
        }
        if body_message.message_type != UnwrappedPacketType::ClientHop {
            return Err(SphinxPacketError::InvalidProcessHop)
        }
        // XXX TODO: remove padding from message body
        let unpadded_body = block.to_vec();
        let new_packet = SphinxPacket {
            delta: unpadded_body,
            ..Default::default()
        };
        let client_id = array_ref!(body_message.value, 0, SECURITY_PARAMETER);
        let p = UnwrappedPacket{
            result_type: UnwrappedPacketType::ProcessHop,
            client_id: Some(*client_id),
            packet: new_packet,
            ..Default::default()
        };
        return Ok(p);
    }
    return Err(SphinxPacketError::InvalidMessage);
}
