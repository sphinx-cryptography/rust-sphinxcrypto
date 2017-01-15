// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mix node cryptographic operations

extern crate lioness;
extern crate rustc_serialize;

use std::collections::HashSet;
pub use crypto_primitives::{GroupCurve25519, SphinxDigest,
                            SphinxLionessBlockCipher, SphinxStreamCipher, CURVE25519_SIZE};
use self::lioness::xor;
use std::error::Error;
use std::fmt;
use rustc_serialize::hex::ToHex;


/// The "security bits" expressed as bytes that Sphinx mix packet crypto provides,
/// curve25519 uses a 256 bit key and provides 128 bits of security. Therefor the
/// Sphinx digest and cipher stream functions are keyed with the 128 bits of security.
pub const SECURITY_PARAMETER: usize = 16;


/// This trait is used to detect packet replays. A unique tag for each
/// packet is remembered and if ever seen again implies a packet
/// replay. Note that we can flush our cache upon mix node key
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

/// mix nodes only need their private key
/// to perform packet unwrapping.
pub trait MixPrivateKey {
    fn get_private_key(&self) -> &[u8; 32];
}

/// this struct represents the Sphinx mix node's current
/// key material state and node identification.
pub struct VolatileMixState {
    /// used to detect replays/duplicate packets
    map: HashSet<[u8; 32]>,
    /// node identification
    pub id: [u8; 16],
    /// public key
    pub public_key: [u8; 32],
    /// private key
    pub private_key: [u8; 32],
}

impl VolatileMixState {
    /// return a new VolatileMixState struct
    pub fn new(id: [u8; 16], public_key: [u8; 32], private_key: [u8; 32],) -> VolatileMixState {
        VolatileMixState{
            map: HashSet::new(),
            id: id,
            public_key: public_key,
            private_key: private_key,
        }
    }
}

impl MixPrivateKey for VolatileMixState {
    /// return the private key
    fn get_private_key(&self) -> &[u8; 32] {
        &self.private_key
    }
}

impl PacketReplayCache for VolatileMixState {
    /// return true if the given tag is present in our HashSet
    ///
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn check(&self, tag: [u8; 32]) -> bool {
        println!("check tag {}", tag.to_hex());
        self.map.contains(&tag)
    }

    /// remember the given tag in our HashSet
    /// # Arguments
    /// * `tag` - a 32 byte value
    fn set(&mut self, tag: [u8; 32]) {
        self.map.insert(tag);
    }

    /// clear the HashSet
    fn flush(&mut self) {
        self.map.clear();
    }
}

/// SphinxPacket represents a decoded sphinx mix packet
#[derive(Default,Clone)]
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
    DuplicatePacket,
    InvalidHMAC,
    InvalidMessage(PrefixFreeDecodeError),
    InvalidHop(UnwrappedPacketType),
    InvalidProcessHop,
}

/// UnwrappedPacketType represents one of three possible
/// types of results
#[derive(Debug,PartialEq)]
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
            // XXX
            //value: s[1..s[0] as usize +1].as_ref().to_vec(),
            //remainder: s[s[0] as usize +1..].as_ref().to_vec(),
            value: s[0..SECURITY_PARAMETER].as_ref().to_vec(),
            remainder: s[SECURITY_PARAMETER..].as_ref().to_vec(),
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


pub struct SphinxParams {
    /// The maximum number of hops a Sphinx packet may contain.
    pub max_hops: usize,
    pub beta_cipher_size: usize,
    /// The size of the Sphinx packet body
    pub payload_size: usize,
}

impl SphinxParams {
    pub fn new(max_hops: usize, payload_size: usize) -> SphinxParams {
        SphinxParams{
            max_hops: max_hops,
            payload_size: payload_size,
            beta_cipher_size: CURVE25519_SIZE + (2 * max_hops+1) * SECURITY_PARAMETER,
        }
    }
}

/// unwrap a single layer of sphinx mix packet encryption
/// and return a Result of either UnwrappedPacket or SphinxPacketError
///
/// # Arguments
///
/// * `params` - a reference to a SphinxParams struct
/// * `state` - an implementation of the PacketReplayCache trait + MixPrivateKey trait
/// * `packet` - a reference to a SphinxPacket
///
/// # Errors
///
/// * `SphinxPacketError::DuplicatePacket` - indicates a packet that was already seen
/// * `SphinxPacketError::InvalidHMAC` - computed HMAC doesn't match the gamma element
/// * `SphinxPacketError::InvalidMessage` - prefix-free encoding error, invalid message type
/// * `SphinxPacketError::InvalidHop(ClientHop)` - invalid client hop
/// * `SphinxPacketError::InvalidHop(ProcessHop)` - invalid process hop
///
pub fn sphinx_packet_unwrap<S>(params: &SphinxParams, state: &mut S, packet: SphinxPacket)
  -> Result<UnwrappedPacket, SphinxPacketError>
  where S: PacketReplayCache + MixPrivateKey
{
    // derive shared secret from alpha using our private key
    let group = GroupCurve25519::new();
    let mut alpha_array = [0u8; 32];
    for (place, element) in alpha_array.iter_mut().zip(packet.alpha.iter()) {
        *place = *element;
    }
    let shared_secret = {
        let private_key = state.get_private_key();
        group.exp_on(&alpha_array, private_key.as_ref()) 
    };

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
    if state.check(tag) {
        return Err(SphinxPacketError::DuplicatePacket)
    }
    state.set(tag);

    // unwrap body, lioness decrypt block
    let mut block_cipher = SphinxLionessBlockCipher::new();
    let block_cipher_key = block_cipher.derive_key(&shared_secret);
    let mut block = packet.delta.clone();
    block_cipher.decrypt(&block_cipher_key, block.as_mut_slice());

    // unwrap beta
    let stream_key = digest.derive_stream_cipher_key(&shared_secret);
    let stream_cipher = SphinxStreamCipher::new();
    let stream = stream_cipher.generate_stream(&stream_key, params.beta_cipher_size);
    let mut unwrapped_beta = vec![0u8; params.beta_cipher_size];
    let padding = [0u8; 2*SECURITY_PARAMETER];
    let mut beta_copy = packet.beta;
    beta_copy.extend(padding.as_ref());
    xor(&stream, beta_copy.as_ref(), unwrapped_beta.as_mut_slice());

    let beta_message = match prefix_free_decode(unwrapped_beta.as_slice()) {
        Ok(m) => m,
        Err(e) => return Err(SphinxPacketError::InvalidMessage(e)),
    };
    match beta_message.message_type {
      UnwrappedPacketType::MixHop => {
        let blinding_factor = digest.hash_blinding(array_ref!(&packet.alpha, 0, CURVE25519_SIZE), &shared_secret);
        let alpha = group.exp_on(array_ref!(packet.alpha, 0, CURVE25519_SIZE), &blinding_factor);
        let (gamma0,beta) = unwrapped_beta.split_at(SECURITY_PARAMETER*2);
        // let gamma = array_ref!(gamma0, SECURITY_PARAMETER, SECURITY_PARAMETER*2);
        assert!(beta.len() > 0);
        let new_packet = SphinxPacket {
            alpha: alpha.to_vec(),
            beta: beta.to_vec(),
            gamma: gamma0.to_vec(),
            delta: block.to_vec(),
        };
        let mix_id = array_ref!(beta_message.value, 0, SECURITY_PARAMETER);
        let p = UnwrappedPacket{
            result_type: UnwrappedPacketType::MixHop,
            next_mix_id: Some(*mix_id),
            packet: new_packet,
            ..Default::default()
        };
        Ok(p)
      },
      UnwrappedPacketType::ClientHop => {
        if beta_message.remainder.len() < SECURITY_PARAMETER {
            return Err(SphinxPacketError::InvalidHop(UnwrappedPacketType::ClientHop))
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
        Ok(p)
      },
      UnwrappedPacketType::ProcessHop => {
        let zeros = [0u8; SECURITY_PARAMETER];
        let (body_head,body_tail) = block.split_at(SECURITY_PARAMETER);
        if zeros != *body_head {
            return Err(SphinxPacketError::InvalidHop(UnwrappedPacketType::ProcessHop))
        }
        let body_message = match prefix_free_decode(body_tail) {
            Ok(m) => m,
            Err(_) => return Err(SphinxPacketError::InvalidProcessHop),
        };
        if body_message.message_type != UnwrappedPacketType::ClientHop {
            return Err(SphinxPacketError::InvalidHop(UnwrappedPacketType::ProcessHop))
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
        Ok(p)
      },
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    use super::*;
    use self::rustc_serialize::hex::FromHex;
    //use self::rustc_serialize::hex::{FromHex, ToHex};

    #[test]
    fn packet_replay_test() {
        let max_hops = 5;
        let payload_size = 1024;
        let params = SphinxParams::new(max_hops, payload_size);

        let node_id_bytes = "ff81855a360000000000000000000000".from_hex().unwrap();
        let node_id = array_ref!(node_id_bytes, 0, 16);
        let pub_key_bytes = "73514173ee741afacdd4733e84f629b5cb9e34d28d072d749a8171fc6d64a930".from_hex().unwrap();
        let pub_key = array_ref!(pub_key_bytes, 0, 32);
        let priv_key_bytes = "9863a8f1b5307938cd4bc9782411e9eea0a38b9144d096bd923085dfb8534277".from_hex().unwrap();
        let priv_key = array_ref!(priv_key_bytes, 0, 32);

        let mut mix_state = VolatileMixState::new(*node_id, *pub_key, *priv_key);
        let packet = SphinxPacket{
            alpha: "cbe28bea4d68103461bc0cc2db4b6c4f38bc82af83f5f1de998c33d46c15f72d".from_hex().unwrap(),
            beta: "a5578dc72fcea3501169472b0877ca46627789750820b29a3298151e12e04781645f6007b6e773e4b7177a67adf30d0ec02c472ddf7609eba1a1130c80789832fb201eed849c02244465f39a70d7520d641be371020083946832d2f7da386d93b4627b0121502e5812209d674b3a108016618b2e9f210978f46faaa2a7e97a4d678a106631581cc51120946f5915ee2bfd9db11e5ec93ae7ffe4d4dc8ab66985cfe9da441b708e4e5dc7c00ea42abf1a".from_hex().unwrap(),
            gamma: "976fdfd8262dbb7557c988588ac9a204".from_hex().unwrap(),
            delta: "0a9411a57044d20b6c4004c730a78d79550dc2f22ba1c9c05e1d15e0fcadb6b1b353f028109fd193cb7c14af3251e6940572c7cd4243977896504ce0b59b17e8da04de5eb046a92f1877b55d43def3cc11a69a11050a8abdceb45bc1f09a22960fdffce720e5ed5767fbb62be1fd369dcdea861fd8582d01666a08bf3c8fb691ac5d2afca82f4759029f8425374ae4a4c91d44d05cb1a64193319d9413de7d2cfdffe253888535a8493ab8a0949a870ae512d2137630e2e4b2d772f6ee9d3b9d8cadd2f6dc34922701b21fa69f1be6d0367a26c2875cb7afffe60d59597cc084854beebd80d559cf14fcb6642c4ab9102b2da409685f5ca9a23b6c718362ccd6405d993dbd9471b4e7564631ce714d9c022852113268481930658e5cee6d2538feb9521164b2b1d4d68c76967e2a8e362ef8f497d521ee0d57bcd7c8fcc4c673f8f8d700c9c71f70c73194f2eddf03f954066372918693f8e12fc980e1b8ad765c8806c0ba144b86277170b12df16b47de5a2596b2149c4408afbe8f790d3cebf1715d1c4a9ed5157b130a66a73001f6f344c74438965e85d3cac84932082e6b17140f6eb901e3de7b3a16a76bdde2972c557d573830e8a455973de43201b562f63f5b3dca8555b5215fa138e81da900358ddb4d123b57b4a4cac0bfebc6ae3c7d54820ca1f3ee9908f7cb81200afeb1fdafdfbbc08b15d8271fd18cfd7344b36bdd16cca082235c3790888dae22e547bf436982c1a1935e2627f1bb16a3b4942f474d2ec1ff15eb6c3c4e320892ca1615ecd462007e51fbc69817719e6d641c101aa153bff207974bbb4f9553a8d6fb0cfa2cb1a497f9eee32f7c084e97256c72f06f020f33a0c079f3f69c2ce0e2826cc396587d80c9485e26f70633b70ad2e2d531a44407d101628c0bdae0cd47d6032e97b73e1231c3db06a2ead13eb20878fc198a345dd9dafc54b0cc56bcf9aa64e85002ff91a3f01dc97de5e85d68707a4909385cefbd6263cf9624a64d9052291da48d33ac401854cce4d6a7d21be4b5f1f4616e1784226603fdadd45d802ab226c81ec1fc1827310c2c99ce1c7ee28f38fbc7cf637132a1a2b1e5835762b41f0c7180a7738bac5cedebc11cdbf229e2155a085349b93cb94ce4285ea739673cc719e46cacb56663564057df1a0a2f688ed216336ff695337d6922f0185c23c3c04294388da192d9ae2b51ff18a8cc4d3212e1b2b19fed7b8f3662c2f9bd463f75e1e7c738db6b204f8f5aa8176e238d41c8d828b124e78c294be2d5b2bf0724958b787b0bea98d9a1534fc9975d66ee119b47b2e3017c9bba9431118c3611840b0ddcb00450024d484080d29c3896d92913eaca52d67f313a482fcc6ab616673926bdbdb1a2e62bcb055755ae5b3a975996e40736fde300717431c7d7b182369f90a092aef94e58e0ea5a4b15e76d".from_hex().unwrap(),
        };

        let packet2 = packet.clone();
        match sphinx_packet_unwrap(&params, &mut mix_state, packet) {
            Ok(_) =>  println!("Ok"),
            Err(e) => panic!("Err: {:?}", e),
        }
        match sphinx_packet_unwrap(&params, &mut mix_state, packet2) {
            Ok(_) =>  panic!("expected replay error"),
            Err(_) => return, // XXX check error type
        }
    }
}
