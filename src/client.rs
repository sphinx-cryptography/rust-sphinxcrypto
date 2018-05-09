// client.rs - sphinx client
// Copyright (C) 2018  David Stainton.

extern crate ecdh_wrapper;
extern crate rustc_serialize;

use std::any::Any;

use self::ecdh_wrapper::{PublicKey, PrivateKey, exp};

use super::utils::xor_assign;
use super::constants::{NODE_ID_SIZE, HEADER_SIZE, NUMBER_HOPS, ROUTING_INFO_SIZE, PER_HOP_ROUTING_INFO_SIZE, V0_AD, FORWARD_PAYLOAD_SIZE, PACKET_SIZE, PAYLOAD_TAG_SIZE};
use super::internal_crypto::{SPRP_KEY_SIZE, SPRP_IV_SIZE, GROUP_ELEMENT_SIZE, PacketKeys, kdf, StreamCipher, MAC_SIZE, hmac, sprp_encrypt};
use super::commands::{RoutingCommand, commands_to_vec, NextHop};
use super::error::{SphinxHeaderCreateError, SphinxPacketCreateError};

use self::rustc_serialize::hex::ToHex;


/// PathHop describes a route hop that a Sphinx Packet will traverse,
/// along with all of the per-hop Commands (excluding the Next Hop
/// command).
pub struct PathHop {
    pub id: [u8; NODE_ID_SIZE],
    pub public_key: PublicKey,
    pub commands: Option<Vec<Box<Any>>>,
}

pub struct SprpKey {
    pub key: [u8; SPRP_KEY_SIZE],
    pub iv: [u8; SPRP_IV_SIZE],
}

impl SprpKey {
    pub fn reset(&mut self) {
        self.key = [0u8; SPRP_KEY_SIZE];
        self.iv = [0u8; SPRP_IV_SIZE];
    }
}


/// create_header creates and returns a new Sphinx header and a vector of SPRP keys.
pub fn create_header(path: Vec<PathHop>) -> Result<([u8; HEADER_SIZE], Vec<SprpKey>), SphinxHeaderCreateError> {
    let num_hops = path.len();
    if num_hops > NUMBER_HOPS {
        return Err(SphinxHeaderCreateError::PathTooLongError);
    }

    // Derive the key material for each hop.
    let _keypair_result = PrivateKey::generate();
    if _keypair_result.is_err() {
        return Err(SphinxHeaderCreateError::KeyGenFail);
    }
    let keypair = _keypair_result.unwrap();
    let mut group_elements: Vec<PublicKey> = vec![];
    let mut keys: Vec<PacketKeys> = vec![];
    let mut shared_secret: [u8; GROUP_ELEMENT_SIZE] = keypair.exp(&path[0].public_key);
    keys.push(kdf(&shared_secret));
    let mut group_element = PublicKey::default();
    let _result = group_element.from_bytes(&keypair.public_key().to_vec());
    if _result.is_err() {
        return Err(SphinxHeaderCreateError::ImpossibleError);
    }
    group_elements.push(group_element);

    let mut i = 1;
    while i < num_hops {
        shared_secret = keypair.exp(&path[i].public_key);
        let mut j = 0;
        while j < i {
            shared_secret = exp(&shared_secret, &keys[j].blinding_factor);
            j += 1;
        }
        keys.push(kdf(&shared_secret));
        keypair.public_key().blind(&keys[i-1].blinding_factor);
        group_elements.push(keypair.public_key());
        i += 1;
    }

    // Derive the routing_information keystream and encrypted padding
    // for each hop.
    let mut ri_keystream: Vec<Vec<u8>> = vec![];
    let mut ri_padding: Vec<Vec<u8>> = vec![];
    let mut i = 0;
    while i < num_hops {
        let mut steam_cipher = StreamCipher::new(&keys[i].header_encryption, &keys[i].header_encryption_iv);
        let stream = steam_cipher.generate(ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE);
        let ks_len = stream.len() - ((i+1) * PER_HOP_ROUTING_INFO_SIZE);
        ri_keystream.push(stream[..ks_len].to_vec());
        ri_padding.push(stream[ks_len..].to_vec());
        if i > 0 {
            let prev_pad_len = ri_padding[i-1].len();
            let current = ri_padding[i-1].clone();
            xor_assign(&mut ri_padding[i][..prev_pad_len], &current);
        }
        i += 1;
    }

    // Create the routing_information block.
    let mut routing_info = vec![];
    let mut mac = [0u8; MAC_SIZE];
    let skipped_hops = NUMBER_HOPS - num_hops;
    if skipped_hops > 0 {
        routing_info = vec![0u8; skipped_hops * PER_HOP_ROUTING_INFO_SIZE];
    }

    let mut i: i8 = num_hops as i8 - 1;
    while i >= 0 {
        let _is_terminal = i == num_hops as i8 - 1;

        // serialize commands for this hop
        let _cmd_vec = path[i as usize].commands.as_ref();
        let _cmd_bytes_result = commands_to_vec(_cmd_vec.as_ref().unwrap(), _is_terminal);
        if _cmd_bytes_result.is_err() {
            return Err(SphinxHeaderCreateError::SerializeCommandsError);
        }
        let mut _ri_fragment = _cmd_bytes_result.unwrap();

        if !_is_terminal {
            let _next_id = path[i as usize + 1].id.clone();
            let _next_mac = mac.clone();
            let _next_cmd = NextHop{
                id: _next_id,
                mac: _next_mac,
            };
            _ri_fragment.extend(_next_cmd.to_vec());
        }

        let _pad_len = PER_HOP_ROUTING_INFO_SIZE - _ri_fragment.len();
        if _pad_len > 0 {
            let _zero_bytes = vec![0u8; PER_HOP_ROUTING_INFO_SIZE];
            _ri_fragment.extend(vec![0u8; _pad_len]);
        }

        // prepend _ri_fragment to routing_info
        let mut _tmp = _ri_fragment.to_owned();
        _tmp.extend(routing_info);
        routing_info = _tmp;

        xor_assign(&mut routing_info, ri_keystream[i as usize].as_slice());
        let mut _data = vec![];
        _data.extend(V0_AD.iter());
        _data.extend(group_elements[i as usize].to_vec());
        _data.extend(routing_info.to_owned());
        if i > 0 {
            _data.extend(&ri_padding[i as usize - 1]);
        }
        mac = hmac(&keys[i as usize].header_mac, &_data);
        i -= 1;
    }

    // Assemble the completed Sphinx Packet Header and Sphinx Packet Payload
    // SPRP key vector.
    let mut _header = vec![];
    _header.extend(V0_AD.iter());
    _header.extend(group_elements[0].to_vec());
    _header.extend(routing_info);
    _header.extend(mac.iter());
    let mut header = [0u8; HEADER_SIZE];
    header.copy_from_slice(&_header);

    let mut sprp_keys = vec![];
    let mut i = 0;
    while i < num_hops {
        let k = SprpKey{
            key: keys[i].payload_encryption,
            iv: keys[i].payload_encryption_iv,
        };
        sprp_keys.push(k);
        i += 1
    }
    return Ok((header, sprp_keys));
}

/// create a new sphinx packet
///
/// # Arguments
///
/// * `path` - a vector of path hops.
/// * `payload` - a payload to be encapsulated.
///
/// # Returns
///
/// * Returns a packet or an error.
///
pub fn new_packet(path: Vec<PathHop>, payload: [u8; FORWARD_PAYLOAD_SIZE]) -> Result<[u8; PACKET_SIZE], SphinxPacketCreateError>{
    let _path_len = path.len();
    let _header_result = create_header(path);
    if _header_result.is_err() {
        return Err(SphinxPacketCreateError::CreateHeaderError);
    }
    let _tmp = _header_result.unwrap();
    let header = _tmp.0;
    let sprp_keys = _tmp.1;

    let mut i = _path_len as i8 - 1;
    let mut _payload = payload.to_vec();
    while i >= 0 {
        let _result = sprp_encrypt(&sprp_keys[i as usize].key, &sprp_keys[i as usize].iv, _payload.clone());
        if _result.is_err() {
            return Err(SphinxPacketCreateError::SPRPEncryptError);
        }
        _payload = _result.unwrap();
        i -= 1;
    }

    let mut packet = [0u8; PACKET_SIZE];
    packet[0..HEADER_SIZE].copy_from_slice(&header);
    packet[HEADER_SIZE+PAYLOAD_TAG_SIZE..].copy_from_slice(&_payload);
    return Ok(packet);
}
