// client.rs - Sphinx client functions
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Client-side Sphinx library functions

extern crate rand;

use subtle::ConstantTimeEq;
use self::rand::Rng;
use ecdh_wrapper::{PublicKey, PrivateKey, exp};

use super::utils::xor_assign;
use super::constants::{NODE_ID_SIZE, HEADER_SIZE, MAX_HOPS, ROUTING_INFO_SIZE, PER_HOP_ROUTING_INFO_SIZE,
                       V0_AD, FORWARD_PAYLOAD_SIZE, PACKET_SIZE, PAYLOAD_TAG_SIZE, SURB_SIZE, PAYLOAD_SIZE};
use super::internal_crypto::{SPRP_KEY_SIZE, SPRP_IV_SIZE, GROUP_ELEMENT_SIZE, PacketKeys, kdf,
                             StreamCipher, MAC_SIZE, hmac, sprp_encrypt, sprp_decrypt};
use super::commands::{RoutingCommand, commands_to_vec};
use super::error::{SphinxHeaderCreateError, SphinxPacketCreateError, SphinxSurbCreateError,
                   SphinxPacketFromSurbError, SphinxDecryptSurbError};

const SPRP_KEY_MATERIAL_SIZE: usize = SPRP_KEY_SIZE + SPRP_IV_SIZE;


/// PathHop describes a route hop that a Sphinx Packet will traverse,
/// along with all of the per-hop Commands (excluding the Next Hop
/// command).
#[derive(Clone)]
pub struct PathHop {
    pub id: [u8; NODE_ID_SIZE],
    pub public_key: PublicKey,
    pub commands: Option<Vec<RoutingCommand>>,
}

/// SprpKey is a struct that contains a SPRP key and SPRP IV.
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

/// create a new sphinx header
///
/// # Arguments
///
/// * `rng` - an implementation of Rng, a random number generator.
/// * `path` - a vector of path hops.
///
/// # Returns
///
/// * Returns a header and a vector of keys or an error.
///
pub fn create_header<R: Rng>(rng: &mut R, path: Vec<PathHop>) -> Result<([u8; HEADER_SIZE], Vec<SprpKey>), SphinxHeaderCreateError> {
    let num_hops = path.len();
    if num_hops > MAX_HOPS {
        return Err(SphinxHeaderCreateError::PathTooLongError);
    }

    // Derive the key material for each hop.
    let _keypair_result = PrivateKey::generate(rng);
    if _keypair_result.is_err() {
        return Err(SphinxHeaderCreateError::KeyGenFail);
    }
    let keypair = _keypair_result.unwrap();
    let mut group_elements: Vec<PublicKey> = vec![];
    let mut keys: Vec<PacketKeys> = vec![];
    let mut shared_secret: [u8; GROUP_ELEMENT_SIZE] = keypair.exp(&path[0].public_key);
    keys.push(kdf(&shared_secret));
    let mut group_element = keypair.public_key();
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
        group_element.blind(&keys[i-1].blinding_factor);
        group_elements.push(group_element);
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
    let skipped_hops = MAX_HOPS - num_hops;
    if skipped_hops > 0 {
        routing_info = vec![0u8; skipped_hops * PER_HOP_ROUTING_INFO_SIZE];
    }

    let mut i: i8 = num_hops as i8 - 1;
    while i >= 0 {
        let _is_terminal = i == num_hops as i8 - 1;

        // serialize commands for this hop
        let _cmd_vec = path[i as usize].commands.as_ref();
        let _cmd_bytes_result = commands_to_vec(_cmd_vec.unwrap(), _is_terminal);
        if _cmd_bytes_result.is_err() {
            return Err(SphinxHeaderCreateError::SerializeCommandsError);
        }
        let mut _ri_fragment = _cmd_bytes_result.unwrap();

        if !_is_terminal {
            let _next_id = path[i as usize + 1].id.clone();
            let _next_mac = mac.clone();
            let _next_cmd = RoutingCommand::NextHop{
                id: _next_id,
                mac: _next_mac,
            };
            _ri_fragment.extend(_next_cmd.to_vec());
        }

        let _pad_len = PER_HOP_ROUTING_INFO_SIZE - _ri_fragment.len();
        if _pad_len > 0 {
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
pub fn new_packet<R: Rng>(rng: &mut R, path: Vec<PathHop>, payload: [u8; FORWARD_PAYLOAD_SIZE]) -> Result<[u8; PACKET_SIZE], SphinxPacketCreateError>{
    let _path_len = path.len();
    let _header_result = create_header(rng, path);
    if _header_result.is_err() {
        return Err(SphinxPacketCreateError::CreateHeaderError);
    }
    let _tmp = _header_result.unwrap();
    let header = _tmp.0;
    let sprp_keys = _tmp.1;

    let mut i = _path_len as i8 - 1;
    let mut _payload = payload.to_vec();

    // prepend payload tag of zero bytes
    let mut _payload = vec![0u8; PAYLOAD_TAG_SIZE];
    _payload.extend(payload.iter());

    // encrypt tagged payload with SPRP
    while i >= 0 {
        let _result = sprp_encrypt(&sprp_keys[i as usize].key, &sprp_keys[i as usize].iv, _payload.clone());
        if _result.is_err() {
            return Err(SphinxPacketCreateError::SPRPEncryptError);
        }
        _payload = _result.unwrap();
        i -= 1;
    }

    // attached Sphinx head to Sphinx body
    let mut packet = [0u8; PACKET_SIZE];
    packet[0..HEADER_SIZE].copy_from_slice(&header);
    packet[HEADER_SIZE..].copy_from_slice(&_payload);
    return Ok(packet);
}

/// create a new SURB
///
/// # Arguments
///
/// * `rng` - an implementation of Rng, a random number generator.
/// * `path` - a vector of path hops.
///
/// # Returns
///
/// * Returns a header and a vector of keys or an error.
///
pub fn new_surb<R: Rng>(rng: &mut R, path: Vec<PathHop>) -> Result<([u8; SURB_SIZE], Vec<u8>), SphinxSurbCreateError> {
    // Create a random SPRP key + iv for the recipient to use to encrypt
    // the payload when using the SURB.
    let _path_len = path.len();
    let mut key_payload = [0u8; SPRP_KEY_MATERIAL_SIZE];
    rng.fill_bytes(&mut key_payload);
    let mut _id = [0u8; NODE_ID_SIZE];
    _id.copy_from_slice(&path[0].id[..]);
    let _header_result = create_header(rng, path);
    if _header_result.is_err() {
        return Err(SphinxSurbCreateError::CreateHeaderError);
    }
    let _tmp = _header_result.unwrap();
    let header = _tmp.0;
    let mut sprp_keys = _tmp.1;

    // Serialize the SPRP keys into an opaque blob, in reverse order to ease
    // decryption.
    let mut k: Vec<u8> = Vec::new();
    let mut i = (_path_len - 1) as i8;
    while i >= 0 {
        k.extend(sprp_keys[i as usize].key.iter());
        k.extend(sprp_keys[i as usize].iv.iter());
        sprp_keys[i as usize].reset();
        i -= 1;
    }
    k.extend(key_payload.iter());

    // Serialize the SURB into an opaque blob.
    let mut _surb: Vec<u8> = vec![];
    _surb.extend(header.iter());
    _surb.extend(_id.iter());
    _surb.extend(key_payload[..].iter());
    let mut surb = [0u8; SURB_SIZE];
    surb.copy_from_slice(_surb.as_slice());

    return Ok((surb, k));
}

/// create a sphinx packet from a SURB and payload
///
/// # Arguments
///
/// * `surb` - a SURB.
/// * `payload` - a payload to be encapsulated.
///
/// # Returns
///
/// * Returns a header and a vector of keys or an error.
///
pub fn new_packet_from_surb(surb: [u8; SURB_SIZE], payload: [u8; FORWARD_PAYLOAD_SIZE]) -> Result<([u8; PACKET_SIZE], [u8; NODE_ID_SIZE]), SphinxPacketFromSurbError>{
    // Deserialize the SURB.
    let (header, id, key, iv) = array_refs![&surb, HEADER_SIZE, NODE_ID_SIZE, SPRP_KEY_SIZE, SPRP_IV_SIZE];

    // Assemble the packet.
    let mut packet = [0u8; PACKET_SIZE];
    packet[..HEADER_SIZE].copy_from_slice(header);

    // Encrypt the payload.
    let mut crypt_payload = [0u8; PAYLOAD_SIZE];
    crypt_payload[PAYLOAD_TAG_SIZE..].copy_from_slice(&payload[..]);
    let _result = sprp_encrypt(key, iv, crypt_payload[..].to_vec());
    if _result.is_err() {
        return Err(SphinxPacketFromSurbError::ImpossibleError);
    }
    packet[HEADER_SIZE..].copy_from_slice(_result.unwrap().as_slice());
    return Ok((packet, *id));
}

/// decrypt a SURB reply payload
///
/// # Arguments
///
/// * `payload` - a payload to be decrypted.
/// * `keys` - a vector of key material.
///
/// # Returns
///
/// * Returns a decrypted payload or an error.
///
pub fn decrypt_surb_payload(payload: [u8; PAYLOAD_SIZE], keys: Vec<u8>) -> Result<Vec<u8>, SphinxDecryptSurbError> {
    assert!(keys.len() % SPRP_KEY_MATERIAL_SIZE == 0);
    let num_hops = keys.len() / SPRP_KEY_MATERIAL_SIZE;
    if keys.len() % SPRP_KEY_MATERIAL_SIZE != 0 || num_hops < 1 {
        return Err(SphinxDecryptSurbError::InvalidSurbKeys);
    }
    if payload.len() < PAYLOAD_TAG_SIZE {
        return Err(SphinxDecryptSurbError::TruncatedPayloadError);
    }
    let mut sprp_key = [0u8; SPRP_KEY_SIZE];
    let mut sprp_iv = [0u8; SPRP_IV_SIZE];
    let mut k = &keys[0..];
    let mut b = payload.to_vec();
    let mut i = 0;
    while i < num_hops {
        sprp_key.copy_from_slice(&k[..SPRP_KEY_SIZE]);
        sprp_iv.copy_from_slice(&k[SPRP_KEY_SIZE..SPRP_KEY_SIZE+SPRP_IV_SIZE]);
        k = &k[SPRP_KEY_SIZE+SPRP_IV_SIZE..];
        if i == num_hops - 1 {
            let _result = sprp_decrypt(&sprp_key, &sprp_iv, b.to_vec());
            if _result.is_err() {
                return Err(SphinxDecryptSurbError::DecryptError);
            }
            b = _result.unwrap();
        } else {
	    // Undo one *decrypt* operation done by the Unwrap.
            let _result = sprp_encrypt(&sprp_key, &sprp_iv, b.to_vec());
            if _result.is_err() {
                return Err(SphinxDecryptSurbError::DecryptError);
            }
            b = _result.unwrap();
        }
        i += 1;
    }

    // Authenticate the payload.
    let tag = [0u8; PAYLOAD_TAG_SIZE];
    if b[..PAYLOAD_TAG_SIZE].ct_eq(&tag).unwrap_u8() == 0 {
        return Err(SphinxDecryptSurbError::InvalidTag)
    }
    return Ok(b[PAYLOAD_TAG_SIZE..].to_vec());
}
