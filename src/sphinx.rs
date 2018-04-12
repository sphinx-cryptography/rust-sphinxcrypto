// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use subtle::ConstantTimeEq;

use super::commands::{RoutingCommand, RECIPIENT_SIZE, SURB_REPLY_SIZE, parse_routing_cmmands};
use super::constants::{NUMBER_HOPS};
use super::ecdh::{CURVE25519_SIZE, PublicKey, PrivateKey};
use super::error::SphinxUnwrapError;
use super::internal_crypto::{SPRP_IV_SIZE, MAC_SIZE, GROUP_ELEMENT_SIZE, StreamCipher, hash, kdf, hmac, sprp_decrypt};


const PER_HOP_ROUTING_INFO_SIZE: usize = RECIPIENT_SIZE + SURB_REPLY_SIZE;
const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * NUMBER_HOPS;
const AD_SIZE: usize = 2;
const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;
const PAYLOAD_TAG_SIZE: usize = 16;

const V0_AD: [u8; 2] = [0u8; 2];
const ZERO_BYTES: [u8; PER_HOP_ROUTING_INFO_SIZE] = [0u8; PER_HOP_ROUTING_INFO_SIZE];

const GROUP_ELEMENT_OFFSET: usize = 2;
const ROUTING_INFO_OFFSET: usize = GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE;
const MAC_OFFSET: usize = ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE;
const PAYLOAD_OFFSET: usize = MAC_OFFSET + MAC_SIZE;


/// unwrap a layer of sphinx packet encryption
///
/// # Arguments
///
/// * `private_key` - an ecdh private key
/// * `packet` - a sphinx packet
///
/// # Returns
///
/// * 3-tuple containing (payload, replay_tag, vector of routing commands) || Error string
///
pub fn sphinx_packet_unwrap(private_key: &PrivateKey, packet: &[u8]) -> Result<(Vec<u8>, [u8; CURVE25519_SIZE], Vec<Box<RoutingCommand>>), &'static str> {
    // Do some basic sanity checking, and validate the AD.
    if packet.len() < HEADER_SIZE {
        return Err("sphinx: invalid packet, truncated");
    }
    if packet[..2].ct_eq(&V0_AD).unwrap_u8() == 0 {
        return Err("sphinx: invalid packet, unknown version");
    }

    // Calculate the hop's shared secret, and replay_tag.
    let mut group_element = PublicKey::default();
    group_element.from_bytes(&packet[GROUP_ELEMENT_OFFSET..ROUTING_INFO_OFFSET])?;
    let shared_secret = private_key.exp(&group_element);
    let replay_tag_raw = hash(&group_element.to_vec());
    let mut replay_tag = [0u8; CURVE25519_SIZE];
    for (l, r) in replay_tag.iter_mut().zip(replay_tag_raw[..].iter()) {
        *l = *r;
    }

    // Derive the various keys required for packet processing.
    let keys = kdf(&shared_secret);

    // Validate the Sphinx Packet Header.
    let mac_key = keys.header_mac;
    let mac = hmac(&mac_key, &packet[..MAC_OFFSET]);
    if mac.ct_eq(&packet[MAC_OFFSET..MAC_OFFSET+MAC_SIZE]).unwrap_u8() == 0 {
        return Err("sphinx: invalid packet, MAC mismatch");
    }

    // Append padding to preserve length invariance, decrypt the (padded)
    // routing_info block, and extract the section for the current hop.
    let mut stream_cipher = StreamCipher::new(&keys.header_encryption, &keys.header_encryption_iv);
    let mut b = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
    stream_cipher.xor_key_stream(&mut b, &packet[ROUTING_INFO_OFFSET..ROUTING_INFO_OFFSET+ROUTING_INFO_SIZE]);
    let new_routing_info = &b[PER_HOP_ROUTING_INFO_SIZE..];
    let cmd_buf = &b[..PER_HOP_ROUTING_INFO_SIZE];

    let zeros = vec![0u8; 3];
    let cmds = Vec::new();

    // Parse the per-hop routing commands.
    let commands = parse_routing_cmmands(cmd_buf);
    let commands = match commands {
        Ok(cmds) => cmds,
        Err(error) => return Ok((zeros, replay_tag, cmds)),
    };

    // Decrypt the Sphinx Packet Payload.
    let payload = &packet[PAYLOAD_OFFSET..];
    let sprp_iv = [0u8; SPRP_IV_SIZE];
    let decrypted_payload = sprp_decrypt(&keys.payload_encryption, &sprp_iv, payload.to_vec());


    // XXX
    let fu = [0u8; CURVE25519_SIZE];
    return Ok((zeros, fu, cmds));
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use self::rand::Rng;
    use self::rand::os::OsRng;
    use subtle::ConstantTimeEq;
    use self::rustc_serialize::hex::ToHex;

    use super::super::internal_crypto::{MAC_SIZE};

    #[test]
    fn subtle_test() {
        let mut rnd = OsRng::new().unwrap();
        let mac1 = rnd.gen_iter::<u8>().take(MAC_SIZE).collect::<Vec<u8>>();
        let mac2 = rnd.gen_iter::<u8>().take(MAC_SIZE).collect::<Vec<u8>>();
        assert_eq!(mac1.ct_eq(&mac2).unwrap_u8(), 0);
        assert_eq!(mac1.ct_eq(&mac1).unwrap_u8(), 1);
    }
}
