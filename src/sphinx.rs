// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use std::any::Any;
use subtle::ConstantTimeEq;

use super::commands::{RoutingCommand, RECIPIENT_SIZE, SURB_REPLY_SIZE, parse_routing_commands};
use super::constants::{NUMBER_HOPS, PACKET_SIZE, FORWARD_PAYLOAD_SIZE, PAYLOAD_SIZE};
use super::ecdh::{CURVE25519_SIZE, PublicKey, PrivateKey};
use super::error::SphinxUnwrapError;
use super::internal_crypto::{HASH_SIZE, SPRP_IV_SIZE, MAC_SIZE, GROUP_ELEMENT_SIZE, StreamCipher, hash, kdf, hmac, sprp_decrypt};


const PER_HOP_ROUTING_INFO_SIZE: usize = RECIPIENT_SIZE + SURB_REPLY_SIZE;
const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * NUMBER_HOPS;
const AD_SIZE: usize = 2;
pub const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;
pub const PAYLOAD_TAG_SIZE: usize = 16;

const V0_AD: [u8; 2] = [0u8; 2];
const ZERO_BYTES: [u8; PER_HOP_ROUTING_INFO_SIZE] = [0u8; PER_HOP_ROUTING_INFO_SIZE];

const GROUP_ELEMENT_OFFSET: usize = AD_SIZE;
const ROUTING_INFO_OFFSET: usize = GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE;
const MAC_OFFSET: usize = ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE;
const PAYLOAD_OFFSET: usize = MAC_OFFSET + MAC_SIZE;


/// unwrap a layer of sphinx packet encryption
///
/// # Arguments
///
/// * `private_key` - an ecdh private key
/// * `packet` - a mutable reference to a Sphinx packet gets updated to the
///    new Sphinx packet to be sent to the next hop.
///
/// # Returns
///
/// * 3-tuple containing (payload, replay_tag, vector of routing commands) || Error string
///
pub fn sphinx_packet_unwrap(private_key: &PrivateKey, packet: &mut [u8; PACKET_SIZE]) -> Result<(Option<[u8; FORWARD_PAYLOAD_SIZE]>, [u8; HASH_SIZE], Vec<Box<Any>>), &'static str> {
    // Split into mutable references and validate the AD
    let (authed_header, mac, payload) = mut_array_refs![packet, MAC_OFFSET, MAC_SIZE, PAYLOAD_SIZE];
    let (ad, group_element_bytes, routing_info) = mut_array_refs![authed_header, AD_SIZE, GROUP_ELEMENT_SIZE, ROUTING_INFO_SIZE];
    if ad.ct_eq(&V0_AD).unwrap_u8() == 0 {
        return Err("sphinx: invalid packet, unknown version");
    }

    // Calculate the hop's shared secret, and replay_tag.
    let mut group_element = PublicKey::default();
    group_element.from_bytes(group_element_bytes)?;
    let shared_secret = private_key.exp(&group_element);
    let replay_tag_raw = hash(&group_element.to_vec());
    let mut replay_tag = [0u8; HASH_SIZE];
    for (l, r) in replay_tag.iter_mut().zip(replay_tag_raw[..].iter()) {
        *l = *r;
    }

    // Derive the various keys required for packet processing.
    let keys = kdf(&shared_secret);

    // Validate the Sphinx Packet Header.
    let mac_key = keys.header_mac;
    let calculated_mac = hmac(&mac_key, mac);
    if calculated_mac.ct_eq(mac).unwrap_u8() == 0 {
        return Err("sphinx: invalid packet, MAC mismatch");
    }

    // Append padding to preserve length invariance, decrypt the (padded)
    // routing_info block, and extract the section for the current hop.
    let mut stream_cipher = StreamCipher::new(&keys.header_encryption, &keys.header_encryption_iv);
    let mut a = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
    let mut b = [0u8; ROUTING_INFO_SIZE + PER_HOP_ROUTING_INFO_SIZE];
    a[..ROUTING_INFO_SIZE].clone_from_slice(routing_info);
    stream_cipher.xor_key_stream(&mut b, &a);
    let new_routing_info = &b[PER_HOP_ROUTING_INFO_SIZE..];
    let cmd_buf = &b[..PER_HOP_ROUTING_INFO_SIZE];

    // Parse the per-hop routing commands.
    let cmds = Vec::new();
    let commands = parse_routing_commands(cmd_buf);
    let commands_tuple = match commands {
        Ok(cmds) => cmds,
        Err(error) => return Ok((None, replay_tag, cmds)),
    };
    let (cmds, maybe_next_hop, maybe_surb_reply) = commands_tuple;

    // Decrypt the Sphinx Packet Payload.
    let sprp_iv = [0u8; SPRP_IV_SIZE];
    let decrypted_payload = sprp_decrypt(&keys.payload_encryption, &sprp_iv, payload.to_vec());

    // Transform the packet for forwarding to the next mix, iff the
    // routing commands vector included a NextNodeHopCommand.
    let mut final_payload: Option<[u8; FORWARD_PAYLOAD_SIZE]> = None;
    if maybe_next_hop.is_some() {
        group_element.blind(&keys.blinding_factor);
        group_element_bytes.copy_from_slice(&group_element.as_array());
        routing_info.copy_from_slice(new_routing_info);
        mac.copy_from_slice(&maybe_next_hop.unwrap().mac);
        payload.copy_from_slice(&decrypted_payload);
    } else {
        // Validate the payload tag, iff this is not a SURB reply.
        if !maybe_surb_reply.is_some() {
            let zeros = [0u8; PAYLOAD_TAG_SIZE];
            if zeros != decrypted_payload[..PAYLOAD_TAG_SIZE] {
                return Err("payload validation tag mismatch failure");
            }
            let mut p = [0u8; FORWARD_PAYLOAD_SIZE];
            p.copy_from_slice(&decrypted_payload[PAYLOAD_TAG_SIZE..]);
            final_payload = Some(p);
        }
    }

    return Ok((final_payload, replay_tag, cmds));
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
