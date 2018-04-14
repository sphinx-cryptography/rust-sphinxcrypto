// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use std::any::Any;
use subtle::ConstantTimeEq;

use super::commands::parse_routing_commands;
use super::constants::{PACKET_SIZE, PAYLOAD_SIZE, AD_SIZE, ROUTING_INFO_SIZE, V0_AD, PER_HOP_ROUTING_INFO_SIZE, PAYLOAD_TAG_SIZE};
use super::ecdh::{PublicKey, PrivateKey};
use super::error::SphinxUnwrapError;
use super::internal_crypto::{HASH_SIZE, SPRP_IV_SIZE, MAC_SIZE, GROUP_ELEMENT_SIZE, StreamCipher, hash, kdf, hmac, sprp_decrypt};

const GROUP_ELEMENT_OFFSET: usize = AD_SIZE;
const ROUTING_INFO_OFFSET: usize = GROUP_ELEMENT_OFFSET + GROUP_ELEMENT_SIZE;
const MAC_OFFSET: usize = ROUTING_INFO_OFFSET + ROUTING_INFO_SIZE;


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
/// * 3-tuple containing (payload, replay_tag, vector of routing commands) || SphinxUnwrapError
///
pub fn sphinx_packet_unwrap(private_key: &PrivateKey, packet: &mut [u8; PACKET_SIZE]) -> (Option<Vec<u8>>, Option<[u8; HASH_SIZE]>, Option<Vec<Box<Any>>>, Option<SphinxUnwrapError>) {
    // Split into mutable references and validate the AD
    let (authed_header, mac, payload) = mut_array_refs![packet, MAC_OFFSET, MAC_SIZE, PAYLOAD_SIZE];
    let (ad, group_element_bytes, routing_info) = mut_array_refs![authed_header, AD_SIZE, GROUP_ELEMENT_SIZE, ROUTING_INFO_SIZE];
    if ad.ct_eq(&V0_AD).unwrap_u8() == 0 {
        return (None, None, None, Some(SphinxUnwrapError::InvalidPacketError));
    }

    // Calculate the hop's shared secret, and replay_tag.
    let mut group_element = PublicKey::default();
    let m = group_element.from_bytes(group_element_bytes);
    match m {
        Ok(_) => {},
        Err(_) => return (None, None, None, Some(SphinxUnwrapError::ImpossibleError)),
    };
    let shared_secret = private_key.exp(&group_element);
    let replay_tag_raw = hash(&group_element.to_vec());
    let mut replay_tag = [0u8; HASH_SIZE];
    replay_tag.copy_from_slice(&replay_tag_raw);

    // Derive the various keys required for packet processing.
    let keys = kdf(&shared_secret);

    // Validate the Sphinx Packet Header.
    let mac_key = keys.header_mac;
    let calculated_mac = hmac(&mac_key, mac);
    if calculated_mac.ct_eq(mac).unwrap_u8() == 0 {
        return (None, Some(replay_tag), None, Some(SphinxUnwrapError::MACError));
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
        Err(_) => return (None, Some(replay_tag), Some(cmds), Some(SphinxUnwrapError::RouteInfoParseError)),
    };
    let (cmds, maybe_next_hop, maybe_surb_reply) = commands_tuple;

    // Decrypt the Sphinx Packet Payload.
    let sprp_iv = [0u8; SPRP_IV_SIZE];
    let m = sprp_decrypt(&keys.payload_encryption, &sprp_iv, payload.to_vec());
    let decrypted_payload = match m {
        Ok(payload) => payload,
        Err(_) => return (None, Some(replay_tag), Some(cmds), Some(SphinxUnwrapError::PayloadDecryptError)),
    };

    // Transform the packet for forwarding to the next mix, iff the
    // routing commands vector included a Next Hop Command.
    let final_payload;
    if maybe_next_hop.is_some() {
        group_element.blind(&keys.blinding_factor);
        group_element_bytes.copy_from_slice(&group_element.as_array());
        routing_info.copy_from_slice(new_routing_info);
        mac.copy_from_slice(&maybe_next_hop.unwrap().mac);
        payload.copy_from_slice(&decrypted_payload);
        final_payload = None;
    } else {
        // Validate the payload tag, iff this is not a SURB reply.
        if !maybe_surb_reply.is_some() {
            let zeros = [0u8; PAYLOAD_TAG_SIZE];
            if zeros != decrypted_payload[..PAYLOAD_TAG_SIZE] {
                return (None, Some(replay_tag), None, Some(SphinxUnwrapError::PayloadError));
            }
            final_payload = Some(decrypted_payload[PAYLOAD_TAG_SIZE..].to_vec());
        } else {
            final_payload = Some(decrypted_payload);
        }
    }

    return (final_payload, Some(replay_tag), Some(cmds), None);
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use self::rand::Rng;
    use self::rand::os::OsRng;
    use subtle::ConstantTimeEq;
    //use self::rustc_serialize::hex::ToHex;

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
