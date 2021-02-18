// sphinx.rs - Sphinx server side function(s)
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

//! an excerpt from **[Sphinx Mix Network Cryptographic Packet Format Specification](https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst#sphinx-packet-processing)**:
//! """
//! An implementation of the server-side of Sphinx, packet processing.
//! Mix nodes process incoming packets first by performing the
//! Sphinx Packet Unwrap operation to authenticate and decrypt the packet, and
//! if applicable prepare the packet to be forwarded to the next node.
//!
//! If the Sphinx Packet Unwrap operation returns an error for any given packet, the packet
//! MUST be discarded with no additional processing.
//!
//! After a packet has been unwrapped successfully, a replay detection
//! tag is checked to ensure that the packet has not been seen before.
//! If the packet is a replay, the packet MUST be discarded with no
//! additional processing.
//!
//! The routing commands for the current hop are interpreted and
//! executed, and finally the packet is forwarded to the next mix node
//! over the network or presented to the application if the current
//! node is the final recipient.
//! """


use subtle::ConstantTimeEq;
use x25519_dalek_ng::{StaticSecret, PublicKey};

use super::commands::{RoutingCommand, parse_routing_commands};
use super::constants::{AD_SIZE, ROUTING_INFO_SIZE, V0_AD, PER_HOP_ROUTING_INFO_SIZE, PAYLOAD_TAG_SIZE};
use super::error::SphinxUnwrapError;
use super::internal_crypto::{HASH_SIZE, MAC_SIZE, GROUP_ELEMENT_SIZE, StreamCipher, hash, kdf, hmac, sprp_decrypt};

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
/// * 4-tuple containing (payload, replay_tag, vector of routing commands, SphinxUnwrapError)
///
pub fn sphinx_packet_unwrap(private_key: &StaticSecret, packet: &mut [u8]) -> (Option<Vec<u8>>, Option<[u8; HASH_SIZE]>, Option<Vec<RoutingCommand>>, Option<SphinxUnwrapError>) {
    // Split into mutable references and validate the AD
    let (header, payload) = packet.split_at_mut(MAC_OFFSET+MAC_SIZE);
    let (authed_header, _mac) = header.split_at_mut(MAC_OFFSET);
    let (ad, _after_ad) = authed_header.split_at_mut(AD_SIZE);
    let after_ad = array_mut_ref![_after_ad, 0, GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE];
    let (group_element_bytes, routing_info) = mut_array_refs![after_ad, GROUP_ELEMENT_SIZE, ROUTING_INFO_SIZE];

    if ad.ct_eq(&V0_AD).unwrap_u8() == 0 {
        return (None, None, None, Some(SphinxUnwrapError::InvalidPacketError));
    }

    // Calculate the hop's shared secret, and replay_tag.
    let mut group_element = PublicKey::from(*group_element_bytes);
    let shared_secret = private_key.diffie_hellman(&group_element);
    let replay_tag_raw = hash(group_element.as_bytes());
    let mut replay_tag = [0u8; HASH_SIZE];
    replay_tag[..].copy_from_slice(&replay_tag_raw);

    // Derive the various keys required for packet processing.
    let keys = kdf(shared_secret.as_bytes());

    // Validate the Sphinx Packet Header.
    let mac_key = keys.header_mac;
    let mut _data = vec![];
    _data.extend(ad.iter());
    _data.extend(group_element_bytes.iter());
    _data.extend(routing_info.iter());
    let calculated_mac = hmac(&mac_key, &_data);

    // compare MAC in constant time
    if calculated_mac.ct_eq(_mac).unwrap_u8() == 0 {
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
    let commands = parse_routing_commands(cmd_buf);
    let commands_tuple = match commands {
        Ok(cmds) => cmds,
        Err(_) => {
            return (None, Some(replay_tag), None, Some(SphinxUnwrapError::RouteInfoParseError))
        },
    };
    let (cmds, maybe_next_hop, maybe_surb_reply) = commands_tuple;

    // Decrypt the Sphinx Packet Payload.
    let mut p = vec![0u8; payload.len()];
    p.copy_from_slice(&payload[..]);
    let decrypted_payload = match sprp_decrypt(&keys.payload_encryption, &keys.header_encryption_iv, payload.to_vec())
    {
        Ok(x) => x,
        Err(_) => {
            return (None, Some(replay_tag), Some(cmds), Some(SphinxUnwrapError::PayloadDecryptError))
        }
    };

    // Transform the packet for forwarding to the next mix, iff the
    // routing commands vector included a Next Hop Command.
    let final_payload;
    let mut final_cmds = vec![];
    final_cmds.extend(cmds);
    if maybe_next_hop.is_some() {
        group_element.blind(keys.blinding_factor);
        group_element_bytes.copy_from_slice(group_element.as_bytes());
        routing_info.copy_from_slice(new_routing_info);
        let next_hop = maybe_next_hop.unwrap();
        match next_hop {
            RoutingCommand::NextHop(next_hop_cmd) => {
                _mac.copy_from_slice(&next_hop_cmd.mac);
                final_cmds.push(RoutingCommand::NextHop(next_hop_cmd));
            },
            _ => unreachable!(),
        }
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
            final_cmds.push(maybe_surb_reply.unwrap());
        }
    }

    return (final_payload, Some(replay_tag), Some(final_cmds), None);
}
