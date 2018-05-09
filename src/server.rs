// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use std::any::Any;
use subtle::ConstantTimeEq;

use super::commands::parse_routing_commands;
use super::constants::{PACKET_SIZE, PAYLOAD_SIZE, AD_SIZE, ROUTING_INFO_SIZE, V0_AD, PER_HOP_ROUTING_INFO_SIZE, PAYLOAD_TAG_SIZE};
use super::ecdh::{PublicKey, PrivateKey};
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
        Err(_) => {
            return (None, None, None, Some(SphinxUnwrapError::ImpossibleError))
        },
    };

    let shared_secret = private_key.exp(&group_element);
    let replay_tag_raw = hash(&group_element.as_array());
    let mut replay_tag = [0u8; HASH_SIZE];
    replay_tag.copy_from_slice(&replay_tag_raw);

    // Derive the various keys required for packet processing.
    let keys = kdf(&shared_secret);

    // Validate the Sphinx Packet Header.
    let mac_key = keys.header_mac;
    let mut _data = vec![];
    _data.extend(ad.iter());
    _data.extend(group_element_bytes.iter());
    _data.extend(routing_info.iter());
    let calculated_mac = hmac(&mac_key, &_data);

    // compare MAC in constant time
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
    let commands = parse_routing_commands(cmd_buf);
    let commands_tuple = match commands {
        Ok(cmds) => cmds,
        Err(_) => {
            return (None, Some(replay_tag), None, Some(SphinxUnwrapError::RouteInfoParseError))
        },
    };
    let (cmds, maybe_next_hop, maybe_surb_reply) = commands_tuple;

    // Decrypt the Sphinx Packet Payload.
    let m = sprp_decrypt(&keys.payload_encryption, &keys.payload_encryption_iv, payload.to_vec());
    let decrypted_payload = match m {
        Ok(x) => x,
        Err(_) => {
            return (None, Some(replay_tag), Some(cmds), Some(SphinxUnwrapError::PayloadDecryptError))
        },
    };

    // Transform the packet for forwarding to the next mix, iff the
    // routing commands vector included a Next Hop Command.
    let final_payload;
    let mut final_cmds = vec![];
    final_cmds.extend(cmds);
    if maybe_next_hop.is_some() {
        group_element.blind(&keys.blinding_factor);
        group_element_bytes.copy_from_slice(&group_element.as_array());
        routing_info.copy_from_slice(new_routing_info);
        let next_hop = maybe_next_hop.unwrap();
        mac.copy_from_slice(&next_hop.mac);
        payload.copy_from_slice(&decrypted_payload);
        final_payload = None;
        final_cmds.push(Box::new(next_hop));
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
            final_cmds.push(Box::new(maybe_surb_reply.unwrap()));
        }
    }

    return (final_payload, Some(replay_tag), Some(final_cmds), None);
}

#[cfg(test)]
mod tests {
    extern crate rand;
    //extern crate rustc_serialize;

    use std::any::Any;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    //use self::rustc_serialize::hex::ToHex;

    use super::sphinx_packet_unwrap;
    use super::super::ecdh::PrivateKey;
    use super::super::client::{new_packet, PathHop};
    use super::super::constants::{NUMBER_HOPS, NODE_ID_SIZE, FORWARD_PAYLOAD_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
    use super::super::commands::{Delay, Recipient, SURBReply, NextHop};


    struct NodeParams {
        pub id: [u8; NODE_ID_SIZE],
        pub private_key: PrivateKey,
    }

    fn os_rng() -> OsRng {
        OsRng::new().expect("failure to create an OS RNG")
    }

    fn new_node<R: Rng>(rng: &mut R) -> NodeParams {
        let mut id = [0u8; NODE_ID_SIZE];
        rng.fill_bytes(&mut id);
        let keypair = PrivateKey::generate(rng).unwrap();
        return NodeParams{
            id: id,
            private_key: keypair,
        };
    }

    fn new_path_vector<R: Rng>(rng: &mut R, num_hops: u8, is_surb: bool) -> (Vec<NodeParams>, Vec<PathHop>) {
        const DELAY_BASE: u32 = 123;

	// Generate the keypairs and node identifiers for the "nodes".
        let mut nodes = vec![];
        let mut i = 0;
        while i < num_hops {
            nodes.push(new_node(rng));
            i += 1;
        }

        // Assemble the path vector.
        let mut path = vec![];
        i = 0;
        while i < num_hops {
            let mut commands: Vec<Box<Any>> = vec![];
            if i < num_hops - 1 {
                // Non-terminal hop, add the delay.
                let delay = Delay {
                    delay: DELAY_BASE * (i as u32 + 1),
                };
                commands.push(Box::new(delay));
            } else {
		// Terminal hop, add the recipient.
                let mut rcpt_id = [0u8; RECIPIENT_ID_SIZE];
                rng.fill_bytes(&mut rcpt_id);
                let rcpt = Recipient {
                    id: rcpt_id,
                };
                commands.push(Box::new(rcpt));

                if is_surb {
                    let mut surb_id = [0u8; SURB_ID_SIZE];
                    rng.fill_bytes(&mut surb_id);
                    let surb_reply = SURBReply {
                        id: surb_id,
                    };
                    commands.push(Box::new(surb_reply));
                }
            }
            let hop = PathHop {
                id: nodes[i as usize].id,
                public_key: nodes[i as usize].private_key.public_key(),
                commands: Some(commands),
            };
            path.push(hop);
            i += 1;
        }
        return (nodes, path);
    }

    #[test]
    fn sphinx_forward_test() {
        let mut payload = [0u8; FORWARD_PAYLOAD_SIZE];
        let s = String::from("We must defend our own privacy if we expect to have any. \
We must come together and create systems which allow anonymous transactions to take place. \
People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
privacy, but electronic technologies do.");
        let _s_len = s.len();
        let string_bytes = s.into_bytes();
        payload[.._s_len].copy_from_slice(&string_bytes);

	// Generate the "nodes" and path for the forward sphinx packet.
        let mut r = os_rng();
        let is_surb = false;

        let mut num_hops = 1;
        while num_hops < NUMBER_HOPS {
            let _tuple = new_path_vector(&mut r, num_hops as u8, is_surb);
            let nodes = _tuple.0;
            let path = _tuple.1;

	    // Create the packet.
            let _packet_result = new_packet(&mut r, path, payload);
            let mut packet = _packet_result.unwrap();

            // Unwrap the packet, validating the output.
            let mut i = 0;
            while i < num_hops {
                let _unwrap_tuple = sphinx_packet_unwrap(&nodes[i].private_key, &mut packet);
                let option_cmds = _unwrap_tuple.2;
                let err = _unwrap_tuple.3;
                let final_payload = _unwrap_tuple.0;
                let cmds = option_cmds.unwrap();

                assert!(err.is_none());
                if i == nodes.len() - 1 {
                    assert!(cmds.len() == 1);
                    assert_eq!(final_payload.unwrap().as_slice(), &payload[..]);
                    assert!(cmds[0].downcast_ref::<Recipient>().is_some());
                } else {
                    assert!(cmds.len() == 2);
                    assert!(final_payload.is_none());
                    assert!(cmds[0].downcast_ref::<Delay>().is_some());
                }
                i += 1;
            }
            num_hops += 1;
        }

    } // end of fn sphinx_packet_unwrap_test() {

} // tests
