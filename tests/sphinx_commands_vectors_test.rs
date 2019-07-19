// sphinx_test.rs - sphinx cryptographic packet format tests
// Copyright (C) 2019  David Stainton.

extern crate rand;
extern crate sphinxcrypto;
extern crate ecdh_wrapper;
extern crate rustc_serialize;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate hex;

use sphinxcrypto::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
use sphinxcrypto::commands::{NextHop, Delay, SURBReply, Recipient};

use std::fs::File;
use std::io::Read;

pub const MAC_SIZE: usize = 16;

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct SphinxCommandsTest {
    NextHopID: String,
    NextHopMAC: String,
    NextHopCmdWant: String,
    RecipientID: String,
    RecipientCmdWant: String,
    SURBReplyID: String,
    SURBReplyCmdWant: String,
    NodeDelay: u32,
    NodeDelayCmdWant: String,
}

#[test]
fn sphinx_command_vector_test() {
    let mut file = File::open("sphinx_commands_vectors.json").unwrap();
    let mut vectors = String::new();
    file.read_to_string(&mut vectors).unwrap();
    let tests: SphinxCommandsTest = serde_json::from_str(&vectors).unwrap();

    // Next Hop command
    let next_hop_id = hex::decode(tests.NextHopID).unwrap();
    let next_hop_mac = hex::decode(tests.NextHopMAC).unwrap();
    let mut node_id = [0u8; NODE_ID_SIZE];
    node_id.copy_from_slice(&next_hop_id);
    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(&next_hop_mac);
    let next_hop_cmd = NextHop{
        id: node_id,
        mac: mac,
    };
    let next_hop_cmd_want = hex::decode(tests.NextHopCmdWant).unwrap();
    assert_eq!(next_hop_cmd_want, next_hop_cmd.to_vec());

    // Recipient command
    let recipient_id = hex::decode(tests.RecipientID).unwrap();
    let mut rcpt_id = [0u8; RECIPIENT_ID_SIZE];
    rcpt_id.copy_from_slice(&recipient_id);
    let recipient = Recipient{
        id: rcpt_id,
    };
    let recipient_cmd_want = hex::decode(tests.RecipientCmdWant).unwrap();
    assert_eq!(recipient_cmd_want, recipient.to_vec());

    // SURB Reply command
    let reply_id = hex::decode(tests.SURBReplyID).unwrap();
    let mut surb_reply_id = [0u8; SURB_ID_SIZE];
    surb_reply_id.copy_from_slice(&reply_id);
    let surb_reply = SURBReply{
        id: surb_reply_id,
    };
    let surb_reply_cmd_want = hex::decode(tests.SURBReplyCmdWant).unwrap();
    assert_eq!(surb_reply_cmd_want, surb_reply.to_vec());

    // Delay command
    let node_delay = Delay{
        delay: tests.NodeDelay,
    };
    let delay_cmd_want = hex::decode(tests.NodeDelayCmdWant).unwrap();
    assert_eq!(delay_cmd_want, node_delay.to_vec());
    
}
