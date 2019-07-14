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

use self::rand::Rng;
use self::rand::os::OsRng;
use ecdh_wrapper::PrivateKey;

use sphinxcrypto::server::sphinx_packet_unwrap;
use sphinxcrypto::client::{new_packet, PathHop, new_surb, new_packet_from_surb, decrypt_surb_payload};
use sphinxcrypto::constants::{MAX_HOPS, NODE_ID_SIZE, FORWARD_PAYLOAD_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE, PAYLOAD_SIZE};
use sphinxcrypto::commands::{NextHop, RoutingCommand, Delay, SURBReply, Recipient};

use std::fs::File;
use std::io::Read;

pub const MAC_SIZE: usize = 16;

#[derive(Deserialize, Debug)]
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
    let nextHopID = hex::decode(tests.NextHopID).unwrap();
    let nextHopMAC = hex::decode(tests.NextHopMAC).unwrap();
    let mut nodeID = [0u8; NODE_ID_SIZE];
    nodeID.copy_from_slice(&nextHopID);
    let mut mac = [0u8; MAC_SIZE];
    mac.copy_from_slice(&nextHopMAC);
    let nextHopCmd = NextHop{
        id: nodeID,
        mac: mac,
    };
    let nextHopCmdWant = hex::decode(tests.NextHopCmdWant).unwrap();
    assert_eq!(nextHopCmdWant, nextHopCmd.to_vec());

    // Recipient command
    let recipientID = hex::decode(tests.RecipientID).unwrap();
    let mut rcptID = [0u8; RECIPIENT_ID_SIZE];
    rcptID.copy_from_slice(&recipientID);
    let recipient = Recipient{
        id: rcptID,
    };
    let recipientCmdWant = hex::decode(tests.RecipientCmdWant).unwrap();
    assert_eq!(recipientCmdWant, recipient.to_vec());

    // SURB Reply command
    let replyID = hex::decode(tests.SURBReplyID).unwrap();
    let mut surbReplyID = [0u8; SURB_ID_SIZE];
    surbReplyID.copy_from_slice(&replyID);
    let surbReply = SURBReply{
        id: surbReplyID,
    };
    let surbReplyCmdWant = hex::decode(tests.SURBReplyCmdWant).unwrap();
    assert_eq!(surbReplyCmdWant, surbReply.to_vec());

    // Delay command
    let nodeDelay = Delay{
        delay: tests.NodeDelay,
    };
    let delayCmdWant = hex::decode(tests.NodeDelayCmdWant).unwrap();
    assert_eq!(delayCmdWant, nodeDelay.to_vec());
    
}
