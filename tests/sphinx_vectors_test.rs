// sphinx_vectors_test.rs - sphinx cryptographic packet format vector tests
// Copyright (C) 2019  David Stainton.

#[macro_use]
extern crate arrayref;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate hex;
extern crate x25519_dalek_ng;
extern crate sphinxcrypto;


use std::fs::File;
use std::io::Read;

use x25519_dalek_ng::{StaticSecret};

use sphinxcrypto::server::sphinx_packet_unwrap;
use sphinxcrypto::commands::RoutingCommand;
use sphinxcrypto::client::decrypt_surb_payload;


#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct HexNodeParams {
    ID: String,
    PrivateKey: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct HexPathHop {
    ID: String,
    PublicKey: String,
    Commands: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct HexSphinxTest {
    Nodes: Vec<HexNodeParams>,
    Path: Vec<HexPathHop>,
    Packets: Vec<String>,
    Payload: String,
    Surb: String,
    SurbKeys: String,
}


#[test]
fn sphinx_vector_test() {
    let mut file = File::open("sphinx_vectors.json").unwrap();
    let mut vectors = String::new();
    file.read_to_string(&mut vectors).unwrap();
    let tests: Vec<HexSphinxTest> = serde_json::from_str(&vectors).unwrap();

    let mut i = 0;
    while i < tests.len() {
        let mut j = 0;
        let mut packet: Vec<u8> = Vec::new();
        packet.extend(hex::decode(&tests[i].Packets[0]).unwrap());
        while j < tests[i].Nodes.len() {
            let private_key_bytes = hex::decode(&tests[i].Nodes[j].PrivateKey).unwrap();
            let private_key_array = array_ref![private_key_bytes, 0, 32];
            let node_keypair = StaticSecret::from(*private_key_array);
            let (payload, _tag, commands, err) = sphinx_packet_unwrap(&node_keypair, &mut packet);
            assert!(err.is_none());
            if j == tests[i].Path.len()-1 {
                // last hop
                if tests[i].Surb.len() > 0 {
                    let commands = commands.unwrap();
                    assert_eq!(2, commands.len());
                    assert_eq!(commands[0].to_vec(), hex::decode(&tests[i].Path[j].Commands[0]).unwrap());
                    assert_eq!(commands[1].to_vec(), hex::decode(&tests[i].Path[j].Commands[1]).unwrap());
                    let plaintext = decrypt_surb_payload(payload.unwrap(), hex::decode(&tests[i].SurbKeys).unwrap()).unwrap();
                    assert_eq!(plaintext, hex::decode(&tests[i].Payload).unwrap());
                } else {
                    let commands = commands.unwrap();
                    assert_eq!(1, commands.len());
                    assert_eq!(commands[0].to_vec(), hex::decode(&tests[i].Path[j].Commands[0]).unwrap());
                    assert_eq!(payload.unwrap(), hex::decode(&tests[i].Payload).unwrap());
                }
            } else {
                // not last hop
                let commands = commands.unwrap();
                assert_eq!(packet, hex::decode(&tests[i].Packets[j+1]).unwrap());
                assert_eq!(2, commands.len());
                assert_eq!(commands[0].to_vec(), hex::decode(&tests[i].Path[j].Commands[0]).unwrap());
                if let RoutingCommand::NextHop(n) = &commands[1] {
                    assert_eq!(hex::decode(&tests[i].Path[j+1].ID).unwrap(), n.id);
                } else {
                    panic!("next hop command not found");
                }
            }

            j += 1;
        }
        i += 1;
    }
}
