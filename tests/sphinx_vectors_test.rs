// sphinx_vectors_test.rs - sphinx cryptographic packet format vector tests
// Copyright (C) 2019  David Stainton.

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;
extern crate hex;
extern crate sphinxcrypto;
extern crate ecdh_wrapper;

use std::fs::File;
use std::io::Read;

use ecdh_wrapper::{PublicKey, PrivateKey};

use sphinxcrypto::server::sphinx_packet_unwrap;


#[derive(Deserialize, Debug)]
struct HexNodeParams {
    ID: String,
    PrivateKey: String,
}

#[derive(Deserialize, Debug)]
struct HexPathHop {
    ID: String,
    PublicKey: String,
    Commands: Vec<String>,
}

#[derive(Deserialize, Debug)]
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
            let node_keypair = PrivateKey::from_bytes(&hex::decode(&tests[i].Nodes[j].PrivateKey).unwrap()).unwrap();
            let (payload, tag, commands, err) = sphinx_packet_unwrap(&node_keypair, &mut packet);
            //assert!(err.is_none());
            eprintln!("Sphinx Unwrap error: {:?}", err);
            j += 1;
        }
        i += 1;
    }
}
