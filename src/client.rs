// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

extern crate ecdh_wrapper;

use std::any::Any;

use super::constants::{NODE_ID_SIZE, HEADER_SIZE, NUMBER_HOPS};
use super::internal_crypto::{SPRP_KEY_SIZE, SPRP_IV_SIZE, GROUP_ELEMENT_SIZE, PacketKeys, kdf};
use self::ecdh_wrapper::{PublicKey, PrivateKey, exp};

/// PathHop describes a route hop that a Sphinx Packet will traverse,
/// along with all of the per-hop Commands (excluding the Next Hop
/// command).
pub struct PathHop {
    id: [u8; NODE_ID_SIZE],
    public_key: PublicKey,
    commands: Option<Vec<Box<Any>>>,
}

pub struct SprpKey {
    pub key: [u8; SPRP_KEY_SIZE],
    pub iv: [u8; SPRP_IV_SIZE],
}

impl SprpKey {
    fn reset(&mut self) {
        self.key = [0u8; SPRP_KEY_SIZE];
        self.iv = [0u8; SPRP_IV_SIZE];
    }
}

pub fn create_header(path: Vec<PathHop>) -> Result<([u8; HEADER_SIZE], [SprpKey; NUMBER_HOPS]), &'static str> {
    let num_hops = path.len();
    if num_hops > NUMBER_HOPS {
        return Err("sphinx: path too long");
    }

    // Derive the key material for each hop.
    let keypair = PrivateKey::generate()?;
    let mut group_elements: Vec<PublicKey> = vec![];
    let mut keys: Vec<PacketKeys> = vec![];
    let mut shared_secret: [u8; GROUP_ELEMENT_SIZE] = keypair.exp(&path[0].public_key);
    keys.push(kdf(&shared_secret));
    let mut group_element = PublicKey::default();
    group_element.from_bytes(&keypair.public_key().to_vec());
    group_elements.push(group_element);

    let mut i = 1;
    while i < NUMBER_HOPS {
        shared_secret = keypair.exp(&path[i].public_key);
        let mut j = 0;
        while j < i {
            shared_secret = exp(&shared_secret, &keys[j].blinding_factor);
            j += 1;
        }
        keys[i] = kdf(&shared_secret);
        keypair.public_key().blind(&keys[i-1].blinding_factor);
        group_elements[i].from_bytes(&keypair.public_key().to_vec());
        i += 1;
    }
    // XXX incomplete
    return Err("wtf");
}
