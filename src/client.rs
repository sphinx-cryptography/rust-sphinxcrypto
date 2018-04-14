// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use std::any::Any;

use super::constants::{NODE_ID_SIZE};
use super::internal_crypto::{SPRP_KEY_SIZE, SPRP_IV_SIZE};
use super::ecdh::{PublicKey};

// PathHop describes a hop that a Sphinx Packet will traverse, along with
// all of the per-hop Commands (excluding the Next Hop command).
pub struct PathHop {
    id: [u8; NODE_ID_SIZE],
    public_key: PublicKey,
    commands: Option<Vec<Box<Any>>>,
}

struct SprpKey {
    key: [u8; SPRP_KEY_SIZE],
    iv: [u8; SPRP_IV_SIZE],
}

impl SprpKey {
    fn reset(&mut self) {
        self.key = [0u8; SPRP_KEY_SIZE];
        self.iv = [0u8; SPRP_IV_SIZE];
    }
}

