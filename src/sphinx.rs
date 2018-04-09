// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use super::commands::RoutingCommand;
use super::ecdh::{CURVE25519_SIZE, PublicKey, PrivateKey};
use super::error::SphinxUnwrapError;

/// unwrap a layer of sphinx packet encryption
///
/// # Arguments
///
/// * `private_key` - an ecdh private key
/// * `packet` - a sphinx packet
///
/// # Returns
///
/// * 3-tuple containing (payload, replay_tag, vectory of routing commands)
///
pub fn sphinx_packet_unwrap(private_key: &PrivateKey, packet: &[u8]) -> Result<(Vec<u8>, [u8; CURVE25519_SIZE], Vec<Box<RoutingCommand>>), SphinxUnwrapError> {
    let fu = [0u8; CURVE25519_SIZE];
    let zeros = vec![0u8; 3];
    let mut cmds = Vec::new();
    return Ok((zeros, fu, cmds))
}
