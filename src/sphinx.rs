// sphinx.rs - sphinx cryptographic packet format
// Copyright (C) 2018  David Stainton.

use subtle::ConstantTimeEq;

use super::commands::RoutingCommand;
use super::ecdh::{CURVE25519_SIZE, PublicKey, PrivateKey};
use super::error::SphinxUnwrapError;
use super::internal_crypto::{MAC_SIZE};

/// unwrap a layer of sphinx packet encryption
///
/// # Arguments
///
/// * `private_key` - an ecdh private key
/// * `packet` - a sphinx packet
///
/// # Returns
///
/// * 3-tuple containing (payload, replay_tag, vector of routing commands) || SphinxUnwrapError
///
pub fn sphinx_packet_unwrap(private_key: &PrivateKey, packet: &[u8]) -> Result<(Vec<u8>, [u8; CURVE25519_SIZE], Vec<Box<RoutingCommand>>), SphinxUnwrapError> {
    let fu = [0u8; CURVE25519_SIZE];
    let zeros = vec![0u8; 3];
    let cmds = Vec::new();
    return Ok((zeros, fu, cmds))
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use self::rand::Rng;
    use self::rand::os::OsRng;
    use subtle::ConstantTimeEq;
    use self::rustc_serialize::hex::ToHex;

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
