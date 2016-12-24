// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx crypto primitives

extern crate crypto;

use crypto::curve25519::{Fe, curve25519_base};

pub const CURVE25519_SIZE: usize = 32;

/// Group operations in the curve25519
pub struct GroupCurve25519 {
    g: [u8; CURVE25519_SIZE],
}

impl GroupCurve25519 {
    fn new() -> GroupCurve25519 {
        GroupCurve25519 {
            g: [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    /// Perform scalar multiplication
    pub fn exp_on(self, base: [u8; CURVE25519_SIZE], exp: [u8; CURVE25519_SIZE]) -> [u8; CURVE25519_SIZE] {
        let out: [u8; CURVE25519_SIZE] = [0; 32];
        out
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    use super::*;
    use self::rustc_serialize::hex::{FromHex,ToHex};
    use crypto::curve25519::{Fe, curve25519};

    #[test]
    fn commutativity_test() {
        let mut curve1 = "82c8ad63392a5f59347b043e1244e68d52eb853921e2656f188d33e59a1410b4".from_hex().unwrap();
        curve1[0] &= 248;
        curve1[31] &= 127;
        curve1[31] |= 64;

        let mut curve2 = "4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae".from_hex().unwrap();
        curve2[0] &= 248;
        curve2[31] &= 127;
        curve2[31] |= 64;

        let g: &[u8; CURVE25519_SIZE] = &[9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let exp1 = curve25519(&curve1, g);
        let exp1 = curve25519(&curve2, &exp1);
        let exp2 = curve25519(&curve2, g);
        let exp2 = curve25519(&curve1, &exp2);
        assert!(exp1 == exp2);
        let want = "84b87479a6036249a18ef279b73db5a4811f641c50337ae3f21fb0be43cc8040".from_hex().unwrap();
        assert!(exp1 == want.as_slice());
    }
}
