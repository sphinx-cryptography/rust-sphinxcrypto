// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx crypto primitives

extern crate crypto;

use crypto::curve25519::{curve25519};

pub const CURVE25519_SIZE: usize = 32;

/// Group operations in the curve25519
#[derive(Clone, Copy)]
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

    /// Perform scalar multiplication on curve25519
    pub fn exp_on(self, base: &[u8], n: &[u8]) -> [u8; CURVE25519_SIZE] {
        let mut e = [0u8; 32];
        for (d,s) in e.iter_mut().zip(n.iter()) {
            *d = *s;
        }
        e[0] &= 248;
        e[31] &= 127;
        e[31] |= 64;
        curve25519(e.as_ref(), base.as_ref())
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
        let mut curve2 = "4171bd9a48a58cf7579e9fa662fe0ac2acb8c6eed3056cd970fd35dd4d026cae".from_hex().unwrap();

        let group = GroupCurve25519::new();
        let generator = group.g;
        let exp1 = group.exp_on(generator.as_ref(), curve1.as_slice().as_ref());
        let exp1 = group.exp_on(exp1.as_ref(), curve2.as_slice().as_ref());
        let exp2 = group.exp_on(generator.as_ref(), curve2.as_slice().as_ref());
        let exp2 = group.exp_on(exp2.as_ref(), curve1.as_slice().as_ref());

        assert!(exp1 == exp2);
        let want = "84b87479a6036249a18ef279b73db5a4811f641c50337ae3f21fb0be43cc8040".from_hex().unwrap();
        assert!(exp1 == want.as_slice());
    }
}
