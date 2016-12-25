// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mixnet packet crypto

extern crate crypto;

#[macro_use]
extern crate arrayref;

pub mod crypto_primitives;
pub use crypto_primitives::GroupCurve25519;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
