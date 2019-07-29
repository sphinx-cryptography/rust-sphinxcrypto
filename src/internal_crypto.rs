// internal_crypto.rs - internal cryptographic functions
// Copyright (C) 2018  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Sphinx crypto primitives

extern crate aez;
extern crate aes_ctr;
extern crate keystream;
extern crate hkdf;
extern crate sha2;
extern crate digest;
extern crate hmac;

use ecdh_wrapper::KEY_SIZE;
use self::aes_ctr::Aes128Ctr;
use self::aes_ctr::stream_cipher::NewStreamCipher;
use self::aes_ctr::stream_cipher::SyncStreamCipher;
use self::aez::aez::{encrypt, decrypt, AEZ_KEY_SIZE, AEZ_NONCE_SIZE};
use self::sha2::{Sha256, Digest, Sha512Trunc256};
use self::hkdf::Hkdf;
use self::hmac::{Hmac, Mac};

/// the output size of the unkeyed hash in bytes
pub const HASH_SIZE: usize = 32;

/// the key size of the MAC in bytes
pub const MAC_KEY_SIZE: usize = 32;

/// the output size of the MAC in bytes.
pub const MAC_SIZE: usize = 16;

/// the key size of the stream cipher in bytes.
pub const STREAM_KEY_SIZE: usize = 16;

/// the IV size of the stream cipher in bytes.
pub const STREAM_IV_SIZE: usize = 16;

/// the key size of the SPRP in bytes.
pub const SPRP_KEY_SIZE: usize = AEZ_KEY_SIZE;

/// the IV size of the SPRP in bytes.
/// STREAM_IV_SIZE == AEZ_NONCE_SIZE == 16 bytes
pub const SPRP_IV_SIZE: usize = AEZ_NONCE_SIZE;

/// the size of the DH group element in bytes.
pub const GROUP_ELEMENT_SIZE: usize = KEY_SIZE;

const KDF_OUTPUT_SIZE: usize = MAC_KEY_SIZE + STREAM_KEY_SIZE + STREAM_IV_SIZE + SPRP_KEY_SIZE + KEY_SIZE;

const KDF_INFO_STR: &str = "katzenpost-kdf-v0-hkdf-sha256";



/// stream cipher for sphinx crypto usage
pub struct StreamCipher {
    cipher: aes_ctr::Aes128Ctr,
}

impl StreamCipher {
    /// create a new StreamCipher struct
    pub fn new(raw_key: &[u8; STREAM_KEY_SIZE], raw_iv: &[u8; STREAM_IV_SIZE]) -> StreamCipher {
        use self::aes_ctr::stream_cipher::generic_array::GenericArray;
        let key = GenericArray::from_slice(&raw_key[..]);
        let iv = GenericArray::from_slice(raw_iv);
        StreamCipher {
            cipher: Aes128Ctr::new(&key, &iv),
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        let mut output = vec![0u8; n];
        self.cipher.apply_keystream(&mut output);
        output
    }

    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
        self.cipher.apply_keystream(dst);
    }
}

/// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
/// DH key exchange.
pub struct PacketKeys {
    pub header_mac: [u8; MAC_KEY_SIZE],
    pub header_encryption: [u8; STREAM_KEY_SIZE],
    pub header_encryption_iv: [u8; STREAM_IV_SIZE],
    pub payload_encryption: [u8; SPRP_KEY_SIZE],
    pub blinding_factor: [u8; KEY_SIZE],
}

/// kdf takes the input key material and returns the Sphinx Packet keys.
pub fn kdf(input: &[u8; KEY_SIZE]) -> PacketKeys {
    let output = hkdf_expand(input, String::from(KDF_INFO_STR).into_bytes().as_slice());
    let (a1,a2,a3,a4,a5) = array_refs![&output,MAC_KEY_SIZE,STREAM_KEY_SIZE,STREAM_IV_SIZE,SPRP_KEY_SIZE,KEY_SIZE];
    PacketKeys{
        header_mac: *a1,
        header_encryption: *a2,
        header_encryption_iv: *a3,
        payload_encryption: *a4,
        blinding_factor: *a5,
    }
}

pub fn hkdf_expand(prk: &[u8], info: &[u8]) -> [u8; KDF_OUTPUT_SIZE] {
    let mut output = [0u8; KDF_OUTPUT_SIZE];
    let hk = Hkdf::<Sha256>::from_prk(prk).unwrap();
    hk.expand(info, &mut output).unwrap();
    output
}

/// hash calculates the digest of a message
pub fn hash(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512Trunc256::new();
    hasher.input(input);
    let output = hasher.result().to_vec();
    assert!(output.len() == HASH_SIZE);
    output
}

/// hmac returns the hmac of the data using a given key
pub fn hmac(key: &[u8; MAC_KEY_SIZE], data: &[u8]) -> [u8; MAC_SIZE] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey(key).unwrap();
    mac.input(data);
    let mut output = [0u8; MAC_SIZE];
    output.copy_from_slice(&mac.result().code().to_vec()[..MAC_SIZE]);
    output
}

/// returns the plaintext of the message msg, decrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_decrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Result<Vec<u8>, aez::error::AezDecryptionError> {
    let output = decrypt(key, iv, &msg)?;
    Ok(output)
}

/// returns the ciphertext of the message msg, encrypted via the
/// Sphinx SPRP with a given key and IV.
pub fn sprp_encrypt(key: &[u8; SPRP_KEY_SIZE], iv: &[u8; SPRP_IV_SIZE], msg: Vec<u8>) -> Vec<u8> {
    let output = encrypt(key, iv, &msg);
    output
}


#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate hex;

    use super::*;

    #[test]
    fn stream_cipher_vector_test() {
        let raw_key = hex::decode("053ac00139e7bbd473953a6c310e26b6").unwrap();
        let raw_iv = hex::decode("ff03c942f5c95a5eca94b1047a6e327e").unwrap();
        let mut key = [0u8; STREAM_KEY_SIZE];
        let mut iv = [0u8; STREAM_IV_SIZE];
        key.copy_from_slice(raw_key.as_slice());
        iv.copy_from_slice(raw_iv.as_slice());
        let mut s = StreamCipher::new(&key, &iv);
        let actual = s.generate(1024);
        let expected = hex::decode("ee67d27a5853ae79bc0b7fae1bdfccfa2b3f01fb7d86287606a46ca5e580655cb8078db09e79fc2f6bf2a70c3baee04c72870aea12a3a8689b8ce32f1a370405e497df8a9d4df19bb793149dfbac4e1daeff4093c760f5d2a2733cee176f39957a0cafb1abb912cfaa610571fa234a01b79d73c23eea88f0e9d29603e7dfbe2708d8dbb162871b5b2a6cecb2ff6159f6b02bb7b3bb8f20e950f81bf53be772b9654cdb7084c924d09d15d1fda1206f21e2dc0d8012faa6761396c2b81b1d772b6b12a8249cf57bfc1be9471c9b5a9445c06662f3877578b7ffb91c18fa67fdcf62643ed0923f432760c36ca4a145f8e955fb4e04ef491dd274f436986bf3e2fa784f8c7a819d083f3b85e916edf0399d13168357ffcc15902eda24dfbcacd1a75765c1cae161c464851d1d8dfdb5ca302b0afcbb2968ec795a9c51738e3d71737f494d337a662be6e5c35b696b1523c3d0f5c2bddc8074c27a0c4a19e41d55a3d9093d6f5f77b804536b82e815e7dd9433e5cb0269ae71087d0b76b883c09728d089433a07a078944054943afc66e72a9bcd4993346ab5a676ca52e25ff0efd21643b65b69285719551a3d8d74b324ccaf7e3df43cac63fb5f1b1f5f8b3b89f9897c0e798f5b1c6f00e3558afb1b48763a2274709b59b856eae1cc27e4bddff635a24b00e2d074b0e9bef9933e8988dd6db2512e259aecf6e2c8979468375372ff87a3b6414aaa2d40c2db24fb13ee6687b5d6573a9d029cd37b2a151c392a99068d67d5e4ca46610b2e12da4ca1dd52eb8fa25bccea462c02a6f20a2a6e719f056685cacbf82af7f60018b4bdb94b22ea682956d062141220bed5d0d3e857864dd5903585e5374c766077d4f3f1e8347ee5263966b267497e8437617d0890631c37d7484890055a0279d01a280db37fb9c7f6b034cf979f49a93291b7599b1a6f91a9236857a8e313e6851e0c9cc7ecf03409b3adb825e9cb999b100af2a3f0b0202d89491346f5aa075478d4db9ebf0d15b43ec3a982d1d855251118a675b01c752ebe18c6642302c8b28cb4def2a897abdd5673fc9305c42deb610825f49155a81eb9bcb4813ad06ed66f4af79fd5184a7d650bea4cbde9069e21361376deae3a92a6828bc0349b78519f7237459f29aaf8c9b5b38c0b554e45e2dd8f89b6c1923b58d1103f5a33542759b746b9c14d0ede2f8b25714623bee152800014e1fce4cc990338f32e215f4b4e27206fcc4b3a5e68512290fd3c67fc0ea91db63f4314960ccbd36a3f7d0c2378d3d8c4dbb5269da62863970f96d7ee05e60da9b633adaf32c5575cb18f22acd62b3beb6d4eb38f291a6fe0534feb393baf38ec34ab05817bfcb789d794766a9fb319d35fac5940db3f98df3acc1385dae636b30211e5754df434e39041c9386d9b08c1cd1af3b0d8c026ce4a4e908153d3f93b8c").unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn kdf_vector_test() {
        let input = hex::decode("9dd74a26535e05ba0ddb62e06ef9b3b29b089707b4652b9172d91e529c938b51").unwrap();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&input);
        let packet_keys = kdf(&key);
        let header_mac = hex::decode("56a3cca100da21fa9823df7884132e89e2155dadbf425e62ba43392c81581a69").unwrap();
        assert_eq!(header_mac, packet_keys.header_mac);
        let header_encryption = hex::decode("fa4f8808bad302e8247cf71dbaefe3ae").unwrap();
        assert_eq!(header_encryption, packet_keys.header_encryption);
        let header_encryption_iv = hex::decode("3499437e566a8f8cae363b428db7eff9").unwrap();
        assert_eq!(header_encryption_iv, packet_keys.header_encryption_iv);
        let payload_encryption = hex::decode("382d5480e7ebc3c001d04a350f6da76882f26dff7fd14e304bce0aa6d464e6e4a440aad784b18c062700c352e7df6c44").unwrap();
        assert_eq!(&payload_encryption, &packet_keys.payload_encryption[..].to_vec());
        let blinding_factor = hex::decode("22884af95653aef353d3bd3e8b7f9ac2214d4d4f4d726c7bd78553fb60982444").unwrap();
        assert_eq!(blinding_factor, packet_keys.blinding_factor);
    }

    #[test]
    fn hash_vector_test() {
        let input = hex::decode("f72fbd7f19e0f192524aea4973354479d6507d964242b30ded31c87e81c5c889").unwrap();
        let want = hex::decode("9b931e466dc077f2cdf57784996dd19006a60e411692a8bdca4882c129c03a86").unwrap();
        let actual = hash(&input);
        assert_eq!(want, actual);
    }

    #[test]
    fn hmac_vector_test() {
        let raw_key = hex::decode("913058c7b4cd2fa62b7bae9a472ec5a661b3dd9dde95a9a66c86a806c1d16dd9").unwrap();
        let mut key = [0u8; MAC_KEY_SIZE];
        key.copy_from_slice(&raw_key);
        let input = hex::decode("5fdc32e6ad5a1481154ff32f63b98d40bf0fd9cbb9338345d7651f472eb0effde63f121eede186b90c030fcf0b32277d11912d565b588f22d50a0b5dd5d64c4f362ff4d274420355223b784e3ed23aaef7f75083231ced2d75f7cb00e10f3e74eccef8529aaba7903a503412f2d63180e3792098fb99a63f77dd3ee45b40ac4a4968bda0641829a3edfe0eedb258f153e8da57e793a2846a4b15c9cdc3ef582d701d9a3d3b0a50b14f4efcfbd4f0ec39586ee4aa7adeee16074a458796db97e7d68172e3246aa03c551a5e7856c26df3ef9847087afa2028957a946abf07dd9af6b4b3506edcccddce9eb2817d6b241ca087f4a65c9e0d7a2babea036b2f61fa").unwrap();
        let want = hex::decode("889e54ad527eefe52eea004a07660d7a").unwrap();
        let actual = hmac(&key, &input);
        assert_eq!(want, actual);
    }
}
