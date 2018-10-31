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

extern crate chacha;
extern crate keystream;
extern crate hkdf;
extern crate blake2b;
extern crate aez;
extern crate sha2;

use self::sha2::Sha256;
use self::aez::aez::{encrypt, decrypt, AEZ_KEY_SIZE, AEZ_NONCE_SIZE};
use ecdh_wrapper::KEY_SIZE;

use self::chacha::ChaCha as ChaCha20;
use self::keystream::KeyStream;
use self::blake2b::{blake2b, blake2b_keyed};
use self::hkdf::Hkdf;


/// the output size of the unkeyed hash in bytes
pub const HASH_SIZE: usize = 32;

/// the key size of the MAC in bytes
pub const MAC_KEY_SIZE: usize = 32;

/// the output size of the MAC in bytes.
pub const MAC_SIZE: usize = 16;

/// the key size of the stream cipher in bytes.
pub const STREAM_KEY_SIZE: usize = 32;

/// the IV size of the stream cipher in bytes.
pub const STREAM_IV_SIZE: usize = 12;

/// the key size of the SPRP in bytes.
pub const SPRP_KEY_SIZE: usize = AEZ_KEY_SIZE;

/// the IV size of the SPRP in bytes.
pub const SPRP_IV_SIZE: usize = AEZ_NONCE_SIZE;

/// the size of the DH group element in bytes.
pub const GROUP_ELEMENT_SIZE: usize = KEY_SIZE;

const KDF_OUTPUT_SIZE: usize = MAC_KEY_SIZE + STREAM_KEY_SIZE + STREAM_IV_SIZE + SPRP_KEY_SIZE + SPRP_IV_SIZE + KEY_SIZE;

const KDF_INFO_STR: &str = "panoramix-kdf-v0-hkdf-sha256";



/// stream cipher for sphinx crypto usage
pub struct StreamCipher {
    cipher: ChaCha20,
}

impl StreamCipher {
    /// create a new StreamCipher struct
    pub fn new(key: &[u8; STREAM_KEY_SIZE], iv: &[u8; STREAM_IV_SIZE]) -> StreamCipher {
        StreamCipher {
            cipher: ChaCha20::new_ietf(key, iv),
        }
    }

    /// given a key return a cipher stream of length n
    pub fn generate(&mut self, n: usize) -> Vec<u8> {
        let mut output = vec![0u8; n];
        self.cipher.xor_read(&mut output).unwrap();
        output
    }

    pub fn xor_key_stream(&mut self, mut dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);
        self.cipher.xor_read(&mut dst).unwrap();
    }
}

/// PacketKeys are the per-hop Sphinx Packet Keys, derived from the blinded
/// DH key exchange.
pub struct PacketKeys {
    pub header_mac: [u8; MAC_KEY_SIZE],
    pub header_encryption: [u8; STREAM_KEY_SIZE],
    pub header_encryption_iv: [u8; STREAM_IV_SIZE],
    pub payload_encryption: [u8; SPRP_KEY_SIZE],
    pub payload_encryption_iv: [u8; SPRP_IV_SIZE],
    pub blinding_factor: [u8; KEY_SIZE],
}

/// kdf takes the input key material and returns the Sphinx Packet keys.
pub fn kdf(input: &[u8; KEY_SIZE]) -> PacketKeys {
    let mut output = [0u8; KDF_OUTPUT_SIZE];
    let hk = Hkdf::<Sha256>::extract(None, &input[..]);

    hk.expand(String::from(KDF_INFO_STR).into_bytes().as_slice(), &mut output).unwrap();
    let (a1,a2,a3,a4,a5,a6) = array_refs![&output,MAC_KEY_SIZE,STREAM_KEY_SIZE,STREAM_IV_SIZE,SPRP_KEY_SIZE,SPRP_IV_SIZE,KEY_SIZE];
    PacketKeys{
        header_mac: *a1,
        header_encryption: *a2,
        header_encryption_iv: *a3,
        payload_encryption: *a4,
        payload_encryption_iv: *a5,
        blinding_factor: *a6,
    }
}

/// hash calculates the digest of a message
pub fn hash(input: &[u8]) -> Vec<u8> {
    let h = blake2b(HASH_SIZE, input);
    let mut out = Vec::new();
    out.extend(h.iter());
    return out;
}

/// hmac returns the hmac of the data using a given key
pub fn hmac(key: &[u8; MAC_KEY_SIZE], data: &[u8]) -> [u8; MAC_SIZE] {
    let _out = blake2b_keyed(MAC_SIZE, key, data);
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&_out.to_vec());
    return out;
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
