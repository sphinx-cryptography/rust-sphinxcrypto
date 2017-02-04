// Copyright 2016 Jeffrey Burdges and David Stainton

//! Sphinx mix client cryptographic operations

extern crate lioness;
extern crate rustc_serialize;

/// i am a protocol agnostic trait representing mix network addresses.
pub trait MixAddr {

}

/// mix network public key infrastructure trait
pub trait MixPKI {
    /// set a new mix node's PKI entry
    fn set(&mut self, node_id: [u8; 16], public_key: [u8; 32], address: MixAddr);

    /// get the public key of a node
    fn get(&self, node_id) -> [u8; 32];

    /// return all the node IDs
    fn identities(&self) -> Vec<[u8; 16]>;

    /// given a node id and a transport name return the network address
    fn get_mix_addr(&self, transport_name: String, node_id: [u8; 16]) -> MixAddr;

    /// rotate mixnet node keys; I remove the old PKI entry's public key
    /// and replace it with the new public key if the signature
    /// can be verified using the old public key.
    fn rotate(&self, node_id: [u8; 16], new_public_key: [u8; 32], signature: [u8; 64]) -> bool;
}

/// this struct represents the Sphinx mix packet header
pub struct SphinxHeader {
    /// alpha is the curve25519 public key element
    pub alpha: [u8; 32],
    /// beta is the encrypted routing information
    pub beta: Vec<u8>,
    /// gamma is the message authenticating code
    pub gamma: [u8; 16],
}

/// i am a factory, i build Sphinx headers
pub struct SphinxHeaderFactory {
   
}
