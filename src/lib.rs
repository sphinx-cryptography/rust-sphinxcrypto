// lib.rs - The Sphinx cryptographic packet library
// Copyright (C) 2018  David Anthony Stainton.
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.


//! An implementation of the Sphinx cryptographic packet library
//!
//! # The Sphinx Cryptographic Packet Format
//!
//! Sphinx can be used to build high or low latency traffic analysis resistance
//! communication networks.
//!
//! # Features of the Sphinx packet format
//!
//! * Single Use Reply Blocks
//! * per hop bitwise unlinkability
//! * indistinguishable replies
//! * hidden the path length
//! * hidden the relay position
//! * tagging attack detection
//! * reply attack detection
//!
//! **Sphinx Mix Network Cryptographic Packet Format Specification**\
//! https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst
//!
//! **Sphinx: A Compact and Provably Secure Mix Format**\
//! https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf

#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;
extern crate byteorder;
extern crate rust_lioness;
extern crate subtle;
extern crate keystream;
extern crate chacha;
extern crate blake2b;

pub mod constants;
pub mod commands;
pub mod error;
pub mod server;
pub mod client;
pub mod ecdh;

mod internal_crypto;
mod utils;
