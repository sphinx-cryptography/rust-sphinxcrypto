// lib.rs - The Sphinx cryptographic packet library
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


//! An implementation of the Sphinx cryptographic packet library
//!
//! # The Sphinx Cryptographic Packet Format
//!
//! The Sphinx cryptographic packet format is a compact and provably
//! secure design introduced by George Danezis and Ian Goldberg.
//!
//! # Security Features of the Sphinx packet format
//!
//! * Single Use Reply Blocks
//! * per hop bitwise unlinkability
//! * indistinguishable replies
//! * hidden the path length
//! * hidden the relay position
//! * tagging attack detection
//! * reply attack detection
//!
//! **[Sphinx Mix Network Cryptographic Packet Format Specification](https://github.com/katzenpost/docs/blob/master/specs/sphinx.rst)**
//!
//! **[Sphinx: A Compact and Provably Secure Mix Format](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf)**

#[macro_use]
extern crate arrayref;
extern crate ecdh_wrapper;
extern crate byteorder;
extern crate aez;
extern crate subtle;
extern crate keystream;
extern crate chacha;
extern crate blake2b_simd;

pub mod constants;
pub mod commands;
pub mod error;
pub mod server;
pub mod client;

mod internal_crypto;
mod utils;
