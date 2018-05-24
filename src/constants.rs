// constants.rs - sphinx cryptographic packet format constants
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

use super::internal_crypto::{GROUP_ELEMENT_SIZE, MAC_SIZE, SPRP_KEY_SIZE, SPRP_IV_SIZE};
use super::commands::{RECIPIENT_SIZE, SURB_REPLY_SIZE};


/// The maximum number of hops a packet will traverse.
pub const MAX_HOPS: usize = 5;

/// The length of the usable forward payload
/// of a Sphinx packet in bytes.
pub const FORWARD_PAYLOAD_SIZE: usize = 2 * 1024;

/// The node identifier size in bytes.
pub const NODE_ID_SIZE: usize = 32;

/// The recipient identifier size in bytes.
pub const RECIPIENT_ID_SIZE: usize = 64;

/// The SURB identifier size in bytes.
pub const SURB_ID_SIZE: usize = 16;

/// The "authenticated data" portion of the Sphinx
/// packet header which as specified contains the
/// version number.
pub const AD_SIZE: usize = 2;

/// The first section of our Sphinx packet, the authenticated
/// unencrypted data containing version number.
pub const V0_AD: [u8; 2] = [0u8; 2];

/// The size in bytes of the payload tag.
pub const PAYLOAD_TAG_SIZE: usize = 16;

/// The size of a BlockSphinxPlaintext in bytes.
pub const SPHINX_PLAINTEXT_HEADER_SIZE: usize = 1 + 1;

/// The size of the user portion of the forward payload.
pub const USER_FORWARD_PAYLOAD_SIZE: usize = FORWARD_PAYLOAD_SIZE - (SPHINX_PLAINTEXT_HEADER_SIZE + SURB_SIZE);

/// The size of a Single Use Reply Block
pub const SURB_SIZE: usize = HEADER_SIZE + NODE_ID_SIZE + SPRP_KEY_SIZE + SPRP_IV_SIZE;

/// The size of the Sphinx packet header in bytes.
pub const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// The Sphinx packet payload size in bytes.
pub const PAYLOAD_SIZE: usize = PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE;

/// The size of a Sphinx packet in bytes.
pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

/// The size in bytes of each routing info slot.
pub const PER_HOP_ROUTING_INFO_SIZE: usize = RECIPIENT_SIZE + SURB_REPLY_SIZE;

/// The size in bytes of the routing info section of the packet
/// header.
pub const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * MAX_HOPS;
