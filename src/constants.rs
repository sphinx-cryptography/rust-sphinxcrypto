// constants.rs - sphinx cryptographic packet format constants
// Copyright (C) 2018  David Stainton.

use super::internal_crypto::{GROUP_ELEMENT_SIZE, MAC_SIZE, SPRP_KEY_SIZE};
use super::commands::{RECIPIENT_SIZE, SURB_REPLY_SIZE};


/// The number of hops a packet will traverse.
pub const NUMBER_HOPS: usize = 5;

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

/// The size of a Single Use Reply Block
pub const SURB_SIZE: usize = HEADER_SIZE + NODE_ID_SIZE + SPRP_KEY_SIZE;

/// The size of a Sphinx packet in bytes.
pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE;

/// The size of the Sphinx packet header in bytes.
pub const HEADER_SIZE: usize = AD_SIZE + GROUP_ELEMENT_SIZE + ROUTING_INFO_SIZE + MAC_SIZE;

/// The Sphinx packet payload size in bytes.
pub const PAYLOAD_SIZE: usize = PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE;

/// The size in bytes of each routing info slot.
pub const PER_HOP_ROUTING_INFO_SIZE: usize = RECIPIENT_SIZE + SURB_REPLY_SIZE;

/// The size in bytes of the routing info section of the packet
/// header.
pub const ROUTING_INFO_SIZE: usize = PER_HOP_ROUTING_INFO_SIZE * NUMBER_HOPS;
