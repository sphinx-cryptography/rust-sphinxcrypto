// constants.rs - sphinx cryptographic packet format constants
// Copyright (C) 2018  David Stainton.

use super::sphinx::{HEADER_SIZE, PAYLOAD_TAG_SIZE};

/// The size of a Sphinx packet in bytes.
pub const PACKET_SIZE: usize = HEADER_SIZE + PAYLOAD_SIZE;

/// The Sphinx packet payload size in bytes.
pub const PAYLOAD_SIZE: usize = PAYLOAD_TAG_SIZE + FORWARD_PAYLOAD_SIZE;

/// The length of the usable forward payload
/// of a Sphinx packet in bytes.
pub const FORWARD_PAYLOAD_SIZE: usize = 2 * 1024;

/// The node identifier size in bytes.
pub const NODE_ID_SIZE: usize = 32;

/// The recipient identifier size in bytes.
pub const RECIPIENT_ID_SIZE: usize = 64;

/// The SURB identifier size in bytes.
pub const SURB_ID_SIZE: usize = 16;

/// The number of hops a packet will traverse.
pub const NUMBER_HOPS: usize = 5;
