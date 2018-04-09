// constants.rs - sphinx cryptographic packet format constants
// Copyright (C) 2018  David Stainton.

/// The node identifier size in bytes.
pub const NODE_ID_SIZE: usize = 32;

/// The recipient identifier size in bytes.
pub const RECIPIENT_ID_SIZE: usize = 64;

/// The SURB identifier size in bytes.
pub const SURB_ID_SIZE: usize = 16;

/// The number of hops a packet will traverse.
pub const NUMBER_HOPS: usize = 5;
