// error.rs - Sphinx error types
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

//! Sphinx error types.

extern crate ecdh_wrapper;

use std::error::Error;
use std::fmt;

use ecdh_wrapper::errors::KeyError;


#[derive(Debug)]
pub enum SphinxUnwrapError {
    InvalidPacketError,
    PayloadError,
    MACError,
    RouteInfoParseError,
    PayloadDecryptError,
    ImpossibleError,
}

impl fmt::Display for SphinxUnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxUnwrapError::*;
        match *self {
            InvalidPacketError => write!(f, "Sphinx packet must begin with expected authenticated data."),
            PayloadError => write!(f, "Payload failed validation check."),
            MACError => write!(f, "Message authentication code did not match."),
            RouteInfoParseError => write!(f, "Failed to parse route information."),
            PayloadDecryptError => write!(f, "Failed to decrypt payload."),
            ImpossibleError => write!(f, "This is impossible."),
        }
    }
}


impl Error for SphinxUnwrapError {
    fn description(&self) -> &str {
        "I'm a SphinxUnwrapError."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxUnwrapError::*;
        match *self {
            InvalidPacketError => None,
            PayloadError => None,
            MACError => None,
            RouteInfoParseError => None,
            PayloadDecryptError => None,
            ImpossibleError => None,
        }
    }
}

#[derive(Debug)]
pub enum SphinxHeaderCreateError {
    PathTooLongError,
    SerializeCommandsError,
    KeyGenFail(KeyError),
    ImpossibleError,
}

impl fmt::Display for SphinxHeaderCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxHeaderCreateError::*;
        match self {
            PathTooLongError => write!(f, "Path length must not exceed MAX_HOPS."),
            SerializeCommandsError => write!(f, "Failed to serialize commands."),
            KeyGenFail(e) => write!(f, "Key generation failure: {}", e),
            ImpossibleError => write!(f, "This should never happen."),
        }
    }
}


impl Error for SphinxHeaderCreateError {
    fn description(&self) -> &str {
        "I'm a Sphinx Header creation error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxHeaderCreateError::*;
        match *self {
            PathTooLongError => None,
            SerializeCommandsError => None,
            KeyGenFail(_) => None,
            ImpossibleError => None,
        }
    }
}

impl From<KeyError> for SphinxHeaderCreateError {
    fn from(error: KeyError) -> Self {
        SphinxHeaderCreateError::KeyGenFail(error)
    }
}


#[derive(Debug)]
pub enum SphinxPacketCreateError {
    CreateHeaderError,
    ImpossibleError,
    SPRPEncryptError,
}

impl fmt::Display for SphinxPacketCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxPacketCreateError::*;
        match *self {
            CreateHeaderError => write!(f, "Failed to create a header."),
            ImpossibleError => write!(f, "This should never happen."),
            SPRPEncryptError => write!(f, "SPRP Encryption failure."),
        }
    }
}


impl Error for SphinxPacketCreateError {
    fn description(&self) -> &str {
        "I'm a Sphinx Packet creation error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxPacketCreateError::*;
        match *self {
            CreateHeaderError => None,
            ImpossibleError => None,
            SPRPEncryptError => None,
        }
    }
}

#[derive(Debug)]
pub enum SphinxSurbCreateError {
    CreateHeaderError,
}

impl fmt::Display for SphinxSurbCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxSurbCreateError::*;
        match *self {
            CreateHeaderError => write!(f, "Failed to create a header."),
        }
    }
}


impl Error for SphinxSurbCreateError {
    fn description(&self) -> &str {
        "I'm a Sphinx Surb creation error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxSurbCreateError::*;
        match *self {
            CreateHeaderError => None,
        }
    }
}

#[derive(Debug)]
pub enum SphinxPacketFromSurbError {
    ImpossibleError,
}

impl fmt::Display for SphinxPacketFromSurbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxPacketFromSurbError::*;
        match *self {
            ImpossibleError => write!(f, "This should never happen."),
        }
    }
}


impl Error for SphinxPacketFromSurbError {
    fn description(&self) -> &str {
        "I'm a Sphinx packet from SURB creation error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxPacketFromSurbError::*;
        match *self {
            ImpossibleError => None,
        }
    }
}

#[derive(Debug)]
pub enum SphinxDecryptSurbError {
    InvalidSurbKeys,
    TruncatedPayloadError,
    DecryptError,
    InvalidTag,
}

impl fmt::Display for SphinxDecryptSurbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxDecryptSurbError::*;
        match *self {
            InvalidSurbKeys => write!(f, "invalid surb keys"),
            TruncatedPayloadError => write!(f, "invalid payload"),
            DecryptError => write!(f, "decryption failure"),
            InvalidTag  => write!(f, "invalid tag"),
        }
    }
}


impl Error for SphinxDecryptSurbError {
    fn description(&self) -> &str {
        "I'm a Sphinx packet from SURB decryption error."
    }

    fn cause(&self) -> Option<&dyn Error> {
        use self::SphinxDecryptSurbError::*;
        match *self {
            InvalidSurbKeys => None,
            TruncatedPayloadError => None,
            DecryptError => None,
            InvalidTag => None,
        }
    }
}
