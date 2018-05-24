// error.rs - Sphinx error types
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

use std::error::Error;
use std::fmt;


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

    fn cause(&self) -> Option<&Error> {
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
    KeyGenFail,
    ImpossibleError,
}

impl fmt::Display for SphinxHeaderCreateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxHeaderCreateError::*;
        match *self {
            PathTooLongError => write!(f, "Path length must not exceed MAX_HOPS."),
            SerializeCommandsError => write!(f, "Failed to serialize commands."),
            KeyGenFail => write!(f, "Key generation failure."),
            ImpossibleError => write!(f, "This should never happen."),
        }
    }
}


impl Error for SphinxHeaderCreateError {
    fn description(&self) -> &str {
        "I'm a Sphinx Header creation error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SphinxHeaderCreateError::*;
        match *self {
            PathTooLongError => None,
            SerializeCommandsError => None,
            KeyGenFail => None,
            ImpossibleError => None,
        }
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

    fn cause(&self) -> Option<&Error> {
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

    fn cause(&self) -> Option<&Error> {
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

    fn cause(&self) -> Option<&Error> {
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

    fn cause(&self) -> Option<&Error> {
        use self::SphinxDecryptSurbError::*;
        match *self {
            InvalidSurbKeys => None,
            TruncatedPayloadError => None,
            DecryptError => None,
            InvalidTag => None,
        }
    }
}
