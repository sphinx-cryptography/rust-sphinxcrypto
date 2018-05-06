
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
            PathTooLongError => write!(f, "Path length must not exceed NUMBER_HOPS."),
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
