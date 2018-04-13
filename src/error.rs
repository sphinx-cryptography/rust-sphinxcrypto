
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
