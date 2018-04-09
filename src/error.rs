
use std::error::Error;
use std::fmt;


#[derive(Debug)]
pub enum SphinxUnwrapError {
    BlockSizeError,
}

impl fmt::Display for SphinxUnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::SphinxUnwrapError::*;
        match *self {
            BlockSizeError => write!(f, "Lioness block size must exceed 32 bytes."),
        }
    }
}


impl Error for SphinxUnwrapError {
    fn description(&self) -> &str {
        "I'm a Lioness error."
    }

    fn cause(&self) -> Option<&Error> {
        use self::SphinxUnwrapError::*;
        match *self {
            BlockSizeError => None,
        }
    }
}
