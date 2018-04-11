// commands.rs - sphinx cryptographic packet format commands
// Copyright (C) 2018  David Stainton.

use std::ops::Deref;

use super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
use super::internal_crypto::{MAC_SIZE};

/// size of the next hop command in bytes
const NEXT_HOP_SIZE: usize = 1 + NODE_ID_SIZE + MAC_SIZE;

/// size of the recipient command in bytes
const RECIPIENT_SIZE: usize = 1 + RECIPIENT_ID_SIZE;

/// size of the SURB reply command in bytes
const SURB_REPLY_SIZE: usize = 1 + SURB_ID_SIZE;

/// size of the delay command in bytes
const DELAY_SIZE: usize = 1 + 4;

/// Sphinx routing commands.
const NULL_CMD: u8 = 0x0;
const NEXT_HOP_CMD: u8 = 0x1;
const RECIPIENT_CMD: u8 = 0x2;
const SURB_REPLY_CMD: u8 = 0x3;

/// Implementation defined commands.
const DELAY_CMD: u8 = 0x80;

/// RoutingCommand is a trait representing
/// Sphinx routing commands
pub trait RoutingCommand {
    fn to_vec(&self) -> Vec<u8>;
}

/// from_bytes reads from a byte slice and returns a decoded
/// routing command and the rest of the buffer.
pub fn from_bytes(b: &[u8]) -> Result<(Box<RoutingCommand>, Vec<u8>), &'static str> {
    let cmd_id = b[0];
    match cmd_id {
        NEXT_HOP_CMD => {
            let mut id = [0u8; NODE_ID_SIZE];
            id.copy_from_slice(&b[1..NODE_ID_SIZE+1]);
            let mut mac = [0u8; MAC_SIZE];
            mac.clone_from_slice(&b[1+NODE_ID_SIZE..NODE_ID_SIZE+MAC_SIZE+1]);
            let next_hop = NextHop{
                id: id,
                mac: mac,
            };
            return Ok((Box::new(next_hop), b[NEXT_HOP_SIZE..].to_vec()));
        }
        RECIPIENT_CMD => {
            let mut id = [0u8; RECIPIENT_ID_SIZE];
            id.copy_from_slice(&b[1..RECIPIENT_ID_SIZE+1]);
            let recipient = Recipient{
                id: id,
            };
            return Ok((Box::new(recipient), b[RECIPIENT_SIZE..].to_vec()));
        }
        _ => {
            return Err("error failed to decode command(s) from bytes");
        }
    }
    Err("error failed to decode command(s) from bytes")
}

pub struct NextHop {
    id: [u8; NODE_ID_SIZE],
    mac: [u8; MAC_SIZE],
}

impl RoutingCommand for NextHop {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(NEXT_HOP_CMD);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.mac);
        out
    }
}

fn next_hop_from_bytes(b: &[u8]) -> Result<(NextHop, Vec<u8>), &'static str> {
    if b.len() < NEXT_HOP_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; NODE_ID_SIZE];
    id.copy_from_slice(&b[..NODE_ID_SIZE]);
    let mut mac = [0u8; MAC_SIZE];
    mac.clone_from_slice(&b[NODE_ID_SIZE..NODE_ID_SIZE+MAC_SIZE]);
    let cmd = NextHop{
        id: id,
        mac: mac,
    };
    return Ok((cmd, b[NEXT_HOP_SIZE-1..].to_vec()))
}

pub struct Recipient {
    id: [u8; RECIPIENT_ID_SIZE],
}

impl RoutingCommand for Recipient {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RECIPIENT_CMD);
        out.extend_from_slice(&self.id);
        out
    }
}

fn recipient_from_bytes(b: &[u8]) -> Result<(Recipient, Vec<u8>), &'static str> {
    if b.len() < RECIPIENT_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; RECIPIENT_ID_SIZE];
    id.copy_from_slice(&b[..RECIPIENT_ID_SIZE]);
    let cmd = Recipient{
        id: id,
    };
    return Ok((cmd, b[RECIPIENT_SIZE-1..].to_vec()))
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use super::*;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    use self::rustc_serialize::hex::ToHex;

    use super::super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE};
    use super::super::internal_crypto::{MAC_SIZE};

    #[test]
    fn from_bytes_test() {

        // next hop command case
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(NODE_ID_SIZE).collect::<Vec<u8>>();
        let mut idArr = [0u8; NODE_ID_SIZE];
        idArr.copy_from_slice(id.as_slice());

        let mac = rnd.gen_iter::<u8>().take(MAC_SIZE).collect::<Vec<u8>>();
        let mut macArr = [0u8; MAC_SIZE];
        macArr.copy_from_slice(mac.as_slice());

        let cmd = NextHop{
            id: idArr,
            mac: macArr,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, rest) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut RoutingCommand = Box::into_raw(boxed_cmd);
        let cmd_p: Box<NextHop> = unsafe { Box::from_raw(trait_ptr as *mut NextHop) };
        assert_eq!(cmd.id, cmd_p.id);
        assert_eq!(cmd.mac, cmd_p.mac);
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);


        // recipient command case
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(RECIPIENT_ID_SIZE).collect::<Vec<u8>>();
        let mut idArr = [0u8; RECIPIENT_ID_SIZE];
        idArr.copy_from_slice(id.as_slice());

        let cmd = Recipient{
            id: idArr,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, rest) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut RoutingCommand = Box::into_raw(boxed_cmd);
        let cmd_p: Box<Recipient> = unsafe { Box::from_raw(trait_ptr as *mut Recipient) };
        assert_eq!(cmd.id.to_vec(), cmd_p.id.to_vec());
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);
    }
}
