// commands.rs - sphinx cryptographic packet format commands
// Copyright (C) 2018  David Stainton.

use byteorder::{ByteOrder, BigEndian};
use std::any::Any;

use super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
use super::internal_crypto::{MAC_SIZE};

/// size of the next hop command in bytes
const NEXT_HOP_SIZE: usize = 1 + NODE_ID_SIZE + MAC_SIZE;

/// size of the recipient command in bytes
pub const RECIPIENT_SIZE: usize = 1 + RECIPIENT_ID_SIZE;

/// size of the SURB reply command in bytes
pub const SURB_REPLY_SIZE: usize = 1 + SURB_ID_SIZE;

/// size of the delay command in bytes
const DELAY_SIZE: usize = 1 + 4;

/// Sphinx routing commands.
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

/// Parse the per-hop routing commands.
pub fn parse_routing_commands(b: &[u8]) -> Result<(Vec<Box<Any>>, Option<NextHop>, Option<SURBReply>), &'static str> {
    let mut ret = Vec::new();
    let mut maybe_next_hop: Option<NextHop> = None;
    let mut maybe_surb_reply: Option<SURBReply> = None;
    let mut b_copy = Vec::new();
    b_copy.clone_from_slice(b);

    loop {
        let (boxed_cmd, _) = from_bytes(&b_copy)?;

        // next hop
        let result = boxed_cmd.downcast_ref::<NextHop>();
        if result.is_some() {
            maybe_next_hop = Some((*result.expect("value")).clone());
        }

        // surb reply
        let result = boxed_cmd.downcast_ref::<SURBReply>();
        if result.is_some() {
            maybe_surb_reply = Some((*result.expect("value")).clone());
        }

        let (boxed_cmd, rest) = from_bytes(&b)?;
        ret.push(boxed_cmd);

        if rest.len() == 0 {
            break;
        }
    }
    return Ok((ret, maybe_next_hop, maybe_surb_reply));
}

/// from_bytes reads from a byte slice and returns a decoded
/// routing command and the rest of the buffer.
pub fn from_bytes(b: &[u8]) -> Result<(Box<Any>, Vec<u8>), &'static str> {
    let cmd_id = b[0];
    match cmd_id {
        NEXT_HOP_CMD => {
            let (next_hop_cmd, rest) = next_hop_from_bytes(&b[1..])?;
            return Ok((Box::new(next_hop_cmd), rest))
        }
        RECIPIENT_CMD => {
            let (recipient_cmd, rest) = recipient_from_bytes(&b[1..])?;
            return Ok((Box::new(recipient_cmd), rest))
        }
        SURB_REPLY_CMD => {
            let (surb_reply_cmd, rest) = surb_reply_from_bytes(&b[1..])?;
            return Ok((Box::new(surb_reply_cmd), rest))
        }
        DELAY_CMD => {
            let (delay_cmd, rest) = delay_from_bytes(&b[1..])?;
            return Ok((Box::new(delay_cmd), rest))
        }
        _ => {
            return Err("error failed to decode command(s) from bytes");
        }
    }
    Err("error failed to decode command(s) from bytes")
}

/// The next hop command is used to route
/// the Sphinx packet onto the next hop.
#[derive(Clone)]
pub struct NextHop {
    id: [u8; NODE_ID_SIZE],
    pub mac: [u8; MAC_SIZE],
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

/// The recipient command is used to deliver a payload
/// to the specified message queue.
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

/// This command is used by a SURB reply on it's last hop.
#[derive(Clone)]
pub struct SURBReply {
    id: [u8; SURB_ID_SIZE],
}

impl RoutingCommand for SURBReply {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SURB_REPLY_CMD);
        out.extend_from_slice(&self.id);
        out
    }
}

fn surb_reply_from_bytes(b: &[u8]) -> Result<(SURBReply, Vec<u8>), &'static str> {
    if b.len() < SURB_REPLY_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; SURB_ID_SIZE];
    id.copy_from_slice(&b[..SURB_ID_SIZE]);
    let cmd = SURBReply{
        id: id,
    };
    return Ok((cmd, b[SURB_REPLY_SIZE-1..].to_vec()))
}

/// This command is used by for the Poisson mix strategy
/// where clients compose the Sphinx packet with the
/// per hop delay of their choosing.
pub struct Delay {
    delay: u32,
}

impl RoutingCommand for Delay {
    fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(DELAY_CMD);
        let mut delay = [0; 4];
        BigEndian::write_u32(&mut delay, self.delay);
        out.extend_from_slice(&delay);
        out
    }
}

fn delay_from_bytes(b: &[u8]) -> Result<(Delay, Vec<u8>), &'static str> {
    if b.len() < DELAY_SIZE-1 {
        return Err("invalid command error")
    }
    let cmd = Delay{
        delay: BigEndian::read_u32(b),
    };
    return Ok((cmd, b[DELAY_SIZE-1..].to_vec()))
}


#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use super::*;
    use std::any::Any;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    //use self::rustc_serialize::hex::ToHex;

    use super::super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
    use super::super::internal_crypto::{MAC_SIZE};

    #[test]
    fn from_bytes_test() {

        // next hop command case
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(NODE_ID_SIZE).collect::<Vec<u8>>();
        let mut id_arr = [0u8; NODE_ID_SIZE];
        id_arr.copy_from_slice(id.as_slice());

        let mac = rnd.gen_iter::<u8>().take(MAC_SIZE).collect::<Vec<u8>>();
        let mut mac_arr = [0u8; MAC_SIZE];
        mac_arr.copy_from_slice(mac.as_slice());

        let cmd = NextHop{
            id: id_arr,
            mac: mac_arr,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, _) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd);
        let cmd_p: Box<NextHop> = unsafe { Box::from_raw(trait_ptr as *mut NextHop) };
        assert_eq!(cmd.id, cmd_p.id);
        assert_eq!(cmd.mac, cmd_p.mac);
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);


        // recipient command case
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(RECIPIENT_ID_SIZE).collect::<Vec<u8>>();
        let mut id_arr = [0u8; RECIPIENT_ID_SIZE];
        id_arr.copy_from_slice(id.as_slice());

        let cmd = Recipient{
            id: id_arr,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, _) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd);
        let cmd_p: Box<Recipient> = unsafe { Box::from_raw(trait_ptr as *mut Recipient) };
        assert_eq!(cmd.id.to_vec(), cmd_p.id.to_vec());
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);


        // surb reply command case
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(SURB_ID_SIZE).collect::<Vec<u8>>();
        let mut id_arr = [0u8; SURB_ID_SIZE];
        id_arr.copy_from_slice(id.as_slice());

        let cmd = SURBReply{
            id: id_arr,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, _) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd);
        let cmd_p: Box<SURBReply> = unsafe { Box::from_raw(trait_ptr as *mut SURBReply) };
        assert_eq!(cmd.id.to_vec(), cmd_p.id.to_vec());
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);

        // delay command case
        let cmd = Delay{
            delay: 3,
        };
        let raw1 = cmd.to_vec();
        let (boxed_cmd, _) = from_bytes(&raw1).unwrap();
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd);
        let cmd_p: Box<Delay> = unsafe { Box::from_raw(trait_ptr as *mut Delay) };
        assert_eq!(cmd.delay, cmd_p.delay);
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);
    }
}
