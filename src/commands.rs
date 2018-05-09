// commands.rs - sphinx cryptographic packet format commands
// Copyright (C) 2018  David Stainton.

use byteorder::{ByteOrder, BigEndian};
use std::any::Any;

use super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE, PER_HOP_ROUTING_INFO_SIZE};
use super::internal_crypto::{MAC_SIZE};

/// size of the next hop command in bytes
pub const NEXT_HOP_SIZE: usize = 1 + NODE_ID_SIZE + MAC_SIZE;

/// size of the recipient command in bytes
pub const RECIPIENT_SIZE: usize = 1 + RECIPIENT_ID_SIZE;

/// size of the SURB reply command in bytes
pub const SURB_REPLY_SIZE: usize = 1 + SURB_ID_SIZE;

/// size of the delay command in bytes
pub const DELAY_SIZE: usize = 1 + 4;

/// Sphinx routing commands.
const NULL_CMD: u8 = 0x00;
const NEXT_HOP_CMD: u8 = 0x01;
const RECIPIENT_CMD: u8 = 0x02;
const SURB_REPLY_CMD: u8 = 0x03;

/// Implementation defined commands.
const DELAY_CMD: u8 = 0x80;

/// RoutingCommand is a trait representing
/// Sphinx routing commands.
pub trait RoutingCommand {
    fn to_vec(&self) -> Vec<u8>;
}

/// The commands_to_vec function is used to serialize a vector of
/// routing commands, however it is considered an error to supply
/// such a vector of commands with a NextHop command.
pub fn commands_to_vec(commands: &Vec<Box<Any>>, is_terminal: bool) -> Result<Vec<u8>, &'static str> {
    let mut output: Vec<u8> = Vec::new();
    if commands.len() == 0 {
        return Ok(output);
    }
    for boxed_cmd in commands.iter() {
        // XXX fix me: use match_cast crate here
        let result = boxed_cmd.downcast_ref::<NextHop>();
        if result.is_some() {
            return Err("invalid commands, NextHop");
        }
        let result = boxed_cmd.downcast_ref::<Recipient>();
        if result.is_some() {
            output.extend((*result.expect("value")).clone().to_vec());
            continue
        }
        let result = boxed_cmd.downcast_ref::<SURBReply>();
        if result.is_some() {
            output.extend((*result.expect("value")).clone().to_vec());
            continue
        }
        let result = boxed_cmd.downcast_ref::<Delay>();
        if result.is_some() {
            output.extend((*result.expect("value")).clone().to_vec());
        } else {
            return Err("commands_to_bytes failed to serialize the commands");
        }
        if output.len() > PER_HOP_ROUTING_INFO_SIZE {
            return Err("invalid commands, oversized serialized block");
        }
        if !is_terminal && PER_HOP_ROUTING_INFO_SIZE - output.len() < NEXT_HOP_SIZE {
            return Err("invalid commands, insufficient remaining capabity");
        }
    }
    return Ok(output);
}

/// Parse the per-hop routing commands.
pub fn parse_routing_commands(b: &[u8]) -> Result<(Vec<Box<Any>>, Option<NextHop>, Option<SURBReply>), &'static str> {
    let mut ret: Vec<Box<Any>> = Vec::new();
    let mut maybe_next_hop: Option<NextHop> = None;
    let mut maybe_surb_reply: Option<SURBReply> = None;
    let mut boxed_cmd: Box<Any> = Box::new(Delay{
        delay: 123,
    });
    let mut rest = vec![];
    let mut b_copy = Vec::new();
    b_copy.extend_from_slice(b);
    loop {
        let _result = from_bytes(&b_copy)?;
        match _result {
            (x, y) => {
                rest = y;
                let _option_cmd = x;
                match _option_cmd {
                    Some(j) => {
                        boxed_cmd = j;
                        if boxed_cmd.downcast_ref::<NextHop>().is_some() {
                            let result = boxed_cmd.downcast_ref::<NextHop>();
                            maybe_next_hop = Some((result.unwrap()).clone());
                        } else if boxed_cmd.downcast_ref::<SURBReply>().is_some() {
                            let result = boxed_cmd.downcast_ref::<SURBReply>();
                            maybe_surb_reply = Some((result.unwrap()).clone());
                        } else {
                            ret.push(boxed_cmd);
                        }
                    },
                    None => {
                        break
                    },
                }
            },
        }
        b_copy = rest;
    }
    return Ok((ret, maybe_next_hop, maybe_surb_reply));
}

/// from_bytes reads from a byte slice and returns a decoded
/// routing command and the rest of the buffer.
pub fn from_bytes(b: &[u8]) -> Result<(Option<Box<Any>>, Vec<u8>), &'static str> {
    if b.len() == 0 {
        return Ok((None, b.to_vec()))
    }
    let cmd_id = b[0];
    match cmd_id {
        NULL_CMD => {
            return Ok((None, b.to_vec()))
        }
        NEXT_HOP_CMD => {
            let (next_hop_cmd, rest) = next_hop_from_bytes(&b[1..])?;
            return Ok((Some(Box::new(next_hop_cmd)), rest))
        }
        RECIPIENT_CMD => {
            let (recipient_cmd, rest) = recipient_from_bytes(&b[1..])?;
            return Ok((Some(Box::new(recipient_cmd)), rest))
        }
        SURB_REPLY_CMD => {
            let (surb_reply_cmd, rest) = surb_reply_from_bytes(&b[1..])?;
            return Ok((Some(Box::new(surb_reply_cmd)), rest))
        }
        DELAY_CMD => {
            let (delay_cmd, rest) = delay_from_bytes(&b[1..])?;
            return Ok((Some(Box::new(delay_cmd)), rest))
        }
        _ => {
            return Err("error failed to decode command(s) from bytes");
        }
    }
}

/// The next hop command is used to route
/// the Sphinx packet onto the next hop.
#[derive(Clone)]
pub struct NextHop {
    pub id: [u8; NODE_ID_SIZE],
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
#[derive(Clone)]
pub struct Recipient {
    pub id: [u8; RECIPIENT_ID_SIZE],
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
    pub id: [u8; SURB_ID_SIZE],
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
#[derive(Clone)]
pub struct Delay {
    pub delay: u32,
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
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd.unwrap());
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
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd.unwrap());
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
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd.unwrap());
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
        let trait_ptr: *mut Any = Box::into_raw(boxed_cmd.unwrap());
        let cmd_p: Box<Delay> = unsafe { Box::from_raw(trait_ptr as *mut Delay) };
        assert_eq!(cmd.delay, cmd_p.delay);
        let raw2 = cmd.to_vec();
        assert_eq!(raw1, raw2);
    }

    #[test]
    fn parse_routing_commands_test() {
        let mut raw_commands = vec![];

        // delay command
        let mut rng = OsRng::new().unwrap();
        let delay = Delay{
            delay: 3,
        };
        raw_commands.extend(delay.to_vec());

        // next hop command
        let mut id = [0u8; NODE_ID_SIZE];
        let mut mac = [0u8; MAC_SIZE];
        rng.fill_bytes(&mut id);
        rng.fill_bytes(&mut mac);
        let next_hop = NextHop{
            id: id,
            mac: mac,
        };
        raw_commands.extend(next_hop.to_vec());

        let _result = parse_routing_commands(&raw_commands);
        assert!(_result.is_ok());
        match _result.unwrap() {
            (x, y, z) => {
                let cmds = x;
                let my_next_hop = y;
                let my_surb_reply = z;
                assert!(cmds.len() == 1);
                assert!(my_next_hop.is_some());
                assert!(my_surb_reply.is_none());
            }
        }
    }
}
