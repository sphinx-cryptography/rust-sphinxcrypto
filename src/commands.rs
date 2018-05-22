// commands.rs - sphinx cryptographic packet format commands
// Copyright (C) 2018  David Stainton.

use byteorder::{ByteOrder, BigEndian};

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

#[derive(Clone)]
pub enum RoutingCommand {
    /// The next hop command is used to route
    /// the Sphinx packet onto the next hop.
    NextHop {
        id: [u8; NODE_ID_SIZE],
        mac: [u8; MAC_SIZE],
    },

    /// The recipient command is used to deliver a payload
    /// to the specified message queue.
    Recipient {
        id: [u8; RECIPIENT_ID_SIZE],
    },

    /// SURBReply is used by a SURB reply on it's last hop.
    SURBReply {
        id: [u8; SURB_ID_SIZE],
    },

    /// The Delay command is used by for the Poisson mix strategy
    /// where clients compose the Sphinx packet with the
    /// per hop delay of their choosing.
    Delay {
        delay: u32,
    },
}

impl RoutingCommand {
    /// from_bytes reads from a byte slice and returns a decoded
    /// routing command and the rest of the buffer.
    pub fn from_bytes(b: &[u8]) -> Result<(Option<RoutingCommand>, Vec<u8>), &'static str> {
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
                return Ok((Some(next_hop_cmd), rest))
            }
            RECIPIENT_CMD => {
                let (recipient_cmd, rest) = recipient_from_bytes(&b[1..])?;
                return Ok((Some(recipient_cmd), rest))
            }
            SURB_REPLY_CMD => {
                let (surb_reply_cmd, rest) = surb_reply_from_bytes(&b[1..])?;
                return Ok((Some(surb_reply_cmd), rest))
            }
            DELAY_CMD => {
                let (delay_cmd, rest) = delay_from_bytes(&b[1..])?;
                return Ok((Some(delay_cmd), rest))
            }
            _ => {
                return Err("error failed to decode command(s) from bytes");
            }
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match *self {
            RoutingCommand::NextHop{
                id, mac
            } => {
                let mut out = Vec::new();
                out.push(NEXT_HOP_CMD);
                out.extend_from_slice(&id);
                out.extend_from_slice(&mac);
                return out;
            },
            RoutingCommand::Recipient{
                id
            } => {
                let mut out = Vec::new();
                out.push(RECIPIENT_CMD);
                out.extend_from_slice(&id);
                return out;
            },
            RoutingCommand::SURBReply{
                id
            } => {
                let mut out = Vec::new();
                out.push(SURB_REPLY_CMD);
                out.extend_from_slice(&id);
                return out;
            },
            RoutingCommand::Delay{
                delay
            } => {
                let mut out = Vec::new();
                out.push(DELAY_CMD);
                let mut _delay = [0; 4];
                BigEndian::write_u32(&mut _delay, delay);
                out.extend_from_slice(&_delay);
                return out;
            },
        }
    }
}

fn next_hop_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < NEXT_HOP_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; NODE_ID_SIZE];
    id.copy_from_slice(&b[..NODE_ID_SIZE]);
    let mut mac = [0u8; MAC_SIZE];
    mac.clone_from_slice(&b[NODE_ID_SIZE..NODE_ID_SIZE+MAC_SIZE]);
    let cmd = RoutingCommand::NextHop{
        id: id,
        mac: mac,
    };
    return Ok((cmd, b[NEXT_HOP_SIZE-1..].to_vec()))
}

fn recipient_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < RECIPIENT_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; RECIPIENT_ID_SIZE];
    id.copy_from_slice(&b[..RECIPIENT_ID_SIZE]);
    let cmd = RoutingCommand::Recipient{
        id: id,
    };
    return Ok((cmd, b[RECIPIENT_SIZE-1..].to_vec()))
}

fn surb_reply_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < SURB_REPLY_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; SURB_ID_SIZE];
    id.copy_from_slice(&b[..SURB_ID_SIZE]);
    let cmd = RoutingCommand::SURBReply{
        id: id,
    };
    return Ok((cmd, b[SURB_REPLY_SIZE-1..].to_vec()))
}

fn delay_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < DELAY_SIZE-1 {
        return Err("invalid command error")
    }
    let cmd = RoutingCommand::Delay{
        delay: BigEndian::read_u32(b),
    };
    return Ok((cmd, b[DELAY_SIZE-1..].to_vec()))
}

/// The commands_to_vec function is used to serialize a vector of
/// routing commands, however it is considered an error to supply
/// such a vector of commands with a NextHop command.
pub fn commands_to_vec(commands: &Vec<RoutingCommand>, is_terminal: bool) -> Result<Vec<u8>, &'static str> {
    let mut output: Vec<u8> = Vec::new();
    if commands.len() == 0 {
        return Ok(output);
    }
    for cmd in commands.iter() {
        output.extend(cmd.to_vec());
    }
    if output.len() > PER_HOP_ROUTING_INFO_SIZE {
        return Err("sphinx: invalid commands, oversized serialized block")
    }
    if !is_terminal && PER_HOP_ROUTING_INFO_SIZE - output.len() < NEXT_HOP_SIZE {
        return Err("sphinx: invalid commands, insufficient remaining capacity")
    }
    return Ok(output);
}

/// Parse the per-hop routing commands.
pub fn parse_routing_commands(b: &[u8]) -> Result<(Vec<RoutingCommand>, Option<RoutingCommand>, Option<RoutingCommand>), &'static str> {
    let mut ret: Vec<RoutingCommand> = Vec::new();
    let mut maybe_next_hop: Option<RoutingCommand> = None;
    let mut maybe_surb_reply: Option<RoutingCommand> = None;
    let mut b_copy = Vec::new();
    b_copy.extend_from_slice(b);
    loop {
        let (_cmd, _rest) = match RoutingCommand::from_bytes(&b_copy) {
            Ok(x) => x,
            Err(e) => return Err(e),
        };
        if _cmd.is_none() {
            break
        }
        b_copy = _rest;
        let cmd = _cmd.unwrap();
        match cmd {
            RoutingCommand::NextHop{
                id: _, mac: _
            } => {
                maybe_next_hop = Some(cmd);
            },
            RoutingCommand::SURBReply{
                id: _,
            } => {
                maybe_surb_reply = Some(cmd);
            },
            RoutingCommand::Recipient{
                id: _,
            } => {
                ret.push(cmd);
            },
            RoutingCommand::Delay{
                delay: _,
            } => {
                ret.push(cmd);
            },
        }
    }
    return Ok((ret, maybe_next_hop, maybe_surb_reply));
}

#[cfg(test)]
mod tests {
    extern crate rand;
    extern crate rustc_serialize;

    use super::*;
    use self::rand::Rng;
    use self::rand::os::OsRng;
    //use self::rustc_serialize::hex::ToHex;

    use super::super::constants::{NODE_ID_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
    use super::super::internal_crypto::{MAC_SIZE};

    #[test]
    fn from_bytes_test() {
        let mut rng = OsRng::new().unwrap();

        // next hop command case
        let mut _id = [0u8; NODE_ID_SIZE];
        rng.fill_bytes(&mut _id);
        let mut _mac = [0u8; MAC_SIZE];
        rng.fill_bytes(&mut _mac);
        let cmd = RoutingCommand::NextHop{
            id: _id,
            mac: _mac,
        };
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::NextHop{
                id, mac
            } => {
                assert_eq!(id, _id);
                assert_eq!(mac, _mac);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // recipient command case
        let mut _id = [0u8; RECIPIENT_ID_SIZE];
        rng.fill_bytes(&mut _id);
        let cmd = RoutingCommand::Recipient{
            id: _id,
        };
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::Recipient{
                id
            } => {
                assert_eq!(id[..], _id[..]);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // surb reply command case
        let mut _id = [0u8; SURB_ID_SIZE];
        rng.fill_bytes(&mut _id);
        let cmd = RoutingCommand::SURBReply{
            id: _id,
        };
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::SURBReply{
                id
            } => {
                assert_eq!(id[..], _id[..]);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // delay command case
        let _delay = 3;
        let cmd = RoutingCommand::Delay{
            delay: _delay,
        };
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::Delay{
                delay
            } => {
                assert_eq!(delay, _delay);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);
    }

    #[test]
    fn parse_routing_commands_test() {
        let mut raw_commands = vec![];

        // delay command
        let mut rng = OsRng::new().unwrap();
        let delay = RoutingCommand::Delay{
            delay: 3,
        };
        raw_commands.extend(delay.to_vec());

        // next hop command
        let mut id = [0u8; NODE_ID_SIZE];
        let mut mac = [0u8; MAC_SIZE];
        rng.fill_bytes(&mut id);
        rng.fill_bytes(&mut mac);
        let next_hop = RoutingCommand::NextHop{
            id: id,
            mac: mac,
        };
        let delay = RoutingCommand::Delay{
            delay: 123,
        };
        raw_commands.extend(next_hop.to_vec());
        raw_commands.extend(delay.to_vec());
        let _result = parse_routing_commands(&raw_commands);
        assert!(_result.is_ok());
        match _result.unwrap() {
            (x, y, z) => {
                let cmds = x;
                let my_next_hop = y;
                let my_surb_reply = z;
                assert!(cmds.len() == 2);
                assert!(my_next_hop.is_some());
                assert!(my_surb_reply.is_none());
            }
        }
    }
}
