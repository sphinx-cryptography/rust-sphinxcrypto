// commands.rs - Sphinx routing commands
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

//! Sphinx routing commands

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

/// Sphinx routing command byte constants.
const NULL_CMD: u8 = 0x00;
const NEXT_HOP_CMD: u8 = 0x01;
const RECIPIENT_CMD: u8 = 0x02;
const SURB_REPLY_CMD: u8 = 0x03;

/// Implementation defined commands.
const DELAY_CMD: u8 = 0x80;


#[derive(Clone)]
pub struct NextHop {
    pub id: [u8; NODE_ID_SIZE],
    pub mac: [u8; MAC_SIZE],
}

impl NextHop {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(NEXT_HOP_CMD);
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.mac);
        return out;
    }
}

#[derive(Clone)]
pub struct Recipient {
    pub id: [u8; RECIPIENT_ID_SIZE],
}

impl Recipient {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(RECIPIENT_CMD);
        out.extend_from_slice(&self.id);
        return out;
    }
}

#[derive(Clone)]
pub struct SURBReply {
    pub id: [u8; SURB_ID_SIZE],
}

impl SURBReply {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(SURB_REPLY_CMD);
        out.extend_from_slice(&self.id);
        return out;
    }
}

#[derive(Clone)]
pub struct Delay {
    pub delay: u32,
}

impl Delay {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(DELAY_CMD);
        let mut _delay = [0; 4];
        BigEndian::write_u32(&mut _delay, self.delay);
        out.extend_from_slice(&_delay);
        return out;
    }
}


/// Sphinx routing commands are decrypted by each mix in the route.
/// The Poisson mix strategy uses the Delay command, other mix
/// strategies may need to add additional commands.
#[derive(Clone)]
pub enum RoutingCommand {
    /// The next hop command is used to route
    /// the Sphinx packet onto the next hop.
    NextHop(NextHop),

    /// The recipient command is used to deliver a payload
    /// to the specified message queue.
    Recipient(Recipient),

    /// SURBReply is used by a SURB reply on it's last hop.
    SURBReply(SURBReply),

    /// The Delay command is used by for the Poisson mix strategy
    /// where clients compose the Sphinx packet with the
    /// per hop delay of their choosing.
    Delay(Delay),
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

    /// to_vec returns a vector of serialized commands
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            RoutingCommand::NextHop(ref next_hop) => next_hop.to_vec(),
            RoutingCommand::Recipient(ref recipient) => recipient.to_vec(),
            RoutingCommand::SURBReply(ref surb_reply) => surb_reply.to_vec(),
            RoutingCommand::Delay(ref delay) => delay.to_vec(),
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
    let cmd = RoutingCommand::NextHop(
        NextHop {
            id: id,
            mac: mac,
        }
    );
    return Ok((cmd, b[NEXT_HOP_SIZE-1..].to_vec()))
}

fn recipient_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < RECIPIENT_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; RECIPIENT_ID_SIZE];
    id.copy_from_slice(&b[..RECIPIENT_ID_SIZE]);
    let cmd = RoutingCommand::Recipient(
        Recipient{
            id: id,
        }
    );
    return Ok((cmd, b[RECIPIENT_SIZE-1..].to_vec()))
}

fn surb_reply_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < SURB_REPLY_SIZE-1 {
        return Err("invalid command error")
    }
    let mut id = [0u8; SURB_ID_SIZE];
    id.copy_from_slice(&b[..SURB_ID_SIZE]);
    let cmd = RoutingCommand::SURBReply(
        SURBReply{
            id: id,
        }
    );
    return Ok((cmd, b[SURB_REPLY_SIZE-1..].to_vec()))
}

fn delay_from_bytes(b: &[u8]) -> Result<(RoutingCommand, Vec<u8>), &'static str> {
    if b.len() < DELAY_SIZE-1 {
        return Err("invalid command error")
    }
    let cmd = RoutingCommand::Delay(
        Delay{
            delay: BigEndian::read_u32(b),
        }
    );
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
            RoutingCommand::NextHop(next_hop) => {
                maybe_next_hop = Some(RoutingCommand::NextHop(next_hop));
            },
            RoutingCommand::SURBReply(surb_reply) => {
                maybe_surb_reply = Some(RoutingCommand::SURBReply(surb_reply));
            },
            RoutingCommand::Recipient(recipient) => {
                ret.push(RoutingCommand::Recipient(recipient));
            },
            RoutingCommand::Delay(delay) => {
                ret.push(RoutingCommand::Delay(delay));
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
        let cmd = RoutingCommand::NextHop(
            NextHop{
                id: _id,
                mac: _mac,
            }
        );
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::NextHop(ref next_hop) => {
                assert_eq!(next_hop.id, _id);
                assert_eq!(next_hop.mac, _mac);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // recipient command case
        let mut _id = [0u8; RECIPIENT_ID_SIZE];
        rng.fill_bytes(&mut _id);
        let cmd = RoutingCommand::Recipient(
            Recipient{
                id: _id,
            }
        );
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::Recipient(ref recipient) => {
                assert_eq!(recipient.id[..], _id[..]);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // surb reply command case
        let mut _id = [0u8; SURB_ID_SIZE];
        rng.fill_bytes(&mut _id);
        let cmd = RoutingCommand::SURBReply(
            SURBReply {
                id: _id,
            }
        );
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::SURBReply(ref surb_reply) => {
                assert_eq!(surb_reply.id[..], _id[..]);
            }
            _ => {}
        }
        let raw2 = cmd_p.to_vec();
        assert_eq!(raw1, raw2);

        // delay command case
        let _delay = 3;
        let cmd = RoutingCommand::Delay(
            Delay{
                delay: _delay,
            }
        );
        let raw1 = cmd.to_vec();
        let (maybe_cmd, _) = RoutingCommand::from_bytes(&raw1).unwrap();
        let cmd_p = maybe_cmd.unwrap();
        match cmd_p {
            RoutingCommand::Delay(ref delay) => {
                assert_eq!(delay.delay, _delay);
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
        let delay = RoutingCommand::Delay(
            Delay{
                delay: 3,
            }
        );
        raw_commands.extend(delay.to_vec());

        // next hop command
        let mut id = [0u8; NODE_ID_SIZE];
        let mut mac = [0u8; MAC_SIZE];
        rng.fill_bytes(&mut id);
        rng.fill_bytes(&mut mac);
        let next_hop = RoutingCommand::NextHop(
            NextHop{
                id: id,
                mac: mac,
            }
        );
        let delay = RoutingCommand::Delay(
            Delay{
                delay: 123,
            }
        );
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
