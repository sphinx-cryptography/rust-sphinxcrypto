// commands.rs - sphinx cryptographic packet format commands
// Copyright (C) 2018  David Stainton.

use super::constants::{NODE_ID_SIZE};
use super::internal_crypto::{MAC_SIZE};

/// length of the next hop command
const NEXT_HOP_SIZE: usize = 1 + NODE_ID_SIZE + MAC_SIZE;

/// Sphinx routing commands.
const NEXT_HOP: u8 = 0x1;

/// RoutingCommand is a trait representing 
pub trait RoutingCommand {
    fn to_bytes(&self) -> Vec<u8>;
}

#[derive(Copy,Clone)]
pub struct NextHop {
    id: [u8; NODE_ID_SIZE],
    mac: [u8; MAC_SIZE],
}

impl RoutingCommand for NextHop {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(NEXT_HOP);
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


#[cfg(test)]
mod tests {
    extern crate rand;
    use super::*;
    use self::rand::Rng;
    use self::rand::os::OsRng;

    use super::super::constants::{NODE_ID_SIZE};
    use super::super::internal_crypto::{MAC_SIZE};
    
    #[test]
    fn next_hop_test() {
        let mut rnd = OsRng::new().unwrap();

        let id = rnd.gen_iter::<u8>().take(NODE_ID_SIZE).collect::<Vec<u8>>();
        let mut idArr = [0u8; NODE_ID_SIZE];
        idArr.copy_from_slice(id.as_slice());

        let mac = rnd.gen_iter::<u8>().take(MAC_SIZE).collect::<Vec<u8>>();
        let mut macArr = [0u8; MAC_SIZE];
        macArr.copy_from_slice(mac.as_slice());
        
        let cmd1 = NextHop{
            id: idArr,
            mac: macArr,
        };
        let raw1 = cmd1.to_bytes();
        let (cmd, rest) = super::next_hop_from_bytes(&raw1[1..]).unwrap();     
        let raw2 = cmd.to_bytes();
        assert_eq!(raw1, raw2);
    }
}
