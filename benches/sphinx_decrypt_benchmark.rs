// sphinx_benchmark_test.rs - sphinx cryptographic packet format tests
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

#[macro_use]
extern crate criterion;
extern crate rand;
extern crate ecdh_wrapper;
extern crate sphinxcrypto;

use criterion::Criterion;
use self::rand::Rng;
use self::rand::os::OsRng;
use ecdh_wrapper::PrivateKey;

use sphinxcrypto::server::sphinx_packet_unwrap;
use sphinxcrypto::client::{new_packet, PathHop};
use sphinxcrypto::constants::{MAX_HOPS, NODE_ID_SIZE, FORWARD_PAYLOAD_SIZE, RECIPIENT_ID_SIZE, SURB_ID_SIZE};
use sphinxcrypto::commands::{RoutingCommand, Delay, SURBReply, Recipient};


struct NodeParams {
    pub id: [u8; NODE_ID_SIZE],
    pub private_key: PrivateKey,
}

fn os_rng() -> OsRng {
    OsRng::new().expect("failure to create an OS RNG")
}

fn new_node<R: Rng>(rng: &mut R) -> NodeParams {
    let mut id = [0u8; NODE_ID_SIZE];
    rng.fill_bytes(&mut id);
    let keypair = PrivateKey::generate(rng).unwrap();
    return NodeParams{
        id: id,
        private_key: keypair,
    };
}

fn new_path_vector<R: Rng>(rng: &mut R, num_hops: u8, is_surb: bool) -> (Vec<NodeParams>, Vec<PathHop>) {
    const DELAY_BASE: u32 = 123;

    // Generate the keypairs and node identifiers for the "nodes".
    let mut nodes = vec![];
    let mut i = 0;
    while i < num_hops {
        nodes.push(new_node(rng));
        i += 1;
    }

    // Assemble the path vector.
    let mut path = vec![];
    i = 0;
    while i < num_hops {
        let mut commands: Vec<RoutingCommand> = vec![];
        if i < num_hops - 1 {
            // Non-terminal hop, add the delay.
            let delay = RoutingCommand::Delay(
                Delay{
                    delay: DELAY_BASE * (i as u32 + 1),
                }
            );
            commands.push(delay);
        } else {
	    // Terminal hop, add the recipient.
            let mut rcpt_id = [0u8; RECIPIENT_ID_SIZE];
            rng.fill_bytes(&mut rcpt_id);
            let rcpt = RoutingCommand::Recipient(
                Recipient{
                    id: rcpt_id,
                }
            );
            commands.push(rcpt);

            if is_surb {
                let mut surb_id = [0u8; SURB_ID_SIZE];
                rng.fill_bytes(&mut surb_id);
                let surb_reply = RoutingCommand::SURBReply(
                    SURBReply{
                        id: surb_id,
                    }
                );
                commands.push(surb_reply);
            }
        }
        let hop = PathHop {
            id: nodes[i as usize].id,
            public_key: nodes[i as usize].private_key.public_key(),
            commands: Some(commands),
        };
        path.push(hop);
        i += 1;
    }
    return (nodes, path);
}

fn criterion_sphinx_unwrap_benchmark(c: &mut Criterion) {
    let mut payload = [0u8; FORWARD_PAYLOAD_SIZE];
    let s = String::from("We must defend our own privacy if we expect to have any. \
                          We must come together and create systems which allow anonymous transactions to take place. \
                          People have been defending their own privacy for centuries with whispers, darkness, envelopes, \
                          closed doors, secret handshakes, and couriers. The technologies of the past did not allow for strong \
                          privacy, but electronic technologies do.");
    let _s_len = s.len();
    let string_bytes = s.into_bytes();
    payload[.._s_len].copy_from_slice(&string_bytes);

    let mut r = os_rng();
    let is_surb = false;
    let _tuple = new_path_vector(&mut r, MAX_HOPS as u8, is_surb);

    let nodes = _tuple.0;
    let path = _tuple.1;

    let packet = new_packet(&mut r, path, payload).unwrap();

    c.bench_function("sphinx unwrap", move |b| b.iter(|| {
        let _unwrap_tuple = sphinx_packet_unwrap(&nodes[0].private_key, &mut packet.clone());
    }));
}


criterion_group!(benches, criterion_sphinx_unwrap_benchmark);
criterion_main!(benches);
