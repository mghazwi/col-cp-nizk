pub mod tests;

use crate::globals::{
    add_bytes, add_field_elements, add_g1_elements, add_g2_elements, add_incoming_msg_channel,
    get_n_connected_parties, get_n_parties, get_party_id, increment_n_connected_parties,
    print_stats, set_n_parties, set_party_id, INCOMING_MSG_CHANNELS, MY_PEERS, N_CONNECTED_PARTIES,
    STATS,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, Write};
use bytes::Bytes;
use futures::executor::block_on;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::ops::AddAssign;
use std::thread::{self, ThreadId};
use std::time::Duration;

#[derive(Copy, Clone)]
pub enum ElementType {
    Field,
    G1,
    G2,
}

// TODO: Instead of having a fixed vector, just use the party id to generate the host address
pub const PARTY_HOSTS: [&str; 128] = [
    "127.0.0.1:3000",
    "127.0.0.1:3001",
    "127.0.0.1:3002",
    "127.0.0.1:3003",
    "127.0.0.1:3004",
    "127.0.0.1:3005",
    "127.0.0.1:3006",
    "127.0.0.1:3007",
    "127.0.0.1:3008",
    "127.0.0.1:3009",
    "127.0.0.1:3010",
    "127.0.0.1:3011",
    "127.0.0.1:3012",
    "127.0.0.1:3013",
    "127.0.0.1:3014",
    "127.0.0.1:3015",
    "127.0.0.1:3016",
    "127.0.0.1:3017",
    "127.0.0.1:3018",
    "127.0.0.1:3019",
    "127.0.0.1:3020",
    "127.0.0.1:3021",
    "127.0.0.1:3022",
    "127.0.0.1:3023",
    "127.0.0.1:3024",
    "127.0.0.1:3025",
    "127.0.0.1:3026",
    "127.0.0.1:3027",
    "127.0.0.1:3028",
    "127.0.0.1:3029",
    "127.0.0.1:3030",
    "127.0.0.1:3031",
    "127.0.0.1:3032",
    "127.0.0.1:3033",
    "127.0.0.1:3034",
    "127.0.0.1:3035",
    "127.0.0.1:3036",
    "127.0.0.1:3037",
    "127.0.0.1:3038",
    "127.0.0.1:3039",
    "127.0.0.1:3040",
    "127.0.0.1:3041",
    "127.0.0.1:3042",
    "127.0.0.1:3043",
    "127.0.0.1:3044",
    "127.0.0.1:3045",
    "127.0.0.1:3046",
    "127.0.0.1:3047",
    "127.0.0.1:3048",
    "127.0.0.1:3049",
    "127.0.0.1:3050",
    "127.0.0.1:3051",
    "127.0.0.1:3052",
    "127.0.0.1:3053",
    "127.0.0.1:3054",
    "127.0.0.1:3055",
    "127.0.0.1:3056",
    "127.0.0.1:3057",
    "127.0.0.1:3058",
    "127.0.0.1:3059",
    "127.0.0.1:3060",
    "127.0.0.1:3061",
    "127.0.0.1:3062",
    "127.0.0.1:3063",
    "127.0.0.1:3064",
    "127.0.0.1:3065",
    "127.0.0.1:3066",
    "127.0.0.1:3067",
    "127.0.0.1:3068",
    "127.0.0.1:3069",
    "127.0.0.1:3070",
    "127.0.0.1:3071",
    "127.0.0.1:3072",
    "127.0.0.1:3073",
    "127.0.0.1:3074",
    "127.0.0.1:3075",
    "127.0.0.1:3076",
    "127.0.0.1:3077",
    "127.0.0.1:3078",
    "127.0.0.1:3079",
    "127.0.0.1:3080",
    "127.0.0.1:3081",
    "127.0.0.1:3082",
    "127.0.0.1:3083",
    "127.0.0.1:3084",
    "127.0.0.1:3085",
    "127.0.0.1:3086",
    "127.0.0.1:3087",
    "127.0.0.1:3088",
    "127.0.0.1:3089",
    "127.0.0.1:3090",
    "127.0.0.1:3091",
    "127.0.0.1:3092",
    "127.0.0.1:3093",
    "127.0.0.1:3094",
    "127.0.0.1:3095",
    "127.0.0.1:3096",
    "127.0.0.1:3097",
    "127.0.0.1:3098",
    "127.0.0.1:3099",
    "127.0.0.1:3100",
    "127.0.0.1:3101",
    "127.0.0.1:3102",
    "127.0.0.1:3103",
    "127.0.0.1:3104",
    "127.0.0.1:3105",
    "127.0.0.1:3106",
    "127.0.0.1:3107",
    "127.0.0.1:3108",
    "127.0.0.1:3109",
    "127.0.0.1:3110",
    "127.0.0.1:3111",
    "127.0.0.1:3112",
    "127.0.0.1:3113",
    "127.0.0.1:3114",
    "127.0.0.1:3115",
    "127.0.0.1:3116",
    "127.0.0.1:3117",
    "127.0.0.1:3118",
    "127.0.0.1:3119",
    "127.0.0.1:3120",
    "127.0.0.1:3121",
    "127.0.0.1:3122",
    "127.0.0.1:3123",
    "127.0.0.1:3124",
    "127.0.0.1:3125",
    "127.0.0.1:3126",
    "127.0.0.1:3127",
];

#[derive(Clone)]
pub struct Net {}

pub struct Peer {
    pub id: usize,
    pub host: String,
}

fn handle_client(mut stream: TcpStream) {
    let (sender, receiver) = std::sync::mpsc::channel();

    let mut buffer = [0; 2048];

    // Read the party id
    let party_id = match stream.read_exact(&mut buffer[0..1]) {
        Ok(_) => buffer[0] as usize,
        Err(e) => {
            panic!("Failed to read party id from stream: {}", e);
        }
    };

    add_incoming_msg_channel(party_id, receiver);

    loop {
        // Read first byte from the stream that represents the size of the message
        let n_bytes = match stream.read_exact(&mut buffer[0..1]) {
            Ok(_) => buffer[0] as usize,
            Err(_e) => {
                return;
            }
        };

        let mut bytes = vec![0; n_bytes];

        // Read the actual message from the stream
        match stream.read_exact(&mut bytes) {
            Ok(_) => {
                sender.send(Bytes::from(bytes));
            }
            Err(e) => {
                panic!("Failed to read from stream: {}", e);
            }
        }
    }
}

impl Net {
    pub fn init_network(party_id: usize, n_parties: usize) {
        set_party_id(party_id);
        set_n_parties(n_parties);

        let host = PARTY_HOSTS[party_id];

        println!("Party {} is listening on {}", party_id, host);

        let listener = TcpListener::bind(host).unwrap();

        std::thread::spawn(move || loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    println!("New connection: {}", stream.peer_addr().unwrap());
                    increment_n_connected_parties();

                    std::thread::spawn(move || {
                        handle_client(stream);
                    });
                }
                Err(e) => {
                    eprintln!("Connection failed: {}", e);
                }
            }
        });

        // Connect to all other parties
        let n_parties = get_n_parties();
        let other_hosts = PARTY_HOSTS.iter().take(n_parties).cloned();

        for (i, host) in other_hosts.enumerate() {
            if i != party_id {
                println!("Connecting to party {} on {}", i, host);

                // Retry if connection is not established
                let stream;

                loop {
                    match TcpStream::connect(host) {
                        Ok(mut s) => {
                            println!("Connected to party {}", i);
                            s.write_all(&[party_id as u8]).unwrap();
                            stream = s;

                            break;
                        }
                        Err(e) => {
                            println!("Failed to connect to party {}: {}", i, e);
                            thread::sleep(Duration::from_secs(1));
                        }
                    }
                }

                // Store the stream in a global variable
                MY_PEERS.lock().unwrap().push(stream);
            }
        }

        while get_n_connected_parties() < n_parties - 1 {
            println!(
                "Waiting for all parties to connect, connected: {}/{}",
                get_n_connected_parties(),
                n_parties - 1
            );
            thread::sleep(Duration::from_secs(1));
        }

        println!("Connected: {}/{}", get_n_connected_parties(), n_parties - 1);

        println!("Party {} is ready", party_id);
    }

    pub fn deinit_network() {
        let my_peers = MY_PEERS.lock().unwrap();

        for peer in my_peers.iter() {
            if let Err(_) = peer.shutdown(std::net::Shutdown::Both) {
                // Ignore shutdown errors
            }
        }

        print_stats();
    }

    // Generic function to exchange elements (field or group) between parties
    pub fn exchange_elements<E>(msg: E, element_type: ElementType) -> Vec<E>
        where
            E: CanonicalSerialize + CanonicalDeserialize + Send + Sync,
    {
        // println!("exchange called");
        let my_peers = MY_PEERS.lock().unwrap();

        let n_bytes = msg.compressed_size();
        let mut bytes: Vec<u8> = Vec::with_capacity(n_bytes);
        msg.serialize_compressed(&mut bytes).unwrap();
        // Prepend bytes with one byte representing the size of the msg
        bytes.insert(0, n_bytes as u8);

        let bytes_len = bytes.len();
        for mut peer in my_peers.iter() {
            peer.write(&bytes).unwrap();
            add_bytes(bytes_len);
        }

        match element_type {
            ElementType::Field => add_field_elements(my_peers.len()),
            ElementType::G1 => add_g1_elements(my_peers.len()),
            ElementType::G2 => add_g2_elements(my_peers.len()),
        }

        let mut shares = Vec::with_capacity(get_n_parties());

        let n_parties = get_n_parties();

        for receiver in INCOMING_MSG_CHANNELS.lock().unwrap().iter_mut() {
            let r = receiver.as_mut();

            if r.is_none() {
                continue;
            }

            let share = r.unwrap().recv().unwrap();

            let reader = &mut share.as_ref();
            shares.push(E::deserialize_compressed(reader).unwrap());
        }

        // Add my share to the vector
        shares.push(msg);

        shares
    }

    pub fn distribute_witnesses<E>(witnesses: &Vec<E>)
        where
            E: CanonicalSerialize + Send + Sync,
    {
        let my_peers = MY_PEERS.lock().unwrap();

        for (i, mut peer) in my_peers.iter().enumerate() {
            let witness = &witnesses[i];

            let n_bytes = witness.compressed_size();
            let mut bytes: Vec<u8> = Vec::with_capacity(n_bytes);

            witness.serialize_compressed(&mut bytes).unwrap();

            // Prepend bytes with one byte representing the size of the msg
            bytes.insert(0, n_bytes as u8);

            let len = bytes.len();
            peer.write_all(&bytes).unwrap();

            add_bytes(len);
            add_field_elements(1);
        }
    }

    pub fn receive_value_from<E>(party_id: usize) -> E
        where
            E: CanonicalDeserialize + Send + Sync,
    {
        // println!("recieve called");
        let mut receiver = &mut INCOMING_MSG_CHANNELS.lock().unwrap()[party_id];

        let share = receiver.as_mut().unwrap().recv().unwrap();

        let reader = &mut share.as_ref();

        E::deserialize_compressed(reader).unwrap()
    }
}
