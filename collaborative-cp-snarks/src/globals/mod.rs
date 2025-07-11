use crate::stats::Stats;
use bytes::Bytes;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::thread;
use std::{ops::AddAssign, sync::Mutex};

lazy_static! {
    pub static ref INCOMING_MSG_CHANNELS: Mutex<Vec<Option<std::sync::mpsc::Receiver<Bytes>>>> =
        Mutex::new(vec![
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None,
        ]);
    pub static ref MY_PARTY_ID: Mutex<Option<usize>> = Mutex::new(None);
    pub static ref MY_PEERS: Mutex<Vec<std::net::TcpStream>> = Mutex::new(Vec::new());
    pub static ref N_CONNECTED_PARTIES: Mutex<usize> = Mutex::new(0);
    pub static ref N_PARTIES: Mutex<Option<usize>> = Mutex::new(None);
    pub static ref STATS: Mutex<Stats> = Mutex::new(Stats::new());
    pub static ref N_S_S_OPERATIONS: Mutex<usize> = Mutex::new(0);
}

// Stats
pub fn set_phase_time(time: u128) {
    STATS.lock().unwrap().set_phase_time(time);
}

pub fn set_phase(phase: &str) {
    STATS.lock().unwrap().set_phase(phase);
}

pub fn set_experiment_name(experiment_name: &str) {
    STATS.lock().unwrap().set_experiment_name(experiment_name);
}

pub fn print_stats() {
    STATS.lock().unwrap().print_stats();
}

pub fn add_field_elements(n: usize) {
    STATS.lock().unwrap().add_field_elements(n);
}

pub fn add_g1_elements(n: usize) {
    STATS.lock().unwrap().add_g1_elements(n);
}

pub fn add_g2_elements(n: usize) {
    STATS.lock().unwrap().add_g2_elements(n);
}

pub fn add_bytes(n: usize) {
    STATS.lock().unwrap().add_bytes(n);
}

pub fn increment_n_s_s_operations() {
    STATS.lock().unwrap().increment_n_s_s_operations();
}

// Party ID
pub fn set_party_id(party_id: usize) {
    *MY_PARTY_ID.lock().unwrap() = Some(party_id);
}

pub fn get_party_id() -> usize {
    MY_PARTY_ID.lock().unwrap().unwrap()
}

// Number of parties
pub fn set_n_parties(n_parties: usize) {
    *N_PARTIES.lock().unwrap() = Some(n_parties);
}

pub fn get_n_parties() -> usize {
    N_PARTIES.lock().unwrap().unwrap()
}

// Number of connected parties
pub fn get_n_connected_parties() -> usize {
    N_CONNECTED_PARTIES.lock().unwrap().clone()
}
pub fn increment_n_connected_parties() {
    N_CONNECTED_PARTIES.lock().unwrap().add_assign(1);
}

// Message channel
pub fn add_incoming_msg_channel(party_id: usize, receiver: std::sync::mpsc::Receiver<Bytes>) {
    INCOMING_MSG_CHANNELS.lock().unwrap()[party_id] = Some(receiver);
}
