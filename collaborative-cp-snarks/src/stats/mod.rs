use crate::{
    globals::{get_party_id, STATS},
    network::Net,
};
use csv;
use lazy_static::lazy_static;
use std::{collections::HashMap, sync::Mutex};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

lazy_static! {
    static ref MPC_OPERATION_COUNTER: Mutex<usize> = Mutex::new(0);
}

#[derive(Clone, Debug, EnumIter, PartialEq, Copy)]
pub enum Operation {
    Add,
    AddAssign,
    Div,
    DivAssign,
    Mul,
    MulAssign,
    Sub,
    SubAssign,
    Neg,
    Sum,
}

#[derive(Clone, Debug, EnumIter, PartialEq, Copy)]
pub enum StatsField {
    PublicField,
    SharedField,
    PublicGroup,
    SharedGroup,
}

#[derive(Clone, Debug)]
pub struct CommunicationStats {
    pub field_elements_exchanged_counter: usize,
    pub g1_elements_exchanged_counter: usize,
    pub g2_elements_exchanged_counter: usize,
    pub bytes_exchanged_counter: usize,
    pub time: u128,
    pub n_of_s_op_s_operations: usize,
}

#[derive(Clone, Debug)]
pub struct Stats {
    pub stats: HashMap<String, CommunicationStats>,
    pub phase: String,
    pub experiment_name: String,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            phase: "init".to_string(),
            stats: {
                let mut map = HashMap::new();

                map.insert(
                    "total".to_string(),
                    CommunicationStats {
                        field_elements_exchanged_counter: 0,
                        g1_elements_exchanged_counter: 0,
                        g2_elements_exchanged_counter: 0,
                        bytes_exchanged_counter: 0,
                        time: 0,
                        n_of_s_op_s_operations: 0,
                    },
                );
                map
            },
            experiment_name: "".to_string(),
        }
    }

    pub fn set_experiment_name(&mut self, experiment_name: &str) {
        self.experiment_name = experiment_name.to_string();
    }

    pub fn add_field_elements(&mut self, n: usize) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.field_elements_exchanged_counter += n;
        }
        if let Some(communication_stats) = self.stats.get_mut("total") {
            communication_stats.field_elements_exchanged_counter += n;
        }
    }

    pub fn add_g1_elements(&mut self, n: usize) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.g1_elements_exchanged_counter += n;
        }
        if let Some(communication_stats) = self.stats.get_mut("total") {
            communication_stats.g1_elements_exchanged_counter += n;
        }
    }

    pub fn add_g2_elements(&mut self, n: usize) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.g2_elements_exchanged_counter += n;
        }
        if let Some(communication_stats) = self.stats.get_mut("total") {
            communication_stats.g2_elements_exchanged_counter += n;
        }
    }

    pub fn add_bytes(&mut self, n_bytes: usize) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.bytes_exchanged_counter += n_bytes;
        }
        if let Some(communication_stats) = self.stats.get_mut("total") {
            communication_stats.bytes_exchanged_counter += n_bytes;
        }
    }

    pub fn increment_n_s_s_operations(&mut self) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.n_of_s_op_s_operations += 1;
        }
        if let Some(communication_stats) = self.stats.get_mut("total") {
            communication_stats.n_of_s_op_s_operations += 1;
        }
    }
    pub fn set_phase(&mut self, phase: &str) {
        self.stats
            .entry(phase.to_string())
            .or_insert(CommunicationStats {
                field_elements_exchanged_counter: 0,
                g1_elements_exchanged_counter: 0,
                g2_elements_exchanged_counter: 0,
                bytes_exchanged_counter: 0,
                time: 0,
                n_of_s_op_s_operations: 0,
            });

        self.phase = phase.to_string();
    }

    pub fn set_phase_time(&mut self, time: u128) {
        if let Some(communication_stats) = self.stats.get_mut(&self.phase) {
            communication_stats.time = time;
        }
    }

    pub fn print_stats(&self) {
        println!("{:#?}", self.stats);

        let dir_name = "experiments/";
        let dir_name = dir_name.to_string() + &self.experiment_name + "/";
        let dir_name = dir_name + &get_party_id().to_string() + "/";

        // Write to file per phase
        for (phase, stats) in &self.stats {
            std::fs::create_dir_all(&dir_name.clone()).unwrap();

            let file_name = dir_name.clone() + phase + "_stats.csv";

            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&file_name)
                .unwrap();

            file.set_len(0).unwrap();

            let mut wtr = csv::Writer::from_writer(file);

            wtr.write_record(&[
                "Field Elements",
                "G1 Elements",
                "G2 Elements",
                "Bytes",
                "Total Time",
            ])
            .unwrap();

            wtr.write_record(&[
                format!("{}", stats.field_elements_exchanged_counter),
                format!("{}", stats.g1_elements_exchanged_counter),
                format!("{}", stats.g2_elements_exchanged_counter),
                format!("{}", stats.bytes_exchanged_counter),
                format!("{}", stats.time),
            ])
            .unwrap();

            wtr.flush().unwrap();
        }
    }
}

pub fn write_to_file(
    file: &std::fs::File,
    mut operation_count: Vec<(String, Operation, StatsField, StatsField, usize, u128)>,
) {
    file.set_len(0).unwrap();

    operation_count.sort_by(|(_, _, _, _, _, count1), (_, _, _, _, _, count2)| count2.cmp(count1));

    let mut wtr = csv::Writer::from_writer(file);

    wtr.write_record(&[
        "Phase",
        "Operation",
        "LHS",
        "RHS",
        "Count",
        "Time",
        "Average Time",
    ])
    .unwrap();

    for (phase, operation, lhs, rhs, count, time) in operation_count {
        if count == 0 {
            continue;
        }

        wtr.write_record(&[
            phase,
            format!("{:?}", operation),
            format!("{:?}", lhs),
            format!("{:?}", rhs),
            format!("{}", count),
            format!("{}", time),
            format!("{}", time / count as u128),
        ])
        .unwrap();

        wtr.flush().unwrap();
    }
}
