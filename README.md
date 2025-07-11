# Collaborative CP-NIZKs: Modular, Composable Proofs for Distributed Secrets

### This code is for academic purposes ONLY. DO NOT USE IT IN PRACTICE.

This repository contains the source code for implementing the protocols described in the paper.

The repository contains the following main components:

- The `mpc` module contains all the functionality for implementing the MPC primitives on Arkworks;
- The `network` module implements all the networking and communication functionalities required for the parties to communicate with each other;
- The `snark` module contains the implementation for the collaborative Groth16 and LegoGro16;
- The `bp` module contains the implementation for the collaborative CP-Bulletproofs.