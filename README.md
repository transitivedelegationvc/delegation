#### Decentralized and Transitive Delegation with Verifiable Credentials 
This repository contains the implementation associated with the paper "Decentralized and Transitive Delegation with 
Verifiable Credentials". The Rust-based code provides a benchmark of the proposed protocol against the protocol 
proposed by the short paper "A Self Sovereign Identity Approach to Decentralized Access Control with Transitive 
Delegations" by Pieter Jan Vrielynck et Al. available [here](https://dl.acm.org/doi/10.1145/3649158.3657045). Their
work is coded in specific structures having the prefix PJV which is the acronym of the first author. 

The benchmark produces a way to get key metrics for both methods:
- The issuance time required to produce a VC.
- The issuance time required to produce a VP.
- The time required to verify a VP for a given verifier.
- The length of the VP encoded in a JWT.

The high level API allow to specify custom parameters in the `main.rs` file of the library.

To run all the available tests in the library, execute in the project directory `cargo test`.

To run the benchmark, execute in the project directory `cargo run -r`.

