run_groth_test.zshcargo test --package collaborative-cp-snarks --lib -- snark::groth16::tests::test_groth16::maf_groth16 --exact --nocapture 0 5 2 &
cargo test --package collaborative-cp-snarks --lib -- snark::groth16::tests::test_groth16::maf_groth16 --exact --nocapture 1 5 2 &
#cargo test --package collaborative-cp-snarks --lib -- snark::groth16::tests::test_groth16::groth16 --exact --nocapture 2 7 4 3
