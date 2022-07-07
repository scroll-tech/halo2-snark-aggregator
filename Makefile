evm_bench:
	cargo test --profile bench bench_evm_circuit_prover_halo2ecc --features benches -p halo2-snark-aggregator-sdk -- --nocapture
