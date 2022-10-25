Below, sample circuit will be zkevm circuit.

1. generate params and vkey for sample circuit.

run sample circuit with some random input, and create proof.

```
cargo run --example zkevm --release -- --command sample_run --folder-path ./output
// Input:
// Output: sample circuit's instances and transcripts (with random run)
```

2. Remember to change `halo2-snark-aggregator-circuit/configs/verify_circuit.config`

3. Since vkey read/write doesn't currently work (see https://github.com/zcash/halo2/pull/661), we do vkey, pkey, create_proof, verify_proof, and solidity code generation all in one step.

```
cargo run --example zkevm --release -- --command verify_run --folder-path ./output --template-path ../halo2-snark-aggregator-solidity/templates
// Input: sample circuit's params and vkey, nproofs * sample circuit's instances and transcript, verify circuit's params
// Output: verify circuit's vkey, instances and proof transcript, verify result (console only), verify circuit's solidity code
```

TODO:

1. expose the final pair as instances.
2. see if we can load vkey from file instead of generating it again due to issue see https://github.com/zcash/halo2/issues/449, then verify circuit doesn't depend on concret circuit anymore.

Args:
args for services:
setup: 1. target_circuit params, 2. target_circuit vkey, 3. sample target_circuit intances and transcript (so user should run it once).
run: N \* (intances and transcript)
