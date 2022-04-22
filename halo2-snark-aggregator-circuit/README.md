1. generate params and vkey for sample circuit.
```
mkdir output
cargo run --release -- --command sample_setup --nproofs 2 --folder-path ./output
```

2. run sample circuit with some random input, and create proof.
```
cargo run --release -- --command sample_run --nproofs 2 --folder-path ./output
```

3. generate params and vkey for verify circuit, it takes long time to generate large params in the first run.
```
cargo run --release -- --command verify_setup --nproofs 2 --folder-path ./output
```

4. run verify circuit to verify the proof of sample circuits generated in step 2.
```
cargo run --release -- --command verify_run --nproofs 2 --folder-path ./output
```

TODO:
1. implement verify_check command to verify the proof generated in step 4
2. expose the final pair as instances.
3. see if we can load vkey from file instead of generating it again due to issue see https://github.com/zcash/halo2/issues/449
