rm -rf output
mkdir output
cargo run --example $1 --release -- --command sample_setup --nproofs 2 --folder-path ./output
cargo run --example $1 --release -- --command sample_run --nproofs 2 --folder-path ./output &&
cargo run --example $1 --release -- --command verify_setup --nproofs 2 --folder-path ./output &&
cargo run --example $1 --release -- --command verify_run --nproofs 2 --folder-path ./output &&
cargo run --example $1 --release -- --command verify_check --nproofs 2 --folder-path ./output &&
cargo run --example $1 --release -- --command verify_solidity --nproofs 2 --folder-path ./output --template-path ../halo2-snark-aggregator-solidity/templates

cd ../halo2-snark-aggregator-solidity
bash setup.sh
cd waffle
yarn test
