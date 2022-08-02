set -x

rm -rf output
mkdir output
cargo run --example $1 --release -- --command sample_setup --folder-path ./output
cargo run --example $1 --release -- --command sample_run --folder-path ./output &&
cargo run --example $1 --release -- --command verify_setup --folder-path ./output &&
cargo run --example $1 --release -- --command verify_run --folder-path ./output &&
cargo run --example $1 --release -- --command verify_check --folder-path ./output &&
cargo run --example $1 --release -- --command verify_solidity --folder-path ./output --template-path ../halo2-snark-aggregator-solidity/templates

cd ../halo2-snark-aggregator-solidity
bash setup.sh
cd waffle
yarn test
