use halo2_snark_aggregator_sdk::builder;
use test_circuit::TestCircuit;

mod test_circuit;

pub fn main() {
    builder::<TestCircuit, 22>();
}
