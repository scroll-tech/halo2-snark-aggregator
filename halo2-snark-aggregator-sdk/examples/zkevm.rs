use eth_types::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use halo2_snark_aggregator_circuit::sample_circuit::TargetCircuit;
use halo2_snark_aggregator_sdk::zkaggregate;
use pairing_bn256::bn256::{Bn256, Fr, G1Affine};
use zkevm_circuits::evm_circuit::{witness::Block, EvmCircuit};

#[derive(Debug, Default)]
pub struct TestCircuit<F> {
    block: Block<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = EvmCircuit<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let tx_table = [(); 4].map(|_| meta.advice_column());
        let rw_table = [(); 11].map(|_| meta.advice_column());
        let bytecode_table = [(); 5].map(|_| meta.advice_column());
        let block_table = [(); 3].map(|_| meta.advice_column());
        // Use constant expression to mock constant instance column for a more
        // reasonable benchmark.
        let power_of_randomness = [(); 31].map(|_| Expression::Constant(F::one()));

        EvmCircuit::configure(
            meta,
            power_of_randomness,
            &tx_table,
            &rw_table,
            &bytecode_table,
            &block_table,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.assign_block(&mut layouter, &self.block)?;
        Ok(())
    }
}

impl TargetCircuit<G1Affine, Bn256> for TestCircuit<Fr> {
    const TARGET_CIRCUIT_K: u32 = 18;
    const PUBLIC_INPUT_SIZE: usize = (Self::TARGET_CIRCUIT_K * 2) as usize;
    const N_PROOFS: usize = 1;
    const NAME: &'static str = "zkevm";
    const PARAMS_NAME: &'static str = "zkevm";
    const READABLE_VKEY: bool = false;

    type Circuit = TestCircuit<Fr>;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<Fr>>) {
        (Self::Circuit::default(), vec![])
    }

    fn load_instances(buf: &Vec<u8>) -> Vec<Vec<Vec<Fr>>> {
        vec![vec![]]
    }
}

type ZkEvm = TestCircuit<Fr>;
zkaggregate! {1, vec![], ZkEvm}

pub fn main() {
    let builder = zkcli::builder(25);
    builder.run()
}
