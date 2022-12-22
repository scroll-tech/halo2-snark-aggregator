use eth_types::Field;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};
use halo2_snark_aggregator_circuit::sample_circuit::TargetCircuit;
use halo2_snark_aggregator_sdk::zkaggregate;
use zkevm_circuits::evm_circuit::{witness::Block, EvmCircuit};
use zkevm_circuits::table::{BlockTable, BytecodeTable, RwTable, TxTable};

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
        let tx_table = TxTable::construct(meta);
        let rw_table = RwTable::construct(meta);
        let bytecode_table = BytecodeTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let copy_table = [(); 11].map(|_| meta.advice_column());
        let keccak_table = [(); 4].map(|_| meta.advice_column());

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
            &copy_table,
            &keccak_table,
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

impl TargetCircuit<Bn256> for TestCircuit<Fr> {
    const TARGET_CIRCUIT_K: u32 = 18;
    const PUBLIC_INPUT_SIZE: usize = 0; // (Self::TARGET_CIRCUIT_K * 2) as usize;
    const N_PROOFS: usize = 1;
    const NAME: &'static str = "zkevm";
    const PARAMS_NAME: &'static str = "zkevm";
    const READABLE_VKEY: bool = false;

    type Circuit = TestCircuit<Fr>;

    fn instance_builder() -> (Self::Circuit, Vec<Vec<Fr>>) {
        (Self::Circuit::default(), vec![])
    }

    fn load_instances(_buf: &[u8]) -> Vec<Vec<Vec<Fr>>> {
        vec![vec![]]
    }
}

type ZkEvm = TestCircuit<Fr>;
zkaggregate! {1, vec![], ZkEvm}

pub fn main() {
    // read in degree of test circuit from file
    let k = halo2_snark_aggregator_circuit::fs::load_verify_circuit_degree();

    let builder = zkcli::builder(k as u32);
    builder.run()
}
