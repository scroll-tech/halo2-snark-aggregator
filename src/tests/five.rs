use crate::five::{FiveBaseGate, FiveBaseGateConfig, MUL_COLUMNS, VAR_COLUMNS};
use crate::{
    base_gate::{BaseRegion, ValueSchema},
    pair_empty,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

#[derive(Clone)]
struct TestFiveBaseGateConfig {
    base_gate_config: FiveBaseGateConfig,
}

#[derive(Default)]
struct TestFiveBaseGateCircuit<N: FieldExt> {
    success: bool,
    _marker: PhantomData<N>,
}

impl<N: FieldExt> Circuit<N> for TestFiveBaseGateCircuit<N> {
    type Config = TestFiveBaseGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FiveBaseGate::<N>::configure(meta);
        TestFiveBaseGateConfig { base_gate_config }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let base_gate = FiveBaseGate::new(config.base_gate_config);

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut r = BaseRegion::new(&mut region, &mut base_offset);

                let seed = chrono::offset::Utc::now().timestamp_nanos().try_into().unwrap();
                let rng = XorShiftRng::seed_from_u64(seed);
                let var_rands = [(); VAR_COLUMNS * 2].map(|_| N::random(rng.clone()));
                let mul_rands = [(); MUL_COLUMNS].map(|_| N::random(rng.clone()));
                let next_rands = [(); 2].map(|_| N::random(rng.clone()));

                let result = (0..VAR_COLUMNS).fold(N::zero(), |acc, i| acc + var_rands[i] * var_rands[i + VAR_COLUMNS]);
                let result = (0..MUL_COLUMNS).fold(result, |acc, i| {
                    acc + var_rands[i * 2] * var_rands[i * 2 + 1] * mul_rands[i]
                });
                let result = result + next_rands[0] * next_rands[1];

                let result = if self.success { result } else { result - N::one() };

                let schemas: Vec<_> = (0..VAR_COLUMNS)
                    .map(|i| (ValueSchema::Unassigned(var_rands[i]), var_rands[i + VAR_COLUMNS]))
                    .collect();

                base_gate.one_line(
                    &mut r,
                    schemas.try_into().unwrap(),
                    -result,
                    (mul_rands.into(), next_rands[0]),
                )?;

                base_gate.one_line(
                    &mut r,
                    vec![
                        pair_empty!(N),
                        pair_empty!(N),
                        pair_empty!(N),
                        pair_empty!(N),
                        (ValueSchema::Unassigned(next_rands[1]), N::zero()),
                    ],
                    N::zero(),
                    (vec![], N::zero()),
                )?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_base_gate_success() {
    const K: u32 = 8;
    let circuit = TestFiveBaseGateCircuit::<Fp> {
        success: true,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_ok());
}

#[test]
fn test_five_base_gate_failure() {
    const K: u32 = 8;
    let circuit = TestFiveBaseGateCircuit::<Fp> {
        success: false,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_err());
}
