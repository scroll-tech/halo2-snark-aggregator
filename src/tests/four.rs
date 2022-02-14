use crate::base_gate::four::{MUL_COLUMNS, VAR_COLUMNS};
use crate::base_gate::{
    four::{FourBaseGate, FourBaseGateConfig},
    BaseRegion, ValueSchema,
};
use crate::pair_empty;
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
struct TestFourBaseGateConfig {
    base_gate_config: FourBaseGateConfig,
}

#[derive(Default)]
struct TestFourBaseGateCircuit<N: FieldExt> {
    success: bool,
    _marker: PhantomData<N>,
}

impl<N: FieldExt> Circuit<N> for TestFourBaseGateCircuit<N> {
    type Config = TestFourBaseGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FourBaseGate::<N>::configure(meta);
        TestFourBaseGateConfig { base_gate_config }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let base_gate = FourBaseGate::new(config.base_gate_config);

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
fn test_four_base_gate_success() {
    const K: u32 = 8;
    let circuit = TestFourBaseGateCircuit::<Fp> {
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
fn test_four_base_gate_failure() {
    const K: u32 = 8;
    let circuit = TestFourBaseGateCircuit::<Fp> {
        success: false,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_err());
}
