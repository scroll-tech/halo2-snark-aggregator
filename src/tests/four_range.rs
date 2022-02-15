use crate::{
    base_gate::BaseRegion,
    four::{FourBaseGate, FourBaseGateConfig, FourRangeGate},
    range_gate::RangeGateConfig,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    pasta::Fp,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::random;
use std::marker::PhantomData;

#[derive(Clone)]
struct TestRangeGateConfig {
    base_gate_config: FourBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestRangeGateCircuit<N: FieldExt> {
    success: bool,
    _marker: PhantomData<N>,
}

const BITS: u32 = 8u32;

impl<N: FieldExt> Circuit<N> for TestRangeGateCircuit<N> {
    type Config = TestRangeGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FourBaseGate::<N>::configure(meta);
        let range_gate_config = FourRangeGate::<N>::configure(meta, &base_gate_config, BITS);
        TestRangeGateConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let base_gate = FourBaseGate::<N>::new(config.base_gate_config);
        let range_gate = FourRangeGate::<N>::new(config.range_gate_config, &base_gate);
        range_gate.init_table(&mut layouter)?;

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut r = BaseRegion::new(&mut region, &mut base_offset);

                let n = 1u64 << BITS;
                let a = if self.success {
                    N::from(random::<u64>() % n)
                } else {
                    N::from(random::<u64>() % n + n)
                };
                range_gate.assign_ranged_values(&mut r, vec![a])?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_range_gate_success() {
    const K: u32 = BITS + 1;
    let circuit = TestRangeGateCircuit::<Fp> {
        success: true,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_range_gate_failure() {
    const K: u32 = BITS + 1;
    let circuit = TestRangeGateCircuit::<Fp> {
        success: false,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_err());
}
