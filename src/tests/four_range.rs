use crate::four::{FourBaseGate, FourBaseGateConfig, FourRangeGate};
use crate::gates::{base_gate::BaseRegion, range_gate::RangeGateConfig};
use crate::pair;
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
struct TestFourRangeGateConfig {
    base_gate_config: FourBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFourRangeGateCircuit<N: FieldExt> {
    success: bool,
    _marker: PhantomData<N>,
}

const BITS: usize = 8usize;

impl<N: FieldExt> Circuit<N> for TestFourRangeGateCircuit<N> {
    type Config = TestFourRangeGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FourBaseGate::<N>::configure(meta);
        let range_gate_config = FourRangeGate::<N, BITS>::configure(meta, &base_gate_config);
        TestFourRangeGateConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let base_gate = FourBaseGate::<N>::new(config.base_gate_config);
        let range_gate = FourRangeGate::<N, BITS>::new(config.range_gate_config, &base_gate);
        range_gate.init_table(&mut layouter)?;

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut r = BaseRegion::new(&mut region, &mut base_offset);

                let zero = N::zero();
                let n = 1u64 << BITS;
                let a = if self.success {
                    N::from(random::<u64>() % n)
                } else {
                    N::from(random::<u64>() % n + n)
                };
                range_gate.one_line_ranged(&mut r, vec![pair!(a, zero)], zero, (vec![], zero))?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_range_gate_success() {
    const K: u32 = BITS as u32 + 1;
    let circuit = TestFourRangeGateCircuit::<Fp> {
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
    const K: u32 = BITS as u32 + 1;
    let circuit = TestFourRangeGateCircuit::<Fp> {
        success: false,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_err());
}
