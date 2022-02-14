use crate::base_gate::{
    four::{FourBaseGate, FourBaseGateConfig},
    BaseRegion,
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
struct TestFourBaseGateBopConfig {
    base_gate_config: FourBaseGateConfig,
}

#[derive(Default)]
struct TestFourBaseGateBopCircuit<N: FieldExt> {
    _marker: PhantomData<N>,
}

impl<N: FieldExt> Circuit<N> for TestFourBaseGateBopCircuit<N> {
    type Config = TestFourBaseGateBopConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FourBaseGate::<N>::configure(meta);
        TestFourBaseGateBopConfig { base_gate_config }
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
                let a = N::random(rng.clone());
                let b = N::random(rng.clone());
                let c = a + b;
                let d = a * b;

                let a = base_gate.assign_constant(&mut r, a)?;
                let b = base_gate.assign_constant(&mut r, b)?;
                let c0 = base_gate.assign_constant(&mut r, c)?;
                let d0 = base_gate.assign_constant(&mut r, d)?;

                let c1 = base_gate.add(&mut r, &a, &b)?;
                let d1 = base_gate.mul(&mut r, &a, &b)?;
                base_gate.assert_equal(&mut r, &c0, &c1)?;
                base_gate.assert_equal(&mut r, &d0, &d1)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_four_base_gate_bop() {
    const K: u32 = 8;
    let circuit = TestFourBaseGateBopCircuit::<Fp> {
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert!(prover.verify().is_ok());
}
