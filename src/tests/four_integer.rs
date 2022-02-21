use crate::four::{FourBaseGate, FourBaseGateConfig, FourIntegerGate, FourRangeGate};
use crate::gates::base_gate::BaseRegion;
use crate::gates::range_gate::RangeGateConfig;
use crate::pair;
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
struct TestFourIntegerGateConfig {
    base_gate_config: FourBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

const BITS: usize = 16usize;
const LIMB_WIDTH: usize = 64usize;

#[derive(Default)]
struct TestFourIntegerGateCircuit<N: FieldExt> {
    _marker: PhantomData<N>,
}

impl<N: FieldExt> Circuit<N> for TestFourIntegerGateCircuit<N> {
    type Config = TestFourIntegerGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FourBaseGate::<N>::configure(meta);
        let range_gate_config = FourRangeGate::<N, BITS>::configure(meta, &base_gate_config);
        TestFourIntegerGateConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<N>) -> Result<(), Error> {
        let base_gate = FourBaseGate::new(config.base_gate_config);
        let range_gate = FourRangeGate::<N, BITS>::new(config.range_gate_config, &base_gate);
        let integer_gate = FourIntegerGate::<'_, '_, N, N, LIMB_WIDTH, BITS>::new(&range_gate);

        range_gate.init_table(&mut layouter)?;

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut region = BaseRegion::new(&mut region, &mut base_offset);
                let r = &mut region;

                let zero = N::zero();
                let one = N::one();

                let seed = chrono::offset::Utc::now().timestamp_nanos().try_into().unwrap();
                let rng = XorShiftRng::seed_from_u64(seed);
                let a = N::random(rng.clone());
                let b = N::random(rng.clone());

                let mut assigned_a = integer_gate.assign_integer(r, &a)?;
                let mut assigned_b = integer_gate.assign_integer(r, &b)?;

                let c = a + b;
                let mut c0 = integer_gate.assign_integer(r, &c)?;
                let mut c1 = integer_gate.add(r, &assigned_a, &assigned_b)?;
                let c0n = integer_gate.native(r, &mut c0)?;
                let c1n = integer_gate.native(r, &mut c1)?;
                base_gate.assert_equal(r, c0n, c1n)?;

                let d = -a;
                let assigned_d = integer_gate.assign_integer(r, &d)?;
                let mut ad = integer_gate.add(r, &assigned_a, &assigned_d)?;
                let reduced_ad = integer_gate.reduce(r, &mut ad)?;
                base_gate.one_line_add(r, reduced_ad.limbs_le.iter().map(|v| pair!(v, one)).collect(), zero)?;

                let e = a - b;
                let mut e0 = integer_gate.assign_integer(r, &e)?;
                let mut e1 = integer_gate.sub(r, &assigned_a, &assigned_b)?;
                let e0n = integer_gate.native(r, &mut e0)?;
                let e1n = integer_gate.native(r, &mut e1)?;
                base_gate.assert_equal(r, e0n, e1n)?;

                let f = a * b;
                let mut f0 = integer_gate.assign_integer(r, &f)?;
                let mut f1 = integer_gate.mul(r, &mut assigned_a, &mut assigned_b)?;
                let f0n = integer_gate.native(r, &mut f0)?;
                let f1n = integer_gate.native(r, &mut f1)?;
                base_gate.assert_equal(r, f0n, f1n)?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_four_integer_gate_ops_success() {
    const K: u32 = BITS as u32 + 1;
    let circuit = TestFourIntegerGateCircuit::<Fp> {
        success: true,
        _marker: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
