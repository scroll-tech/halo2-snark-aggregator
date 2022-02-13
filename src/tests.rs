use crate::base_gate::{
    five::{FiveBaseGate, FiveBaseGateConfig},
    BaseRegion, ValueSchema,
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

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_gate_chip = FiveBaseGate::new(config.base_gate_config);

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut r = BaseRegion::new(&mut region, &mut base_offset);

                let seed = chrono::offset::Utc::now()
                    .timestamp_nanos()
                    .try_into()
                    .unwrap();
                let rng = XorShiftRng::seed_from_u64(seed);
                let rands = [(); 14].map(|_| N::random(rng.clone()));

                let result = (0..5).fold(N::zero(), |acc, i| acc + rands[i] * rands[i + 5])
                    + rands[10] * rands[0] * rands[1]
                    + rands[11] * rands[2] * rands[3]
                    + rands[12] * rands[13];

                let result = if self.success { result } else { result - N::one() };

                base_gate_chip.one_line(
                    &mut r,
                    [
                        (&ValueSchema::Unassigned(rands[0]), rands[5]),
                        (&ValueSchema::Unassigned(rands[1]), rands[6]),
                        (&ValueSchema::Unassigned(rands[2]), rands[7]),
                        (&ValueSchema::Unassigned(rands[3]), rands[8]),
                        (&ValueSchema::Unassigned(rands[4]), rands[9]),
                    ],
                    (-result, [rands[10], rands[11]], rands[12]),
                )?;

                base_gate_chip.one_line(&mut r,
                    [
                        (&ValueSchema::Empty, N::zero()),
                        (&ValueSchema::Empty, N::zero()),
                        (&ValueSchema::Empty, N::zero()),
                        (&ValueSchema::Empty, N::zero()),
                        (&ValueSchema::Unassigned(rands[13]), N::zero()),
                    ],
                    (N::zero(), [N::zero(), N::zero()], N::zero())
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_base_gate_success() {
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
fn test_base_gate_failure() {
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
