use crate::gates::base_gate::five::{
    FiveColumnBaseGate, FiveColumnBaseGateConfig,
};
use crate::gates::base_gate::RegionAux;
use crate::gates::integer_gate::five::FiveColumnIntegerGate;
use crate::gates::integer_gate::IntegerGateOps;
use crate::gates::range_gate::five::FiveColumnRangeGate;
use crate::gates::range_gate::RangeGateConfig;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    pasta::Fp,
    pasta::Fq,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Add,
    Neg,
    Sub,
    Mul,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Add
    }
}

#[derive(Clone)]
struct TestFiveColumnIntegerGateConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnIntegerGateCircuit<W: FieldExt, N: FieldExt> {
    test_case: TestCase,
    _phantom_w: PhantomData<W>,
    _phantom_n: PhantomData<N>,
}

impl<W: FieldExt, N: FieldExt> TestFiveColumnIntegerGateCircuit<W, N> {
    fn setup_test_add(
        &self,
        integer_gate: &FiveColumnIntegerGate<'_, '_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);

        let a = W::random(rng.clone());
        let b = W::random(rng.clone());
        let c = a + b;

        let assigned_a = integer_gate.assigned_constant(r, a)?;
        let assigned_b = integer_gate.assigned_constant(r, b)?;
        let assigned_c = integer_gate.assigned_constant(r, c)?;

        let res = integer_gate.add(r, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_sub(
        &self,
        integer_gate: &FiveColumnIntegerGate<'_, '_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        let a = W::random(rng.clone());
        let b = W::random(rng.clone());
        let c = a - b;

        let assigned_a = integer_gate.assigned_constant(r, a)?;
        let assigned_b = integer_gate.assigned_constant(r, b)?;
        let assigned_c = integer_gate.assigned_constant(r, c)?;

        let res = integer_gate.sub(r, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_neg(
        &self,
        integer_gate: &FiveColumnIntegerGate<'_, '_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        let a = W::random(rng.clone());
        let c = -a;

        let assigned_a = integer_gate.assigned_constant(r, a)?;
        let assigned_c = integer_gate.assigned_constant(r, c)?;

        let res = integer_gate.neg(r, &assigned_a)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_mul(
        &self,
        integer_gate: &FiveColumnIntegerGate<'_, '_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        let a = W::random(rng.clone());
        let b = W::random(rng.clone());
        let c = a * b;

        let mut assigned_a = integer_gate.assigned_constant(r, a)?;
        let mut assigned_b = integer_gate.assigned_constant(r, b)?;
        let assigned_c = integer_gate.assigned_constant(r, c)?;

        let res = integer_gate.mul(r, &mut assigned_a, &mut assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl<W: FieldExt, N: FieldExt> Circuit<N> for TestFiveColumnIntegerGateCircuit<W, N> {
    type Config = TestFiveColumnIntegerGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<N>::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, W, N, COMMON_RANGE_BITS>::configure(meta, &base_gate_config);
        TestFiveColumnIntegerGateConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::new(config.range_gate_config, &base_gate);
        let integer_gate = FiveColumnIntegerGate::new(&range_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut aux = RegionAux::new(&mut region, &mut base_offset);
                let r = &mut aux;
                let round = 100;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Add => self.setup_test_add(&integer_gate, r),
                        TestCase::Sub => self.setup_test_sub(&integer_gate, r),
                        TestCase::Neg => self.setup_test_neg(&integer_gate, r),
                        TestCase::Mul => self.setup_test_mul(&integer_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_integer_gate_add() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerGateCircuit::<Fq, Fp> {
        test_case: TestCase::Add,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_integer_gate_sub() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerGateCircuit::<Fq, Fp> {
        test_case: TestCase::Sub,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_integer_gate_neg() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerGateCircuit::<Fq, Fp> {
        test_case: TestCase::Neg,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_integer_gate_mul() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerGateCircuit::<Fq, Fp> {
        test_case: TestCase::Mul,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
