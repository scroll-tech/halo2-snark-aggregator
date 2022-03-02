use crate::circuits::five::integer_circuit::FiveColumnIntegerCircuit;
use crate::circuits::integer_circuit::IntegerCircuitOps;
use crate::gates::base_gate::RegionAux;
use crate::gates::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::gates::five::range_gate::FiveColumnRangeGate;
use crate::gates::range_gate::RangeGateConfig;
use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pairing_bn256::bn256::{Fq, Fr};
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Add,
    Neg,
    Sub,
    Mul,
    Square,
    IsZero,
    Div,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Add
    }
}

#[derive(Clone)]
struct TestFiveColumnIntegerCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnIntegerCircuitCircuit<W: BaseExt, N: FieldExt> {
    test_case: TestCase,
    _phantom_w: PhantomData<W>,
    _phantom_n: PhantomData<N>,
}

impl<W: BaseExt, N: FieldExt> TestFiveColumnIntegerCircuitCircuit<W, N> {
    fn random() -> W {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        W::random(rng)
    }
    fn setup_test_add(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a + b;
        let assigned_a = integer_gate.assign_constant(r, a)?;
        let assigned_b = integer_gate.assign_constant(r, b)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;

        let res = integer_gate.add(r, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_sub(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a - b;

        let assigned_a = integer_gate.assign_constant(r, a)?;
        let assigned_b = integer_gate.assign_constant(r, b)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;

        let res = integer_gate.sub(r, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_neg(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let c = -a;

        let assigned_a = integer_gate.assign_constant(r, a)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;

        let res = integer_gate.neg(r, &assigned_a)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_mul(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a * b;

        let mut assigned_a = integer_gate.assign_constant(r, a)?;
        let mut assigned_b = integer_gate.assign_constant(r, b)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;

        let res = integer_gate.mul(r, &mut assigned_a, &mut assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_square(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let c = a * a;

        let mut assigned_a = integer_gate.assign_constant(r, a)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;

        let res = integer_gate.square(r, &mut assigned_a)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_div(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let b = b.invert().unwrap_or(W::one());
        let c = a * b.invert().unwrap();

        let mut assigned_a = integer_gate.assign_constant(r, a)?;
        let mut assigned_b = integer_gate.assign_constant(r, b)?;
        let assigned_c = integer_gate.assign_constant(r, c)?;
        let mut assigned_zero = integer_gate.assign_constant(r, W::zero())?;

        let (cond, res) = integer_gate.div(r, &mut assigned_a, &mut assigned_b)?;
        integer_gate.assert_equal(r, &assigned_c, &res)?;
        integer_gate
            .base_gate()
            .assert_constant(r, &cond.into(), N::zero())?;

        let (cond, res) = integer_gate.div(r, &mut assigned_a, &mut assigned_zero)?;
        integer_gate.assert_equal(r, &assigned_zero, &res)?;
        integer_gate
            .base_gate()
            .assert_constant(r, &cond.into(), N::one())?;
        Ok(())
    }

    fn setup_test_is_zero(
        &self,
        integer_gate: &FiveColumnIntegerCircuit<'_, W, N>,
        r: &mut RegionAux<'_, '_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let b = if b == a { a + W::one() } else { b };

        let assigned_a = integer_gate.assign_constant(r, a)?;
        let assigned_b = integer_gate.assign_constant(r, b)?;

        let zero = N::zero();
        let one = N::one();

        let mut vzero = integer_gate.sub(r, &assigned_a, &assigned_a)?;
        let vtrue = integer_gate.is_zero(r, &mut vzero)?;
        integer_gate
            .base_gate()
            .assert_constant(r, &(&vtrue).into(), one)?;

        let mut vnzero = integer_gate.sub(r, &assigned_a, &assigned_b)?;
        let vfalse = integer_gate.is_zero(r, &mut vnzero)?;
        integer_gate
            .base_gate()
            .assert_constant(r, &(&vfalse).into(), zero)?;

        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl<W: BaseExt, N: FieldExt> Circuit<N> for TestFiveColumnIntegerCircuitCircuit<W, N> {
    type Config = TestFiveColumnIntegerCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<N>::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, W, N, COMMON_RANGE_BITS>::configure(meta, &base_gate_config);
        TestFiveColumnIntegerCircuitConfig {
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
        let range_gate = FiveColumnRangeGate::<'_, W, N, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerCircuit::new(&range_gate);

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
                        TestCase::IsZero => self.setup_test_is_zero(&integer_gate, r),
                        TestCase::Div => self.setup_test_div(&integer_gate, r),
                        TestCase::Square => self.setup_test_square(&integer_gate, r),
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
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
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
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
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
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
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
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
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

#[test]
fn test_five_column_integer_gate_square() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
        test_case: TestCase::Square,
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
fn test_five_column_integer_gate_is_zero() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
        test_case: TestCase::IsZero,
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
fn test_five_column_integer_gate_div() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerCircuitCircuit::<Fq, Fr> {
        test_case: TestCase::Div,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
