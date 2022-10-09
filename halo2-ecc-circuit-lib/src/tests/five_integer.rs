use crate::chips::integer_chip::IntegerChipOps;
use crate::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::five::integer_chip::FiveColumnIntegerChip;
use crate::five::range_gate::FiveColumnRangeGate;
use crate::gates::base_gate::Context;
use crate::gates::range_gate::RangeGateConfig;
use crate::utils::field_to_bn;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::bn256::{Fq, Fr};
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
    LastBit,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Add
    }
}

#[derive(Clone)]
struct TestFiveColumnIntegerChipConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnIntegerChipCircuit<W: FieldExt, N: FieldExt> {
    test_case: TestCase,
    _phantom_w: PhantomData<W>,
    _phantom_n: PhantomData<N>,
}

impl<W: FieldExt, N: FieldExt> TestFiveColumnIntegerChipCircuit<W, N> {
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
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a + b;
        let assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_b = integer_gate.assign_constant(ctx, b)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;

        let res = integer_gate.add(ctx, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_sub(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a - b;

        let assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_b = integer_gate.assign_constant(ctx, b)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;

        let res = integer_gate.sub(ctx, &assigned_a, &assigned_b)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_neg(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let c = -a;

        let assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;

        let res = integer_gate.neg(ctx, &assigned_a)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_mul(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let c = a * b;

        let mut assigned_a = integer_gate.assign_constant(ctx, a)?;
        let mut assigned_b = integer_gate.assign_constant(ctx, b)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;

        let res = integer_gate.mul(ctx, &mut assigned_a, &mut assigned_b)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_square(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let c = a * a;

        let mut assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;

        let res = integer_gate.square(ctx, &mut assigned_a)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_last_bit(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let c = if field_to_bn(&a).bit(0) {
            N::one()
        } else {
            N::zero()
        };

        let mut assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_c = integer_gate.base_gate().assign_constant(ctx, c)?;

        let res = integer_gate.get_last_bit(ctx, &mut assigned_a)?;
        integer_gate
            .base_gate()
            .assert_equal(ctx, &assigned_c, &res)?;
        Ok(())
    }

    fn setup_test_div(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let b = b.invert().unwrap_or(W::one());
        let c = a * b.invert().unwrap();

        let mut assigned_a = integer_gate.assign_constant(ctx, a)?;
        let mut assigned_b = integer_gate.assign_constant(ctx, b)?;
        let assigned_c = integer_gate.assign_constant(ctx, c)?;
        let mut assigned_zero = integer_gate.assign_constant(ctx, W::zero())?;

        let (cond, res) = integer_gate.div(ctx, &mut assigned_a, &mut assigned_b)?;
        integer_gate.assert_equal(ctx, &assigned_c, &res)?;
        integer_gate
            .base_gate()
            .assert_constant(ctx, &cond.into(), N::zero())?;

        let (cond, res) = integer_gate.div(ctx, &mut assigned_a, &mut assigned_zero)?;
        integer_gate.assert_equal(ctx, &assigned_zero, &res)?;
        integer_gate
            .base_gate()
            .assert_constant(ctx, &cond.into(), N::one())?;
        Ok(())
    }

    fn setup_test_is_zero(
        &self,
        integer_gate: &FiveColumnIntegerChip<'_, W, N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let a = Self::random();
        let b = Self::random();
        let b = if b == a { a + W::one() } else { b };

        let assigned_a = integer_gate.assign_constant(ctx, a)?;
        let assigned_b = integer_gate.assign_constant(ctx, b)?;

        let zero = N::zero();
        let one = N::one();

        let mut vzero = integer_gate.sub(ctx, &assigned_a, &assigned_a)?;
        let vtrue = integer_gate.is_zero(ctx, &mut vzero)?;
        integer_gate
            .base_gate()
            .assert_constant(ctx, &(&vtrue).into(), one)?;

        let mut vnzero = integer_gate.sub(ctx, &assigned_a, &assigned_b)?;
        let vfalse = integer_gate.is_zero(ctx, &mut vnzero)?;
        integer_gate
            .base_gate()
            .assert_constant(ctx, &(&vfalse).into(), zero)?;

        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl<W: FieldExt, N: FieldExt> Circuit<N> for TestFiveColumnIntegerChipCircuit<W, N> {
    type Config = TestFiveColumnIntegerChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<N>::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, W, N, COMMON_RANGE_BITS>::configure(meta, &base_gate_config);
        TestFiveColumnIntegerChipConfig {
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
        let integer_gate = FiveColumnIntegerChip::new(&range_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |region| {
                let base_offset = 0usize;
                let mut aux = Context::new(region, base_offset);
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
                        TestCase::LastBit => self.setup_test_last_bit(&integer_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_integer_chip_add() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_sub() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_neg() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_mul() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_square() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_is_zero() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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
fn test_five_column_integer_chip_div() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
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

#[test]
fn test_five_column_integer_chip_last_bit() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnIntegerChipCircuit::<Fq, Fr> {
        test_case: TestCase::LastBit,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
