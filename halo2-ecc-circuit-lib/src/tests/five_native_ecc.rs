use crate::chips::ecc_chip::EccChipOps;
use crate::chips::native_ecc_chip::NativeEccChip;
use crate::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::five::integer_chip::FiveColumnIntegerChip;
use crate::five::range_gate::FiveColumnRangeGate;
use crate::gates::base_gate::Context;
use crate::gates::range_gate::RangeGateConfig;
use group::ff::Field;
use group::Group;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{ConstraintSystem, Error},
};
use halo2curves::bn256::G1Affine;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Add,
    Double,
    Mul,
    ShaMir,
    ConstantMul,
    Sub,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Add
    }
}

#[derive(Clone)]
struct TestFiveColumnNativeEccChipConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnNativeEccChipCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<C::ScalarExt>,
}

impl<C: CurveAffine> TestFiveColumnNativeEccChipCircuit<C> {
    fn random() -> C::ScalarExt {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        C::ScalarExt::random(rng)
    }

    fn setup_test_add(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 + s2;
        let s4 = s1 + s1;
        let identity = C::ScalarExt::zero();

        let pi = ecc_gate.assign_constant_point_from_scalar(ctx, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(ctx, s1)?;
        let p2 = ecc_gate.assign_constant_point_from_scalar(ctx, s2)?;

        let mut p1_ = ecc_gate.add(ctx, &mut p1, &pi)?;
        ecc_gate.assert_equal(ctx, &mut p1, &mut p1_)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(ctx, s3)?;
        let mut p3_ = ecc_gate.add(ctx, &mut p1, &p2)?;
        ecc_gate.assert_equal(ctx, &mut p3, &mut p3_)?;

        let mut p4 = ecc_gate.assign_constant_point_from_scalar(ctx, s4)?;
        let mut p4_ = ecc_gate.add(ctx, &mut p1.clone(), &p1)?;
        ecc_gate.assert_equal(ctx, &mut p4, &mut p4_)?;

        Ok(())
    }

    fn setup_test_sub(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 - s2;
        let identity = C::ScalarExt::zero();

        let mut pi = ecc_gate.assign_constant_point_from_scalar(ctx, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(ctx, s1)?;
        let p2 = ecc_gate.assign_constant_point_from_scalar(ctx, s2)?;

        let mut p1_ = ecc_gate.sub(ctx, &mut p1, &pi)?;
        ecc_gate.assert_equal(ctx, &mut p1, &mut p1_)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(ctx, s3)?;
        let mut p3_ = ecc_gate.sub(ctx, &mut p1, &p2)?;
        ecc_gate.assert_equal(ctx, &mut p3, &mut p3_)?;

        let mut p4_ = ecc_gate.sub(ctx, &mut p1.clone(), &p1)?;
        ecc_gate.assert_equal(ctx, &mut pi, &mut p4_)?;

        Ok(())
    }

    fn setup_test_mul(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = ecc_gate.base_gate();

        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 * s2;
        let identity = C::ScalarExt::zero();

        let mut p1 = ecc_gate.assign_constant_point_from_scalar(ctx, s1)?;
        let s2 = base_gate.assign_constant(ctx, s2)?;
        let mut pi = ecc_gate.assign_identity(ctx)?;
        let si = base_gate.assign_constant(ctx, identity)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(ctx, s3)?;
        let mut p3_ = ecc_gate.mul(ctx, &mut p1, &s2)?;
        ecc_gate.assert_equal(ctx, &mut p3, &mut p3_)?;

        let mut pi_ = ecc_gate.mul(ctx, &mut p1, &si)?;
        ecc_gate.assert_equal(ctx, &mut pi, &mut pi_)?;

        let mut pi_ = ecc_gate.mul(ctx, &mut pi, &s2)?;
        ecc_gate.assert_equal(ctx, &mut pi, &mut pi_)?;

        let mut pi_ = ecc_gate.mul(ctx, &mut pi, &si)?;
        ecc_gate.assert_equal(ctx, &mut pi, &mut pi_)?;

        Ok(())
    }

    fn setup_test_shamir(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = ecc_gate.base_gate();

        let s1 = Self::random();
        let s2 = Self::random();
        let s3 = Self::random();
        let s4 = Self::random();

        let p1 = ecc_gate.assign_constant_point_from_scalar(ctx, s1)?;
        let p2 = ecc_gate.assign_constant_point_from_scalar(ctx, s2)?;
        let assigned_s3 = base_gate.assign_constant(ctx, s3)?;
        let assigned_s4 = base_gate.assign_constant(ctx, s4)?;

        let mut p = ecc_gate.shamir(
            ctx,
            &mut vec![p1.clone(), p2],
            &vec![assigned_s3, assigned_s4],
        )?;
        let mut p_ = ecc_gate.assign_constant_point_from_scalar(ctx, s1 * s3 + s2 * s4)?;
        ecc_gate.assert_equal(ctx, &mut p, &mut p_)?;

        let mut p = ecc_gate.shamir(ctx, &mut vec![p1], &vec![assigned_s3])?;
        let mut p_ = ecc_gate.assign_constant_point_from_scalar(ctx, s1 * s3)?;
        ecc_gate.assert_equal(ctx, &mut p, &mut p_)?;

        Ok(())
    }

    fn setup_test_constant_mul(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = ecc_gate.base_gate();

        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 * s2;
        let identity = C::ScalarExt::zero();

        let p1 = C::generator() * s1;
        let s2 = base_gate.assign_constant(ctx, s2)?;
        let pi = C::CurveExt::identity();
        let mut assigned_pi = ecc_gate.assign_identity(ctx)?;
        let si = base_gate.assign_constant(ctx, identity)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(ctx, s3)?;
        let mut p3_ = ecc_gate.constant_mul(ctx, p1, &s2)?;
        ecc_gate.assert_equal(ctx, &mut p3, &mut p3_)?;

        let mut pi_ = ecc_gate.constant_mul(ctx, p1, &si)?;
        ecc_gate.assert_equal(ctx, &mut assigned_pi, &mut pi_)?;

        let mut pi_ = ecc_gate.constant_mul(ctx, pi, &s2)?;
        ecc_gate.assert_equal(ctx, &mut assigned_pi, &mut pi_)?;

        let mut pi_ = ecc_gate.constant_mul(ctx, pi, &si)?;
        ecc_gate.assert_equal(ctx, &mut assigned_pi, &mut pi_)?;

        Ok(())
    }

    fn setup_test_double(
        &self,
        ecc_gate: &NativeEccChip<'_, C>,
        ctx: &mut Context<'_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = s1 + s1;
        let identity = C::ScalarExt::zero();

        let mut pi = ecc_gate.assign_constant_point_from_scalar(ctx, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(ctx, s1)?;
        let mut p2 = ecc_gate.assign_constant_point_from_scalar(ctx, s2)?;

        let mut p2_ = ecc_gate.double(ctx, &mut p1)?;
        ecc_gate.assert_equal(ctx, &mut p2, &mut p2_)?;

        let mut pi_ = ecc_gate.double(ctx, &mut pi)?;
        ecc_gate.assert_equal(ctx, &mut pi, &mut pi_)?;

        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl<C: CurveAffine> Circuit<C::ScalarExt> for TestFiveColumnNativeEccChipCircuit<C> {
    type Config = TestFiveColumnNativeEccChipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<C::ScalarExt>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<C::ScalarExt>::configure(meta);
        let range_gate_config =
            FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::configure(
                meta,
                &base_gate_config,
            );
        TestFiveColumnNativeEccChipConfig {
            base_gate_config,
            range_gate_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);
        let range_gate = FiveColumnRangeGate::<'_, C::Base, C::ScalarExt, COMMON_RANGE_BITS>::new(
            config.range_gate_config,
            &base_gate,
        );
        let integer_gate = FiveColumnIntegerChip::new(&range_gate);
        let ecc_gate = NativeEccChip::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |region| {
                let base_offset = 0usize;
                let mut aux = Context::new(region, base_offset);
                let r = &mut aux;
                r.in_shape_mode = base_gate.in_shape_mode(r)?;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Add => self.setup_test_add(&ecc_gate, r),
                        TestCase::Double => self.setup_test_double(&ecc_gate, r),
                        TestCase::Mul => self.setup_test_mul(&ecc_gate, r),
                        TestCase::Sub => self.setup_test_sub(&ecc_gate, r),
                        TestCase::ConstantMul => self.setup_test_constant_mul(&ecc_gate, r),
                        TestCase::ShaMir => self.setup_test_shamir(&ecc_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_natvie_ecc_chip_add() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::Add,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_natvie_ecc_chip_double() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::Double,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_natvie_ecc_chip_mul() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::Mul,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_natvie_ecc_chip_sub() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::Sub,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_natvie_ecc_chip_constant_mul() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::ConstantMul,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_natvie_ecc_chip_shamir() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let chip = TestFiveColumnNativeEccChipCircuit::<G1Affine> {
        test_case: TestCase::ShaMir,
        _phantom_w: PhantomData,
        _phantom_n: PhantomData,
    };
    let prover = match MockProver::run(K, &chip, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
