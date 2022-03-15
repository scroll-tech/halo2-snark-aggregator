use crate::circuits::ecc_circuit::EccCircuitOps;
use crate::circuits::five::integer_circuit::FiveColumnIntegerCircuit;
use crate::circuits::native_ecc_circuit::NativeEccCircuit;
use crate::gates::base_gate::RegionAux;
use crate::gates::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::gates::five::range_gate::FiveColumnRangeGate;
use crate::gates::range_gate::RangeGateConfig;
use group::ff::Field;
use halo2_proofs::arithmetic::CurveAffine;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pairing_bn256::bn256::G1Affine;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    Add,
    Double,
    Mul,
    Sub,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::Add
    }
}

#[derive(Clone)]
struct TestFiveColumnNativeEccCircuitConfig {
    base_gate_config: FiveColumnBaseGateConfig,
    range_gate_config: RangeGateConfig,
}

#[derive(Default)]
struct TestFiveColumnNativeEccCircuitCircuit<C: CurveAffine> {
    test_case: TestCase,
    _phantom_w: PhantomData<C>,
    _phantom_n: PhantomData<C::ScalarExt>,
}

impl<C: CurveAffine> TestFiveColumnNativeEccCircuitCircuit<C> {
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
        ecc_gate: &NativeEccCircuit<'_, C>,
        r: &mut RegionAux<'_, '_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 + s2;
        let s4 = s1 + s1;
        let identity = C::ScalarExt::zero();

        let pi = ecc_gate.assign_constant_point_from_scalar(r, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(r, s1)?;
        let p2 = ecc_gate.assign_constant_point_from_scalar(r, s2)?;

        let mut p1_ = ecc_gate.add(r, &mut p1, &pi)?;
        ecc_gate.assert_equal(r, &mut p1, &mut p1_)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(r, s3)?;
        let mut p3_ = ecc_gate.add(r, &mut p1, &p2)?;
        ecc_gate.assert_equal(r, &mut p3, &mut p3_)?;

        let mut p4 = ecc_gate.assign_constant_point_from_scalar(r, s4)?;
        let mut p4_ = ecc_gate.add(r, &mut p1.clone(), &p1)?;
        ecc_gate.assert_equal(r, &mut p4, &mut p4_)?;

        Ok(())
    }

    fn setup_test_sub(
        &self,
        ecc_gate: &NativeEccCircuit<'_, C>,
        r: &mut RegionAux<'_, '_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 - s2;
        let identity = C::ScalarExt::zero();

        let mut pi = ecc_gate.assign_constant_point_from_scalar(r, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(r, s1)?;
        let p2 = ecc_gate.assign_constant_point_from_scalar(r, s2)?;

        let mut p1_ = ecc_gate.sub(r, &mut p1, &pi)?;
        ecc_gate.assert_equal(r, &mut p1, &mut p1_)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(r, s3)?;
        let mut p3_ = ecc_gate.sub(r, &mut p1, &p2)?;
        ecc_gate.assert_equal(r, &mut p3, &mut p3_)?;

        let mut p4_ = ecc_gate.sub(r, &mut p1.clone(), &p1)?;
        ecc_gate.assert_equal(r, &mut pi, &mut p4_)?;

        Ok(())
    }

    fn setup_test_mul(
        &self,
        ecc_gate: &NativeEccCircuit<'_, C>,
        r: &mut RegionAux<'_, '_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let base_gate = ecc_gate.base_gate();

        let s1 = Self::random();
        let s2 = Self::random();

        let s3 = s1 * s2;
        let identity = C::ScalarExt::zero();

        let mut p1 = ecc_gate.assign_constant_point_from_scalar(r, s1)?;
        let s2 = base_gate.assign_constant(r, s2)?;
        let mut pi = ecc_gate.assign_identity(r)?;
        let si = base_gate.assign_constant(r, identity)?;

        let mut p3 = ecc_gate.assign_constant_point_from_scalar(r, s3)?;
        let mut p3_ = ecc_gate.mul(r, &mut p1, &s2)?;
        ecc_gate.assert_equal(r, &mut p3, &mut p3_)?;

        let mut pi_ = ecc_gate.mul(r, &mut p1, &si)?;
        ecc_gate.assert_equal(r, &mut pi, &mut pi_)?;

        let mut pi_ = ecc_gate.mul(r, &mut pi, &s2)?;
        ecc_gate.assert_equal(r, &mut pi, &mut pi_)?;

        let mut pi_ = ecc_gate.mul(r, &mut pi, &si)?;
        ecc_gate.assert_equal(r, &mut pi, &mut pi_)?;
        Ok(())
    }

    fn setup_test_double(
        &self,
        ecc_gate: &NativeEccCircuit<'_, C>,
        r: &mut RegionAux<'_, '_, C::ScalarExt>,
    ) -> Result<(), Error> {
        let s1 = Self::random();
        let s2 = s1 + s1;
        let identity = C::ScalarExt::zero();

        let mut pi = ecc_gate.assign_constant_point_from_scalar(r, identity)?;
        let mut p1 = ecc_gate.assign_constant_point_from_scalar(r, s1)?;
        let mut p2 = ecc_gate.assign_constant_point_from_scalar(r, s2)?;

        let mut p2_ = ecc_gate.double(r, &mut p1)?;
        ecc_gate.assert_equal(r, &mut p2, &mut p2_)?;

        let mut pi_ = ecc_gate.double(r, &mut pi)?;
        ecc_gate.assert_equal(r, &mut pi, &mut pi_)?;

        Ok(())
    }
}

const COMMON_RANGE_BITS: usize = 17usize;

impl<C: CurveAffine> Circuit<C::ScalarExt> for TestFiveColumnNativeEccCircuitCircuit<C> {
    type Config = TestFiveColumnNativeEccCircuitConfig;
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
        TestFiveColumnNativeEccCircuitConfig {
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
        let integer_gate = FiveColumnIntegerCircuit::new(&range_gate);
        let ecc_gate = NativeEccCircuit::new(&integer_gate);

        range_gate
            .init_table(&mut layouter, &integer_gate.helper.integer_modulus)
            .unwrap();

        layouter.assign_region(
            || "base",
            |mut region| {
                let mut base_offset = 0usize;
                let mut aux = RegionAux::new(&mut region, &mut base_offset);
                let r = &mut aux;
                let round = 1;
                for _ in 0..round {
                    match self.test_case {
                        TestCase::Add => self.setup_test_add(&ecc_gate, r),
                        TestCase::Double => self.setup_test_double(&ecc_gate, r),
                        TestCase::Mul => self.setup_test_mul(&ecc_gate, r),
                        TestCase::Sub => self.setup_test_sub(&ecc_gate, r),
                    }?;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_ecc_gate_add() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnNativeEccCircuitCircuit::<G1Affine> {
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
fn test_five_column_ecc_gate_double() {
    const K: u32 = (COMMON_RANGE_BITS + 1) as u32;
    let circuit = TestFiveColumnNativeEccCircuitCircuit::<G1Affine> {
        test_case: TestCase::Double,
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
fn test_five_column_ecc_gate_mul() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let circuit = TestFiveColumnNativeEccCircuitCircuit::<G1Affine> {
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
fn test_five_column_ecc_gate_sub() {
    const K: u32 = (COMMON_RANGE_BITS + 2) as u32;
    let circuit = TestFiveColumnNativeEccCircuitCircuit::<G1Affine> {
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
