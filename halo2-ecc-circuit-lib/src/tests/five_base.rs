use crate::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::five::config::{MUL_COLUMNS, VAR_COLUMNS};
use crate::gates::base_gate::{BaseGateOps, Context};
use crate::pair;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use pairing_bn256::bn256::Fr;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;

enum TestCase {
    OneLine,
    SumWithConstant,
    Add,
    Mul,
    MulAdd,
    MulAddWithNextLine,
    InvertUnsafe,
    DivUnsafe,
}

impl Default for TestCase {
    fn default() -> TestCase {
        TestCase::OneLine
    }
}

#[derive(Clone)]
struct TestFiveColumnBaseGateConfig {
    base_gate_config: FiveColumnBaseGateConfig,
}

#[derive(Default)]
struct TestFiveColumnBaseGateCircuit<N: FieldExt> {
    test_case: TestCase,
    _phantom: PhantomData<N>,
}

impl<N: FieldExt> TestFiveColumnBaseGateCircuit<N> {
    fn random() -> N {
        let seed = chrono::offset::Utc::now()
            .timestamp_nanos()
            .try_into()
            .unwrap();
        let rng = XorShiftRng::seed_from_u64(seed);
        N::random(rng)
    }

    fn setup_test_one_line(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        let vars = [(); VAR_COLUMNS].map(|_| Self::random());
        let coeffs = [(); VAR_COLUMNS].map(|_| Self::random());
        let muls_coeffs = [(); MUL_COLUMNS].map(|_| Self::random());
        let next_var = Self::random();
        let next_coeff = Self::random();

        let result = {
            let mut result = N::zero();
            for i in 0..VAR_COLUMNS {
                result = result + vars[i] * coeffs[i]
            }
            for i in 0..MUL_COLUMNS {
                result = result + muls_coeffs[i] * vars[i * 2] * vars[i * 2 + 1]
            }
            result + next_var * next_coeff
        };

        base_gate.one_line(
            ctx,
            (0..VAR_COLUMNS)
                .map(|i| pair!(vars[i], coeffs[i]))
                .collect(),
            -result,
            (muls_coeffs.try_into().unwrap(), next_coeff),
        )?;

        base_gate.one_line_with_last_base(
            ctx,
            vec![],
            pair!(next_var, N::zero()),
            N::zero(),
            (vec![], N::zero()),
        )?;
        Ok(())
    }

    fn setup_test_sum_with_constant(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = VAR_COLUMNS - 1usize;
        const NCOEFFS: usize = VAR_COLUMNS - 1usize;
        let vars = [(); NVARS].map(|_| Self::random());
        let coeffs = [(); NCOEFFS].map(|_| Self::random());
        let constant = Self::random();
        let result = {
            let mut result = N::zero();
            for i in 0..VAR_COLUMNS - 1 {
                result = result + vars[i] * coeffs[i]
            }
            result + constant
        };

        let mut assigned_vars = vec![];
        for i in 0..VAR_COLUMNS - 1 {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result =
            base_gate.sum_with_constant(ctx, assigned_vars.iter().zip(coeffs).collect(), constant)?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }

    fn setup_test_add(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 2usize;
        let vars = [(); NVARS].map(|_| Self::random());
        let result = vars[0] + vars[1];

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.add(ctx, &assigned_vars[0], &assigned_vars[1])?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }

    fn setup_test_mul(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 2usize;
        let vars = [(); NVARS].map(|_| Self::random());
        let result = vars[0] * vars[1];

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.mul(ctx, &assigned_vars[0], &assigned_vars[1])?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }

    fn setup_test_mul_add(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 3usize;
        const NCOEFFS: usize = 1usize;
        let vars = [(); NVARS].map(|_| Self::random());
        let coeffs = [(); NCOEFFS].map(|_| Self::random());
        let result = vars[0] * vars[1] + vars[2] * coeffs[0];

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.mul_add(
            ctx,
            &assigned_vars[0],
            &assigned_vars[1],
            &assigned_vars[2],
            coeffs[0],
        )?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }

    fn setup_test_mul_add_with_next_line(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 6usize;
        const NCOEFFS: usize = 2usize;
        let vars = [(); NVARS].map(|_| Self::random());
        let coeffs = [(); NCOEFFS].map(|_| Self::random());
        let result =
            vars[0] * vars[1] + vars[2] * coeffs[0] + vars[3] * vars[4] + vars[5] * coeffs[1];

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.mul_add_with_next_line(
            ctx,
            vec![
                (
                    &assigned_vars[0],
                    &assigned_vars[1],
                    &assigned_vars[2],
                    coeffs[0],
                ),
                (
                    &assigned_vars[3],
                    &assigned_vars[4],
                    &assigned_vars[5],
                    coeffs[1],
                ),
            ],
        )?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }

    fn setup_test_invert_unsafe(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 1usize;
        let vars = [(); NVARS].map(|_| {
            let v = Self::random();
            if v.is_zero().into() {
                N::one()
            } else {
                v
            }
        });
        let result = vars[0].invert().unwrap();

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.invert_unsafe(ctx, &assigned_vars[0])?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;

        Ok(())
    }

    fn setup_test_div_unsafe(
        &self,
        base_gate: &FiveColumnBaseGate<N>,
        ctx: &mut Context<'_, N>,
    ) -> Result<(), Error> {
        const NVARS: usize = 2usize;
        let vars = [(); NVARS].map(|_| {
            let v = Self::random();
            if v.is_zero().into() {
                v + N::one()
            } else {
                v
            }
        });
        let result = vars[0] * vars[1].invert().unwrap();

        let mut assigned_vars = vec![];
        for i in 0..NVARS {
            let c = base_gate.assign_constant(ctx, vars[i])?;
            assigned_vars.push(c);
        }

        let assigned_result = base_gate.assign_constant(ctx, result)?;

        let op_result = base_gate.div_unsafe(ctx, &assigned_vars[0], &assigned_vars[1])?;

        base_gate.assert_equal(ctx, &assigned_result, &op_result)?;
        Ok(())
    }
}

impl<N: FieldExt> Circuit<N> for TestFiveColumnBaseGateCircuit<N> {
    type Config = TestFiveColumnBaseGateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<N>) -> Self::Config {
        let base_gate_config = FiveColumnBaseGate::<N>::configure(meta);
        TestFiveColumnBaseGateConfig { base_gate_config }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<N>,
    ) -> Result<(), Error> {
        let base_gate = FiveColumnBaseGate::new(config.base_gate_config);

        layouter.assign_region(
            || "base",
            |region| {
                let base_offset = 0usize;
                let mut aux = Context::new(region, base_offset);
                let r = &mut aux;
                match self.test_case {
                    TestCase::OneLine => self.setup_test_one_line(&base_gate, r),
                    TestCase::SumWithConstant => self.setup_test_sum_with_constant(&base_gate, r),
                    TestCase::Add => self.setup_test_add(&base_gate, r),
                    TestCase::Mul => self.setup_test_mul(&base_gate, r),
                    TestCase::MulAdd => self.setup_test_mul_add(&base_gate, r),
                    TestCase::MulAddWithNextLine => {
                        self.setup_test_mul_add_with_next_line(&base_gate, r)
                    }
                    TestCase::InvertUnsafe => self.setup_test_invert_unsafe(&base_gate, r),
                    TestCase::DivUnsafe => self.setup_test_div_unsafe(&base_gate, r),
                }
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_five_column_base_gate_one_line() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::OneLine,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_sum_with_constant() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::SumWithConstant,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_add() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::Add,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_mul() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::Mul,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_mul_add() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::MulAdd,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_mul_add_with_next_line() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::MulAddWithNextLine,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_mul_invert_unsafe() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::InvertUnsafe,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}

#[test]
fn test_five_column_base_gate_mul_div_unsafe() {
    const K: u32 = 8;
    let circuit = TestFiveColumnBaseGateCircuit::<Fr> {
        test_case: TestCase::DivUnsafe,
        _phantom: PhantomData,
    };
    let prover = match MockProver::run(K, &circuit, vec![]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));
}
