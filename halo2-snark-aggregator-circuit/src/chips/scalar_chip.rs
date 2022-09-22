use std::marker::PhantomData;

use halo2_ecc::gates::{
    flex_gate::FlexGateConfig,
    Context, GateInstructions,
    QuantumCell::{self, Constant, Existing, Witness},
};
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, field::ArithFieldChip};

pub struct ScalarChip<'a, 'b, N: FieldExt>(pub &'a FlexGateConfig<N>, PhantomData<&'b N>);

// It seems the aggregation api wants to get the value of constant assigned cells, see `to_value` below
// Because keygen_vk does not actually assign_regions (it only cares about fixed columns), we need to create a wrapper that keeps track of constant values separately in the second coordinate
#[derive(Clone, Debug)]
pub struct AssignedValue<F: FieldExt>(pub AssignedCell<F, F>, pub Option<F>);

impl<'a, 'b, N: FieldExt> ScalarChip<'a, 'b, N> {
    pub fn new(gate: &'a FlexGateConfig<N>) -> Self {
        ScalarChip(gate, PhantomData)
    }
}

impl<'a, 'b, N: FieldExt> ArithCommonChip for ScalarChip<'a, 'b, N> {
    type Context = Context<'b, N>;
    type Value = N;
    type AssignedValue = AssignedValue<N>;
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(AssignedValue(self.0.add(ctx, &Existing(&a.0), &Existing(&b.0))?, None))
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(AssignedValue(self.0.sub(ctx, &Existing(&a.0), &Existing(&b.0))?, None))
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, N::zero())
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.assign_const(ctx, N::one())
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let assignments =
            self.0.assign_region_smart(ctx, vec![Constant(c)], vec![], vec![], vec![])?;
        Ok(AssignedValue(assignments.last().unwrap().clone(), Some(c)))
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let assignments =
            self.0.assign_region_smart(ctx, vec![Witness(Some(v))], vec![], vec![], vec![])?;
        Ok(AssignedValue(assignments.last().unwrap().clone(), None))
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        if v.1.is_none() {
            panic!("calling to_value on a non constant cell!");
        }
        Ok(v.1.unwrap())
    }

    fn normalize(
        &self,
        _ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v.clone())
    }
}

impl<'a, 'b, N: FieldExt> ArithFieldChip for ScalarChip<'a, 'b, N> {
    type Field = N;
    type AssignedField = AssignedValue<N>;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(AssignedValue(self.0.mul(ctx, &Existing(&a.0), &Existing(&b.0))?, None))
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(AssignedValue(self.0.div_unsafe(ctx, &Existing(&a.0), &Existing(&b.0))?, None))
    }

    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.mul(ctx, a, a)
    }

    // this is an inner product on `a_with_coeff` and then `+ b`
    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error> {
        let (_, _, sum, gate_index) = self.0.inner_product(
            ctx,
            &a_with_coeff.iter().map(|(a, _)| Existing(&a.0)).collect(),
            &a_with_coeff.iter().map(|(_, c)| Constant(*c)).collect(),
        )?;

        let sum = sum.value().map(|&sum| sum + b);
        let (assignments, _) = self.0.assign_region(
            ctx,
            vec![Constant(N::one()), Constant(b), Witness(sum)],
            vec![(-1, None)],
            Some(gate_index),
        )?;
        Ok(AssignedValue(assignments.last().unwrap().clone(), None))
    }

    fn sum_with_constant(
        &self,
        ctx: &mut Self::Context,
        a: Vec<&Self::AssignedField>,
        b: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.sum_with_coeff_and_constant(
            ctx,
            a.into_iter().map(|x| (x, Self::Value::one())).collect(),
            b,
        )
    }

    fn mul_add_constant(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error> {
        let d = a.0.value().zip(b.0.value()).map(|(&a, &b)| a * b + c);
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Constant(c), Existing(&a.0), Existing(&b.0), Witness(d)],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(AssignedValue(assignments.last().unwrap().clone(), None))
    }

    fn mul_add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let d = a.0.value().zip(b.0.value()).zip(c.0.value()).map(|((&a, &b), &c)| a * b + c);
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Existing(&c.0), Existing(&a.0), Existing(&b.0), Witness(d)],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(AssignedValue(assignments.last().unwrap().clone(), None))
    }

    // default impl of mul_add_accumulate

    /// ASSUME `base` is not zero
    fn pow_constant(
        &self,
        ctx: &mut Self::Context,
        base: &Self::AssignedField,
        exponent: u32,
    ) -> Result<Self::AssignedField, Self::Error> {
        fn get_naf(mut e: u32) -> Vec<i8> {
            // https://en.wikipedia.org/wiki/Non-adjacent_form
            // NAF for exp:
            let mut naf: Vec<i8> = Vec::with_capacity(32);

            // generate the NAF for exp
            for _ in 0..32 {
                if e & 1 == 1 {
                    let z = 2i8 - (e % 4) as i8;
                    e = e / 2;
                    if z == -1 {
                        e += 1;
                    }
                    naf.push(z);
                } else {
                    naf.push(0);
                    e = e / 2;
                }
            }
            if e != 0 {
                assert_eq!(e, 1);
                naf.push(1);
            }
            naf
        }

        assert!(exponent >= 1);
        let naf = get_naf(exponent);
        let mut acc = base.clone();
        let mut is_started = false;

        for &z in naf.iter().rev() {
            if is_started {
                acc = self.square(ctx, &acc)?;
            }
            if z != 0 {
                if is_started {
                    acc =
                        if z == 1 { self.mul(ctx, &acc, base) } else { self.div(ctx, &acc, base) }?;
                } else {
                    is_started = true;
                }
            }
        }
        Ok(acc)
    }
}
