use halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context,
    QuantumCell::{Constant, Existing, Witness},
};
use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, field::ArithFieldChip};

pub struct ScalarChip<'a, N>(pub &'a FlexGateConfig<N>)
where
    N: FieldExt<Repr = [u8; 32]>;

// // It seems the aggregation api wants to get the value of constant assigned cells, see `to_value` below
// // Because keygen_vk does not actually assign_regions (it only cares about fixed columns), we need to create a wrapper that keeps track of constant values separately in the second coordinate
// #[derive(Clone, Debug)]
// pub struct AssignedValue<F: FieldExt>(pub AssignedCell<F, F>, pub Option<F>);

impl<'a, N> ScalarChip<'a, N>
where
    N: FieldExt<Repr = [u8; 32]>,
{
    pub fn new(gate: &'a FlexGateConfig<N>) -> Self {
        ScalarChip(gate)
    }
}

impl<'a, N> ArithCommonChip for ScalarChip<'a, N>
where
    N: FieldExt<Repr = [u8; 32]>,
{
    type Context = Context<'a, N>;
    type Value = N;
    type AssignedValue = AssignedValue<'a, N>;
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.0.add(ctx, Existing(&a), Existing(&b)))
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.0.sub(ctx, Existing(&a), Existing(&b)))
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
            self.0
                .assign_region_smart(ctx, vec![Constant(c)], vec![], vec![], vec![]);
        Ok(assignments[0])
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let assignments =
            self.0
                .assign_region_smart(ctx, vec![Witness(Value::known(v))], vec![], vec![], vec![]);
        Ok(assignments.last().unwrap().clone())
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        if v.value.is_none() {
            panic!("calling to_value on a non constant cell!");
        }
        Ok(v.value.inner.unwrap())
    }

    fn normalize(
        &self,
        _ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v.clone())
    }
}

impl<'a, N> ArithFieldChip for ScalarChip<'a, N>
where
    N: FieldExt<Repr = [u8; 32]>,
{
    type Field = N;
    type AssignedField = AssignedValue<'a, N>;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(self.0.mul(ctx, Existing(&a), Existing(&b)))
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(self.0.div_unsafe(ctx, Existing(&a), Existing(&b)))
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
        let sum = self.0.inner_product(
            ctx,
            a_with_coeff.iter().map(|(&a, _)| Existing(&a)),
            a_with_coeff.iter().map(|(_, c)| Constant(*c)),
        );

        let sum = sum.value().map(|&sum| sum + b);
        let assignments = self.0.assign_region(
            ctx,
            vec![Constant(N::one()), Constant(b), Witness(sum)],
            vec![(-1, None)],
        );
        Ok(assignments.last().unwrap().clone())
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
        let d = a.value * b.value + Value::known(c);
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Constant(c), Existing(&a), Existing(&b), Witness(d)],
            vec![0],
            vec![],
            vec![],
        );
        Ok(assignments.last().unwrap().clone())
    }

    fn mul_add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let d = a.value * b.value + c.value;
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Existing(&c), Existing(&a), Existing(&b), Witness(d)],
            vec![0],
            vec![],
            vec![],
        );
        Ok(assignments.last().unwrap().clone())
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
                    acc = if z == 1 {
                        self.mul(ctx, &acc, base)
                    } else {
                        self.div(ctx, &acc, base)
                    }?;
                } else {
                    is_started = true;
                }
            }
        }
        Ok(acc)
    }
}
