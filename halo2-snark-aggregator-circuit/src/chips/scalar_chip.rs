use std::marker::PhantomData;

use halo2_ecc::{
    bigint::add_no_carry::assign,
    gates::{
        flex_gate::FlexGateConfig,
        Context, GateInstructions,
        QuantumCell::{self, Constant, Existing, Witness},
    },
};
use halo2_proofs::{arithmetic::FieldExt, circuit::AssignedCell, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, field::ArithFieldChip};

pub struct ScalarChip<'a, 'b, N: FieldExt>(&'a FlexGateConfig<N>, PhantomData<&'b N>);

impl<'a, 'b, N: FieldExt> ScalarChip<'a, 'b, N> {
    pub fn new(gate: &'a FlexGateConfig<N>) -> Self {
        ScalarChip(gate, PhantomData)
    }
}

impl<'a, 'b, N: FieldExt> ArithCommonChip for ScalarChip<'a, 'b, N> {
    type Context = Context<'b, N>;
    type Value = N;
    type AssignedValue = AssignedCell<N, N>;
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.0.add(ctx, &Existing(a), &Existing(b))
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.0.sub(ctx, &Existing(a), &Existing(b))
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
                .assign_region_smart(ctx, vec![Constant(c)], vec![], vec![], vec![])?;
        Ok(assignments.last().unwrap().clone())
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let assignments =
            self.0
                .assign_region_smart(ctx, vec![Witness(Some(v))], vec![], vec![], vec![])?;
        Ok(assignments.last().unwrap().clone())
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        v.value().map(|v| v.clone()).ok_or(Error::Synthesis)
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
    type AssignedField = AssignedCell<N, N>;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.mul(ctx, &Existing(a), &Existing(b))
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.div_unsafe(ctx, &Existing(a), &Existing(b))
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
        // copying from FlexGateConfig::inner_product to save 1 cell in the final + b
        let mut cells: Vec<QuantumCell<N>> = Vec::with_capacity(3 * a_with_coeff.len() + 4);
        cells.push(Constant(N::from(0)));

        let mut sum = Some(N::zero());
        for (a, c) in a_with_coeff {
            sum = sum.zip(a.value()).map(|(sum, &a)| sum + a * c);

            cells.push(Existing(a));
            cells.push(Constant(c));
            cells.push(Witness(sum));
        }
        let mut gate_offsets = Vec::with_capacity(a_with_coeff.len() + 1);
        for i in 0..a_with_coeff.len() {
            gate_offsets.push(3 * i);
        }
        gate_offsets.push(cells.len() - 1);
        sum = sum.map(|sum| sum + b);
        cells.extend([Constant(N::one()), Constant(b), Witness(sum)]);

        let assigned_cells =
            self.0
                .assign_region_smart(ctx, cells, gate_offsets, vec![], vec![])?;
        Ok(assigned_cells.last().unwrap().clone())
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
        let d = a.value().zip(b.value()).map(|(&a, &b)| a * b + c);
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Constant(c), Existing(a), Existing(b), Witness(d)],
            vec![0],
            vec![],
            vec![],
        )?;
        Ok(assignments.last().unwrap().clone())
    }

    fn mul_add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let d = a
            .value()
            .zip(b.value())
            .zip(c.value())
            .map(|((&a, &b), &c)| a * b + c);
        let assignments = self.0.assign_region_smart(
            ctx,
            vec![Existing(c), Existing(a), Existing(b), Witness(d)],
            vec![0],
            vec![],
            vec![],
        )?;
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
            for i in 0..32 {
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
