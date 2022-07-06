use std::marker::PhantomData;

use halo2_ecc_circuit_lib::{
    five::base_gate::FiveColumnBaseGate,
    gates::base_gate::{AssignedValue, BaseGateOps, Context},
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, field::ArithFieldChip};

pub struct ScalarChip<'a, 'b, N: FieldExt>(&'a FiveColumnBaseGate<N>, PhantomData<&'b N>);

impl<'a, 'b, N: FieldExt> ScalarChip<'a, 'b, N> {
    pub fn new(base_gate: &'a FiveColumnBaseGate<N>) -> Self {
        ScalarChip(base_gate, PhantomData)
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
        self.0.add(ctx, a, b)
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.0.sub(ctx, a, b)
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.0.assign_constant(ctx, N::zero())
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.0.assign_constant(ctx, N::one())
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.0.assign_constant(ctx, c)
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.0.assign(ctx, v)
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(v.value)
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
        self.0.mul(ctx, a, b)
    }

    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.div_unsafe(ctx, a, b)
    }

    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.mul(ctx, a, a)
    }

    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.sum_with_constant(ctx, a_with_coeff, b)
    }

    fn mul_add_constant(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error> {
        self.0.mul_add_constant(ctx, a, b, c)
    }
}
