use crate::arith::{common::ArithCommonChip, field::ArithFieldChip};
use halo2_proofs::arithmetic::FieldExt;
use std::marker::PhantomData;

pub struct MockFieldChip<F: FieldExt, E> {
    zero: F,
    one: F,
    _data: PhantomData<E>,
}

impl<F: FieldExt, E> Default for MockFieldChip<F, E> {
    fn default() -> Self {
        Self {
            zero: F::zero(),
            one: F::one(),
            _data: PhantomData,
        }
    }
}

impl<F: FieldExt, E> ArithCommonChip for MockFieldChip<F, E> {
    type Context = ();
    type Value = F;
    type AssignedValue = F;
    type Error = E;

    fn add(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(*a + *b)
    }

    fn sub(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(*a - *b)
    }

    fn assign_zero(&self, _ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.zero)
    }

    fn assign_one(&self, _ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.one)
    }

    fn assign_const(
        &self,
        _ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(c)
    }

    fn assign_var(
        &self,
        _ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v)
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(*v)
    }
}

impl<F: FieldExt, E> ArithFieldChip for MockFieldChip<F, E> {
    type Field = F;
    type AssignedField = F;

    fn mul(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *b)
    }

    fn div(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * b.invert().unwrap())
    }

    fn square(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *a)
    }

    fn sum_with_coeff_and_constant(
        &self,
        _ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        let mut acc = b;
        for (x, coeff) in a_with_coeff {
            acc = acc + *x * coeff
        }
        Ok(acc)
    }

    fn mul_add_constant(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *b + c)
    }
}
