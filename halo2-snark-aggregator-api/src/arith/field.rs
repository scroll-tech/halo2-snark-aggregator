use super::common::ArithCommonChip;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

pub trait ArithFieldChip:
    ArithCommonChip<Value = Self::Field, AssignedValue = Self::AssignedField>
{
    type Field: FieldExt;
    type AssignedField: Clone + Debug;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error>;
    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error>;
    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error>;

    // keep for optimization opportunity
    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Value,
    ) -> Result<Self::AssignedField, Self::Error>;
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
    ) -> Result<Self::AssignedField, Self::Error>;

    fn mul_add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let t = self.mul(ctx, a, b)?;
        self.add(ctx, &t, c)
    }

    fn mul_add_accumulate(
        &self,
        ctx: &mut Self::Context,
        a: Vec<&Self::AssignedField>,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        let mut acc = self.assign_zero(ctx)?;

        for v in a.into_iter() {
            acc = self.mul_add(ctx, &acc, b, v)?;
        }

        Ok(acc)
    }

    fn pow_constant(
        &self,
        ctx: &mut Self::Context,
        base: &Self::AssignedField,
        exponent: u32,
    ) -> Result<Self::AssignedField, Self::Error> {
        assert!(exponent >= 1);
        let mut acc = base.clone();
        let mut second_bit = 1;
        while second_bit <= exponent {
            second_bit <<= 1;
        }
        second_bit >>= 2;
        while second_bit > 0 {
            acc = self.square(ctx, &acc)?;
            if exponent & second_bit != 0 {
                acc = self.mul(ctx, &acc, base)?;
            }
            second_bit >>= 1;
        }
        Ok(acc)
    }
}
