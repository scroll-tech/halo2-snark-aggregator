use super::common::ArithCommonChip;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

pub trait ArithFieldChip:
    ArithCommonChip<Self::Context, Self::Value, Self::AssignedValue, Self::Error>
{
    type Context;
    type Value: FieldExt;
    type AssignedValue: Clone + Debug;
    type Error;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;

    // keep for optimization opportunity
    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedValue, Self::Value)>,
        b: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn sum_with_constant(
        &self,
        ctx: &mut Self::Context,
        a: Vec<&Self::AssignedValue>,
        b: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.sum_with_coeff_and_constant(
            ctx,
            a.into_iter().map(|x| (x, Self::Value::one())).collect(),
            b,
        )
    }
    fn mul_add_constant(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error>;

    fn pow_constant(
        &self,
        ctx: &mut Self::Context,
        base: &Self::AssignedValue,
        exponent: u32,
    ) -> Result<Self::AssignedValue, Self::Error> {
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
