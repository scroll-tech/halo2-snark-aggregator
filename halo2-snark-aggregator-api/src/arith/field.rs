use super::common::ArithCommon;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

pub trait ArithField: ArithCommon<Self::Context, Self::Value, Self::Assigned, Self::Error> {
    type Context;
    type Value: FieldExt;
    type Assigned: Clone + Debug;
    type Error;

    fn mul(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
        b: &Self::Assigned,
    ) -> Result<Self::Assigned, Self::Error>;
    fn div(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
        b: &Self::Assigned,
    ) -> Result<Self::Assigned, Self::Error>;
    fn square(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
    ) -> Result<Self::Assigned, Self::Error>;

    // keep for optimization opportunity
    fn sum_with_coeff_and_constant(
        &self,
        ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::Assigned, Self::Value)>,
        b: Self::Value,
    ) -> Result<Self::Assigned, Self::Error>;
    fn sum_with_constant(
        &self,
        ctx: &mut Self::Context,
        a: Vec<&Self::Assigned>,
        b: Self::Value,
    ) -> Result<Self::Assigned, Self::Error> {
        self.sum_with_coeff_and_constant(
            ctx,
            a.into_iter().map(|x| (x, Self::Value::one())).collect(),
            b,
        )
    }
    fn mul_add_constant(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
        b: &Self::Assigned,
        c: Self::Value,
    ) -> Result<Self::Assigned, Self::Error>;

    fn pow_constant(
        &self,
        ctx: &mut Self::Context,
        base: &Self::Assigned,
        exponent: u32,
    ) -> Result<Self::Assigned, Self::Error> {
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
