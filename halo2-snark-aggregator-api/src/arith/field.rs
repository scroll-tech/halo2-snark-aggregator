use super::common::ArithCommon;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::arithmetic::FieldExt;

pub trait ArithField: ArithCommon<Self::Value, Self::Error> {
    type Value: FieldExt;
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
}
