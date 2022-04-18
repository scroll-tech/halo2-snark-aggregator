use super::field::MockFieldChip;
use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use group::{Curve, Group};
use halo2_proofs::arithmetic::CurveAffine;

pub(crate) struct MockEccChip<C: CurveAffine> {
    zero: C::CurveExt,
    one: C::CurveExt,
}

impl<C: CurveAffine> Default for MockEccChip<C> {
    fn default() -> Self {
        Self {
            zero: <C as CurveAffine>::CurveExt::identity(),
            one: <C as CurveAffine>::CurveExt::generator(),
        }
    }
}

impl<C: CurveAffine> ArithCommonChip for MockEccChip<C> {
    type Context = ();
    type Value = C;
    type AssignedValue = C::CurveExt;
    type Error = ();

    fn add(&self, _ctx: &mut (), a: &C::CurveExt, b: &C::CurveExt) -> Result<C::CurveExt, ()> {
        Ok(*a + *b)
    }

    fn sub(&self, _ctx: &mut (), a: &C::CurveExt, b: &C::CurveExt) -> Result<C::CurveExt, ()> {
        Ok(*a - *b)
    }

    fn assign_zero(&self, _ctx: &mut ()) -> Result<C::CurveExt, ()> {
        Ok(self.zero)
    }

    fn assign_one(&self, _ctx: &mut ()) -> Result<C::CurveExt, ()> {
        Ok(self.one)
    }

    fn assign_const(&self, _ctx: &mut (), c: C) -> Result<C::CurveExt, ()> {
        Ok(c.to_curve())
    }

    fn assign_var(&self, _ctx: &mut (), v: C) -> Result<C::CurveExt, ()> {
        Ok(v.to_curve())
    }

    fn to_value(&self, v: &C::CurveExt) -> Result<C, ()> {
        Ok(v.to_affine())
    }
}

impl<C: CurveAffine> ArithEccChip for MockEccChip<C> {
    type Point = C;
    type AssignedPoint = C::CurveExt;
    type Scalar = C::ScalarExt;
    type AssignedScalar = C::ScalarExt;
    type Native = C::ScalarExt;
    type AssignedNative = C::ScalarExt;

    type ScalarChip = MockFieldChip<C::ScalarExt>;
    type NativeChip = MockFieldChip<C::ScalarExt>;

    fn scalar_mul(
        &self,
        _ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        Ok(*rhs * *lhs)
    }
}
