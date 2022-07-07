use super::field::{MockEccChipCtx, MockFieldChip};
use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use group::{Curve, Group};
use halo2_proofs::arithmetic::CurveAffine;
use std::{marker::PhantomData, task::Context};

pub struct MockEccChip<C: CurveAffine, E> {
    zero: C::CurveExt,
    one: C::CurveExt,
    _data: PhantomData<E>,
}

impl<C: CurveAffine, E> Default for MockEccChip<C, E> {
    fn default() -> Self {
        Self {
            zero: <C as CurveAffine>::CurveExt::identity(),
            one: <C as CurveAffine>::CurveExt::generator(),
            _data: PhantomData,
        }
    }
}

impl<C: CurveAffine, E> ArithCommonChip for MockEccChip<C, E> {
    type Context = MockEccChipCtx;
    type Value = C;
    type AssignedValue = C::CurveExt;
    type Error = E;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &C::CurveExt,
        b: &C::CurveExt,
    ) -> Result<C::CurveExt, Self::Error> {
        Ok(*a + *b)
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &C::CurveExt,
        b: &C::CurveExt,
    ) -> Result<C::CurveExt, Self::Error> {
        Ok(*a - *b)
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<C::CurveExt, Self::Error> {
        Ok(self.zero)
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<C::CurveExt, Self::Error> {
        Ok(self.one)
    }

    fn assign_const(&self, ctx: &mut Self::Context, c: C) -> Result<C::CurveExt, Self::Error> {
        Ok(c.to_curve())
    }

    fn assign_var(&self, ctx: &mut Self::Context, v: C) -> Result<C::CurveExt, Self::Error> {
        Ok(v.to_curve())
    }

    fn to_value(&self, v: &C::CurveExt) -> Result<C, Self::Error> {
        Ok(v.to_affine())
    }
}

impl<C: CurveAffine, E> ArithEccChip for MockEccChip<C, E> {
    type Point = C;
    type AssignedPoint = C::CurveExt;
    type Scalar = C::ScalarExt;
    type AssignedScalar = C::ScalarExt;
    type Native = C::ScalarExt;
    type AssignedNative = C::ScalarExt;

    type ScalarChip = MockFieldChip<C::ScalarExt, E>;
    type NativeChip = MockFieldChip<C::ScalarExt, E>;

    fn print_debug_info(&self, c: &Self::Context, desc: &str) {
        // println!("print_debug_info MockEccChip: none");
    }
    fn record_scalar_mul(&self, c: &mut Self::Context, k: &str) {
        c.point_list.push(format!("{}{}", c.tag, k));
    }
    fn scalar_mul(
        &self,
        _ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        Ok(*rhs * *lhs)
    }
}
