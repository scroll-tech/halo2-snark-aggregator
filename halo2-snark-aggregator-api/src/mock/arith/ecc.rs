use super::field::MockFieldChip;
use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use crate::mock::arith::field::MockChipCtx;
use group::{Curve, Group};
use halo2_proofs::arithmetic::CurveAffine;
use std::marker::PhantomData;

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
    type Context = MockChipCtx;
    type Value = C;
    type AssignedValue = C::CurveExt;
    type Error = E;

    fn add(
        &self,
        _ctx: &mut Self::Context,
        a: &C::CurveExt,
        b: &C::CurveExt,
    ) -> Result<C::CurveExt, Self::Error> {
        Ok(*a + *b)
    }

    fn sub(
        &self,
        _ctx: &mut Self::Context,
        a: &C::CurveExt,
        b: &C::CurveExt,
    ) -> Result<C::CurveExt, Self::Error> {
        Ok(*a - *b)
    }

    fn assign_zero(&self, _ctx: &mut Self::Context) -> Result<C::CurveExt, Self::Error> {
        Ok(self.zero)
    }

    fn assign_one(&self, _ctx: &mut Self::Context) -> Result<C::CurveExt, Self::Error> {
        Ok(self.one)
    }

    fn assign_const(&self, _ctx: &mut Self::Context, c: C) -> Result<C::CurveExt, Self::Error> {
        Ok(c.to_curve())
    }

    fn assign_var(&self, _ctx: &mut Self::Context, v: C) -> Result<C::CurveExt, Self::Error> {
        Ok(v.to_curve())
    }

    fn to_value(&self, v: &C::CurveExt) -> Result<C, Self::Error> {
        Ok(v.to_affine())
    }

    fn normalize(
        &self,
        _ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(*v)
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

    fn scalar_mul(
        &self,
        _ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        Ok(*rhs * *lhs)
    }

    fn scalar_mul_constant(
        &self,
        _ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: Self::Point,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        Ok(rhs * *lhs)
    }

    fn multi_exp(
        &self,
        ctx: &mut Self::Context,
        points: Vec<Self::AssignedPoint>,
        scalars: Vec<Self::AssignedScalar>,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        ctx.point_list = points
            .clone()
            .into_iter()
            .map(|x| format!("{:?}", x))
            .collect();
        let mut acc = None;
        for (p, s) in points.iter().zip(scalars.iter()) {
            let curr = self.scalar_mul(ctx, s, p)?;
            acc = match acc {
                None => Some(curr),
                Some(_acc) => {
                    let p = self.add(ctx, &_acc, &curr)?;
                    Some(p)
                }
            }
        }
        Ok(acc.unwrap())
    }
}
