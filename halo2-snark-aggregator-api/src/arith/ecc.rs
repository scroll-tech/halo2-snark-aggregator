use super::{common::ArithCommonChip, field::ArithFieldChip};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use std::fmt::Debug;

pub trait ArithEccChip:
    ArithCommonChip<Value = Self::Point, AssignedValue = Self::AssignedPoint>
{
    type Point: CurveAffine;
    type AssignedPoint: Clone + Debug;
    type Scalar: FieldExt;
    type AssignedScalar: Clone + Debug;
    type Native: FieldExt;
    type AssignedNative: Clone + Debug;

    type ScalarChip: ArithFieldChip<
        Context = Self::Context,
        Field = Self::Scalar,
        AssignedField = Self::AssignedScalar,
        Error = Self::Error,
    >;
    type NativeChip: ArithFieldChip<
        Context = Self::Context,
        Field = Self::Native,
        AssignedField = Self::AssignedNative,
        Error = Self::Error,
    >;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error>;

    fn scalar_mul_constant(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: Self::Point,
    ) -> Result<Self::AssignedPoint, Self::Error>;

    fn multi_exp(
        &self,
        ctx: &mut Self::Context,
        points: Vec<Self::AssignedPoint>,
        scalars: Vec<Self::AssignedScalar>,
    ) -> Result<Self::AssignedPoint, Self::Error> {
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
