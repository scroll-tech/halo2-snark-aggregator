use super::{common::ArithCommonChip, field::ArithFieldChip};
use halo2_proofs::arithmetic::{CurveAffine, FieldExt};
use std::fmt::Debug;

pub trait ArithEccChip:
    ArithCommonChip<Self::Context, Self::Point, Self::AssignedPoint, Self::Error>
{
    type Context;

    type Point: CurveAffine;
    type AssignedPoint: Clone + Debug;
    type Scalar: FieldExt;
    type AssignedScalar: Clone + Debug;
    type Native: FieldExt;
    type AssignedNative: Clone + Debug;

    type Error;

    type ScalarChip: ArithFieldChip<
        Context = Self::Context,
        Value = Self::Scalar,
        AssignedValue = Self::AssignedScalar,
        Error = Self::Error,
    >;
    type NativeChip: ArithFieldChip<
        Context = Self::Context,
        Value = Self::Native,
        AssignedValue = Self::AssignedNative,
        Error = Self::Error,
    >;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error>;
}
