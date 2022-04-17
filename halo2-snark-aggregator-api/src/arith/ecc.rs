use halo2_proofs::arithmetic::{CurveAffine, FieldExt};

use super::{common::ArithCommon, field::ArithField};
use std::fmt::Debug;

pub trait ArithECC:
    ArithCommon<Self::Context, Self::Point, Self::AssignedPoint, Self::Error>
{
    type Context;

    type Point: CurveAffine;
    type AssignedPoint: Clone + Debug;
    type Scalar;
    type AssignedScalar: Clone + Debug;
    type Native;
    type AssignedNative: Clone + Debug;

    type Error;

    type ScalarChip: ArithField<
        Context = Self::Context,
        Value = Self::Scalar,
        Assigned = Self::AssignedScalar,
        Error = Self::Error,
    >;
    type NativeChip: ArithField<
        Context = Self::Context,
        Value = Self::Native,
        Assigned = Self::AssignedNative,
        Error = Self::Error,
    >;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error>;
}
