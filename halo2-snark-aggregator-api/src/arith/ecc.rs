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

    fn print_debug_info(&self, c: &Self::Context, desc: &'static str) {

    }
    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error>;
}
