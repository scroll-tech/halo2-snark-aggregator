use halo2_proofs::arithmetic::{CurveAffine, FieldExt};

use super::{common::ArithCommon, field::ArithField};

pub trait ArithEcc: ArithCommon<Self::Point, Self::Error> {
    type Point: CurveAffine;
    type Error;
    type AssignedPoint = Self::Assigned;

    type ScalarChip: ArithField<Error = Self::Error>;
    type Scalar: FieldExt = <Self::ScalarChip as ArithField>::Value;
    type AssignedScalar = <Self::ScalarChip as ArithCommon<
        <<Self as ArithEcc>::ScalarChip as ArithField>::Value,
        Self::Error,
    >>::Assigned;

    type NativeChip: ArithField<Error = Self::Error>;
    type Native = <Self::NativeChip as ArithField>::Value;
    type AssignedNative = <Self::NativeChip as ArithCommon<
        <<Self as ArithEcc>::NativeChip as ArithField>::Value,
        Self::Error,
    >>::Assigned;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error>;
}
