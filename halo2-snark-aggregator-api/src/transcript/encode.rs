use crate::arith::ecc::ArithEccChip;

pub trait Encode<A: ArithEccChip> {
    fn encode_point(
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        pchip: &A,
        v: &A::AssignedPoint,
    ) -> Result<Vec<A::AssignedNative>, A::Error>;
    fn encode_scalar(
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        v: &A::AssignedScalar,
    ) -> Result<Vec<A::AssignedNative>, A::Error>;
    fn decode_scalar(
        ctx: &mut A::Context,
        nchip: &A::NativeChip,
        schip: &A::ScalarChip,
        v: &[A::AssignedNative],
    ) -> Result<A::AssignedScalar, A::Error>;
}
