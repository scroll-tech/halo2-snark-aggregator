use crate::arith::ecc::ArithECC;

pub trait Encode<A: ArithECC> {
    fn encode_point(
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
        v: &A::AssignedPoint,
    ) -> Result<Vec<A::AssignedNative>, A::Error>;
    fn encode_scalar(
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
        v: &A::AssignedScalar,
    ) -> Result<Vec<A::AssignedNative>, A::Context>;
}
