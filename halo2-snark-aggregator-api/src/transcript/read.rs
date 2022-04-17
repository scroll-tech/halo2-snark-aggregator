use crate::arith::ecc::ArithEcc;

pub trait TranscriptRead<A: ArithEcc> {
    fn read_point(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
    ) -> Result<A::AssignedPoint, A::Error>;
    fn read_scalar(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error>;

    fn read_constant_point(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
    ) -> Result<A::AssignedPoint, A::Error>;
    fn read_constant_scalar(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error>;

    fn common_point(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
        p: &A::AssignedPoint,
    ) -> Result<(), A::Error>;
    fn common_scalar(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        s: &A::ScalarChip,
    ) -> Result<(), A::Error>;

    fn squeeze_challenge_scalar(
        &mut self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<A::AssignedScalar, A::Error>;
}
