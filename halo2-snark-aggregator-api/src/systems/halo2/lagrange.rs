use super::params::VerifierParams;
use crate::arith::ast::FieldArithHelper;
use crate::{
    arith::{ecc::ArithEccChip, field::ArithFieldChip},
    arith_ast,
};

pub trait LagrangeGenerator<A: ArithEccChip> {
    fn get_lagrange_commits(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<Vec<A::AssignedScalar>, A::Error>;
}

impl<A: ArithEccChip> LagrangeGenerator<A> for VerifierParams<A> {
    fn get_lagrange_commits(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<Vec<A::AssignedScalar>, A::Error> {
        let n = &self.n;
        let xi = &self.x;
        let xi_n = &self.xn;
        let one = &self.one;

        let mut ws = vec![one.clone()];
        for i in 1..=self.common.l {
            let wi = schip.mul(ctx, &ws[(i - 1) as usize], &self.omega)?;
            ws.push(wi)
        }

        (0..=self.common.l as usize)
            .map(|i| {
                let wi = &ws[i];
                arith_ast!((((one / wi) * (xi_n - one)) / (n * (xi - (one / wi))))).eval(ctx, schip)
            })
            .collect()
    }
}
