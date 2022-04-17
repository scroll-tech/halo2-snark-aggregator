use super::verify::VerifierParams;
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
        for _ in 1..=self.common.l {
            let wi = schip.mul(ctx, &one, &self.omega)?;
            ws.push(wi)
        }

        let mut pi_vec = vec![];
        for i in (0..=self.common.l as usize).rev() {
            let wi = &ws[i];
            // li_xi = (w ^ i) * (xi ^ n - 1) / (n * (xi - w ^ i))
            let li_xi =
                arith_ast!((one / wi) * (xi_n - one) / (n * (xi - one / wi))).eval(ctx, schip)?;
            pi_vec.push(li_xi);
        }
        Ok(pi_vec)
    }
}
