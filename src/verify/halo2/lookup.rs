use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::{EvaluationQuery};

use crate::{arith_in_ctx, infix2postfix};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct PermutationCommitments<P> {
    permuted_input_commitment: P,
    permuted_table_commitment: P,
}

pub struct Committed<P> {
    permuted: PermutationCommitments<P>,
    product_commitment: P,
}

pub struct Evaluated<C, S, P, Error> {
    committed: Committed<P>,
    product_eval: S,      // X
    product_next_eval: S, // ωX
    permuted_input_eval: S,
    permuted_input_inv_eval: S,
    permuted_table_eval: S,
    _m: PhantomData<(C, Error)>,
}

impl<C, S:Clone, P:Clone, Error:Debug> Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions(
        &self,
        sgate: &(impl ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>),
        ctx: &mut C,
        l_0: &S,
        l_last: &S,
        l_blind: &S,
        beta: &S,
        gamma: &S,
    ) -> Result<impl Iterator<Item = S>, Error> {
        let _zero = sgate.zero(ctx)?;
        let _one = sgate.one(ctx)?;
        let zero = &_zero;
        let one = &_one;
        let z_wx = &self.product_next_eval;
        let z_x = &self.product_eval;
        let a_x = &self.permuted_input_eval;
        let s_x = &self.permuted_table_eval;
        let a_invwx = &self.permuted_input_inv_eval;

        let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        Ok(iter::empty()
            .chain(
                // l_0(X) * (1 - z'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)),
            )
            .chain(
                // l_last(X) * (z(X)^2 - z(X)) = 0
                arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x)),
            )
            /*
                        .chain(
                            // (1 - (l_last(X) + l_blind(X))) * (
                            //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
                            //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
                            // ) = 0
                            Some(product_expression()),
                        )
            */
            .chain(
                // l_0(X) * (a'(X) - s'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (a_x - s_x)),
            )
            .chain(
                // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
                arith_in_ctx!(
                    [sgate, ctx](a_x - s_x) * (a_x - a_invwx) * (one - (l_last + l_blind))
                ),
            ))
    }

    pub(in crate::verify::halo2) fn queries<'a>(
        &'a self,
        x: &'a S,
        x_inv: &'a S,
        x_next: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
            // Open lookup product commitment at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.product_commitment,
                &self.product_eval,
            )))
            // Open lookup input commitments at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.permuted.permuted_input_commitment,
                &self.permuted_input_eval,
            )))
            // Open lookup table commitments at x
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                &self.committed.permuted.permuted_table_commitment,
                &self.permuted_table_eval,
            )))
            // Open lookup input commitments at \omega^{-1} x
            .chain(Some(EvaluationQuery::new(
                x_inv.clone(),
                &self.committed.permuted.permuted_input_commitment,
                &self.permuted_input_inv_eval,
            )))
            // Open lookup product commitment at \omega x
            .chain(Some(EvaluationQuery::new(
                x_next.clone(),
                &self.committed.product_commitment,
                &self.product_next_eval,
            )))
    }

}
