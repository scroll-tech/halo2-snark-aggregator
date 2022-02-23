use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::{
    CurveArith,
};

use std::fmt::Debug;
use std::marker::PhantomData;
use std::iter;
use crate::{arith_in_ctx, infix2postfix};

pub struct PermutationCommitments<P> {
    permuted_input_commitment: P,
    permuted_table_commitment: P,
}

pub struct Committed<P> {
    permuted: PermutationCommitments<P>,
    product_commitment: P,
}

pub struct Evaluated<S, P> {
    committed: Committed<P>,
    product_eval: S,             // X
    product_next_eval: S,        // ωX
    permuted_input_eval: S,
    permuted_input_inv_eval: S,
    permuted_table_eval: S,
}

struct LookupSchema<'a, C, S:Clone, P:Clone, Error:Debug, Curve:CurveArith<C, S, P, Error>> {
    advice_evals: &'a [S],
    fixed_evals: &'a [S],
    instance_evals: &'a [S],
    l_0: S,
    l_last: S,
    l_blind: S,
    beta: S,
    gamma: S,
    _m: PhantomData<(C, P, Error, Curve)>,
}

impl<'a, C, S:Clone, P:Clone, Error:Debug, Curve:CurveArith<C, S, P, Error>> LookupSchema<'a, C, S, P, Error, Curve> {
    pub(in crate::verify::halo2) fn expressions(
        &'a self,
        evaluated: Evaluated<S, P>,
        sgate: &Curve::ScalarGate,
        ctx: &mut C,
    ) -> Result<impl Iterator<Item = S> + 'a, Error> {
        let zero = sgate.zero();
        let one = sgate.one();
        let beta = &self.beta;
        let gamma = &self.gamma;
        let z_wx = &evaluated.product_next_eval;

        let z_x = &evaluated.product_eval;
        let l_0 = &self.l_0;
        let l_last = &self.l_last;
        let l_blind = &self.l_blind;
        let a_x = &evaluated.permuted_input_eval;
        let s_x = &evaluated.permuted_table_eval;
        let a_invwx = &evaluated.permuted_input_inv_eval;

        let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        Ok(iter::empty()
            .chain(
                // l_0(X) * (1 - z'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (one - z_x))
            )
            .chain(
                // l_last(X) * (z(X)^2 - z(X)) = 0
                arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x))
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
                arith_in_ctx!([sgate, ctx] l_0 * (a_x - s_x))
            )
            .chain(
                // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
                arith_in_ctx!([sgate, ctx] (a_x - s_x) * (a_x - a_invwx) * (one - (l_last + l_blind)))
            )
        )
    }
}
