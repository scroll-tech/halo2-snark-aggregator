use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::CurveArith;

use crate::{arith_in_ctx, infix2postfix};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct VerifyingKey<S> {
    commitments: Vec<S>,
}

pub struct Committed<P> {
    permutation_product_commitments: Vec<P>,
}

pub struct EvaluatedSet<S, P> {
    permutation_product_commitment: P,
    permutation_product_eval: S,
    permutation_product_next_eval: S,
    permutation_product_last_eval: S,
}

pub struct CommonEvaluated<S> {
    permutation_evals: Vec<S>,
}

pub struct Evaluated<S, P> {
    sets: Vec<EvaluatedSet<S, P>>,
}

struct PermutationSchema<'a, C, S: Clone, P: Clone, Error: Debug, Curve: CurveArith<C, S, P, Error>>
{
    vk: &'a VerifyingKey<S>,
    common: &'a CommonEvaluated<S>,
    advice_evals: &'a [S],
    fixed_evals: &'a [S],
    instance_evals: &'a [S],
    l_0: S,
    l_last: S,
    l_blind: S,
    beta: S,
    gamma: S,
    x: S,
    _m: PhantomData<(C, P, Curve, Error)>,
}

impl<'a, C, S: Clone, P: Clone, Error: Debug, Curve: CurveArith<C, S, P, Error>>
    PermutationSchema<'a, C, S, P, Error, Curve>
{
    pub(in crate::verify::halo2) fn expressions(
        &'a self,
        evaluated: Evaluated<S, P>,
        sgate: &Curve::ScalarGate,
        ctx: &mut C,
    ) -> Result<impl Iterator<Item = S> + 'a, Error> {
        let zero = sgate.zero(ctx)?;
        let _one = sgate.one(ctx)?;
        let one = &_one;
        let beta = &self.beta;
        let gamma = &self.gamma;
        let l_0 = &self.l_0;
        let l_last = &self.l_last;
        let l_blind = &self.l_blind;

        //let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        Ok(
            iter::empty()
                // Enforce only for the first set.
                // l_0(X) * (1 - z_0(X)) = 0
                .chain(evaluated.sets.first().map(|first_set| {
                    let z_x = &first_set.permutation_product_eval;
                    arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)).unwrap()
                }))
                // Enforce only for the last set.
                // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
                .chain(evaluated.sets.last().map(|last_set| {
                    let z_x = &last_set.permutation_product_eval;
                    arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x)).unwrap()
                })),
            // Except for the first set, enforce.
            // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0

            // And for all the sets we enforce:
            // (1 - (l_last(X) + l_blind(X))) * (
            //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
            // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
            // )
        )
    }
}
