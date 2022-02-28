use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::{EvaluationQuery};

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
    permutation_product_last_eval: Option<S>,
}

pub struct CommonEvaluated<S> {
    permutation_evals: Vec<S>,
}

pub struct Evaluated<'a, C, S, P, Error> {
    x: &'a S,
    x_next: &'a S,
    x_last: &'a S,
    sets: Vec<EvaluatedSet<S,P>>,
    _m: PhantomData<(C, Error)>,
}

impl<'a, C, S:Clone, P:Clone, Error:Debug> Evaluated<'a, C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions(
        &'a self,
        sgate: &(impl ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>),
        ctx: &mut C,
        l_0: &'a S,
        l_last: &'a S,
        l_blind: &'a S,
        beta: &'a S,
        gamma: &'a S,
    ) -> Result<impl Iterator<Item = S>, Error> {
        let zero = &sgate.zero(ctx)?;
        let one = &sgate.one(ctx)?;

        //let left = arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma));

        Ok(iter::empty()
            // Enforce only for the first set.
            // l_0(X) * (1 - z_0(X)) = 0
            .chain(
                self.sets.first().map(|first_set| {
                    let z_x = &first_set.permutation_product_eval;
                    arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)).unwrap()
                }),
            )
            // Enforce only for the last set.
            // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
            .chain(
                self.sets.last().map(|last_set| {
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
    pub(in crate::verify::halo2) fn queries(
      &'a self,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        iter::empty()
        .chain(self.sets.iter().flat_map(|set| {
            iter::empty()
                // FIXME: double check eval or prev-eval
                // Open permutation product commitments at x and \omega^{-1} x
                // Open permutation product commitments at x and \omega x
                .chain(
                    Some(EvaluationQuery::new(
                    self.x.clone(),
                    &set.permutation_product_commitment,
                    &set.permutation_product_eval,
                )))
                .chain(
                    Some(EvaluationQuery::new(
                    self.x_next.clone(),
                    &set.permutation_product_commitment,
                    &set.permutation_product_next_eval
                )))
        }))
        // Open it at \omega^{last} x for all but the last set
        .chain(self.sets.iter().rev().skip(1).flat_map(|set| {
            Some(EvaluationQuery::new(
                self.x_last.clone(),
                &set.permutation_product_commitment,
                &set.permutation_product_last_eval.as_ref().unwrap(),
            )
        )}))
    }
}
