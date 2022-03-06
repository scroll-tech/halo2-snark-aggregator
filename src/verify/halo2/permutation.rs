use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::{EvaluationQuery};

use crate::{arith_in_ctx, infix2postfix};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct Committed<P> {
    permutation_product_commitments: Vec<P>,
}

pub struct EvaluatedSet<S, P> {
    permutation_product_commitment: P,
    permutation_product_eval: S,
    permutation_product_next_eval: S,
    permutation_product_last_eval: Option<S>,
    chunk_len: usize,
}

pub struct CommonEvaluated<'a, S, P> {
    pub permutation_evals: &'a Vec<S>,
    pub permutation_commitments: &'a Vec<P>,
}

pub struct Evaluated<'a, C, S, P, Error> {
    x: &'a S,
    x_next: &'a S,
    x_last: &'a S,
    sets: Vec<EvaluatedSet<S,P>>,
    evals: Vec<&'a S>,
    chunk_len: usize,
    _m: PhantomData<(C, Error)>,
}

impl<'a, S:Clone, P:Clone> CommonEvaluated<'a, S, P> {
    pub(in crate::verify::halo2) fn queries(
        &'a self,
        x: &'a S,
    ) -> impl Iterator<Item = EvaluationQuery<'a, S, P>> {
        // Open permutation commitments for each permutation argument at x
        self.permutation_commitments.iter().zip(self.permutation_evals.iter())
            .map(|(commitment, eval)|
                EvaluationQuery::<'a, S, P>::new(x.clone(), &commitment, &eval)
            )
    }
}

impl<'a, C, S:Clone, P:Clone, Error:Debug> Evaluated<'a, C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions(
        &'a self,
        sgate: &'a (impl ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>),
        ctx: &'a mut C,
        common: &'a CommonEvaluated<'a, S, P>,
        l_0: &'a S,
        l_last: &'a S,
        l_blind: &'a S,
        delta: &'a S,
        beta: &'a S,
        gamma: &'a S,
        x: &'a S,
    ) -> Result<impl Iterator<Item = S> + 'a, Error> {
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
                }))
            // Except for the first set, enforce.
            // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
            .chain(
                self.sets
                    .iter()
                    .skip(1)
                    .zip(self.sets.iter())
                    .map(|(set, last_set)| {
                        let s = &set.permutation_product_eval;
                        let prev_last = &last_set.permutation_product_last_eval.as_ref().unwrap();
                        arith_in_ctx!([sgate, ctx] (s - prev_last) * l_0).unwrap()
                    })
            )

            // And for all the sets we enforce:
            // (1 - (l_last(X) + l_blind(X))) * (
            //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
            // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
            // )
            .chain({
                // mutable borrow ctx, can not use closure!
                let v = vec![];
                for ((set, evals), permutation_evals) in self.sets.iter()
                    .zip(self.evals.chunks(self.chunk_len))
                    .zip(common.permutation_evals.chunks(self.chunk_len)) {
                        let one = &sgate.one(ctx).unwrap();
                        let mut left = set.permutation_product_next_eval.clone();
                        let mut right = set.permutation_product_eval.clone();
                        let mut d = arith_in_ctx!([sgate, ctx] beta * x * delta).unwrap();
                        for (eval, permutation_eval) in evals.iter().zip(permutation_evals) {
                            let delta_current = &d;
                            let l_current = &left;
                            let r_current = &right;
                            left = arith_in_ctx!([sgate, ctx] (eval + beta * permutation_eval + gamma) * l_current).unwrap();
                            right = arith_in_ctx!([sgate, ctx] (eval + delta + gamma) * r_current).unwrap();
                            d = arith_in_ctx!([sgate, ctx] delta * delta_current).unwrap();
                        }
                        let (l,r) = (&left, &right);
                        v.push(arith_in_ctx!([sgate, ctx] (l- r) * (one - (l_last + l_blind))).unwrap());
                    };
                v
            })
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

