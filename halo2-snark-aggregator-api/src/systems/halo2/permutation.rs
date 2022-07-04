use std::iter;

use super::evaluation::EvaluationQuery;
use crate::arith::ast::FieldArithHelper;
use crate::arith::field::ArithFieldChip;
use crate::{arith::ecc::ArithEccChip, arith_ast};

#[derive(Debug)]
pub struct EvaluatedSet<A: ArithEccChip> {
    pub(in crate::systems::halo2) permutation_product_commitment: A::AssignedPoint,
    pub(in crate::systems::halo2) permutation_product_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permutation_product_next_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permutation_product_last_eval: Option<A::AssignedScalar>,
}

#[derive(Debug)]
pub struct CommonEvaluated<'a, A: ArithEccChip> {
    pub key: String,
    pub permutation_evals: &'a Vec<A::AssignedScalar>,
    pub permutation_commitments: &'a Vec<A::AssignedPoint>,
}

#[derive(Debug)]
pub struct Evaluated<A: ArithEccChip> {
    pub(in crate::systems::halo2) key: String,
    pub(in crate::systems::halo2) blinding_factors: usize,
    pub(in crate::systems::halo2) x: A::AssignedScalar,
    pub(in crate::systems::halo2) sets: Vec<EvaluatedSet<A>>,
    pub(in crate::systems::halo2) evals: Vec<A::AssignedScalar>,
    pub(in crate::systems::halo2) chunk_len: usize,
}

impl<'a, A: ArithEccChip> CommonEvaluated<'a, A> {
    pub fn queries(&self, x: &A::AssignedScalar) -> Vec<EvaluationQuery<A>> {
        // Open permutation commitments for each permutation argument at x
        self.permutation_commitments
            .iter()
            .zip(self.permutation_evals.iter())
            .enumerate()
            .map(|(i, (commitment, eval))| {
                EvaluationQuery::new(
                    0,
                    format!("{}_permutation_commitments{}", self.key, i),
                    x.clone(),
                    commitment.clone(),
                    eval.clone(),
                )
            })
            .collect()
    }
}

impl<A: ArithEccChip> Evaluated<A> {
    pub fn expressions<'a>(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        common: &CommonEvaluated<'a, A>,
        l_0: &A::AssignedScalar,
        l_last: &A::AssignedScalar,
        l_blind: &A::AssignedScalar,
        delta: &A::AssignedScalar,
        beta: &A::AssignedScalar,
        gamma: &A::AssignedScalar,
        x: &A::AssignedScalar,
        one: &A::AssignedScalar,
    ) -> Result<Vec<A::AssignedScalar>, A::Error> {
        let mut res = vec![];

        //let left = arith_ast!(z_wx * (a_x + beta) * (s_x + gamma));

        // Enforce only for the first set.
        // l_0(X) * (1 - z_0(X)) = 0
        for first_set in self.sets.first() {
            let z_x = &first_set.permutation_product_eval;
            res.push(arith_ast!((l_0 * (one - z_x))).eval(ctx, schip)?);
        }

        // Enforce only for the last set.
        // l_last(X) * (z_l(X)^2 - z_l(X)) = 0
        for last_set in self.sets.last() {
            let z_x = &last_set.permutation_product_eval;
            res.push(arith_ast!((l_last * ((z_x * z_x) - z_x))).eval(ctx, schip)?);
        }

        // Except for the first set, enforce.
        // l_0(X) * (z_i(X) - z_{i-1}(\omega^(last) X)) = 0
        for (set, last_set) in self.sets.iter().skip(1).zip(self.sets.iter()) {
            let s = &set.permutation_product_eval;
            let prev_last = last_set.permutation_product_last_eval.as_ref().unwrap();
            res.push(arith_ast!(((s - prev_last) * l_0)).eval(ctx, schip)?);
        }

        // And for all the sets we enforce:
        // (1 - (l_last(X) + l_blind(X))) * (
        //   z_i(\omega X) \prod (p(X) + \beta s_i(X) + \gamma)
        // - z_i(X) \prod (p(X) + \delta^i \beta X + \gamma)
        // )
        let t0 = &arith_ast!((beta * x)).eval(ctx, schip)?;
        let t1 = &arith_ast!(one - (l_last + l_blind)).eval(ctx, schip)?;

        for (chunk_index, ((set, evals), permutation_evals)) in self
            .sets
            .iter()
            .zip(self.evals.chunks(self.chunk_len))
            .zip(common.permutation_evals.chunks(self.chunk_len))
            .enumerate()
        {
            let mut left = set.permutation_product_next_eval.clone();
            let mut right = set.permutation_product_eval.clone();

            let delta_pow = if chunk_index == 0 {
                one.clone()
            } else {
                schip.pow_constant(ctx, delta, (chunk_index * self.chunk_len) as u32)?
            };

            let delta_pow = &delta_pow;
            let mut d = arith_ast!((t0 * delta_pow)).eval(ctx, schip)?;

            for (eval, permutation_eval) in evals.iter().zip(permutation_evals) {
                let t2 = &arith_ast!(eval + gamma).eval(ctx, schip)?;
                let delta_current = &d;
                let l_current = &left;
                let r_current = &right;
                left = arith_ast!(((t2 + (beta * permutation_eval)) * l_current))
                    .eval(ctx, schip)?;
                right =
                    arith_ast!(((t2 + delta_current) * r_current)).eval(ctx, schip)?;
                d = arith_ast!((delta * delta_current)).eval(ctx, schip)?;
            }
            let (l, r) = (&left, &right);
            res.push(arith_ast!(((l - r) * t1)).eval(ctx, schip)?);
        }

        Ok(res)
    }

    pub fn queries(
        &self,
        x_next: &A::AssignedScalar,
        x_last: &A::AssignedScalar,
    ) -> Vec<EvaluationQuery<A>> {
        iter::empty()
            .chain(self.sets.iter().enumerate().flat_map(|(i, set)| {
                iter::empty()
                    // Open permutation product commitments at x and \omega^{-1} x
                    // Open permutation product commitments at x and \omega x
                    .chain(Some(EvaluationQuery::new(
                        0,
                        format!("{}_permutation_product_commitment_{}", self.key, i),
                        self.x.clone(),
                        set.permutation_product_commitment.clone(),
                        set.permutation_product_eval.clone(),
                    )))
                    .chain(Some(EvaluationQuery::new(
                        1,
                        format!("{}_permutation_product_commitment_{}", self.key, i),
                        x_next.clone(),
                        set.permutation_product_commitment.clone(),
                        set.permutation_product_next_eval.clone(),
                    )))
            }))
            // Open it at \omega^{last} x for all but the last set
            .chain(
                self.sets
                    .iter()
                    .enumerate()
                    .rev()
                    .skip(1)
                    .flat_map(|(i, set)| {
                        Some(EvaluationQuery::new(
                            -((self.blinding_factors + 1) as i32),
                            format!("{}_permutation_product_commitment_{}", self.key, i),
                            x_last.clone(),
                            set.permutation_product_commitment.clone(),
                            set.permutation_product_last_eval.as_ref().unwrap().clone(),
                        ))
                    }),
            )
            .collect()
    }
}
