use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

use super::{evaluate::Evaluable, VerifierParams, rotate_omega};
use crate::{
    arith::api::{ContextGroup, ContextRing},
    schema::{ast::ArrayOpAdd, utils::VerifySetupHelper, EvaluationQuery},
    verify::halo2::{permutation, vanish},
};

impl<C, S: Clone, P: Clone, Error: Debug> VerifierParams<C, S, P, Error> {
    fn x_rotate_omega<
        'a,
        T: FieldExt,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    >(
        &self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        at: i32,
    ) -> Result<S, Error> {
        let x = &self.x;
        let omega = sgate.to_value(&self.omega)?;
        rotate_omega(sgate, ctx, x, omega, at)
    }
}

pub trait IVerifierParams<
    'a,
    C,
    S: Clone,
    T,
    P: Clone,
    Error,
    SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
>
{
    fn queries(
        &'a self,
        sgate: &SGate,
        ctx: &mut C,
    ) -> Result<Vec<EvaluationQuery<'a, S, P>>, Error>;
}

impl<
        'a,
        C,
        S: Clone + Debug,
        T: FieldExt,
        P: Clone + Debug,
        Error: Debug,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    > IVerifierParams<'a, C, S, T, P, Error, SGate> for VerifierParams<C, S, P, Error>
{
    fn queries(
        &'a self,
        sgate: &SGate,
        ctx: &mut C,
    ) -> Result<Vec<EvaluationQuery<'a, S, P>>, Error> {
        let x = &self.x;
        let ls = sgate.get_lagrange_commits(
            ctx,
            x,
            &self.xn,
            &self.omega,
            self.common.n,
            self.common.l as i32,
        )?;
        let l_last = &(ls[0]);
        let l_0 = &ls[self.common.l as usize];
        let l_blind = &sgate.add_array(ctx, ls[1..(self.common.l as usize)].iter().collect())?;
        let zero = sgate.zero(ctx)?;

        let pcommon = permutation::CommonEvaluated {
            permutation_evals: &self.permutation_evals,
            permutation_commitments: &self.permutation_commitments,
        };

        let mut expression = vec![];

        /* All calculation relies on ctx thus FnMut for map does not work anymore */
        for k in 0..self.advice_evals.len() {
            let advice_evals = &self.advice_evals[k];
            let instance_evals = &self.instance_evals[k];
            let permutation = &self.permutation_evaluated[k];
            let lookups = &self.lookup_evaluated[k];
            for i in 0..self.gates.len() {
                for j in 0..self.gates[i].len() {
                    let poly = &self.gates[i][j];
                    expression.push(poly.ctx_evaluate(
                        sgate,
                        ctx,
                        &|n| self.fixed_evals[n].clone(),
                        &|n| advice_evals[n].clone(),
                        &|n| instance_evals[n].clone(),
                        &zero,
                    )?);
                }
            }

            let mut p = permutation.expressions(
                //vk,
                //&vk.cs.permutation,
                //&permutations_common,
                //fixed_evals,
                //advice_evals,
                //instance_evals,
                sgate,
                ctx,
                &pcommon,
                l_0,
                l_last,
                l_blind,
                &self.delta,
                &self.beta,
                &self.gamma,
                x,
            )?;
            expression.append(&mut p);

            for i in 0..lookups.len() {
                let l = lookups[i]
                    .expressions(
                        sgate,
                        ctx,
                        &self.fixed_evals.iter().map(|ele| ele).collect(),
                        &instance_evals.iter().map(|ele| ele).collect(),
                        &advice_evals.iter().map(|ele| ele).collect(),
                        l_0,
                        l_last,
                        l_blind,
                        //argument,
                        &self.theta,
                        &self.beta,
                        &self.gamma,
                    )
                    .unwrap();
                expression.extend(l);
            }
        }

        let mut queries = vec![];
        for (
            (
                (((instance_commitments, instance_evals), advice_commitments), advice_evals),
                permutation,
            ),
            lookups,
        ) in self
            .instance_commitments
            .iter()
            .zip(self.instance_evals.iter())
            .zip(self.advice_commitments.iter())
            .zip(self.advice_evals.iter())
            .zip(self.permutation_evaluated.iter())
            .zip(self.lookup_evaluated.iter())
        {
            for (query_index, &(column, at)) in self.instance_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    self.x_rotate_omega(sgate, ctx, at).unwrap(),
                    format!("instance{}", query_index),
                    &instance_commitments[column],
                    &instance_evals[query_index],
                ))
            }

            for (query_index, &(column, at)) in self.advice_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    self.x_rotate_omega(sgate, ctx, at).unwrap(),
                    format!("advice{}", query_index),
                    &advice_commitments[column],
                    &advice_evals[query_index],
                ))
            }

            queries.append(&mut permutation.queries(&self.x_next, &self.x_last).collect()); // tested
            queries.append(
                &mut lookups
                    .iter()
                    .flat_map(move |p| p.queries(x, &self.x_inv, &self.x_next))
                    .collect(),
            );
        }

        for (query_index, &(column, at)) in self.fixed_queries.iter().enumerate() {
            queries.push(EvaluationQuery::<'a, S, P>::new(
                self.x_rotate_omega(sgate, ctx, at).unwrap(),
                format!("query{}", query_index),
                &self.fixed_commitments[column],
                &self.fixed_evals[query_index],
            ))
        }

        let mut pcommon = pcommon.queries(x);
        queries.append(&mut pcommon);

        let vanish = vanish::Evaluated::new(
            sgate,
            ctx,
            expression,
            &self.y,
            &self.xn,
            &self.random_commitment,
            &self.random_eval,
            self.vanish_commitments.iter().map(|ele| ele).collect(),
        )?;
        //vanishing.verify(expressions, y, xn)
        let mut vanish = vanish.queries(x);
        queries.append(&mut vanish);

        Ok(queries)
    }
}
