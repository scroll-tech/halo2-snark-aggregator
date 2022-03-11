use super::verify::Evaluable;
use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::utils::VerifySetupHelper;
use crate::schema::EvaluationQuery;
use crate::{arith_in_ctx, infix2postfix};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::plonk::Expression;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct PermutationCommitments<P> {
    pub(in crate::verify::halo2) permuted_input_commitment: P,
    pub(in crate::verify::halo2) permuted_table_commitment: P,
}

pub struct Committed<P> {
    pub(in crate::verify::halo2) permuted: PermutationCommitments<P>,
    pub(in crate::verify::halo2) product_commitment: P,
}

pub struct Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) input_expressions: Vec<Expression<S>>,
    pub(in crate::verify::halo2) table_expressions: Vec<Expression<S>>,
    pub(in crate::verify::halo2) committed: Committed<P>,
    pub(in crate::verify::halo2) product_eval: S, // X
    pub(in crate::verify::halo2) product_next_eval: S, // ωX
    pub(in crate::verify::halo2) permuted_input_eval: S,
    pub(in crate::verify::halo2) permuted_input_inv_eval: S,
    pub(in crate::verify::halo2) permuted_table_eval: S,
    pub(in crate::verify::halo2) _m: PhantomData<(C, Error)>,
}

impl<'a, C, S: Field, P: Clone, Error: Debug> Evaluated<C, S, P, Error> {
    pub(in crate::verify::halo2) fn expressions(
        &'a self,
        sgate: &(impl ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>),
        ctx: &'a mut C,
        fixed_evals: &'a Vec<&'a S>,
        instance_evals: &'a Vec<&'a S>,
        advice_evals: &'a Vec<&'a S>,
        l_0: &'a S,
        l_last: &'a S,
        l_blind: &'a S,
        theta: &'a S,
        beta: &'a S,
        gamma: &'a S,
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
        let product_eval = &self.product_eval;

        let left = &arith_in_ctx!([sgate, ctx] z_wx * (a_x + beta) * (s_x + gamma))?;

        let input_evals: Vec<S> = self
            .input_expressions
            .iter()
            .map(|expression| {
                expression.ctx_evaluate(
                    sgate,
                    ctx,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                )
            })
            .collect();
        let input_eval = &sgate.mult_and_add(ctx, input_evals.iter(), theta);

        let table_evals: Vec<S> = self
            .input_expressions
            .iter()
            .map(|expression| {
                expression.ctx_evaluate(
                    sgate,
                    ctx,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                )
            })
            .collect();
        let table_eval = &sgate.mult_and_add(ctx, table_evals.iter(), theta);

        Ok(iter::empty()
            .chain(
                // l_0(X) * (1 - z'(X)) = 0
                arith_in_ctx!([sgate, ctx] l_0 * (one - z_x)),
            )
            .chain(
                // l_last(X) * (z(X)^2 - z(X)) = 0
                arith_in_ctx!([sgate, ctx] l_last * (z_x * z_x - z_x)),
            )
            .chain(
                // (1 - (l_last(X) + l_blind(X))) * (
                //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
                //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
                // ) = 0
                arith_in_ctx!(
                    [sgate, ctx](left - product_eval * (input_eval + beta) * (table_eval + gamma))
                        * (one - (l_last + l_blind))
                ), //active rows
            )
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

    pub(in crate::verify::halo2) fn queries(
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
