use super::expression::Evaluable;
use crate::arith::ast::FieldArithHelper;
use crate::arith::field::ArithFieldChip;
use crate::systems::halo2::evaluation::EvaluationQuery;
use crate::{arith::ecc::ArithEccChip, arith_ast};
use halo2_proofs::plonk::Expression;

#[derive(Debug)]
pub struct PermutationCommitments<P> {
    pub(in crate::systems::halo2) permuted_input_commitment: P,
    pub(in crate::systems::halo2) permuted_table_commitment: P,
}

#[derive(Debug)]
pub struct Committed<P> {
    pub(in crate::systems::halo2) permuted: PermutationCommitments<P>,
    pub(in crate::systems::halo2) product_commitment: P,
}

#[derive(Debug)]
pub struct Evaluated<A: ArithEccChip> {
    pub(in crate::systems::halo2) key: String,
    pub(in crate::systems::halo2) input_expressions: Vec<Expression<A::AssignedScalar>>,
    pub(in crate::systems::halo2) table_expressions: Vec<Expression<A::AssignedScalar>>,
    pub(in crate::systems::halo2) committed: Committed<A::AssignedPoint>,
    pub(in crate::systems::halo2) product_eval: A::AssignedScalar, // X
    pub(in crate::systems::halo2) product_next_eval: A::AssignedScalar, // ωX
    pub(in crate::systems::halo2) permuted_input_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permuted_input_inv_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permuted_table_eval: A::AssignedScalar,
}

impl<A: ArithEccChip> Evaluated<A> {
    pub fn expressions(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        fixed_evals: &Vec<A::AssignedScalar>,
        instance_evals: &Vec<A::AssignedScalar>,
        advice_evals: &Vec<A::AssignedScalar>,
        l_0: &A::AssignedScalar,
        l_last: &A::AssignedScalar,
        l_blind: &A::AssignedScalar,
        theta: &A::AssignedScalar,
        beta: &A::AssignedScalar,
        gamma: &A::AssignedScalar,
        zero: &A::AssignedScalar,
        one: &A::AssignedScalar,
    ) -> Result<Vec<A::AssignedScalar>, A::Error> {
        let z_wx = &self.product_next_eval;
        let z_x = &self.product_eval;
        let a_x = &self.permuted_input_eval;
        let s_x = &self.permuted_table_eval;
        let a_invwx = &self.permuted_input_inv_eval;
        let product_eval = &self.product_eval;

        let left = &arith_ast!(((z_wx * (a_x + beta)) * (s_x + gamma))).eval(ctx, schip)?;

        let input_evals = self
            .input_expressions
            .iter()
            .map(|expression| {
                Evaluable::<A>::chip_evaluate(
                    expression,
                    ctx,
                    schip,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                    zero,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let input_eval = &schip.mul_add_accumulate(ctx, input_evals.iter().collect(), theta)?;

        let table_evals = self
            .table_expressions
            .iter()
            .map(|expression| {
                Evaluable::<A>::chip_evaluate(
                    expression,
                    ctx,
                    schip,
                    &|n| fixed_evals[n].clone(),
                    &|n| advice_evals[n].clone(),
                    &|n| instance_evals[n].clone(),
                    zero,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let table_eval = &schip.mul_add_accumulate(ctx, table_evals.iter().collect(), theta)?;

        let t0 = &arith_ast!(one - (l_last + l_blind)).eval(ctx, schip)?;
        let t1 = &arith_ast!(a_x - s_x).eval(ctx, schip)?;

        Ok(vec![
            // l_0(X) * (1 - z'(X)) = 0
            arith_ast!((l_0 * (one - z_x))).eval(ctx, schip)?,
            // l_last(X) * (z(X)^2 - z(X)) = 0
            arith_ast!((l_last * ((z_x * z_x) - z_x))).eval(ctx, schip)?,
            // (1 - (l_last(X) + l_blind(X))) * (
            //   z(\omega X) (a'(X) + \beta) (s'(X) + \gamma)
            //   - z(X) (\theta^{m-1} a_0(X) + ... + a_{m-1}(X) + \beta) (\theta^{m-1} s_0(X) + ... + s_{m-1}(X) + \gamma)
            // ) = 0
            arith_ast!(
                ((left - ((product_eval * (input_eval + beta)) * (table_eval + gamma))) * t0)
            )
            .eval(ctx, schip)?, //active rows
            // l_0(X) * (a'(X) - s'(X)) = 0
            arith_ast!((l_0 * t1)).eval(ctx, schip)?,
            // (1 - (l_last(X) + l_blind(X))) * (a′(X) − s′(X))⋅(a′(X) − a′(\omega^{-1} X)) = 0
            arith_ast!(((t1 * (a_x - a_invwx)) * t0)).eval(ctx, schip)?,
        ])
    }

    pub fn queries(
        &self,
        x: &A::AssignedScalar,
        x_inv: &A::AssignedScalar,
        x_next: &A::AssignedScalar,
    ) -> Vec<EvaluationQuery<A>> {
        vec![
            EvaluationQuery::new(
                0,
                format!("{}_product_commitment", self.key),
                x.clone(),
                self.committed.product_commitment.clone(),
                self.product_eval.clone(),
            ),
            EvaluationQuery::new(
                0,
                format!("{}_permuted_input_commitment", self.key),
                x.clone(),
                self.committed.permuted.permuted_input_commitment.clone(),
                self.permuted_input_eval.clone(),
            ),
            EvaluationQuery::new(
                0,
                format!("{}_permuted_table_commitment", self.key),
                x.clone(),
                self.committed.permuted.permuted_table_commitment.clone(),
                self.permuted_table_eval.clone(),
            ),
            EvaluationQuery::new(
                -1,
                format!("{}_permuted_input_commitment", self.key),
                x_inv.clone(),
                self.committed.permuted.permuted_input_commitment.clone(),
                self.permuted_input_inv_eval.clone(),
            ),
            EvaluationQuery::new(
                1,
                format!("{}_product_commitment", self.key),
                x_next.clone(),
                self.committed.product_commitment.clone(),
                self.product_next_eval.clone(),
            ),
        ]
    }
}
