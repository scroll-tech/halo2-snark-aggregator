use super::{
    evaluation::EvaluationQuery, expression::Evaluable, lagrange::LagrangeGenerator, lookup,
    permutation, vanish,
};
use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip};
use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

pub struct VerifierParams<A: ArithEccChip> {
    pub key: String,
    pub gates: Vec<Vec<Expression<A::AssignedScalar>>>,
    pub common: PlonkCommonSetup,

    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<A>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<A>>,
    pub instance_commitments: Vec<Vec<A::AssignedPoint>>,
    pub instance_evals: Vec<Vec<A::AssignedScalar>>,
    pub instance_queries: Vec<(usize, i32)>,
    pub advice_commitments: Vec<Vec<A::AssignedPoint>>,
    pub advice_evals: Vec<Vec<A::AssignedScalar>>,
    pub advice_queries: Vec<(usize, i32)>,
    pub fixed_commitments: Vec<A::AssignedPoint>,
    pub fixed_evals: Vec<A::AssignedScalar>,
    pub fixed_queries: Vec<(usize, i32)>,
    pub permutation_commitments: Vec<A::AssignedPoint>,
    pub permutation_evals: Vec<A::AssignedScalar>,
    pub vanish_commitments: Vec<A::AssignedPoint>,
    pub random_commitment: A::AssignedPoint,
    pub w: Vec<A::AssignedPoint>,
    pub random_eval: A::AssignedScalar,
    pub beta: A::AssignedScalar,
    pub gamma: A::AssignedScalar,
    pub theta: A::AssignedScalar,
    pub delta: A::AssignedScalar,
    pub x: A::AssignedScalar,
    pub x_next: A::AssignedScalar,
    pub x_last: A::AssignedScalar,
    pub x_inv: A::AssignedScalar,
    pub xn: A::AssignedScalar,
    pub y: A::AssignedScalar,
    pub u: A::AssignedScalar,
    pub v: A::AssignedScalar,
    pub omega: A::AssignedScalar,

    pub zero: A::AssignedScalar,
    pub one: A::AssignedScalar,
    pub n: A::AssignedScalar,
}

impl<Scalar: FieldExt, A: ArithEccChip<Scalar = Scalar>> VerifierParams<A> {
    fn gen_key_x_rotate_omega(&self, p: String, offset: i32) -> String {
        let l = self.common.l;

        if offset == 0 {
            p
        } else if offset == -1 {
            format!("{}_inv", p)
        } else if offset == 1 {
            format!("{}_next", p)
        } else if -(l as i32) == offset {
            format!("{}_last", p)
        } else {
            format!("{}_rotate_{}", p, offset)
        }
    }

    fn x_rotate_omega(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        at: i32,
    ) -> Result<A::AssignedScalar, A::Error> {
        let x = &self.x;
        let omega = schip.to_value(&self.omega)?;
        let (base, exp) = if at < 0 {
            (omega.invert().unwrap(), [(-at) as u64, 0, 0, 0])
        } else {
            (omega, [at as u64, 0, 0, 0])
        };
        let omega_at = base.pow_vartime(exp);
        schip.sum_with_coeff_and_constant(ctx, vec![(x, omega_at)], A::Scalar::zero())
    }

    pub fn queries(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<Vec<EvaluationQuery<A>>, A::Error> {
        let x = &self.x;
        let ls = self.get_lagrange_commits(ctx, schip)?;
        let l_0 = &ls[0];
        let l_last = &ls[self.common.l as usize];
        let l_blind = &schip.sum_with_constant(
            ctx,
            ls[1..(self.common.l as usize)].iter().collect(),
            Scalar::zero(),
        )?;
        let zero = &self.zero;

        let pcommon = permutation::CommonEvaluated {
            key: self.key.clone(),
            permutation_evals: &self.permutation_evals,
            permutation_commitments: &self.permutation_commitments,
        };

        let mut expression = vec![];

        for k in 0..self.advice_evals.len() {
            let advice_evals = &self.advice_evals[k];
            let instance_evals = &self.instance_evals[k];
            let permutation = &self.permutation_evaluated[k];
            let lookups = &self.lookup_evaluated[k];
            for i in 0..self.gates.len() {
                for j in 0..self.gates[i].len() {
                    let poly = &self.gates[i][j];
                    expression.push(Evaluable::<A>::chip_evaluate(
                        poly,
                        ctx,
                        schip,
                        &|n| self.fixed_evals[n].clone(),
                        &|n| advice_evals[n].clone(),
                        &|n| instance_evals[n].clone(),
                        &zero,
                    )?);
                }
            }

            let mut p = permutation.expressions(
                ctx,
                schip,
                &pcommon,
                l_0,
                l_last,
                l_blind,
                &self.delta,
                &self.beta,
                &self.gamma,
                x,
                &self.one,
            )?;
            expression.append(&mut p);

            for lookup in lookups {
                let l = lookup.expressions(
                    ctx,
                    schip,
                    &self.fixed_evals,
                    &instance_evals,
                    &advice_evals,
                    l_0,
                    l_last,
                    l_blind,
                    &self.theta,
                    &self.beta,
                    &self.gamma,
                    &self.one,
                    &self.zero,
                )?;
                expression.extend(l);
            }
        }

        let mut queries = vec![];
        for i in 0..self.instance_commitments.len() {
            let instance_commitments = &self.instance_commitments[i];
            let instance_evals = &self.instance_evals[i];
            let advice_commitments = &self.advice_commitments[i];
            let advice_evals = &self.advice_evals[i];
            let permutation = &self.permutation_evaluated[i];
            let lookups = &self.lookup_evaluated[i];

            for (query_index, &(column, at)) in self.instance_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    self.gen_key_x_rotate_omega("x".to_string(), at),
                    format!("{}_instance_commitments{}", self.key, query_index),
                    self.x_rotate_omega(ctx, schip, at)?,
                    instance_commitments[column].clone(),
                    instance_evals[query_index].clone(),
                ))
            }

            for (query_index, &(column, at)) in self.advice_queries.iter().enumerate() {
                queries.push(EvaluationQuery::new(
                    self.gen_key_x_rotate_omega("x".to_string(), at),
                    format!("{}_advice_commitments{}", self.key, query_index),
                    self.x_rotate_omega(ctx, schip, at)?,
                    advice_commitments[column].clone(),
                    advice_evals[query_index].clone(),
                ))
            }

            queries.append(&mut permutation.queries(&self.x_next, &self.x_last));
            queries.append(
                &mut lookups
                    .iter()
                    .flat_map(move |p| p.queries(x, &self.x_inv, &self.x_next))
                    .collect(),
            );
        }

        for (query_index, &(column, at)) in self.fixed_queries.iter().enumerate() {
            queries.push(EvaluationQuery::new(
                self.gen_key_x_rotate_omega("x".to_string(), at),
                format!("{}_fixed_commitments{}", self.key, query_index),
                self.x_rotate_omega(ctx, schip, at)?,
                self.fixed_commitments[column].clone(),
                self.fixed_evals[query_index].clone(),
            ))
        }

        let mut pcommon = pcommon.queries(x);
        queries.append(&mut pcommon);

        let vanish = vanish::Evaluated::new(
            ctx,
            schip,
            expression,
            &self.y,
            &self.xn,
            &self.random_commitment,
            &self.random_eval,
            &self.vanish_commitments,
            &self.one,
            self.key.clone(),
        )?;
        //vanishing.verify(expressions, y, xn)
        let mut vanish = vanish.queries(x);
        queries.append(&mut vanish);

        Ok(queries)
    }
}
