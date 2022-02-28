use crate::schema::ast::{CommitQuery, MultiOpenProof, EvaluationAST, SchemaItem};
use crate::schema::utils::{RingUtils};
use crate::schema::{SchemaGenerator, EvaluationProof, EvaluationQuery};
use crate::arith::api::{ContextRing, ContextGroup};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::iter;
use crate::{commit, scalar};
use super::{lookup, permutation};
use halo2_proofs::plonk::Expression;
use halo2_proofs::arithmetic::Field;
use crate::{arith_in_ctx, infix2postfix};

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

trait Evaluable<C, S, Error:Debug, SGate:ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>> {
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S;
}

impl<C, S:Field, Error:Debug, SGate:ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>>
    Evaluable<C, S, Error, SGate> for Expression<S> {
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
        ) -> S {
        match self {
            Expression::Constant(scalar) => *scalar,
            Expression::Selector(selector) => panic!("virtual selectors are removed during optimization"),
            Expression::Fixed {
                query_index,
                column_index,
                rotation,
            } => fixed(*query_index),
            Expression::Advice {
                query_index,
                column_index,
                rotation,
            } => advice(*query_index),
            Expression::Instance {
                query_index,
                column_index,
                rotation,
            } => instance(*query_index),
            Expression::Negated(a) => {
                let a = &a.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                let zero = sgate.zero();
                arith_in_ctx!([sgate, ctx] zero - a).unwrap()
            }
            Expression::Sum(a, b) => {
                let a = &a.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                let b = &b.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                arith_in_ctx!([sgate, ctx] a + b).unwrap()
            }
            Expression::Product(a, b) => {
                let a = &a.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                let b = &b.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                arith_in_ctx!([sgate, ctx] a * b).unwrap()
            }
            Expression::Scaled(a, f) => {
                let a = &a.ctx_evaluate(
                    sgate,
                    ctx,
                    fixed,
                    advice,
                    instance,
                );
                arith_in_ctx!([sgate, ctx] f * a).unwrap()
            },
        }
    }
}

pub struct VerifierParams <
    'a, C, S:Field, P:Clone, Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
    pub gates: Vec<Vec<Expression<S>>>,
    pub common: PlonkCommonSetup,
    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<C, S, P, Error>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<'a, C, S, P, Error>>,
    pub instance_commitments: Vec<Vec<&'a P>>,
    pub instance_evals: Vec<Vec<&'a S>>,
    pub instance_queries: Vec<(usize, usize)>,
    pub advice_commitments: Vec<Vec<&'a P>>,
    pub advice_evals: Vec<Vec<&'a S>>,
    pub advice_queries: Vec<(usize, usize)>,
    pub fixed_commitments: Vec<&'a P>,
    pub fixed_evals: Vec<&'a S>,
    pub fixed_queries: Vec<(usize, usize)>,
    pub permutation_common: Vec<&'a P>,
    pub beta: &'a S,
    pub gamma: &'a S,
    pub alpha: &'a S,
    pub theta: &'a S,
    pub u: &'a S,
    pub v: &'a S,
    pub xi: &'a S,
    pub sgate: &'a SGate,
    pub pgate: &'a PGate,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>
}

impl<'a, C:Clone, S:Field, P:Clone,
    Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate:ContextGroup<C, S, P, Error>>
    VerifierParams<'a, C, S, P, Error, SGate, PGate> {
    fn rotate_omega(&self, at: usize) -> S {
        unimplemented!("rotate omega")
    }
    fn queries(
        &self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        x: &'a S,
        x_inv: &'a S,
        x_next: &'a S,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let xns = sgate.pow_constant_vec(ctx, x, self.common.n);
        let l_0 = x; //sgate.get_laguerre_commits
        let l_last = x; //TODO
        let l_blind = x; //TODO

        let mut r = vec![];

        /* All calculation relies on ctx thus FnMut for map does not work anymore */
        for k in 0 .. self.advice_evals.len(){
            let advice_evals = &self.advice_evals[k];
            let instance_evals = &self.instance_evals[k];
            let permutation = &self.permutation_evaluated[k];
            let lookups = &self.lookup_evaluated[k];
            for i in 0..self.gates.len() {
                for j in 0..self.gates[i].len() {
                    let poly = &self.gates[i][j];
                    r.push(poly.ctx_evaluate(
                            sgate,
                            ctx,
                            &|n| self.fixed_evals[n].clone(),
                            &|n| advice_evals[n].clone(),
                            &|n| instance_evals[n].clone(),
                    ));
                }
            }
            let p = permutation.expressions(
                   //vk,
                   //&vk.cs.permutation,
                   //&permutations_common,
                   //advice_evals,
                   //fixed_evals,
                   //instance_evals,
                   sgate,
                   ctx,
                   l_0,
                   l_last,
                   l_blind,
                   self.beta,
                   self.gamma,
                   //x,
                ).unwrap();
            r.extend(p);
            for i in 0..lookups.len() {
                let l = lookups[i].expressions(
                    sgate,
                    ctx,
                    l_0,
                    l_last,
                    l_blind,
                    //argument,
                    //self.theta,
                    self.beta,
                    self.gamma,
                    //advice_evals,
                    //fixed_evals,
                    //instance_evals,
                ).unwrap();
                r.extend(l);
            }
        }

        //vanishing.verify(expressions, y, xn)

        let queries = self.instance_commitments.iter()
        .zip(self.instance_evals.iter())
        .zip(self.advice_commitments.iter())
        .zip(self.advice_evals.iter())
        .zip(self.permutation_evaluated.iter())
        .zip(self.lookup_evaluated.iter())
        .flat_map(
            |(
                (
                    (((instance_commitments, instance_evals), advice_commitments), advice_evals),
                    permutation,
                ),
                lookups,
            )| {
                iter::empty()
                    .chain(self.instance_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            EvaluationQuery::new(
                                self.rotate_omega(at),
                                instance_commitments[column],
                                instance_evals[query_index],
                            )
                        },
                    ))
                    .chain(self.advice_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            EvaluationQuery::new(
                                self.rotate_omega(at),
                                advice_commitments[column],
                                advice_evals[query_index],
                            )
                        },
                    ))
                    .chain(permutation.queries())
                    .chain(
                        lookups
                            .iter()
                            .flat_map(move |p| p.queries(x, x_inv, x_next))
                            .into_iter(),
                    )
            },
        )
        .chain(
                self.fixed_queries.iter().enumerate().map(
                    |(query_index, &(column, at))| {
                    EvaluationQuery::<'a, S, P>::new(
                        self.rotate_omega(at),
                        &self.fixed_commitments[column],
                        &self.fixed_evals[query_index],
                    )
                }),
        )
        //.chain(self.permutations_common.queries(&vk.permutation, x))
        //.chain(vanishing.queries(x))
        ;
        unimplemented!("get point schemas not implemented")
    }
}

impl<'a, C:Clone, S:Field, P:Clone,
    Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate:ContextGroup<C, S, P, Error>>
    SchemaGenerator<'a, C, S, P, Error> for
    VerifierParams<'a, C, S, P, Error, SGate, PGate> {
    fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        unimplemented!("get point schemas not implemented")
    }
    fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let mut proofs = self.get_point_schemas(ctx)?;
        proofs.reverse();
        let (mut w_x, mut w_g) = {
            let s = &proofs[0].s;
            let w = CommitQuery {c: Some(proofs[0].w), v:None};
            (commit!(w), scalar!(proofs[0].point) * commit!(w) + s.clone())
        };
        let _ = proofs[1..].iter().map(|p| {
            let s = &p.s;
            let w = CommitQuery {c: Some(p.w), v:None};
            w_x = scalar!(self.u) * w_x.clone() + commit!(w);
            w_g = scalar!(self.u) * w_g.clone() + scalar!(p.point) * commit!(w) + s.clone();
        });
        Ok(MultiOpenProof {w_x, w_g})
    }
}



