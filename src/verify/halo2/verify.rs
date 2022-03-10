use super::{lookup, permutation, vanish};
use crate::arith::api::{ContextGroup, ContextRing};
use crate::arith::code::{FieldCode, PointCode};
use crate::schema::ast::{CommitQuery, MultiOpenProof, SchemaItem};
use crate::schema::utils::RingUtils;
use crate::schema::{EvaluationProof, EvaluationQuery, SchemaGenerator};
use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, scalar};
use group::Curve;
use halo2_proofs::arithmetic::{CurveAffine, Field, MultiMillerLoop};
use halo2_proofs::plonk::{Expression, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsVerifier};
use halo2_proofs::transcript::{EncodedChallenge, TranscriptRead};
use pairing_bn256::bn256::G1Affine;
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct PlonkCommonSetup {
    pub l: u32,
    pub n: u32,
}

pub trait Evaluable<
    C,
    S,
    Error: Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
    ) -> S;
}

impl<
        C,
        S: Field,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    > Evaluable<C, S, Error, SGate> for Expression<S>
{
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
            Expression::Selector(selector) => {
                panic!("virtual selectors are removed during optimization")
            }
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
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let zero = &sgate.zero(ctx).unwrap();
                arith_in_ctx!([sgate, ctx] zero - a).unwrap()
            }
            Expression::Sum(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a + b).unwrap()
            }
            Expression::Product(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] a * b).unwrap()
            }
            Expression::Scaled(a, f) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance);
                arith_in_ctx!([sgate, ctx] f * a).unwrap()
            }
        }
    }
}

pub struct VerifierParams<
    C,
    S: Field,
    P: Clone,
    Error: Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
    pub gates: Vec<Vec<Expression<S>>>,
    pub common: PlonkCommonSetup,
    pub lookup_evaluated: Vec<Vec<lookup::Evaluated<C, S, P, Error>>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<C, S, P, Error>>,
    pub instance_commitments: Vec<Vec<P>>,
    pub instance_evals: Vec<Vec<S>>,
    pub instance_queries: Vec<(usize, usize)>,
    pub advice_commitments: Vec<Vec<P>>,
    pub advice_evals: Vec<Vec<S>>,
    pub advice_queries: Vec<(usize, usize)>,
    pub fixed_commitments: Vec<P>,
    pub fixed_evals: Vec<S>,
    pub fixed_queries: Vec<(usize, usize)>,
    pub permutation_commitments: Vec<P>,
    pub permutation_evals: Vec<S>, // permutations common evaluation
    pub vanish_commitments: Vec<P>,
    pub random_commitment: P,
    pub random_eval: S,
    pub beta: S,
    pub gamma: S,
    pub alpha: S,
    pub theta: S,
    pub delta: S,
    pub u: S,
    pub v: S,
    pub xi: S,
    pub sgate: SGate,
    pub pgate: PGate,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>,
}

impl<
        'a,
        C: Clone,
        S: Field,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, Error>,
    > VerifierParams<C, S, P, Error, SGate, PGate>
{
    fn rotate_omega(&self, at: usize) -> S {
        unimplemented!("rotate omega")
    }
    fn queries(
        &'a self,
        sgate: &'a SGate,
        ctx: &'a mut C,
        y: &'a S,
        x: &'a S,
        x_inv: &'a S,
        x_next: &'a S,
        xn: &'a S,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let xns = sgate.pow_constant_vec(ctx, x, self.common.n);
        let l_0 = x; //sgate.get_laguerre_commits
        let l_last = x; //TODO
        let l_blind = x; //TODO

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
                    ));
                }
            }
            let p = permutation
                .expressions(
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
                )
                .unwrap();
            expression.extend(p);
            for i in 0..lookups.len() {
                let l = lookups[i]
                    .expressions(
                        sgate,
                        ctx,
                        &self.fixed_evals.iter().map(|ele| ele).collect(),
                        &advice_evals.iter().map(|ele| ele).collect(),
                        &instance_evals.iter().map(|ele| ele).collect(),
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

        let vanish = vanish::Evaluated::new(
            sgate,
            ctx,
            expression,
            y,
            xn,
            &self.random_commitment,
            &self.random_eval,
            self.vanish_commitments.iter().map(|ele| ele).collect(),
        );

        //vanishing.verify(expressions, y, xn)

        let queries = self
            .instance_commitments
            .iter()
            .zip(self.instance_evals.iter())
            .zip(self.advice_commitments.iter())
            .zip(self.advice_evals.iter())
            .zip(self.permutation_evaluated.iter())
            .zip(self.lookup_evaluated.iter())
            .flat_map(
                |(
                    (
                        (
                            ((instance_commitments, instance_evals), advice_commitments),
                            advice_evals,
                        ),
                        permutation,
                    ),
                    lookups,
                )| {
                    iter::empty()
                        .chain(self.instance_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(at),
                                    &instance_commitments[column],
                                    &instance_evals[query_index],
                                )
                            },
                        ))
                        .chain(self.advice_queries.iter().enumerate().map(
                            move |(query_index, &(column, at))| {
                                EvaluationQuery::new(
                                    self.rotate_omega(at),
                                    &advice_commitments[column],
                                    &advice_evals[query_index],
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
                self.fixed_queries
                    .iter()
                    .enumerate()
                    .map(|(query_index, &(column, at))| {
                        EvaluationQuery::<'a, S, P>::new(
                            self.rotate_omega(at),
                            &self.fixed_commitments[column],
                            &self.fixed_evals[query_index],
                        )
                    }),
            )
            .chain(pcommon.queries(x))
            .chain(vanish.queries(x));
        unimplemented!("get point schemas not implemented")
    }
}

impl<
        'a,
        C: Clone,
        S: Field,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, Error>,
    > SchemaGenerator<'a, C, S, P, Error> for VerifierParams<C, S, P, Error, SGate, PGate>
{
    fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        unimplemented!("get point schemas not implemented")
    }
    fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let mut proofs = self.get_point_schemas(ctx)?;
        proofs.reverse();
        let (mut w_x, mut w_g) = {
            let s = &proofs[0].s;
            let w = CommitQuery {
                c: Some(proofs[0].w),
                v: None,
            };
            (
                commit!(w),
                scalar!(proofs[0].point) * commit!(w) + s.clone(),
            )
        };
        let _ = proofs[1..].iter().map(|p| {
            let s = &p.s;
            let w = CommitQuery {
                c: Some(p.w),
                v: None,
            };
            w_x = scalar!(self.u) * w_x.clone() + commit!(w);
            w_g = scalar!(self.u) * w_g.clone() + scalar!(p.point) * commit!(w) + s.clone();
        });
        Ok(MultiOpenProof { w_x, w_g })
    }
}

impl<'a>
    VerifierParams<
        (),
        <G1Affine as CurveAffine>::ScalarExt,
        <G1Affine as CurveAffine>::CurveExt,
        (),
        FieldCode<<G1Affine as CurveAffine>::ScalarExt>,
        PointCode<G1Affine>,
    >
{
    pub fn from_transcript<
        'params,
        C: MultiMillerLoop,
        E: EncodedChallenge<C::G1Affine>,
        T: TranscriptRead<C::G1Affine, E>,
    >(
        instances: &[&[&[C::Scalar]]],
        vk: &VerifyingKey<C::G1Affine>,
        params: &'params ParamsVerifier<C>,
        _transcript: &mut T,
    ) -> Result<
        VerifierParams<
            (),
            <C::G1Affine as CurveAffine>::ScalarExt,
            <C::G1Affine as CurveAffine>::CurveExt,
            (),
            FieldCode<<C::G1Affine as CurveAffine>::ScalarExt>,
            PointCode<C::G1Affine>,
        >,
        halo2_proofs::plonk::Error,
    > {
        let instance_commitments = instances
            .iter()
            .map(|instance| {
                instance
                    .iter()
                    .map(|instance| {
                        if instance.len() > params.n as usize - (vk.cs.blinding_factors() + 1) {
                            return Err(halo2_proofs::plonk::Error::InstanceTooLarge);
                        }

                        Ok(params.commit_lagrange(instance.to_vec()))
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(VerifierParams::<
            (), // Dummy Context
            <C::G1Affine as CurveAffine>::ScalarExt,
            <C::G1Affine as CurveAffine>::CurveExt,
            (), //Error
            FieldCode<<C::G1Affine as CurveAffine>::ScalarExt>,
            PointCode<C::G1Affine>,
        > {
            gates: todo!(),
            common: todo!(),
            lookup_evaluated: todo!(),
            permutation_evaluated: todo!(),
            instance_commitments: instance_commitments,
            instance_evals: todo!(),
            instance_queries: todo!(),
            advice_commitments: todo!(),
            advice_evals: todo!(),
            advice_queries: todo!(),
            fixed_commitments: todo!(),
            fixed_evals: todo!(),
            fixed_queries: todo!(),
            permutation_commitments: todo!(),
            permutation_evals: todo!(),
            vanish_commitments: todo!(),
            random_commitment: todo!(),
            random_eval: todo!(),
            beta: todo!(),
            gamma: todo!(),
            alpha: todo!(),
            theta: todo!(),
            delta: todo!(),
            u: todo!(),
            v: todo!(),
            xi: todo!(),
            sgate: todo!(),
            pgate: todo!(),
            _ctx: todo!(),
            _error: todo!(),
        })
    }
}
