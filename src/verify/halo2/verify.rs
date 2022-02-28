use crate::schema::ast::{CommitQuery, MultiOpenProof, EvaluationAST, SchemaItem};
use crate::schema::{SchemaGenerator, EvaluationProof, EvaluationQuery};
use crate::arith::api::{ContextRing, ContextGroup};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::iter;
use crate::{commit, scalar};
use super::{lookup, permutation};

pub struct VerifierParams <
    'a, C, S:Clone, P:Clone, Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
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

impl<'a, C:Clone, S:Clone, P:Clone,
    Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate:ContextGroup<C, S, P, Error>>
    VerifierParams<'a, C, S, P, Error, SGate, PGate> {
    fn rotate_omega(&self, at: usize) -> S {
        unimplemented!("rotate omega")
    }
    fn queries(
        &self,
        ctx: &mut C,
        x: &'a S,
        x_inv: &'a S,
        x_next: &'a S,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
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

impl<'a, C:Clone, S:Clone, P:Clone,
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



