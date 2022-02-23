use crate::schema::ast::{CommitQuery, MultiOpenProof, EvaluationAST, SchemaItem};
use crate::schema::{SchemaGenerator, EvaluationProof};
use crate::arith::api::{ContextRing, ContextGroup};
use std::fmt::Debug;
use std::marker::PhantomData;
use crate::{commit, eval, scalar};
use super::{lookup, permutation};

pub struct VerifierParams <
    'a, C, S:Clone, P:Clone, Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
    pub lookup_evaluated: Vec<lookup::Evaluated<S, P>>,
    pub permutation_evaluated: Vec<permutation::Evaluated<S, P>>,
    pub instances_commits: Vec<&'a P>,
    pub instances_evals: Vec<&'a S>,
    pub advice_commits: Vec<&'a P>,
    pub advice_evals: Vec<&'a S>,
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
    fn queries(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
/*
        let queries = instance_commitments.iter()
        .zip(instance_evals.iter())
        .zip(advice_commitments.iter())
        .zip(advice_evals.iter())
        .zip(permutations_evaluated.iter())
        .zip(lookups_evaluated.iter())
        .flat_map(
            |(
                (
                    (((instance_commitments, instance_evals), advice_commitments), advice_evals),
                    permutation,
                ),
                lookups,
            )| {
                iter::empty()
                    .chain(vk.cs.instance_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            VerifierQuery::new_commitment(
                                &instance_commitments[column.index()],
                                vk.domain.rotate_omega(*x, at),
                                instance_evals[query_index],
                            )
                        },
                    ))
                    .chain(vk.cs.advice_queries.iter().enumerate().map(
                        move |(query_index, &(column, at))| {
                            VerifierQuery::new_commitment(
                                &advice_commitments[column.index()],
                                vk.domain.rotate_omega(*x, at),
                                advice_evals[query_index],
                            )
                        },
                    ))
                    .chain(permutation.queries(vk, x))
                    .chain(
                        lookups
                            .iter()
                            .flat_map(move |p| p.queries(vk, x))
                            .into_iter(),
                    )
            },
        )
*/
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



