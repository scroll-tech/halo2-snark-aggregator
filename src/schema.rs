pub mod ast;
pub mod utils;
use crate::{
    arith::api::{ContextGroup, ContextRing},
    commit, eval,
};
use ast::{CommitQuery, MultiOpenProof, SchemaItem};

pub struct EvaluationProof<'a, S: Clone, P: Clone> {
    pub point: S,
    pub s: SchemaItem<'a, S, P>, // f, e pair
    pub w: &'a P,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationQuery<'a, S: Clone, P: Clone> {
    pub point: S,
    pub s: SchemaItem<'a, S, P>, // f, e pair
}

impl<'a, S: Clone, P: Clone> EvaluationQuery<'a, S, P> {
    pub fn new(point: S, c: &'a P, v: &'a S) -> Self {
        let s = CommitQuery {
            c: Some(c),
            v: Some(v),
        };
        EvaluationQuery {
            point: point,
            s: commit!(s) + eval!(s),
        }
    }
    pub fn new_from_query(point: S, s: SchemaItem<'a, S, P>) -> Self {
        EvaluationQuery { point: point, s }
    }
}

pub trait SchemaGenerator<
    'a,
    C: Clone,
    S: Clone,
    P: Clone,
    TS,
    TP,
    E,
    SGate: ContextGroup<C, S, S, TS, E> + ContextRing<C, S, S, E>,
    PGate: ContextGroup<C, S, P, TP, E>,
>
{
    fn get_point_schemas(
        &'a self,
        ctx: &mut C,
        sgate: & SGate,
        pgate: &PGate,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, E>;
    fn batch_multi_open_proofs(
        &'a self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<MultiOpenProof<'a, S, P>, E>;
}
