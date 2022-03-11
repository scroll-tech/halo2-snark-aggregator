pub mod ast;
pub mod utils;
use crate::{commit, eval};
use ast::{CommitQuery, MultiOpenProof, SchemaItem};

pub struct EvaluationProof<'a, S: Clone, P: Clone> {
    pub point: S,
    pub s: SchemaItem<'a, S, P>, // f, e pair
    pub w: &'a P,
}

#[derive(Debug)]
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

pub trait SchemaGenerator<'a, C, S: Clone, P: Clone, E> {
    fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, E>;
    fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, E>;
}
