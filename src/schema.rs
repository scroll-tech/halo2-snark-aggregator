pub mod ast;
pub mod utils;
use ast::{SchemaItem, MultiOpenProof};
use crate::arith::api:: {ContextGroup, ContextRing};
use std::fmt::Debug;

pub struct EvaluationProof<'a, S:Clone, P:Clone> {
  pub point: S,
  pub s: SchemaItem<'a, S, P>, // f, e pair
  pub w: &'a P,
}

pub trait CurveArith<C, S:Clone, P:Clone, Error:Debug> {
    type ScalarGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>;
    type PointGate: ContextGroup<C, S, P, Error>;
    fn pgate(&self) -> Result<&Self::PointGate, Error>;
    fn sgate(&self) -> Result<&Self::ScalarGate, Error>;
}

pub trait SchemaGenerator<'a, C, S:Clone, P:Clone, E> {
  fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, E>;
  fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, E>;
}



