pub mod ast;
pub mod utils;
use ast::{SchemaItem};

pub struct EvaluationProof<'a, S:Clone, P:Clone> {
  pub point: S,
  pub s: SchemaItem<'a, S, P>, // f, e pair
  pub w: P,
}

pub trait SchemaGenerator<'a, C, S:Clone, P:Clone, E> {
  fn getPointSchemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, E>;
}
