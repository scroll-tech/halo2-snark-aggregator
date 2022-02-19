pub mod ast;
pub mod utils;
use ast::{SchemaItem, MultiOpenProof};

pub struct EvaluationProof<'a, S:Clone, P:Clone> {
  pub point: S,
  pub s: SchemaItem<'a, S, P>, // f, e pair
  pub w: &'a P,
}

pub trait SchemaGenerator<'a, C, S:Clone, P:Clone, E> {
  fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, E>;
  fn batch_multi_open_proofs(&self, ctx: &mut C) -> Result<MultiOpenProof<'a, S, P>, E>;
}
