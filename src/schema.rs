pub mod ast;
pub mod utils;
use ast::{SchemaItem};

pub struct EvaluationProof<'a, S:Clone, P:Clone> {
  pub point: S,
  pub s: SchemaItem<'a, S, P>, // f, e pair
  pub w: P,
}

pub trait SchemaGenerator<'a, S:Clone, P:Clone> {
  fn getPointSchemas(&self) -> Vec<EvaluationProof<'a, S, P>>;
}
