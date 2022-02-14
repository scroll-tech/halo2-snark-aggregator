pub mod ast;
pub mod utils;
use ast::{SchemaItem};

pub struct PointSchema<'a, S, P> {
  point: S,
  schema: SchemaItem<'a, S, P>,
}

pub trait SchemaGenerator<'a, S, P> {
  fn getPointSchemas(&self) -> Vec<PointSchema<'a, S, P>>;
}
