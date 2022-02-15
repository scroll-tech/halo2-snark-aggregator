use halo2_proofs::{
    arithmetic::FieldExt,
};

use super::api::{
    ContextGroup,
    ContextRing,
};

pub struct FieldCode <F:FieldExt> {
  pub one: F,
  pub zero: F,
}


impl<F:FieldExt> ContextGroup<(), F, F, ()> for FieldCode<F> {
  fn add(&self, _ctx:&mut (), lhs:&F, rhs:&F) -> Result<F, ()> {
    let t = *lhs + *rhs;
    Ok(t)
  }
  fn minus(&self, _ctx:&mut (), lhs:&F, rhs:&F) -> Result<F, ()> {
    let t = *lhs - *rhs;
    Ok(t)
  }
  fn scalar_mul(&self, _ctx:&mut (), lhs:&F, rhs:&F) -> Result<F, ()> {
    let t = (*lhs) * (*rhs);
    Ok(t)
  }
  fn one(&self) -> &F {
    &self.one
  }
  fn zero(&self) -> &F {
    &self.zero
  }
  fn from_constant(&self, c: u32) -> Result<F, ()> {
    Ok(F::from(c as u64))
  }
}


