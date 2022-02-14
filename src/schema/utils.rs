use crate::arith::api::{ContextRing, ContextGroup, PowConstant};

/*
pub trait GetCommonSetup <C, S, P, Error> {
  fn get_common_setup (l: u32, n: u32) -> PlonkCommonSetup<S, P> {
  }
}
*/

pub trait RingUtils <C, S, Error> {
    fn pow_constant_vec(
        &self,
        ctx: &mut C,
        base: &S,
        exponent: u32,
    ) -> Result<Vec<S>, Error>;
}

impl<'a, C, S:Clone, Error, SGate: ContextRing<C, S, S, Error>> RingUtils<C, S, Error> for SGate {
    fn pow_constant_vec(
        &self,
        ctx: &mut C,
        base: &S,
        exponent: u32,
    ) -> Result<Vec<S>, Error> {
        let mut ret = vec![];
        let mut curr = base.clone();
        for _ in 0..exponent {
            let next = self.pow_constant(ctx, &curr, 2)?;
            ret.push(curr);
            curr = next;
        }
        ret.push(curr);
        Ok(ret)
    }
}




