use crate::arith::api::{ContextGroup, ContextRing, PowConstant};
use crate::{arith_in_ctx, infix2postfix};
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

pub trait RingUtils<C, S, Error> {
    fn pow_constant_vec(&self, ctx: &mut C, base: &S, exponent: u32) -> Result<Vec<S>, Error>;
}

impl<'a, C, S: Clone, Error, SGate: ContextRing<C, S, S, Error>> RingUtils<C, S, Error> for SGate {
    fn pow_constant_vec(&self, ctx: &mut C, base: &S, exponent: u32) -> Result<Vec<S>, Error> {
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

pub trait VerifySetupHelper<'a, C, S, T, Error: Debug> {
    fn get_lagrange_commits(
        &self,
        ctx: &mut C,
        xi: &S,
        xi_n: &S,
        w: &S,
        n: u32,
        l: i32,
    ) -> Result<Vec<S>, Error>;
    fn commit_instance(&self, ctx: &mut C, wits: Vec<S>, ls: Vec<S>) -> Result<S, Error>;
    fn mult_and_add(&'a self, ctx: &'a mut C, wits: Vec<S>, y: &'a S) -> Result<S, Error>;
}

impl<
        'a,
        C,
        S: Clone + Debug,
        T: FieldExt,
        Error: Debug,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    > VerifySetupHelper<'a, C, S, T, Error> for SGate
{
    fn get_lagrange_commits(
        &self,
        ctx: &mut C,
        xi: &S,
        xi_n: &S,
        w: &S,
        n: u32,
        l: i32,
    ) -> Result<Vec<S>, Error> {
        let n = &self.from_constant(ctx, T::from(n as u64))?;
        let _one = self.one(ctx)?;
        let one = &_one;
        let mut ws = vec![one.clone()];
        for i in 1..=l {
            ws.push(self.pow_constant(ctx, w, i as u32)?);
        }
        let mut pi_vec = vec![];
        for i in (-l)..=0 {
            let wi = &ws[-i as usize];
            // li_xi = (w ^ i) * (xi ^ n - 1) / (n * (xi - w ^ i))
            let li_xi = arith_in_ctx!([self, ctx](one / wi) * (xi_n - one) / (n * (xi - one / wi)))
                .unwrap();
            pi_vec.push(li_xi);
        }
        Ok(pi_vec)
    }

    fn commit_instance(&self, ctx: &mut C, wits: Vec<S>, ls: Vec<S>) -> Result<S, Error> {
        let r1 = &wits[0];
        let r2 = &ls[0];
        let mut r = arith_in_ctx!([self, ctx] r1 * r2)?;
        for (x, y) in wits.iter().zip(ls.iter()).skip(1) {
            let prev = &r;
            r = arith_in_ctx!([self, ctx] prev + (x * y))?;
        }
        Ok(r)
    }

    /* TODO, this needs optimize in circuits */
    fn mult_and_add(&'a self, ctx: &'a mut C, wits: Vec<S>, y: &'a S) -> Result<S, Error> {
        let mut wits = wits.clone();
        let mut r1 = None;
        for v in wits {
            if r1.is_none() {
                r1 = Some(v);
            } else {
                let e = r1.as_ref().unwrap();
                let v = &v;
                let r = arith_in_ctx!([self, ctx] e * y + v)?;
                r1 = Some(r);
            }
        }
        Ok(r1.unwrap())
    }
}
