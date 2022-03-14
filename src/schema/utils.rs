use crate::arith::api::{ContextGroup, ContextRing, PowConstant};
use crate::{arith_in_ctx, infix2postfix};
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

pub trait VerifySetupHelper<'a, C, S, Error: Debug> {
    fn get_lagrange_commits(
        &self,
        ctx: &mut C,
        xi: &S,
        xi_n: &S,
        w: &S,
        n: u32,
        l: u32,
    ) -> Result<Vec<S>, Error>;
    fn commit_instance(&self, ctx: &mut C, wits: Vec<S>, ls: Vec<S>) -> Result<S, Error>;
    fn mult_and_add(
        &'a self,
        ctx: &'a mut C,
        wits: impl Iterator<Item = &'a S> + Clone,
        y: &'a S,
    ) -> S;
}

impl<
        'a,
        C,
        S: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    > VerifySetupHelper<'a, C, S, Error> for SGate
{
    fn get_lagrange_commits(
        &self,
        ctx: &mut C,
        xi: &S,
        xi_n: &S,
        w: &S,
        n: u32,
        l: u32,
    ) -> Result<Vec<S>, Error> {
        let n = &self.from_constant(ctx, n)?;
        let _one = self.one(ctx)?;
        let one = &_one;
        let ws = self.pow_constant_vec(ctx, w, l)?;
        let mut pi_vec = vec![];
        for i in 0..l {
            let wi = &ws[i as usize];
            // li_xi = (w ^ i) * (xi ^ n - 1) / (n * (xi - w ^ i))
            let li_xi = arith_in_ctx!([self, ctx] wi * (xi_n - one) / (n * (xi - wi))).unwrap();
            pi_vec.push(li_xi);
        }
        Ok(pi_vec)
    }

    fn commit_instance(&self, ctx: &mut C, wits: Vec<S>, ls: Vec<S>) -> Result<S, Error> {
        let r1 = &wits[0];
        let r2 = &ls[0];
        let mut r = arith_in_ctx!([self, ctx] r1 * r2)?;
        wits.iter().zip(ls.iter()).skip(1).map(|(x, y)| {
            let prev = &r;
            r = arith_in_ctx!([self, ctx] prev + (x * y)).unwrap();
        });
        Ok(r)
    }

    /* TODO, this needs optimize in circuits */
    fn mult_and_add(
        &'a self,
        ctx: &'a mut C,
        wits: impl Iterator<Item = &'a S> + Clone,
        y: &'a S,
    ) -> S {
        let mut wits = wits.clone();
        let r1 = wits.next().unwrap().clone();
        wits.fold(r1, |e, v| {
            let e = &e;
            arith_in_ctx!([self, ctx] e * y + v).unwrap()
        })
    }
}
