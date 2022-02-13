use crate::arith::api::{ContextRing, ContextGroup};
use std::fmt::Debug;

trait ArrayOpMul<C, S, G, Error> {
    fn mul_array(
        &self,
        ctx: &mut C,
        l: Vec<&G>,
    ) -> Result<G, Error>;
}

trait ArrayOpAdd<C, S, G, Error> {
    fn add_array(
        &self,
        ctx: &mut C,
        l: Vec<&G>,
    ) -> Result<G, Error>;
}

impl<C, S, G:Clone, Error, T:ContextRing<C, S, G, Error>> ArrayOpMul<C, S, G, Error> for T
{
    fn mul_array(
        &self,
        ctx: &mut C,
        l: Vec<&G>,
    ) -> Result<G, Error> {
        let mut base:G = (*l[0]).clone();
        for i in 1..l.len() {
            base = self.mul(ctx, &base, l[i])?;
        }
        Ok(base)
    }
}

impl<C, S, G:Clone, Error, T:ContextGroup<C, S, G, Error>> ArrayOpAdd<C, S, G, Error> for T
{
    fn add_array(
        &self,
        ctx: &mut C,
        l: Vec<&G>,
    ) -> Result<G, Error> {
        let mut base:G = l[0].clone();
        for i in 1..l.len() {
            base = self.add(ctx, &base, l[i])?;
        }
        Ok(base)
    }
}

#[derive(Clone, Debug)]
pub struct CommitQuery<'a, S, P> {
    pub c: Option<&'a P>,
    pub v: Option<&'a S>,
}

pub enum SchemeItem<'a, S, P> {
    Commit(CommitQuery<'a, S, P>),
    Eval(CommitQuery<'a, S, P>),
    Scalar(S),
    Add(Vec<SchemeItem<'a, S, P>>),
    Mul(Vec<SchemeItem<'a, S, P>>),
}

impl<S, P> std::ops::Add for SchemeItem<'_, S, P> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        match self {
            SchemeItem::<S, P>::Add(mut ls) => {
                ls.push(other);
                SchemeItem::Add(ls)
            },
            _ => SchemeItem::<S, P>::Add(vec![self, other]),
        }
    }
}

impl<S, P> std::ops::Mul for SchemeItem<'_, S, P> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        match self {
            SchemeItem::<S, P>::Mul(mut ls) => {
                ls.push(other);
                SchemeItem::Mul(ls)
            },
            _ => SchemeItem::<S, P>::Mul(vec![self, other]),
        }
    }
}

trait EvaluationAST <S, C, P, SGate, PGate, Error>
where
    SGate: ContextRing<C, S, S, Error> + ContextGroup<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>
{
    fn eval(
        &self,
        sgate: &SGate,
        pgate: &PGate,
        context: &mut C,
    ) -> Result<(Option<P>, Option<S>), Error>;
}


impl<C, S:Clone, P:Clone, Error:Debug, SGate:ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>, PGate:ContextGroup<C, S, P, Error>>
    EvaluationAST<S, C, P, SGate, PGate, Error> for SchemeItem<'_, S, P>
{
    fn eval(
        &self,
        sgate: &SGate,
        pgate: &PGate,
        context: &mut C,
    ) -> Result<(Option<P>, Option<S>), Error> {
        match self {
            SchemeItem::Commit(cq) => {
                Ok((cq.c.map(|c| c.clone()), None))
            },
            SchemeItem::Eval(cq) => {
                Ok((None, cq.v.map(|c| c.clone())))
            },

            SchemeItem::Scalar(s) => {
                Ok((None, Some (s.clone())))
            },
            SchemeItem::Add(ls) => {
                let mut cs = Vec::new();
                let mut vs = Vec::new();
                ls.iter().for_each(|val| {
                    let (c, v) = val.eval(sgate, pgate, context).unwrap();
                    c.map(|c| cs.push(c));
                    v.map(|v| vs.push(v));
                });
                let vs = vs.iter().collect::<Vec<_>>();
                let v = match vs[..] {
                    [] => None,
                    _ => Some (sgate.add_array(context, vs)?)
                };
                let cs = cs.iter().collect::<Vec<_>>();
                let c = match cs[..] {
                    [] => None,
                    _ => Some (pgate.add_array(context, cs)?)
                };
                Ok((c, v))
            }
            SchemeItem::Mul(ls) => {
                let mut cs = Vec::new();
                let mut vs = Vec::new();
                ls.iter().for_each(|val| {
                    let (c, v) = val.eval(sgate, pgate, context).unwrap();
                    c.map(|c| cs.push(c));
                    v.map(|v| vs.push(v));
                });
                let vs = vs.iter().collect::<Vec<_>>();
                let v = match vs[..] {
                    [] => None,
                    _ => Some (sgate.mul_array(context, vs)?)
                };
                let cs = cs.iter().collect::<Vec<_>>();
                match cs[..] {
                    [] => Ok((None, v)),
                    [c] => {
                        match v {
                            None => Ok((Some(c.clone()), None)),
                            Some(v) => Ok((Some(pgate.scalar_mul(context, &v, c)?), None))
                        }
                    },
                    _ => unreachable!()
                }
            }
        }
    }
}

#[macro_export]
macro_rules! commit {
    ($x:expr) => {
        SchemeItem::<C>::Commit(($x.clone()))
    };
}
#[macro_export]
macro_rules! eval {
    ($x:expr) => {
        SchemeItem::<C>::Eval(($x.clone()))
    };
}
#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        SchemeItem::<C>::Scalar($x.clone())
    };
}

/*
pub struct SingleOpeningProof<C: CurveAffine> {
    pub w: AssignedPoint<C::ScalarExt>,
    pub z: AssignedValue<C::ScalarExt>,
    pub f: AssignedPoint<C::ScalarExt>,
    pub eval: AssignedValue<C::ScalarExt>,
}

// (g^e + w_g, [1]) and (w_x, [x])
pub struct MultiOpeningProof<C: CurveAffine> {
    pub w_x: AssignedPoint<C::ScalarExt>,
    pub w_g: AssignedPoint<C::ScalarExt>,
    pub f: AssignedPoint<C::ScalarExt>,
    pub e: AssignedValue<C::ScalarExt>,
}
*/
