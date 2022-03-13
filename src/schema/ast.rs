use crate::arith::api::{ContextGroup, ContextRing};
use std::fmt::Debug;

trait ArrayOpMul<C, S, G, Error> {
    fn mul_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error>;
}

trait ArrayOpAdd<C, S, G, Error> {
    fn add_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error>;
}

impl<C, S, G: Clone, Error, T: ContextRing<C, S, G, Error>> ArrayOpMul<C, S, G, Error> for T {
    fn mul_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error> {
        let mut base: G = (*l[0]).clone();
        for i in 1..l.len() {
            base = self.mul(ctx, &base, l[i])?;
        }
        Ok(base)
    }
}

impl<C, S, G: Clone, Error, T: ContextGroup<C, S, G, Error>> ArrayOpAdd<C, S, G, Error> for T {
    fn add_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error> {
        let mut base: G = l[0].clone();
        for i in 1..l.len() {
            base = self.add(ctx, &base, l[i])?;
        }
        Ok(base)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CommitQuery<'a, S: Clone, P: Clone> {
    pub c: Option<&'a P>,
    pub v: Option<&'a S>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SchemaItem<'a, S: Clone, P: Clone> {
    Commit(CommitQuery<'a, S, P>),
    Eval(CommitQuery<'a, S, P>),
    Scalar(S),
    Add(Vec<SchemaItem<'a, S, P>>),
    Mul(Vec<SchemaItem<'a, S, P>>),
}

impl<S: Clone, P: Clone> std::ops::Add for SchemaItem<'_, S, P> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        match self {
            SchemaItem::<S, P>::Add(mut ls) => {
                ls.push(other);
                SchemaItem::Add(ls)
            }
            _ => SchemaItem::<S, P>::Add(vec![self, other]),
        }
    }
}

impl<S: Clone, P: Clone> std::ops::Mul for SchemaItem<'_, S, P> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        match self {
            SchemaItem::<S, P>::Mul(mut ls) => {
                ls.push(other);
                SchemaItem::Mul(ls)
            }
            _ => SchemaItem::<S, P>::Mul(vec![self, other]),
        }
    }
}

pub trait EvaluationAST<S, C, P, SGate, PGate, Error>
where
    SGate: ContextRing<C, S, S, Error> + ContextGroup<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
{
    fn eval(
        &self,
        sgate: &SGate,
        pgate: &PGate,
        context: &mut C,
    ) -> Result<(Option<P>, Option<S>), Error>;
}

impl<
        C,
        S: Clone,
        P: Clone,
        Error: Debug,
        SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, Error>,
    > EvaluationAST<S, C, P, SGate, PGate, Error> for SchemaItem<'_, S, P>
{
    fn eval(
        &self,
        sgate: &SGate,
        pgate: &PGate,
        context: &mut C,
    ) -> Result<(Option<P>, Option<S>), Error> {
        match self {
            SchemaItem::Commit(cq) => Ok((cq.c.map(|c| c.clone()), None)),
            SchemaItem::Eval(cq) => Ok((None, cq.v.map(|c| c.clone()))),

            SchemaItem::Scalar(s) => Ok((None, Some(s.clone()))),
            SchemaItem::Add(ls) => {
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
                    _ => Some(sgate.add_array(context, vs)?),
                };
                let cs = cs.iter().collect::<Vec<_>>();
                let c = match cs[..] {
                    [] => None,
                    _ => Some(pgate.add_array(context, cs)?),
                };
                Ok((c, v))
            }
            SchemaItem::Mul(ls) => {
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
                    _ => Some(sgate.mul_array(context, vs)?),
                };
                let cs = cs.iter().collect::<Vec<_>>();
                match cs[..] {
                    [] => Ok((None, v)),
                    [c] => match v {
                        None => Ok((Some(c.clone()), None)),
                        Some(v) => Ok((Some(pgate.scalar_mul(context, &v, c)?), None)),
                    },
                    _ => unreachable!(),
                }
            }
        }
    }
}

#[macro_export]
macro_rules! commit {
    ($x:expr) => {
        SchemaItem::<S, P>::Commit($x.clone())
    };
}

#[macro_export]
macro_rules! eval {
    ($x:expr) => {
        SchemaItem::<S, P>::Eval($x.clone())
    };
}

#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        SchemaItem::<S, P>::Scalar($x.clone())
    };
}

// (g^e + w_g, [1]) and (w_x, [x])
pub struct MultiOpenProof<'a, S: Clone, P: Clone> {
    pub w_x: SchemaItem<'a, S, P>,
    pub w_g: SchemaItem<'a, S, P>,
}
