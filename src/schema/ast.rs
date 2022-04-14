use crate::arith::api::{ContextGroup, ContextRing};
use std::fmt::Debug;

pub trait ArrayOpMul<C, S, G, Error> {
    fn mul_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error>;
}

pub trait ArrayOpAdd<C, S, G, T, Error> {
    fn add_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error>;
}

impl<C, S, G: Clone, Error, Gate: ContextRing<C, S, G, Error>> ArrayOpMul<C, S, G, Error> for Gate {
    fn mul_array(&self, ctx: &mut C, l: Vec<&G>) -> Result<G, Error> {
        let mut base: G = (*l[0]).clone();
        for i in 1..l.len() {
            base = self.mul(ctx, &base, l[i])?;
        }
        Ok(base)
    }
}

impl<C, S, T, G: Clone, Error, Gate: ContextGroup<C, S, G, T, Error>> ArrayOpAdd<C, S, G, T, Error>
    for Gate
{
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
    pub key: String,
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

pub trait EvaluationAST<S, C, P, TS, TP, SGate, PGate, Error>
where
    SGate: ContextRing<C, S, S, Error> + ContextGroup<C, S, S, TS, Error>,
    PGate: ContextGroup<C, S, P, TP, Error>,
{
    fn eval(
        &self,
        sgate: &SGate,
        pgate: &PGate,
        context: &mut C,
    ) -> Result<(Option<P>, Option<S>), Error>;
}

impl<S: Clone + Debug, P: Clone + Debug> SchemaItem<'_, S, P> {
    fn _eval<
        'a,
        C,
        TS,
        Error: Debug,
        SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
    >(
        &'a self,
        sgate: &SGate,
        context: &mut C,
        one: &S,
    ) -> Result<Vec<(&'a str, Option<&'a CommitQuery<S, P>>, Option<S>)>, Error> {
        match self {
            SchemaItem::Commit(cq) => Ok(vec![(&cq.key, Some(cq), None)]),
            SchemaItem::Eval(cq) => Ok(vec![("", None, Some(cq.v.unwrap().clone()))]),
            SchemaItem::Scalar(s) => Ok(vec![("", None, Some(s.clone()))]),
            SchemaItem::Add(ls) => {
                let mut els: Vec<(_, _, Vec<_>)> = vec![];
                for s in ls {
                    let res = s._eval(sgate, context, one)?;
                    for r in res {
                        let mut found = None;
                        for p in els.iter_mut() {
                            if p.0 == r.0 {
                                found = Some(&mut p.2);
                            }
                        }

                        match found {
                            Some(p) => p.push(r.2),
                            None => els.push((r.0, r.1, vec![r.2])),
                        }
                    }
                }

                let mut res = vec![];
                for e in els {
                    assert!(!e.2.is_empty());
                    let e2 = if e.2.len() == 1 {
                        e.2.into_iter().nth(0).unwrap()
                    } else {
                        Some(sgate.add_array(
                            context,
                            e.2.iter().map(|x| x.as_ref().unwrap_or(one)).collect(),
                        )?)
                    };
                    res.push((e.0, e.1, e2));
                }

                Ok(res)
            }
            SchemaItem::Mul(ls) => {
                let mut s_vec = vec![];
                let mut p_vec = None;
                for s in ls {
                    let res = s._eval(sgate, context, one)?;

                    if res.len() == 1 && res[0].1.is_none() {
                        for s in res {
                            s.2.map(|s| s_vec.push(s.clone()));
                        }
                    } else {
                        assert!(p_vec.is_none());
                        p_vec = Some(res);
                    }
                }

                if s_vec.is_empty() {
                    Ok(p_vec.unwrap())
                } else {
                    let s = sgate.mul_array(context, s_vec.iter().collect())?;
                    p_vec.map_or(Ok(vec![("", None, Some(s.clone()))]), |p_vec| {
                        p_vec
                            .into_iter()
                            .map(|p| -> Result<_, Error> {
                                let p2 = match p.2 {
                                    Some(p2) => Some(sgate.mul(context, &p2, &s)?),
                                    None => Some(s.clone()),
                                };
                                Ok((p.0, p.1, p2))
                            })
                            .collect()
                    })
                }
            }
        }
    }
}

impl<
        C,
        S: Clone + Debug,
        P: Clone + Debug,
        TS,
        TP,
        Error: Debug,
        SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, TP, Error>,
    > EvaluationAST<S, C, P, TS, TP, SGate, PGate, Error> for SchemaItem<'_, S, P>
{
    fn eval(&self, sgate: &SGate, pgate: &PGate, context: &mut C) -> Result<(Option<P>, Option<S>), Error> {
        let one = sgate.one(context)?;
        let p_vec = self._eval(sgate, context, &one)?;
        let mut acc = None;
        let mut s = None;

        for p in p_vec {
            let base = p.1;
            let scalar = p.2;
            match &base {
                Some(base) => {
                    let p_res = scalar.map_or_else(
                        || Ok(base.c.unwrap().clone()),
                        |scalar| pgate.scalar_mul(context, &scalar, base.c.unwrap()),
                    )?;
                    acc = match acc {
                        Some(acc) => Some(pgate.add(context, &acc, &p_res)?),
                        None => Some(p_res),
                    }
                }
                None => {
                    s = scalar;
                }
            };
        }

        Ok((acc, s))
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
