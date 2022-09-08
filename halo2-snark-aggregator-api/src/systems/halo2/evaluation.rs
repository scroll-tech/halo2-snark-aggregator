use halo2_proofs::arithmetic::FieldExt;

use crate::arith::{common::ArithCommonChip, ecc::ArithEccChip, field::ArithFieldChip};

#[derive(Clone, Debug, PartialEq)]
pub struct CommitQuery<P, S> {
    pub key: String,
    pub commitment: Option<P>,
    pub eval: Option<S>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EvaluationQuerySchema<P, S> {
    Commitment(CommitQuery<P, S>),
    Eval(CommitQuery<P, S>),
    Scalar(S),
    Add(
        Box<(EvaluationQuerySchema<P, S>, bool)>,
        Box<(EvaluationQuerySchema<P, S>, bool)>,
    ),
    Mul(
        Box<(EvaluationQuerySchema<P, S>, bool)>,
        Box<(EvaluationQuerySchema<P, S>, bool)>,
    ),
}

impl<P, S> EvaluationQuerySchema<P, S> {
    pub fn has_commitment(&self) -> bool {
        match self {
            EvaluationQuerySchema::Commitment(_) => true,
            EvaluationQuerySchema::Eval(_) => false,
            EvaluationQuerySchema::Scalar(_) => false,
            EvaluationQuerySchema::Add(a, b) => a.1 || b.1,
            EvaluationQuerySchema::Mul(a, b) => a.1 || b.1,
        }
    }
}

#[macro_export]
macro_rules! commit {
    ($x:expr) => {
        EvaluationQuerySchema::Commitment($x.clone())
    };
}

#[macro_export]
macro_rules! eval {
    ($x:expr) => {
        EvaluationQuerySchema::Eval($x.clone())
    };
}

#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        EvaluationQuerySchema::Scalar($x.clone())
    };
}

impl<P, S> std::ops::Add for EvaluationQuerySchema<P, S> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let l_has_commitment = self.has_commitment();
        let r_has_commitment = other.has_commitment();
        EvaluationQuerySchema::Add(
            Box::new((self, l_has_commitment)),
            Box::new((other, r_has_commitment)),
        )
    }
}

impl<P, S> std::ops::Mul for EvaluationQuerySchema<P, S> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let l_has_commitment = self.has_commitment();
        let r_has_commitment = other.has_commitment();
        EvaluationQuerySchema::Mul(
            Box::new((self, l_has_commitment)),
            Box::new((other, r_has_commitment)),
        )
    }
}

pub struct EvaluationProof<'a, A: ArithEccChip> {
    pub point: A::AssignedScalar,
    pub s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    pub w: &'a A::AssignedPoint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationQuery<A: ArithEccChip> {
    pub point: A::AssignedScalar,
    pub rotation: i32,
    pub s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
}

impl<A: ArithEccChip> EvaluationQuery<A> {
    pub fn new(
        rotation: i32,
        commitment_key: String,
        point: A::AssignedScalar,
        commitment: A::AssignedPoint,
        eval: A::AssignedScalar,
    ) -> Self {
        let s = CommitQuery {
            key: commitment_key,
            commitment: Some(commitment),
            eval: Some(eval),
        };

        EvaluationQuery {
            point,
            rotation,
            s: EvaluationQuerySchema::Commitment(s.clone()) + EvaluationQuerySchema::Eval(s),
        }
    }

    pub fn new_from_query(
        rotation: i32,
        point: A::AssignedScalar,
        s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    ) -> Self {
        EvaluationQuery { rotation, point, s }
    }
}

impl<P: Clone, S: Clone> EvaluationQuerySchema<P, S> {
    pub fn eval<
        Scalar: FieldExt,
        A: ArithEccChip<AssignedPoint = P, AssignedScalar = S, Scalar = Scalar>,
    >(
        self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        pchip: &A,
        one: &A::AssignedScalar,
    ) -> Result<(A::AssignedPoint, Option<A::AssignedScalar>), A::Error> {
        let points = self.eval_prepare::<Scalar, A>(ctx, schip, one, None)?;
        let s = points
            .iter()
            .find(|b| b.0 == "")
            .map(|b| b.2.as_ref().unwrap().clone());
        let p_wo_scalar = points
            .iter()
            .filter_map(|b| if b.2.is_none() { b.1.clone() } else { None })
            .collect::<Vec<_>>();
        let (p_l, s_l) = points
            .into_iter()
            .filter_map(|(_, p, s)| p.and_then(|p| s.and_then(|s| Some((p, s)))))
            .unzip();
        let mut acc = pchip.multi_exp(ctx, p_l, s_l)?;
        for p in p_wo_scalar {
            acc = pchip.add(ctx, &acc, &p)?;
        }

        Ok((acc, s))
    }

    fn eval_prepare<
        Scalar: FieldExt,
        A: ArithEccChip<AssignedPoint = P, AssignedScalar = S, Scalar = Scalar>,
    >(
        self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        one: &A::AssignedScalar,
        scalar: Option<A::AssignedScalar>,
    ) -> Result<Vec<(String, Option<A::AssignedPoint>, Option<A::AssignedScalar>)>, A::Error> {
        match self {
            EvaluationQuerySchema::Commitment(cq) => {
                Ok(vec![(cq.key, Some(cq.commitment.unwrap()), scalar)])
            }
            EvaluationQuerySchema::Eval(cq) => {
                let e = match scalar {
                    Some(s) => schip.mul(ctx, &s, &cq.eval.unwrap())?,
                    None => cq.eval.unwrap(),
                };
                Ok(vec![("".to_owned(), None, Some(e))])
            }
            EvaluationQuerySchema::Scalar(s) => {
                let s = match scalar {
                    Some(scalar) => schip.mul(ctx, &s, &scalar)?,
                    None => s,
                };
                Ok(vec![("".to_owned(), None, Some(s))])
            }
            EvaluationQuerySchema::Add(l, r) => {
                if !l.1 && !r.1 {
                    let l = l.0.eval_prepare::<Scalar, A>(ctx, schip, one, None)?;
                    let r = r.0.eval_prepare::<Scalar, A>(ctx, schip, one, None)?;
                    assert!(l.len() == 1);
                    assert!(r.len() == 1);
                    let sum =
                        schip.add(ctx, l[0].2.as_ref().unwrap(), &r[0].2.as_ref().unwrap())?;
                    let sum = match scalar {
                        Some(scalar) => schip.mul(ctx, &scalar, &sum)?,
                        None => sum,
                    };
                    Ok(vec![("".to_owned(), None, Some(sum))])
                } else {
                    let mut res: Vec<(_, _, Option<_>)> = vec![];
                    for s in vec![l, r] {
                        for evalated in
                            s.0.eval_prepare::<Scalar, A>(ctx, schip, one, scalar.clone())?
                        {
                            let found = res.iter_mut().find(|p| p.0 == evalated.0);

                            match found {
                                Some(p) => {
                                    let s = schip.add(
                                        ctx,
                                        p.2.as_ref().unwrap_or(one),
                                        evalated.2.as_ref().unwrap_or(one),
                                    )?;
                                    p.2 = Some(s);
                                }
                                None => {
                                    res.push(evalated);
                                }
                            }
                        }
                    }
                    Ok(res)
                }
            }
            EvaluationQuerySchema::Mul(l, r) => {
                let (s, rem) = if !l.1 {
                    let s = l.0.eval_prepare::<Scalar, A>(ctx, schip, one, None)?;
                    let rem = r.0;
                    (s, rem)
                } else {
                    let s = r.0.eval_prepare::<Scalar, A>(ctx, schip, one, None)?;
                    let rem = l.0;
                    (s, rem)
                };

                assert_eq!(s.len(), 1);

                let s = s[0].2.clone();
                let s = match scalar {
                    Some(scalar) => schip.mul(ctx, &scalar, s.as_ref().unwrap())?,
                    None => s.unwrap(),
                };

                rem.eval_prepare::<Scalar, A>(ctx, schip, one, Some(s))
            }
        }
    }

    pub fn estimate(&self, scalar: Option<()>) -> usize {
        match self {
            EvaluationQuerySchema::Commitment(_) => 1,
            EvaluationQuerySchema::Eval(_) => match scalar {
                Some(_) => 1,
                None => 0,
            },
            EvaluationQuerySchema::Scalar(_) => match scalar {
                Some(_) => 1,
                None => 0,
            },
            EvaluationQuerySchema::Add(l, r) => {
                if !l.1 && !r.1 {
                    let l = l.0.estimate(None);
                    let r = r.0.estimate(None);
                    match scalar {
                        Some(_) => l + r + 1,
                        None => l + r,
                    }
                } else {
                    let mut est = 0;
                    for s in vec![l, r] {
                        est += s.0.estimate(scalar.clone())
                    }
                    est
                }
            }
            EvaluationQuerySchema::Mul(l, r) => {
                if !l.1 {
                    r.0.estimate(Some(()))
                } else {
                    l.0.estimate(Some(()))
                }
            }
        }
    }
}
