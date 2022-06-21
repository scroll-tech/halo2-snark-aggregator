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
        Box<EvaluationQuerySchema<P, S>>,
        Box<EvaluationQuerySchema<P, S>>,
    ),
    Mul(
        Box<EvaluationQuerySchema<P, S>>,
        Box<EvaluationQuerySchema<P, S>>,
    ),
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
        EvaluationQuerySchema::Add(Box::new(self), Box::new(other))
    }
}

impl<P, S> std::ops::Mul for EvaluationQuerySchema<P, S> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        EvaluationQuerySchema::Mul(Box::new(self), Box::new(other))
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

impl<P, S: Clone> EvaluationQuerySchema<P, S> {
    fn sum_scalar_array<
        Scalar: FieldExt,
        A: ArithEccChip<AssignedPoint = P, AssignedScalar = S, Scalar = Scalar>,
    >(
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        a: Vec<Option<A::AssignedScalar>>,
    ) -> Result<Option<A::AssignedScalar>, A::Error> {
        assert_ne!(a.len(), 0);

        if a.len() == 1 {
            Ok(a[0].clone())
        } else {
            let constant = a.iter().filter(|a| a.is_none()).count();
            let vars: Vec<&A::AssignedScalar> = a.iter().filter_map(|p| p.as_ref()).collect();

            if vars.len() == 0 {
                Ok(Some(
                    schip.assign_const(ctx, Scalar::from(constant as u64))?,
                ))
            } else {
                Ok(Some(schip.sum_with_constant(
                    ctx,
                    vars,
                    Scalar::from(constant as u64),
                )?))
            }
        }
    }

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
        pchip.print_debug_info(ctx, "before eval_prepare");
        let points = self.eval_prepare::<Scalar, A>(ctx, schip, one)?;

        pchip.print_debug_info(ctx, "after eval_prepare");
        let mut p_acc: Option<A::AssignedPoint> = None;
        let mut s: Option<A::AssignedScalar> = None;
        for (idx, b) in points.into_iter().enumerate() {
            //println!("eval point idx {}", idx);
            pchip.print_debug_info(ctx, "before sum_scalar_array");
            let scalar = Self::sum_scalar_array::<Scalar, A>(ctx, schip, b.2)?;

            pchip.print_debug_info(ctx, "after sum_scalar_array");
            if b.0 == "" {
                assert!(b.1.is_none());
                assert!(s.is_none());
                s = scalar;
            } else {
                assert!(b.1.is_some());
                let p = match scalar {
                    None => b.1.unwrap(),
                    Some(s) => {
                        pchip.print_debug_info(ctx, "before point scalar_mul");
                        let r = pchip.scalar_mul(ctx, &s, b.1.as_ref().unwrap())?;

                        pchip.print_debug_info(ctx, "after point scalar_mul");
                        r
                    }
                };
                p_acc = match p_acc {
                    None => Some(p),
                    Some(p_acc) => {
                        pchip.print_debug_info(ctx, "before point add");
                        let r = Some(pchip.add(ctx, &p_acc, &p)?);
                        pchip.print_debug_info(ctx, "after point add");
                        r
                    }
                }
            }

            //println!("eval done point idx {}", idx);
        }

        Ok((p_acc.unwrap(), s))
    }

    fn eval_prepare<
        Scalar: FieldExt,
        A: ArithEccChip<AssignedPoint = P, AssignedScalar = S, Scalar = Scalar>,
    >(
        self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        one: &A::AssignedScalar,
    ) -> Result<
        Vec<(
            String,
            Option<A::AssignedPoint>,
            Vec<Option<A::AssignedScalar>>,
        )>,
        A::Error,
    > {
        match self {
            EvaluationQuerySchema::Commitment(cq) => {
                Ok(vec![(cq.key, Some(cq.commitment.unwrap()), vec![None])])
            }
            EvaluationQuerySchema::Eval(cq) => {
                Ok(vec![("".to_owned(), None, vec![Some(cq.eval.unwrap())])])
            }
            EvaluationQuerySchema::Scalar(s) => Ok(vec![("".to_owned(), None, vec![Some(s)])]),
            EvaluationQuerySchema::Add(l, r) => {
                let mut res: Vec<(_, _, Vec<_>)> = vec![];
                for s in vec![l, r] {
                    for mut evalated in s.eval_prepare::<Scalar, A>(ctx, schip, one)? {
                        let found = res.iter_mut().find(|p| p.0 == evalated.0);

                        match found {
                            Some(p) => {
                                p.2.append(&mut evalated.2);
             //                   println!("EvaluationQuerySchema::skip {}", res.len());
                            }
                            None => {
                                res.push(evalated);
               //                 println!("EvaluationQuerySchema::Add to {}", res.len());
                            }
                        }
                    }
                }
                Ok(res)
            }
            EvaluationQuerySchema::Mul(l, r) => {
                let l = l.eval_prepare::<Scalar, A>(ctx, schip, one)?;
                let r = r.eval_prepare::<Scalar, A>(ctx, schip, one)?;

                let (coeff, mut base) = if l.len() == 1 && l[0].0 == "" {
                    (l.into_iter().reduce(|x, _| x).unwrap().2, r)
                } else {
                    assert!(r.len() == 1 && r[0].0 == "");
                    (r.into_iter().reduce(|x, _| x).unwrap().2, l)
                };

                let coeff: Option<A::AssignedScalar> =
                    Self::sum_scalar_array::<Scalar, A>(ctx, schip, coeff)?;
                match coeff {
                    Some(coeff) => {
                        for b in base.iter_mut() {
                            let mut scalars = vec![];
                            scalars.append(&mut b.2);
                            let scalar = Self::sum_scalar_array::<Scalar, A>(ctx, schip, scalars)?;

                            match scalar {
                                Some(scalar) => {
                                    let res = schip.mul(ctx, &coeff, &scalar)?;
                                    b.2.push(Some(res));
                                }
                                None => {
                                    b.2.push(Some(coeff.clone()));
                                }
                            }
                        }
                    }
                    _ => {}
                }

                Ok(base)
            }
        }
    }
}
