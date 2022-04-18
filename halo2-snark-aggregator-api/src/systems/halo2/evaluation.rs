use crate::arith::ecc::ArithEccChip;

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

pub struct EvaluationProof<A: ArithEccChip> {
    pub point: A::AssignedScalar,
    pub s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    pub w: A::AssignedPoint,
}

#[derive(Clone, Debug, PartialEq)]
pub struct EvaluationQuery<A: ArithEccChip> {
    pub point: A::AssignedScalar,
    pub s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
}

impl<A: ArithEccChip> EvaluationQuery<A> {
    pub fn new(
        key: String,
        point: A::AssignedScalar,
        commitment: A::AssignedPoint,
        eval: A::AssignedScalar,
    ) -> Self {
        let s = CommitQuery {
            key,
            commitment: Some(commitment),
            eval: Some(eval),
        };

        EvaluationQuery {
            point,
            s: EvaluationQuerySchema::Commitment(s.clone()) + EvaluationQuerySchema::Eval(s),
        }
    }

    pub fn new_from_query(
        point: A::AssignedScalar,
        s: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    ) -> Self {
        EvaluationQuery { point, s }
    }
}
