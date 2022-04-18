use crate::arith::ecc::ArithEccChip;

#[derive(Clone, Debug, PartialEq)]
pub struct CommitQuery<P, S> {
    pub key: String,
    pub commitment: Option<P>,
    pub eval: Option<S>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EvaluationSchema<A: ArithEccChip> {
    Commit(CommitQuery<A::AssignedPoint, A::AssignedScalar>),
    Eval(CommitQuery<A::AssignedPoint, A::AssignedScalar>),
    Scalar(A::AssignedScalar),
    Add(Box<EvaluationSchema<A>>, Box<EvaluationSchema<A>>),
    Mul(Box<EvaluationSchema<A>>, Box<EvaluationSchema<A>>),
}

pub struct EvaluationProof<A: ArithEccChip> {
    pub point: A::AssignedScalar,
    pub s: EvaluationSchema<A>,
    pub w: A::AssignedPoint,
}

impl<A: ArithEccChip> std::ops::Add for EvaluationSchema<A> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        EvaluationSchema::Add(Box::new(self), Box::new(other))
    }
}

impl<A: ArithEccChip> std::ops::Mul for EvaluationSchema<A> {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        EvaluationSchema::Mul(Box::new(self), Box::new(other))
    }
}
