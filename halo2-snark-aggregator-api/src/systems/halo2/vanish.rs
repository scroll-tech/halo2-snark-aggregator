use crate::arith::ast::FieldArithHelper;
use crate::{
    arith::{ecc::ArithEccChip, field::ArithFieldChip},
    arith_ast,
};

use super::evaluation::{CommitQuery, EvaluationQuery, EvaluationQuerySchema};

pub struct Evaluated<'a, A: ArithEccChip> {
    key: String,
    h_commitment: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    expected_h_eval: A::AssignedScalar,
    random_commitment: &'a A::AssignedPoint,
    random_eval: &'a A::AssignedScalar,
}

impl<'a, A: ArithEccChip> Evaluated<'a, A> {
    pub fn new(
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        expressions: Vec<A::AssignedScalar>,
        y: &A::AssignedScalar,
        xn: &A::AssignedScalar,
        random_commitment: &'a A::AssignedPoint,
        random_eval: &'a A::AssignedScalar,
        expect_commitments: &Vec<A::AssignedPoint>,
        one: &A::AssignedScalar,
        key: String,
    ) -> Result<Evaluated<'a, A>, A::Error> {
        let expected_h_eval = &schip.mul_add_accumulate(ctx, expressions.iter().collect(), y)?;
        let expected_h_eval = arith_ast!((expected_h_eval / (xn - one))).eval(ctx, schip)?;

        let h_commitment = expect_commitments
            .iter()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                EvaluationQuerySchema::Commitment(CommitQuery {
                    key: format!("{}_h_commitment{}", key.clone(), i),
                    commitment: Some(c.clone()),
                    eval: None as Option<A::AssignedScalar>,
                })
            })
            .reduce(|acc, commitment| EvaluationQuerySchema::Scalar(xn.clone()) * acc + commitment)
            .unwrap();

        Ok(Evaluated {
            key,
            h_commitment,
            expected_h_eval,
            random_eval,
            random_commitment,
        })
    }

    pub fn queries(&self, x: &A::AssignedScalar) -> Vec<EvaluationQuery<A>> {
        vec![
            EvaluationQuery::new_from_query(
                0,
                x.clone(),
                self.h_commitment.clone()
                    + EvaluationQuerySchema::Scalar(self.expected_h_eval.clone()),
            ),
            EvaluationQuery::new(
                0,
                format!("{}_random_commitment", self.key),
                x.clone(),
                self.random_commitment.clone(),
                self.random_eval.clone(),
            ),
        ]
    }
}
