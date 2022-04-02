use halo2_proofs::arithmetic::FieldExt;

use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::EvaluationQuery;

use crate::schema::ast::{CommitQuery, SchemaItem};

use crate::schema::utils::VerifySetupHelper;

use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, scalar};
use std::fmt::Debug;
use std::iter;
use std::marker::PhantomData;

pub struct Evaluated<'a, C, S: Clone, P: Clone, Error> {
    h_commitment: SchemaItem<'a, S, P>, // calculated
    expected_h_eval: S,                 // calculated
    random_commitment: &'a P,           // from input
    random_eval: &'a S,                 // from input
    _m: PhantomData<(C, Error)>,
}

impl<'a, C, S: Clone + Debug, P: Clone + Debug, Error: Debug> Evaluated<'a, C, S, P, Error> {
    pub(in crate::verify::halo2) fn new<T: FieldExt>(
        sgate: &(impl ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>),
        ctx: &mut C,
        expressions: Vec<S>,
        y: &'a S,
        xn: &'a S,
        random_commitment: &'a P,
        random_eval: &'a S,
        expect_commitments: Vec<&'a P>,
    ) -> Result<Evaluated<'a, C, S, P, Error>, Error> {
        let one = &sgate.one(ctx).unwrap();
        let expected_h_eval = &sgate.mult_and_add(ctx, expressions, y)?;
        let expected_h_eval = arith_in_ctx!([sgate, ctx] expected_h_eval / (xn - one))?;

        let h_commitment: SchemaItem<S, P> = expect_commitments
            .iter()
            .rev()
            .enumerate()
            .map(|(i, c)| {
                commit!(CommitQuery {
                    key: format!("h{}", i),
                    c: Some(c.clone()),
                    v: None,
                })
            })
            .reduce(|acc, commitment| scalar!(xn) * acc + commitment)
            .unwrap();
        Ok(Evaluated {
            h_commitment,
            expected_h_eval,
            random_eval,
            random_commitment,
            _m: PhantomData,
        })
    }

    pub(in crate::verify::halo2) fn queries(&self, x: &'a S) -> Vec<EvaluationQuery<'a, S, P>> {
        iter::empty()
            .chain(Some(EvaluationQuery::new_from_query(
                x.clone(),
                self.h_commitment.clone() + scalar!(&self.expected_h_eval),
            )))
            .chain(Some(EvaluationQuery::new(
                x.clone(),
                "random".to_string(),
                self.random_commitment,
                self.random_eval,
            )))
            .collect()
    }
}
