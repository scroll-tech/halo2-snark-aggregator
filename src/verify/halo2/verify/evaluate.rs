use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};
use crate::{arith::api::{ContextGroup, ContextRing}, arith_in_ctx, infix2postfix};

pub trait Evaluable<
    C,
    S,
    T,
    Error,
    SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
        zero: &S,
    ) -> Result<S, Error>;
}

impl<
        C,
        S: Clone,
        T: FieldExt,
        Error,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    > Evaluable<C, S, T, Error, SGate> for Expression<S>
{
    fn ctx_evaluate(
        &self,
        sgate: &SGate,
        ctx: &mut C,
        fixed: &impl Fn(usize) -> S,
        advice: &impl Fn(usize) -> S,
        instance: &impl Fn(usize) -> S,
        zero: &S,
    ) -> Result<S, Error> {
        let res = match self {
            Expression::Constant(scalar) => scalar.clone(),
            Expression::Selector(_selector) => {
                panic!("virtual selectors are removed during optimization")
            }
            Expression::Fixed {
                query_index,
                column_index: _,
                rotation: _,
            } => fixed(*query_index),
            Expression::Advice {
                query_index,
                column_index: _,
                rotation: _,
            } => advice(*query_index),
            Expression::Instance {
                query_index,
                column_index: _,
                rotation: _,
            } => instance(*query_index),
            Expression::Negated(a) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                arith_in_ctx!([sgate, ctx] zero - a)?
            }
            Expression::Sum(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                arith_in_ctx!([sgate, ctx] a + b)?
            }
            Expression::Product(a, b) => {
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                let b = &b.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                arith_in_ctx!([sgate, ctx] a * b)?
            }
            Expression::Scaled(a, f) => {
                let f = &f;
                let a = &a.ctx_evaluate(sgate, ctx, fixed, advice, instance, zero)?;
                arith_in_ctx!([sgate, ctx] f * a)?
            }
        };

        Ok(res)
    }
}