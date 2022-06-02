use crate::arith::ast::FieldArithHelper;
use crate::{arith::ecc::ArithEccChip, arith_ast};
use halo2_proofs::plonk::Expression;
pub trait Evaluable<A: ArithEccChip> {
    fn chip_evaluate(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        fixed: &impl Fn(usize) -> A::AssignedScalar,
        advice: &impl Fn(usize) -> A::AssignedScalar,
        instance: &impl Fn(usize) -> A::AssignedScalar,
        zero: &A::AssignedScalar,
    ) -> Result<A::AssignedScalar, A::Error>;
}

impl<A: ArithEccChip> Evaluable<A> for Expression<A::AssignedScalar> {
    fn chip_evaluate(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        fixed: &impl Fn(usize) -> A::AssignedScalar,
        advice: &impl Fn(usize) -> A::AssignedScalar,
        instance: &impl Fn(usize) -> A::AssignedScalar,
        zero: &A::AssignedScalar,
    ) -> Result<A::AssignedScalar, A::Error> {
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
                let a = &Evaluable::<A>::chip_evaluate(
                    a.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                arith_ast!(zero - a).eval(ctx, schip)?
            }
            Expression::Sum(a, b) => {
                let a = &Evaluable::<A>::chip_evaluate(
                    a.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                let b = &Evaluable::<A>::chip_evaluate(
                    b.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                arith_ast!(a + b).eval(ctx, schip)?
            }
            Expression::Product(a, b) => {
                let a = &Evaluable::<A>::chip_evaluate(
                    a.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                let b = &Evaluable::<A>::chip_evaluate(
                    b.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                arith_ast!((a * b)).eval(ctx, schip)?
            }
            Expression::Scaled(a, f) => {
                let a = &Evaluable::<A>::chip_evaluate(
                    a.as_ref(),
                    ctx,
                    schip,
                    fixed,
                    advice,
                    instance,
                    zero,
                )?;
                arith_ast!((f * a)).eval(ctx, schip)?
            }
        };

        Ok(res)
    }
}
