use super::config::{MUL_COLUMNS, VAR_COLUMNS};
use crate::{
    gates::base_gate::{
        AssignedCondition, AssignedValue, BaseGate, BaseGateConfig, BaseGateOps, Context,
        ValueSchema,
    },
    pair,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

pub type FiveColumnBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FiveColumnBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;

impl<N: FieldExt> BaseGateOps<N> for FiveColumnBaseGate<N> {
    fn var_columns(&self) -> usize {
        self.var_columns()
    }

    fn mul_columns(&self) -> usize {
        self.mul_columns()
    }

    fn one_line(
        &self,
        ctx: &mut Context<'_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.one_line(ctx, base_coeff_pairs, constant, mul_next_coeffs)
    }

    fn bisec(
        &self,
        ctx: &mut Context<'_, N>,
        cond: &AssignedCondition<N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        let cond_v: AssignedValue<N> = cond.into();
        let c = cond.value * a.value + (one - cond.value) * b.value;
        let cells = self.one_line(
            ctx,
            vec![
                pair!(&cond_v, zero),
                pair!(a, zero),
                pair!(&cond_v, zero),
                pair!(b, one),
                pair!(c, -one),
            ],
            zero,
            (vec![one, -one], zero),
        )?;

        Ok(cells[4])
    }
}
