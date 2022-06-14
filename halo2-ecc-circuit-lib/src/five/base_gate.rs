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

impl<N: FieldExt> FiveColumnBaseGate<N> {
    fn mul_add2(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        c: &AssignedValue<N>,
        c_coeff: N,
        d: &AssignedValue<N>,
        d_coeff: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 5);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let e = a.value * b.value + c.value * c_coeff + d.value * d_coeff;

        let cells = self.one_line(
            ctx,
            vec![
                pair!(a, zero),
                pair!(b, zero),
                pair!(c, c_coeff),
                pair!(d, d_coeff),
                pair!(e, -one),
            ],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[4])
    }
}

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

    fn mul_add_with_next_line(
        &self,
        ctx: &mut Context<'_, N>,
        ls: Vec<(&AssignedValue<N>, &AssignedValue<N>, &AssignedValue<N>, N)>,
    ) -> Result<AssignedValue<N>, Error> {
        let one = N::one();

        let mut i = ls.into_iter();

        let acc = {
            let (a, b, c, c_coeff) = i.next().unwrap();
            self.mul_add(ctx, a, b, c, c_coeff)
        };

        i.fold(acc, |acc, (a, b, c, c_coeff)| {
            let acc = acc?;
            self.mul_add2(ctx, a, b, c, c_coeff, &acc, one)
        })
    }
}
