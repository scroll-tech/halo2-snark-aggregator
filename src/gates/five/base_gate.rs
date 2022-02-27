use halo2_proofs::plonk::Error;

use crate::{
    gates::base_gate::{
        AssignedCondition, AssignedValue, BaseGate, BaseGateConfig, BaseGateOps,
        RegionAux, ValueSchema,
    },
    pair, FieldExt,
};

pub const VAR_COLUMNS: usize = 5;
pub const MUL_COLUMNS: usize = 2;

pub type FiveColumnBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FiveColumnBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;

impl<N: FieldExt> BaseGateOps<N> for FiveColumnBaseGate<N> {
    fn var_columns(&self) -> usize {
        self._var_columns()
    }

    fn mul_columns(&self) -> usize {
        self._mul_columns()
    }

    fn one_line(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self._one_line(r, base_coeff_pairs, constant, mul_next_coeffs)
    }

    fn bisec(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        cond: &AssignedCondition<N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        let cond_v: AssignedValue<N> = cond.into();
        let c = cond.value * a.value + (one - cond.value) * b.value;
        let cells = self.one_line(
            r,
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
