use super::{AssignedValue, BaseGate, BaseRegion, ValueSchema};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

impl<N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize>
    BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>
{
    pub fn one_line(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        base_coeff_pairs: [(&ValueSchema<N>, N); VAR_COLUMNS],
        c_m_n_fixes: (N, [N; MUL_COLUMNS], N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        let mut cells = vec![];

        for (i, (base, coeff)) in base_coeff_pairs.into_iter().enumerate() {
            r.region
                .assign_fixed(
                    || format!("coeff_{}", i),
                    self.config.coeff[i],
                    *r.offset,
                    || Ok(coeff),
                )?
                .cell();

            let cell = r
                .region
                .assign_advice(
                    || format!("base_{}", i),
                    self.config.base[i],
                    *r.offset,
                    || Ok(base.value()),
                )?
                .cell();

            base.constrain_equal_conditionally(r.region, cell)?;
            cells.push(AssignedValue {
                cell,
                value: base.value(),
            });
        }

        let (constant, mul_coeffs, next) = c_m_n_fixes;

        for (i, mul_coeff) in mul_coeffs.into_iter().enumerate() {
            r.region.assign_fixed(
                || format!("mul_coeff_{}", i),
                self.config.mul_coeff[i],
                *r.offset,
                || Ok(mul_coeff),
            )?;
        }

        r.region.assign_fixed(
            || "constant",
            self.config.constant,
            *r.offset,
            || Ok(constant),
        )?;
        r.region.assign_fixed(
            || "next_coeff",
            self.config.next_coeff,
            *r.offset,
            || Ok(next),
        )?;

        *r.offset += 1;

        Ok(cells.try_into().unwrap())
    }
}

pub trait BaseGateOps<N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> {
    /*
    fn sum(region: BaseRegion<'_, N>, elems: Vec<ValueSchema<N>>) -> AssignedCell<N>;
    fn mul(region: BaseRegion<'_, N>, a: ValueSchema<N>, b: ValueSchema<N>) -> AssignedCell<N>;
    fn invert(region: BaseRegion<'_, N>, a: ValueSchema<N>) -> (AssignedCell<N>, AssignedCell<N>);
    fn div(
        region: BaseRegion<'_, N>,
        a: ValueSchema<N>,
        b: ValueSchema<N>,
    ) -> (AssignedCell<N>, AssignedCell<N>);
    fn assert_bit(region: BaseRegion<'_, N>, a: ValueSchema<N>);
    */
}
