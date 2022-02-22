use crate::{
    gates::base_gate::{AssignedValue, BaseGate, RegionAux, ValueSchema},
    pair, utils::field_to_bn,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Error, Selector, TableColumn},
};
use std::marker::PhantomData;

pub mod five;

#[derive(Clone, Debug)]
pub struct RangeGateConfig {
    leading_limb_range_selector: Selector,
    leading_limb_range_table_column: TableColumn,

    common_range_selector: Selector,
    common_range_table_column: TableColumn,
}

pub struct RangeGate<
    'a,
    W: FieldExt,
    N: FieldExt,
    const VAR_COLUMNS: usize,
    const MUL_COLUMNS: usize,
    const COMMON_RANGE_BITS: usize,
> {
    config: RangeGateConfig,
    pub base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>,
    _phantom: PhantomData<W>,
}

impl<
        'a,
        W: FieldExt,
        N: FieldExt,
        const VAR_COLUMNS: usize,
        const MUL_COLUMNS: usize,
        const COMMON_RANGE_BITS: usize,
    > RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>
{
    pub fn init_table(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
        let mut leading_range_bits = (field_to_bn(&-W::one()).bits() as usize) % COMMON_RANGE_BITS;
        leading_range_bits = if leading_range_bits == 0 {
            COMMON_RANGE_BITS
        } else {
            leading_range_bits
        };

        layouter.assign_table(
            || "",
            |mut table| {
                for i in 0..1 << COMMON_RANGE_BITS {
                    table.assign_cell(
                        || "common range table",
                        self.config.common_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }

                for i in 0..1 << leading_range_bits {
                    table.assign_cell(
                        || "leading limb range table",
                        self.config.leading_limb_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn one_line_in_common_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        self.config
            .leading_limb_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    pub fn one_line_in_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        self.config
            .common_range_selector
            .enable(r.region, *r.offset)?;
        self.config
            .leading_limb_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    pub fn assign_common_values(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        v: Vec<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let cells = self.one_line_in_common_range(
            r,
            v.into_iter().map(|v| pair!(v, zero)).collect(),
            zero,
            (vec![], zero),
        )?;
        Ok(cells[0])
    }

    pub fn assign_common_value(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        v: N,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let cells =
            self.one_line_in_common_range(r, vec![pair!(v, zero)], zero, (vec![], zero))?;
        Ok(cells[0])
    }
}
