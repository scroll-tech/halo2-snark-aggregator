use crate::FieldExt;
use crate::{
    gates::base_gate::{AssignedValue, RegionAux, ValueSchema},
    utils::{field_to_bn, get_d_range_bits_in_mul},
};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Error, Selector, TableColumn},
};
use num_bigint::BigUint;
use std::marker::PhantomData;

use super::base_gate::BaseGateOps;

#[derive(Clone, Debug)]
pub struct RangeGateConfig {
    pub(crate) w_ceil_leading_limb_range_selector: Selector,
    pub(crate) w_ceil_leading_limb_range_table_column: TableColumn,

    pub(crate) n_floor_leading_limb_range_selector: Selector,
    pub(crate) n_floor_leading_limb_range_table_column: TableColumn,

    pub(crate) d_leading_limb_range_selector: Selector, // range check for d, d * w + w_ceil <= lcm(integer_modulus, n)
    pub(crate) d_leading_limb_range_table_column: TableColumn,

    pub(crate) common_range_selector: Selector,
    pub(crate) common_range_table_column: TableColumn,
}

pub struct RangeGate<
    'a,
    W: FieldExt,
    N: FieldExt,
    const VAR_COLUMNS: usize,
    const MUL_COLUMNS: usize,
    const COMMON_RANGE_BITS: usize,
> {
    pub config: RangeGateConfig,
    pub base_gate: &'a dyn BaseGateOps<N>,
    pub _phantom: PhantomData<W>,
}

pub trait RangeGateOps<W: FieldExt, N: FieldExt> {
    fn base_gate(&self) -> &dyn BaseGateOps<N>;
    fn one_line_in_common_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error>;

    fn one_line_in_w_ceil_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error>;

    fn one_line_in_n_floor_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error>;

    fn one_line_in_d_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error>;
}

impl<
        'a,
        W: FieldExt,
        N: FieldExt,
        const VAR_COLUMNS: usize,
        const MUL_COLUMNS: usize,
        const COMMON_RANGE_BITS: usize,
    > RangeGateOps<W, N> for RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>
{
    fn one_line_in_common_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.config
            .common_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    fn one_line_in_w_ceil_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.config
            .common_range_selector
            .enable(r.region, *r.offset)?;
        self.config
            .w_ceil_leading_limb_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    fn one_line_in_n_floor_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.config
            .common_range_selector
            .enable(r.region, *r.offset)?;
        self.config
            .n_floor_leading_limb_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    fn one_line_in_d_leading_range(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.config
            .common_range_selector
            .enable(r.region, *r.offset)?;
        self.config
            .d_leading_limb_range_selector
            .enable(r.region, *r.offset)?;
        let assigned_values =
            self.base_gate
                .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    fn base_gate(&self) -> &'a dyn BaseGateOps<N> {
        self.base_gate
    }
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
    pub fn init_table(
        &self,
        layouter: &mut impl Layouter<N>,
        integer_modulus: &BigUint,
    ) -> Result<(), Error> {
        let w_ceil_bits = field_to_bn(&-W::one()).bits() as usize + 1;
        let w_ceil_leading_range_bits = w_ceil_bits % COMMON_RANGE_BITS;
        let w_ceil_leading_range_bits = if w_ceil_leading_range_bits == 0 {
            COMMON_RANGE_BITS
        } else {
            w_ceil_leading_range_bits
        };

        let n_floor_bits = field_to_bn(&-N::one()).bits() as usize;
        let n_floor_leading_range_bits = n_floor_bits % COMMON_RANGE_BITS;
        let n_floor_leading_range_bits = if n_floor_leading_range_bits == 0 {
            COMMON_RANGE_BITS
        } else {
            n_floor_leading_range_bits
        };

        let d_range_bits = get_d_range_bits_in_mul::<W, N>(integer_modulus);
        let d_leading_range_bits = d_range_bits % COMMON_RANGE_BITS;
        let d_leading_range_bits = if d_leading_range_bits == 0 {
            COMMON_RANGE_BITS
        } else {
            d_leading_range_bits
        };

        layouter.assign_table(
            || "common range table",
            |mut table| {
                for i in 0..1 << COMMON_RANGE_BITS {
                    table.assign_cell(
                        || "common range table",
                        self.config.common_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "w ceil leading range table",
            |mut table| {
                for i in 0..1 << w_ceil_leading_range_bits {
                    table.assign_cell(
                        || "w ceil leading limb range table",
                        self.config.w_ceil_leading_limb_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "n floor leading range table",
            |mut table| {
                for i in 0..1 << n_floor_leading_range_bits {
                    table.assign_cell(
                        || "n floor leading limb range table",
                        self.config.n_floor_leading_limb_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_table(
            || "d leading range table",
            |mut table| {
                for i in 0..1 << d_leading_range_bits {
                    table.assign_cell(
                        || "d leading limb range table",
                        self.config.d_leading_limb_range_table_column,
                        i,
                        || Ok(N::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
