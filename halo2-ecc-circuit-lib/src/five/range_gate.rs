use super::config::{MUL_COLUMNS, VAR_COLUMNS};
use crate::five::base_gate::{FiveColumnBaseGate, FiveColumnBaseGateConfig};
use crate::gates::range_gate::{RangeGate, RangeGateConfig};
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::poly::Rotation;
use std::marker::PhantomData;

// In each line of five base gate,
// when enable common range selector, a0 a1 a2 a3 is limited by common range.
// when enable leading range selector, a0 is also limited by leading range.
//
// Usage:
// Suppose we are simulating a 248 bits integer. And we configure COMMON_RANGE_BITS to 16.
// Then each non-leading limb width is 16 * 4 = 64 bits,
// and leading limb width is 56, because 56 + 64 * 3 = 248.
// Then LEADING_RANGE_BITS should be 8, (8 + 16 * 3 = 56).
//
// Suppose we are simulating a 248 bits integer. And we configure COMMON_RANGE_BITS to 17.
// Then each non-leading limb width is 17 * 4 = 68 bits,
// and leading limb width is 56, because 44 + 68 * 3 = 248.
// Then LEADING_RANGE_BITS should be 10, (10 + 17 * 2 = 44).

pub type FiveColumnRangeGate<'a, W, N, const COMMON_RANGE_BITS: usize> =
    RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>;

impl<'a, W: FieldExt, N: FieldExt, const COMMON_RANGE_BITS: usize>
    FiveColumnRangeGate<'a, W, N, COMMON_RANGE_BITS>
{
    pub fn new(config: RangeGateConfig, base_gate: &'a FiveColumnBaseGate<N>) -> Self {
        RangeGate {
            config,
            base_gate,
            _phantom: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        base_gate_config: &'a FiveColumnBaseGateConfig,
    ) -> RangeGateConfig {
        let common_range_selector = meta.fixed_column();
        let common_range_table_column = meta.lookup_table_column();

        base_gate_config.base[0..VAR_COLUMNS - 1]
            .iter()
            .for_each(|column| {
                meta.lookup("common range", |meta| {
                    let exp = meta.query_advice(column.clone(), Rotation::cur());
                    let s = meta.query_fixed(common_range_selector, Rotation::cur());
                    vec![(exp * s, common_range_table_column)]
                });
            });

        let w_ceil_leading_limb_range_selector = meta.fixed_column();
        let w_ceil_leading_limb_range_table_column = meta.lookup_table_column();

        meta.lookup("w ceil leading limb range", |meta| {
            let exp = meta.query_advice(base_gate_config.base[0].clone(), Rotation::cur());
            let s = meta.query_fixed(w_ceil_leading_limb_range_selector, Rotation::cur());
            vec![(exp * s, w_ceil_leading_limb_range_table_column)]
        });

        let n_floor_leading_limb_range_selector = meta.fixed_column();
        let n_floor_leading_limb_range_table_column = meta.lookup_table_column();

        meta.lookup("n floor leading limb range", |meta| {
            let exp = meta.query_advice(base_gate_config.base[0].clone(), Rotation::cur());
            let s = meta.query_fixed(n_floor_leading_limb_range_selector, Rotation::cur());
            vec![(exp * s, n_floor_leading_limb_range_table_column)]
        });

        let d_leading_limb_range_selector = meta.fixed_column();
        let d_leading_limb_range_table_column = meta.lookup_table_column();

        meta.lookup("d leading limb range", |meta| {
            let exp = meta.query_advice(base_gate_config.base[0].clone(), Rotation::cur());
            let s = meta.query_fixed(d_leading_limb_range_selector, Rotation::cur());
            vec![(exp * s, d_leading_limb_range_table_column)]
        });

        RangeGateConfig {
            common_range_selector,
            common_range_table_column,
            w_ceil_leading_limb_range_selector,
            w_ceil_leading_limb_range_table_column,
            n_floor_leading_limb_range_selector,
            n_floor_leading_limb_range_table_column,
            d_leading_limb_range_selector,
            d_leading_limb_range_table_column,
        }
    }
}
