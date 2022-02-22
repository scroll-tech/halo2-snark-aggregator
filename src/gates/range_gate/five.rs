use std::marker::PhantomData;

use super::{RangeGate, RangeGateConfig};
use crate::gates::base_gate::five::{FiveBaseGate, FiveBaseGateConfig, MUL_COLUMNS, VAR_COLUMNS};
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use halo2_proofs::poly::Rotation;
use halo2_proofs::{arithmetic::FieldExt, plonk::ConstraintSystem};

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

type FiveRangeGate<'a, W, N, const COMMON_RANGE_BITS: usize> =
    RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>;

impl<'a, W: FieldExt, N: FieldExt, const COMMON_RANGE_BITS: usize>
    FiveRangeGate<'a, W, N, COMMON_RANGE_BITS>
{
    pub fn new(config: RangeGateConfig, base_gate: &'a FiveBaseGate<N>) -> Self {
        RangeGate {
            config,
            base_gate,
            _phantom: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        base_gate_config: &'a FiveBaseGateConfig,
    ) -> RangeGateConfig {
        let common_range_selector = meta.complex_selector();
        let common_range_table_column = meta.lookup_table_column();

        base_gate_config.base[0..VAR_COLUMNS - 1]
            .iter()
            .for_each(|column| {
                meta.lookup(|meta| {
                    let exp = meta.query_advice(column.clone(), Rotation::cur());
                    let s = meta.query_selector(common_range_selector);
                    vec![(exp * s, common_range_table_column)]
                });
            });

        let leading_limb_range_selector = meta.complex_selector();
        let leading_limb_range_table_column = meta.lookup_table_column();

        meta.lookup(|meta| {
            let exp = meta.query_advice(base_gate_config.base[0].clone(), Rotation::cur());
            let s = meta.query_selector(leading_limb_range_selector);
            vec![(exp * s, leading_limb_range_table_column)]
        });

        RangeGateConfig {
            common_range_selector,
            common_range_table_column,
            leading_limb_range_selector,
            leading_limb_range_table_column,
        }
    }
}
