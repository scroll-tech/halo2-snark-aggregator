use crate::{
    gates::base_gate::{BaseGate, BaseGateConfig},
    gates::integer_gate::IntegerGate,
    gates::range_gate::RangeGate,
};

pub const VAR_COLUMNS: usize = 4;
pub const MUL_COLUMNS: usize = 1;

pub type FourBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FourBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;

pub type FourRangeGate<'a, N, const RANGE_BITS: usize> = RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS, RANGE_BITS>;
pub type FourIntegerGate<'a, 'b, W, N, const LIMB_WIDTH: usize, const RANGE_BITS: usize> =
    IntegerGate<'a, 'b, W, N, VAR_COLUMNS, MUL_COLUMNS, LIMB_WIDTH, RANGE_BITS>;
