use crate::gates::{
    base_gate::{BaseGate, BaseGateConfig},
    range_gate::RangeGate,
};

pub const VAR_COLUMNS: usize = 5;
pub const MUL_COLUMNS: usize = 2;

pub type FiveBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FiveBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;

pub type FiveRangeGate<'a, N, const RANGE_BITS: usize> = RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS, RANGE_BITS>;
