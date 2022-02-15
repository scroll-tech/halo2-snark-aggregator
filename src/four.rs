use crate::{
    base_gate::{BaseGate, BaseGateConfig},
    range_gate::RangeGate,
};

pub const VAR_COLUMNS: usize = 4;
pub const MUL_COLUMNS: usize = 1;

pub type FourBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FourBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;

pub type FourRangeGate<'a, N> = RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS>;
