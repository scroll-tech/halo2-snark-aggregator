use crate::gates::{
    base_gate::{BaseGate, BaseGateConfig},
};

pub const VAR_COLUMNS: usize = 5;
pub const MUL_COLUMNS: usize = 2;

pub type FiveColumnBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FiveColumnBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;
