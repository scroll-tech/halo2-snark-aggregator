use super::{BaseGate, BaseGateConfig};

pub const VAR_COLUMNS: usize = 5;
pub const MUL_COLUMNS: usize = 2;

pub type FiveBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FiveBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;
