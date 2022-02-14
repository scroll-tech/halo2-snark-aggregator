use halo2_proofs::arithmetic::FieldExt;

use super::{BaseGate, BaseGateConfig};

pub const VAR_COLUMNS: usize = 4;
pub const MUL_COLUMNS: usize = 1;

pub type FourBaseGateConfig = BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>;
pub type FourBaseGate<N> = BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>;
