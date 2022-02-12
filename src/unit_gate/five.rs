use halo2_proofs::plonk::{Column, Advice, Fixed};

const COLUMNS: usize = 5;
const MULS: usize = 2;

pub struct UnitGateConfig {
    pub base: [Column<Advice>; COLUMNS],
    pub coeff: [Column<Fixed>; COLUMNS],
    pub constant: Column<Fixed>,
    pub mul_coeff: [Column<Fixed>; MULS],
    pub next: Column<Fixed>
}

pub struct UnitGateChip {

}