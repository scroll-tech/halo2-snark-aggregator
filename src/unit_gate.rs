use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Cell, Region},
};

mod five;

pub struct UnitRegion<'a, N: FieldExt> {
    pub region: &'a mut Region<'a, N>,
    pub offset: &'a mut usize,
}

pub struct AssignedCell<N: FieldExt> {
    cell: Cell,
    value: N,
}

pub enum ValueSchema<'a, N: FieldExt> {
    Copy(&'a AssignedCell<N>),
    Value(N),
}

pub trait UnitGateOps<N: FieldExt, const COLUMNS: usize, const MULS: usize> {
    fn unit(region: UnitRegion<'_, N>, advs: [ValueSchema<N>; COLUMNS], fixs: ([N; MULS], [N; 2])) -> AssignedCell<N>;
    fn sum(region: UnitRegion<'_, N>, elems: Vec<ValueSchema<N>>) -> AssignedCell<N>;
    fn mul(region: UnitRegion<'_, N>, a: ValueSchema<N>, b: ValueSchema<N>) -> AssignedCell<N>;
    fn invert(region: UnitRegion<'_, N>, a: ValueSchema<N>) -> (AssignedCell<N>, AssignedCell<N>);
    fn div(region: UnitRegion<'_, N>, a: ValueSchema<N>, b: ValueSchema<N>) -> (AssignedCell<N>, AssignedCell<N>);
    fn assert_bit(region: UnitRegion<'_, N>, a: ValueSchema<N>);
}
