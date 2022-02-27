use super::{
    base_gate::{AssignedCondition, BaseGateOps, RegionAux},
    integer_gate::{AssignedInteger, IntegerGateOps},
    range_gate::RangeGateOps,
};
use crate::FieldExt;
use halo2_proofs::plonk::Error;

#[derive(Clone)]
pub struct AssignedCurvature<W: FieldExt, N: FieldExt> {
    v: AssignedInteger<W, N>,
    z: AssignedCondition<N>,
}

#[derive(Clone)]
pub struct AssignedPoint<W: FieldExt, N: FieldExt> {
    x: AssignedInteger<W, N>,
    y: AssignedInteger<W, N>,
    z: AssignedCondition<N>,

    curvature: Option<AssignedCurvature<W, N>>,
}

impl<W: FieldExt, N: FieldExt> AssignedPoint<W, N> {
    pub fn new(
        x: AssignedInteger<W, N>,
        y: AssignedInteger<W, N>,
        z: AssignedCondition<N>,
    ) -> Self {
        Self {
            x,
            y,
            z,
            curvature: None,
        }
    }

    pub fn set_curvature(&mut self, curvature: AssignedCurvature<W, N>) {
        self.curvature = Some(curvature);
    }
}

pub struct EccGate<'a, W: FieldExt, N: FieldExt> {
    pub integer_gate: &'a dyn IntegerGateOps<W, N>,
}

impl<'a, W: FieldExt, N: FieldExt> EccGate<'a, W, N> {
    pub fn new(integer_gate: &'a dyn IntegerGateOps<W, N>) -> Self {
        Self { integer_gate }
    }
}

pub trait EccGateOps<'c, W: FieldExt, N: FieldExt, const LIMBS: usize> {
    fn base_gate(&self) -> &dyn BaseGateOps<N>;
    fn range_gate(&self) -> &dyn RangeGateOps<W, N>;
    fn integer_gate(&self) -> &dyn IntegerGateOps<W, N>;
    fn curvature(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedPoint<W, N>,
    ) -> Result<AssignedCurvature<W, N>, Error>;
    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedPoint<W, N>,
        b: &AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error>;
    fn double(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error>;
}
