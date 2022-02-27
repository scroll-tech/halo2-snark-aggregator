use super::{
    base_gate::{AssignedCondition, BaseGate, RegionAux, BaseGateOps},
    integer_gate::{AssignedInteger, IntegerGate},
    range_gate::RangeGate,
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

pub struct EccGate<
    'a,
    'b,
    'c,
    W: FieldExt,
    N: FieldExt,
    const VAR_COLUMNS: usize,
    const MUL_COLUMNS: usize,
    const COMMON_RANGE_BITS: usize,
    const LIMBS: usize,
    const LIMB_WIDTH: usize,
> {
    pub base_gate: &'a dyn BaseGateOps<N>,
    pub range_gate: &'b RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>,
    pub integer_gate: &'c IntegerGate<
        'a,
        'b,
        W,
        N,
        VAR_COLUMNS,
        MUL_COLUMNS,
        COMMON_RANGE_BITS,
        LIMBS,
        LIMB_WIDTH,
    >,
}

impl<
        'a,
        'b,
        'c,
        W: FieldExt,
        N: FieldExt,
        const VAR_COLUMNS: usize,
        const MUL_COLUMNS: usize,
        const COMMON_RANGE_BITS: usize,
        const LIMBS: usize,
        const LIMB_WIDTH: usize,
    > EccGate<'a, 'b, 'c, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS, LIMBS, LIMB_WIDTH>
{
    pub fn new(
        integer_gate: &'c IntegerGate<
            'a,
            'b,
            W,
            N,
            VAR_COLUMNS,
            MUL_COLUMNS,
            COMMON_RANGE_BITS,
            LIMBS,
            LIMB_WIDTH,
        >,
    ) -> Self {
        Self {
            base_gate: integer_gate.base_gate,
            range_gate: integer_gate.range_gate,
            integer_gate,
        }
    }
}

pub trait EccGateOps<'c, W: FieldExt, N: FieldExt, const LIMBS: usize> {
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
