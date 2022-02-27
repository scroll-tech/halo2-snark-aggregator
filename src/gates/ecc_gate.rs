use super::{
    base_gate::{AssignedCondition, BaseGate, RegionAux},
    integer_gate::{AssignedInteger, IntegerGate},
    range_gate::RangeGate,
};
use crate::FieldExt;
use halo2_proofs::plonk::Error;

#[derive(Clone)]
pub struct AssignedCurvature<W: FieldExt, N: FieldExt, const LIMBS: usize> {
    v: AssignedInteger<W, N, LIMBS>,
    z: AssignedCondition<N>,
}

#[derive(Clone)]
pub struct AssignedPoint<W: FieldExt, N: FieldExt, const LIMBS: usize> {
    x: AssignedInteger<W, N, LIMBS>,
    y: AssignedInteger<W, N, LIMBS>,
    z: AssignedCondition<N>,

    curvature: Option<AssignedCurvature<W, N, LIMBS>>,
}

impl<W: FieldExt, N: FieldExt, const LIMBS: usize> AssignedPoint<W, N, LIMBS> {
    pub fn new(
        x: AssignedInteger<W, N, LIMBS>,
        y: AssignedInteger<W, N, LIMBS>,
        z: AssignedCondition<N>,
    ) -> Self {
        Self {
            x,
            y,
            z,
            curvature: None,
        }
    }

    pub fn set_curvature(&mut self, curvature: AssignedCurvature<W, N, LIMBS>) {
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
    pub base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>,
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
        a: &mut AssignedPoint<W, N, LIMBS>,
    ) -> Result<AssignedCurvature<W, N, LIMBS>, Error>;
    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedPoint<W, N, LIMBS>,
        b: &AssignedPoint<W, N, LIMBS>,
    ) -> Result<AssignedPoint<W, N, LIMBS>, Error>;
    fn double(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedPoint<W, N, LIMBS>,
    ) -> Result<AssignedPoint<W, N, LIMBS>, Error>;
}
