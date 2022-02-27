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

impl<W: FieldExt, N: FieldExt> AssignedCurvature<W, N> {
    pub fn new(v: AssignedInteger<W, N>, z: AssignedCondition<N>) -> Self {
        Self { v, z }
    }
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
    ) -> Result<AssignedCurvature<W, N>, Error> {
        // 3 * x ^ 2 / 2 * y
        let integer_gate = self.integer_gate();
        let mut x_square = integer_gate.square(r, &mut a.x)?;
        let mut numerator = integer_gate.mul_small_constant(r, &mut x_square, 3usize)?;
        let mut denominator = integer_gate.mul_small_constant(r, &mut a.y, 2usize)?;

        let (z, v) = integer_gate.div(r, &mut numerator, &mut denominator)?;
        Ok(AssignedCurvature { v, z })
    }

    fn bisec_curvature(
        &self,
        r: &mut RegionAux<N>,
        cond: &AssignedCondition<N>,
        a: &AssignedCurvature<W, N>,
        b: &AssignedCurvature<W, N>,
    ) -> Result<AssignedCurvature<W, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let v = integer_gate.bisec(r, cond, &a.v, &b.v)?;
        let z = base_gate.bisec_cond(r, cond, &a.z, &b.z)?;

        Ok(AssignedCurvature::new(v, z))
    }

    fn bisec_point(
        &self,
        r: &mut RegionAux<N>,
        cond: &AssignedCondition<N>,
        a: &AssignedPoint<W, N>,
        b: &AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.bisec(r, cond, &a.x, &b.x)?;
        let y = integer_gate.bisec(r, cond, &a.y, &b.y)?;
        let z = base_gate.bisec_cond(r, cond, &a.z, &b.z)?;

        Ok(AssignedPoint::new(x, y, z))
    }

    fn lambda_to_point(
        &self,
        r: &mut RegionAux<N>,
        lambda: &mut AssignedCurvature<W, N>,
        a: &AssignedPoint<W, N>,
        b: &AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error> {
        let integer_gate = self.integer_gate();

        let l = &mut lambda.v;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = integer_gate.square(r, l)?;
            let t = integer_gate.sub(r, &l_square, &a.x)?;
            let t = integer_gate.sub(r, &t, &b.x)?;
            t
        };

        let cy = {
            let mut t = integer_gate.sub(r, &a.x, &cx)?;
            let t = integer_gate.mul(r, &mut t, l)?;
            let t = integer_gate.sub(r, &t, &a.y)?;
            t
        };

        Ok(AssignedPoint::new(cx, cy, lambda.z))
    }

    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedPoint<W, N>,
        b: &AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();

        let mut diff_x = integer_gate.sub(r, &a.x, &b.x)?;
        let mut diff_y = integer_gate.sub(r, &a.y, &b.y)?;
        let (x_eq, tangent) = integer_gate.div(r, &mut diff_y, &mut diff_x)?;
        let y_eq = integer_gate.is_zero(r, &mut diff_y)?;
        let eq = base_gate.and(r, &x_eq, &y_eq)?;

        let tangent = AssignedCurvature::new(tangent, x_eq);
        let curvature = self.curvature(r, a)?;
        let mut lambda = self.bisec_curvature(r, &eq, &curvature, &tangent)?;

        let p = self.lambda_to_point(r, &mut lambda, a, b)?;
        let p = self.bisec_point(r, &a.z, b, &p)?;
        let p = self.bisec_point(r, &b.z, a, &p)?;

        Ok(p)
    }

    fn double(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedPoint<W, N>,
    ) -> Result<AssignedPoint<W, N>, Error> {
        let base_gate = self.base_gate();
        let mut curvature = self.curvature(r, a)?;
        let mut p = self.lambda_to_point(r, &mut curvature, a, a)?;
        p.z = base_gate.bisec_cond(r, &a.z, &a.z, &p.z)?;
        Ok(p)
    }
}
