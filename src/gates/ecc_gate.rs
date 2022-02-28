use crate::gates::five::integer_gate;

use super::{
    base_gate::{AssignedCondition, BaseGateOps, RegionAux},
    integer_gate::{AssignedInteger, IntegerGateOps},
    range_gate::RangeGateOps,
};
use group::ff::Field;
use group::Curve;
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::Error,
};

#[derive(Clone)]
pub struct AssignedCurvature<C: CurveAffine, N: FieldExt> {
    v: AssignedInteger<C::Base, N>,
    z: AssignedCondition<N>,
}

impl<C: CurveAffine, N: FieldExt> AssignedCurvature<C, N> {
    pub fn new(v: AssignedInteger<C::Base, N>, z: AssignedCondition<N>) -> Self {
        Self { v, z }
    }
}

#[derive(Clone)]
pub struct AssignedPoint<C: CurveAffine, N: FieldExt> {
    x: AssignedInteger<C::Base, N>,
    y: AssignedInteger<C::Base, N>,
    z: AssignedCondition<N>,

    curvature: Option<AssignedCurvature<C, N>>,
}

impl<C: CurveAffine, N: FieldExt> AssignedPoint<C, N> {
    pub fn new(
        x: AssignedInteger<C::Base, N>,
        y: AssignedInteger<C::Base, N>,
        z: AssignedCondition<N>,
    ) -> Self {
        Self {
            x,
            y,
            z,
            curvature: None,
        }
    }

    pub fn set_curvature(&mut self, curvature: AssignedCurvature<C, N>) {
        self.curvature = Some(curvature);
    }
}

pub struct EccGate<'a, C: CurveAffine, N: FieldExt> {
    pub integer_gate: &'a dyn IntegerGateOps<C::Base, N>,
}

impl<'a, C: CurveAffine, N: FieldExt> EccGate<'a, C, N> {
    pub fn new(integer_gate: &'a dyn IntegerGateOps<C::Base, N>) -> Self {
        Self { integer_gate }
    }
}

pub trait EccGateOps<C: CurveAffine, N: FieldExt> {
    fn integer_gate(&self) -> &dyn IntegerGateOps<C::Base, N>;
    fn base_gate(&self) -> &dyn BaseGateOps<N> {
        self.integer_gate().base_gate()
    }
    fn range_gate(&self) -> &dyn RangeGateOps<C::Base, N> {
        self.integer_gate().range_gate()
    }
    fn curvature(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedCurvature<C, N>, Error> {
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
        a: &AssignedCurvature<C, N>,
        b: &AssignedCurvature<C, N>,
    ) -> Result<AssignedCurvature<C, N>, Error> {
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
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
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
        lambda: &mut AssignedCurvature<C, N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
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
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
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
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let mut curvature = self.curvature(r, a)?;
        let mut p = self.lambda_to_point(r, &mut curvature, a, a)?;
        p.z = base_gate.bisec_cond(r, &a.z, &a.z, &p.z)?;
        Ok(p)
    }
    fn from_constant_scalar(
        &self,
        r: &mut RegionAux<N>,
        scalar: C::ScalarExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let p: C::CurveExt = C::generator() * scalar;
        let coordinates = p.to_affine().coordinates();
        let x = coordinates
            .map(|v| v.x().clone())
            .unwrap_or(C::Base::zero());
        let y = coordinates
            .map(|v| v.x().clone())
            .unwrap_or(C::Base::zero());
        let z = coordinates.map(|v| N::zero()).unwrap_or(N::one());

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.assign_constant(r, x)?;
        let y = integer_gate.assign_constant(r, y)?;
        let z = base_gate.assign_constant(r, z)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assert_equal(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedPoint<C, N>,
        b: &mut AssignedPoint<C, N>
    ) -> Result<(), Error> {
        let one = N::one();

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let eq_x = integer_gate.is_equal(r, &mut a.x, &mut b.x)?;
        let eq_y = integer_gate.is_equal(r, &mut a.y, &mut b.y)?;
        let eq_z = base_gate.xnor(r, &eq_x, &eq_y)?;
        let eq_xy = base_gate.and(r, &eq_x, &eq_y)?;
        let eq_xyz =  base_gate.and(r, &eq_xy, &eq_z)?;

        let is_both_identity = base_gate.and(r, &a.z, &b.z)?;
        let eq = base_gate.or(r, &eq_xyz, &is_both_identity)?;

        base_gate.assert_constant(r, &eq.into(), one)
    }
}

impl<'a, C: CurveAffine, N: FieldExt> EccGateOps<C, N> for EccGate<'a, C, N> {
    fn integer_gate(&self) -> &dyn IntegerGateOps<C::Base, N> {
        self.integer_gate
    }
}
