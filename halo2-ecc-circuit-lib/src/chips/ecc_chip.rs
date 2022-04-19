use super::integer_chip::{AssignedInteger, IntegerChipOps};
use crate::gates::{
    base_gate::{AssignedCondition, BaseGateOps, Context},
    range_gate::RangeGateOps,
};
use group::ff::Field;
use group::Curve;
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::Error,
};

#[derive(Clone, Debug)]
pub struct AssignedCurvature<C: CurveAffine, N: FieldExt> {
    v: AssignedInteger<C::Base, N>,
    z: AssignedCondition<N>,
}

impl<C: CurveAffine, N: FieldExt> AssignedCurvature<C, N> {
    pub fn new(v: AssignedInteger<C::Base, N>, z: AssignedCondition<N>) -> Self {
        Self { v, z }
    }
}

#[derive(Clone, Debug)]
pub struct AssignedPoint<C: CurveAffine, N: FieldExt> {
    pub x: AssignedInteger<C::Base, N>,
    pub y: AssignedInteger<C::Base, N>,
    pub z: AssignedCondition<N>,

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

    pub fn new_with_curvature(
        x: AssignedInteger<C::Base, N>,
        y: AssignedInteger<C::Base, N>,
        z: AssignedCondition<N>,
        curvature: Option<AssignedCurvature<C, N>>,
    ) -> Self {
        Self { x, y, z, curvature }
    }

    pub fn set_curvature(&mut self, curvature: AssignedCurvature<C, N>) {
        self.curvature = Some(curvature);
    }
}

pub struct EccChip<'a, C: CurveAffine, N: FieldExt> {
    pub integer_gate: &'a dyn IntegerChipOps<C::Base, N>,
}

impl<'a, C: CurveAffine, N: FieldExt> EccChip<'a, C, N> {
    pub fn new(integer_gate: &'a dyn IntegerChipOps<C::Base, N>) -> Self {
        Self { integer_gate }
    }
}

const WINDOW_SIZE: usize = 4usize;

pub trait EccChipOps<C: CurveAffine, N: FieldExt> {
    type AssignedScalar;
    fn integer_gate(&self) -> &dyn IntegerChipOps<C::Base, N>;
    fn base_gate(&self) -> &dyn BaseGateOps<N> {
        self.integer_gate().base_gate()
    }
    fn range_gate(&self) -> &dyn RangeGateOps<C::Base, N> {
        self.integer_gate().range_gate()
    }
    fn decompose_scalar(
        &self,
        r: &mut Context<N>,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<N>; WINDOW_SIZE]>, Error>;
    fn mul(
        &self,
        r: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        s: &Self::AssignedScalar,
    ) -> Result<AssignedPoint<C, N>, Error> {
        assert!(WINDOW_SIZE >= 1usize);
        let windows_in_be = self.decompose_scalar(r, s)?;
        let identity = self.assign_identity(r)?;
        let mut candidates = vec![identity, a.clone()];

        for i in 2..(1 << WINDOW_SIZE) {
            let ai = self.add(r, &mut candidates[i - 1], a)?;
            candidates.push(ai)
        }

        let pick_candidate = |r: &mut Context<N>,
                              bits_in_le: &[AssignedCondition<N>; WINDOW_SIZE]|
         -> Result<AssignedPoint<C, N>, Error> {
            let mut curr_candidates = candidates.clone();
            for bit in bits_in_le {
                let mut next_candidates = vec![];
                let len = curr_candidates.len() / 2;
                let mut it = curr_candidates.iter_mut();

                for _ in 0..len {
                    let a0 = it.next().ok_or(Error::Synthesis)?;
                    let a1 = it.next().ok_or(Error::Synthesis)?;

                    let cell = self.bisec_point_with_curvature(r, &bit, a1, a0)?;
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }

            Ok(curr_candidates.first().unwrap().clone())
        };

        if let Some((first, pendings)) = windows_in_be.split_first() {
            let mut acc = pick_candidate(r, first)?;
            for bits_in_le in pendings {
                for _ in 0..WINDOW_SIZE {
                    acc = self.double(r, &mut acc)?;
                }

                let mut curr = pick_candidate(r, bits_in_le)?;
                acc = self.add(r, &mut curr, &acc)?;
            }
            Ok(acc)
        } else {
            Err(Error::Synthesis)
        }
    }
    fn curvature<'a>(
        &self,
        r: &mut Context<N>,
        a: &'a mut AssignedPoint<C, N>,
    ) -> Result<&'a mut AssignedCurvature<C, N>, Error> {
        let new_curvature = match &a.curvature {
            Some(_) => None,
            None => {
                // 3 * x ^ 2 / 2 * y
                let integer_gate = self.integer_gate();
                let mut x_square = integer_gate.square(r, &mut a.x)?;
                let mut numerator = integer_gate.mul_small_constant(r, &mut x_square, 3usize)?;
                let mut denominator = integer_gate.mul_small_constant(r, &mut a.y, 2usize)?;

                let (z, v) = integer_gate.div(r, &mut numerator, &mut denominator)?;
                Some(AssignedCurvature { v, z })
            }
        };

        if new_curvature.is_some() {
            a.curvature = new_curvature;
        }

        match &mut a.curvature {
            Some(c) => Ok(c),
            None => Err(Error::Synthesis),
        }
    }
    fn bisec_curvature(
        &self,
        r: &mut Context<N>,
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
        r: &mut Context<N>,
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
    fn bisec_point_with_curvature(
        &self,
        r: &mut Context<N>,
        cond: &AssignedCondition<N>,
        a: &mut AssignedPoint<C, N>,
        b: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.bisec(r, cond, &a.x, &b.x)?;
        let y = integer_gate.bisec(r, cond, &a.y, &b.y)?;
        let z = base_gate.bisec_cond(r, cond, &a.z, &b.z)?;

        let c_a = self.curvature(r, a)?;
        let c_b = self.curvature(r, b)?;
        let c = self.bisec_curvature(r, cond, c_a, c_b)?;

        Ok(AssignedPoint::new_with_curvature(x, y, z, Some(c)))
    }
    fn lambda_to_point(
        &self,
        r: &mut Context<N>,
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
        r: &mut Context<N>,
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
        r: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let curvature = self.curvature(r, a)?;
        let mut p = self.lambda_to_point(r, &mut curvature.clone(), a, a)?;
        p.z = base_gate.bisec_cond(r, &a.z, &a.z, &p.z)?;
        Ok(p)
    }
    fn assign_constant_point(
        &self,
        r: &mut Context<N>,
        c: C::CurveExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let coordinates = c.to_affine().coordinates();
        let x = coordinates
            .map(|v| v.x().clone())
            .unwrap_or(C::Base::zero());
        let y = coordinates
            .map(|v| v.y().clone())
            .unwrap_or(C::Base::zero());
        let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.assign_constant(r, x)?;
        let y = integer_gate.assign_constant(r, y)?;
        let z = base_gate.assign_constant(r, z)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assign_point(
        &self,
        r: &mut Context<N>,
        c: C::CurveExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let coordinates = c.to_affine().coordinates();
        let x = coordinates
            .map(|v| v.x().clone())
            .unwrap_or(C::Base::zero());
        let y = coordinates
            .map(|v| v.y().clone())
            .unwrap_or(C::Base::zero());
        let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let mut x = integer_gate.assign_w(r, &x)?;
        let mut y = integer_gate.assign_w(r, &y)?;
        let z = base_gate.assign(r, z)?;

        // Constrain y^2 = x^3 + b
        let b = integer_gate.assign_constant(r, C::b())?;
        let mut y2 = integer_gate.square(r, &mut y)?;
        let mut x2 = integer_gate.square(r, &mut x)?;
        let x3 = integer_gate.mul(r, &mut x2, &mut x)?;
        let mut right = integer_gate.add(r, &x3, &b)?;
        let eq = integer_gate.is_equal(r, &mut y2, &mut right)?;
        base_gate.assert_true(r, &eq)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assign_constant_point_from_scalar(
        &self,
        r: &mut Context<N>,
        scalar: C::ScalarExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let p: C::CurveExt = C::generator() * scalar;
        self.assign_constant_point(r, p)
    }
    fn assign_point_from_scalar(
        &self,
        r: &mut Context<N>,
        scalar: C::ScalarExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let p: C::CurveExt = C::generator() * scalar;
        self.assign_point(r, p)
    }
    fn assign_identity(&self, r: &mut Context<N>) -> Result<AssignedPoint<C, N>, Error> {
        let zero = self.integer_gate().assign_constant(r, C::Base::zero())?;
        let one = self.base_gate().assign_constant(r, N::one())?;

        Ok(AssignedPoint::new_with_curvature(
            zero.clone(),
            zero.clone(),
            one.into(),
            Some(AssignedCurvature::new(zero, one.into())),
        ))
    }
    fn assert_equal(
        &self,
        r: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &mut AssignedPoint<C, N>,
    ) -> Result<(), Error> {
        let one = N::one();

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let eq_x = integer_gate.is_equal(r, &mut a.x, &mut b.x)?;
        let eq_y = integer_gate.is_equal(r, &mut a.y, &mut b.y)?;
        let eq_z = base_gate.xnor(r, &eq_x, &eq_y)?;
        let eq_xy = base_gate.and(r, &eq_x, &eq_y)?;
        let eq_xyz = base_gate.and(r, &eq_xy, &eq_z)?;

        let is_both_identity = base_gate.and(r, &a.z, &b.z)?;
        let eq = base_gate.or(r, &eq_xyz, &is_both_identity)?;

        base_gate.assert_constant(r, &eq.into(), one)
    }
    fn neg(
        &self,
        r: &mut Context<N>,
        a: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let x = a.x.clone();
        let y = self.integer_gate().neg(r, &a.y)?;
        let z = a.z.clone();

        Ok(AssignedPoint::new(x, y, z))
    }
    fn sub(
        &self,
        r: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let mut neg_b = self.neg(r, b)?;
        self.add(r, a, &mut neg_b)
    }
}
