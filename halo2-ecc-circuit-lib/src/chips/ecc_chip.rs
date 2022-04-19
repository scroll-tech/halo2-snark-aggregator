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
        ctx: &mut Context<N>,
        s: &Self::AssignedScalar,
    ) -> Result<Vec<[AssignedCondition<N>; WINDOW_SIZE]>, Error>;
    fn mul(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        s: &Self::AssignedScalar,
    ) -> Result<AssignedPoint<C, N>, Error> {
        assert!(WINDOW_SIZE >= 1usize);
        let windows_in_be = self.decompose_scalar(ctx, s)?;
        let identity = self.assign_identity(ctx)?;
        let mut candidates = vec![identity, a.clone()];

        for i in 2..(1 << WINDOW_SIZE) {
            let ai = self.add(ctx, &mut candidates[i - 1], a)?;
            candidates.push(ai)
        }

        let pick_candidate = |ctx: &mut Context<N>,
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

                    let cell = self.bisec_point_with_curvature(ctx, &bit, a1, a0)?;
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }

            Ok(curr_candidates.first().unwrap().clone())
        };

        if let Some((first, pendings)) = windows_in_be.split_first() {
            let mut acc = pick_candidate(ctx, first)?;
            for bits_in_le in pendings {
                for _ in 0..WINDOW_SIZE {
                    acc = self.double(ctx, &mut acc)?;
                }

                let mut curr = pick_candidate(ctx, bits_in_le)?;
                acc = self.add(ctx, &mut curr, &acc)?;
            }
            Ok(acc)
        } else {
            Err(Error::Synthesis)
        }
    }
    fn curvature<'a>(
        &self,
        ctx: &mut Context<N>,
        a: &'a mut AssignedPoint<C, N>,
    ) -> Result<&'a mut AssignedCurvature<C, N>, Error> {
        let new_curvature = match &a.curvature {
            Some(_) => None,
            None => {
                // 3 * x ^ 2 / 2 * y
                let integer_gate = self.integer_gate();
                let mut x_square = integer_gate.square(ctx, &mut a.x)?;
                let mut numerator = integer_gate.mul_small_constant(ctx, &mut x_square, 3usize)?;
                let mut denominator = integer_gate.mul_small_constant(ctx, &mut a.y, 2usize)?;

                let (z, v) = integer_gate.div(ctx, &mut numerator, &mut denominator)?;
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
        ctx: &mut Context<N>,
        cond: &AssignedCondition<N>,
        a: &AssignedCurvature<C, N>,
        b: &AssignedCurvature<C, N>,
    ) -> Result<AssignedCurvature<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let v = integer_gate.bisec(ctx, cond, &a.v, &b.v)?;
        let z = base_gate.bisec_cond(ctx, cond, &a.z, &b.z)?;

        Ok(AssignedCurvature::new(v, z))
    }
    fn bisec_point(
        &self,
        ctx: &mut Context<N>,
        cond: &AssignedCondition<N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.bisec(ctx, cond, &a.x, &b.x)?;
        let y = integer_gate.bisec(ctx, cond, &a.y, &b.y)?;
        let z = base_gate.bisec_cond(ctx, cond, &a.z, &b.z)?;

        Ok(AssignedPoint::new(x, y, z))
    }
    fn bisec_point_with_curvature(
        &self,
        ctx: &mut Context<N>,
        cond: &AssignedCondition<N>,
        a: &mut AssignedPoint<C, N>,
        b: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let x = integer_gate.bisec(ctx, cond, &a.x, &b.x)?;
        let y = integer_gate.bisec(ctx, cond, &a.y, &b.y)?;
        let z = base_gate.bisec_cond(ctx, cond, &a.z, &b.z)?;

        let c_a = self.curvature(ctx, a)?;
        let c_b = self.curvature(ctx, b)?;
        let c = self.bisec_curvature(ctx, cond, c_a, c_b)?;

        Ok(AssignedPoint::new_with_curvature(x, y, z, Some(c)))
    }
    fn lambda_to_point(
        &self,
        ctx: &mut Context<N>,
        lambda: &mut AssignedCurvature<C, N>,
        a: &AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let integer_gate = self.integer_gate();

        let l = &mut lambda.v;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = integer_gate.square(ctx, l)?;
            let t = integer_gate.sub(ctx, &l_square, &a.x)?;
            let t = integer_gate.sub(ctx, &t, &b.x)?;
            t
        };

        let cy = {
            let mut t = integer_gate.sub(ctx, &a.x, &cx)?;
            let t = integer_gate.mul(ctx, &mut t, l)?;
            let t = integer_gate.sub(ctx, &t, &a.y)?;
            t
        };
        Ok(AssignedPoint::new(cx, cy, lambda.z))
    }
    fn add(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();

        let mut diff_x = integer_gate.sub(ctx, &a.x, &b.x)?;
        let mut diff_y = integer_gate.sub(ctx, &a.y, &b.y)?;
        let (x_eq, tangent) = integer_gate.div(ctx, &mut diff_y, &mut diff_x)?;

        let y_eq = integer_gate.is_zero(ctx, &mut diff_y)?;
        let eq = base_gate.and(ctx, &x_eq, &y_eq)?;

        let tangent = AssignedCurvature::new(tangent, x_eq);
        let curvature = self.curvature(ctx, a)?;
        let mut lambda = self.bisec_curvature(ctx, &eq, &curvature, &tangent)?;

        let p = self.lambda_to_point(ctx, &mut lambda, a, b)?;
        let p = self.bisec_point(ctx, &a.z, b, &p)?;
        let p = self.bisec_point(ctx, &b.z, a, &p)?;

        Ok(p)
    }
    fn double(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let curvature = self.curvature(ctx, a)?;
        let mut p = self.lambda_to_point(ctx, &mut curvature.clone(), a, a)?;
        p.z = base_gate.bisec_cond(ctx, &a.z, &a.z, &p.z)?;
        Ok(p)
    }
    fn assign_constant_point(
        &self,
        ctx: &mut Context<N>,
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
        let x = integer_gate.assign_constant(ctx, x)?;
        let y = integer_gate.assign_constant(ctx, y)?;
        let z = base_gate.assign_constant(ctx, z)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assign_point(
        &self,
        ctx: &mut Context<N>,
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
        let mut x = integer_gate.assign_w(ctx, &x)?;
        let mut y = integer_gate.assign_w(ctx, &y)?;
        let z = base_gate.assign(ctx, z)?;

        // Constrain y^2 = x^3 + b
        let b = integer_gate.assign_constant(ctx, C::b())?;
        let mut y2 = integer_gate.square(ctx, &mut y)?;
        let mut x2 = integer_gate.square(ctx, &mut x)?;
        let x3 = integer_gate.mul(ctx, &mut x2, &mut x)?;
        let mut right = integer_gate.add(ctx, &x3, &b)?;
        let eq = integer_gate.is_equal(ctx, &mut y2, &mut right)?;
        base_gate.assert_true(ctx, &eq)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assign_constant_point_from_scalar(
        &self,
        ctx: &mut Context<N>,
        scalar: C::ScalarExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let p: C::CurveExt = C::generator() * scalar;
        self.assign_constant_point(ctx, p)
    }
    fn assign_point_from_scalar(
        &self,
        ctx: &mut Context<N>,
        scalar: C::ScalarExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let p: C::CurveExt = C::generator() * scalar;
        self.assign_point(ctx, p)
    }
    fn assign_identity(&self, ctx: &mut Context<N>) -> Result<AssignedPoint<C, N>, Error> {
        let zero = self.integer_gate().assign_constant(ctx, C::Base::zero())?;
        let one = self.base_gate().assign_constant(ctx, N::one())?;

        Ok(AssignedPoint::new_with_curvature(
            zero.clone(),
            zero.clone(),
            one.into(),
            Some(AssignedCurvature::new(zero, one.into())),
        ))
    }
    fn assert_equal(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &mut AssignedPoint<C, N>,
    ) -> Result<(), Error> {
        let one = N::one();

        let base_gate = self.base_gate();
        let integer_gate = self.integer_gate();
        let eq_x = integer_gate.is_equal(ctx, &mut a.x, &mut b.x)?;
        let eq_y = integer_gate.is_equal(ctx, &mut a.y, &mut b.y)?;
        let eq_z = base_gate.xnor(ctx, &eq_x, &eq_y)?;
        let eq_xy = base_gate.and(ctx, &eq_x, &eq_y)?;
        let eq_xyz = base_gate.and(ctx, &eq_xy, &eq_z)?;

        let is_both_identity = base_gate.and(ctx, &a.z, &b.z)?;
        let eq = base_gate.or(ctx, &eq_xyz, &is_both_identity)?;

        base_gate.assert_constant(ctx, &eq.into(), one)
    }
    fn neg(
        &self,
        ctx: &mut Context<N>,
        a: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let x = a.x.clone();
        let y = self.integer_gate().neg(ctx, &a.y)?;
        let z = a.z.clone();

        Ok(AssignedPoint::new(x, y, z))
    }
    fn sub(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let mut neg_b = self.neg(ctx, b)?;
        self.add(ctx, a, &mut neg_b)
    }
}
