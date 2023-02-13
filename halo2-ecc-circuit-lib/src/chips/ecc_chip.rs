use super::integer_chip::{AssignedInteger, IntegerChipOps};
use crate::gates::{
    base_gate::{AssignedCondition, BaseGateOps, Context},
    range_gate::RangeGateOps,
};
use group::ff::Field;
use group::{Curve, Group};
use halo2_proofs::plonk::Error;
use halo2curves::{CurveAffine, FieldExt};

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
    pub integer_chip: &'a dyn IntegerChipOps<C::Base, N>,
}

impl<'a, C: CurveAffine, N: FieldExt> EccChip<'a, C, N> {
    pub fn new(integer_chip: &'a dyn IntegerChipOps<C::Base, N>) -> Self {
        Self { integer_chip }
    }
}

const CONFIG_WINDOW_SIZE: usize = 2usize;

pub trait EccChipOps<C: CurveAffine, N: FieldExt> {
    type AssignedScalar;
    fn integer_chip(&self) -> &dyn IntegerChipOps<C::Base, N>;
    fn base_gate(&self) -> &dyn BaseGateOps<N> {
        self.integer_chip().base_gate()
    }
    fn range_gate(&self) -> &dyn RangeGateOps<C::Base, N> {
        self.integer_chip().range_gate()
    }
    fn decompose_scalar<const WINDOW_SIZE: usize>(
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
        assert!(CONFIG_WINDOW_SIZE >= 1usize);
        let windows_in_be = self.decompose_scalar::<CONFIG_WINDOW_SIZE>(ctx, s)?;
        let identity = self.assign_identity(ctx)?;
        let mut candidates = vec![identity, a.clone()];

        for i in 2..(1 << CONFIG_WINDOW_SIZE) {
            let ai = self.add(ctx, &mut candidates[i - 1], a)?;
            candidates.push(ai)
        }

        let pick_candidate = |ctx: &mut Context<N>,
                              bits_in_le: &[AssignedCondition<N>; CONFIG_WINDOW_SIZE]|
         -> Result<AssignedPoint<C, N>, Error> {
            let mut curr_candidates = candidates.clone();
            for bit in bits_in_le {
                let mut next_candidates = vec![];
                let len = curr_candidates.len() / 2;
                let mut it = curr_candidates.iter_mut();

                for _ in 0..len {
                    let a0 = it.next().ok_or(Error::Synthesis)?;
                    let a1 = it.next().ok_or(Error::Synthesis)?;

                    let cell = self.bisec_point_with_curvature(ctx, bit, a1, a0)?;
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }

            Ok(curr_candidates.first().unwrap().clone())
        };

        if let Some((first, pendings)) = windows_in_be.split_first() {
            let mut acc = pick_candidate(ctx, first)?;
            for bits_in_le in pendings {
                for _ in 0..CONFIG_WINDOW_SIZE {
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
    fn shamir(
        &self,
        ctx: &mut Context<N>,
        points: &mut Vec<AssignedPoint<C, N>>,
        scalars: &Vec<Self::AssignedScalar>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        assert!(CONFIG_WINDOW_SIZE >= 1usize);
        assert!(points.len() == scalars.len());
        let windows_in_be = scalars
            .iter()
            .map(|s| self.decompose_scalar::<CONFIG_WINDOW_SIZE>(ctx, s))
            .collect::<Result<Vec<_>, _>>()?;
        let windows_pair_in_be = windows_in_be
            .chunks(2)
            .collect::<Vec<_>>();


        let identity = self.assign_identity(ctx)?;
        let point_candidates: Vec<Vec<AssignedPoint<_, _>>> = points
            .iter_mut()
            .map(|a| {
                let mut candidates = vec![identity.clone(), a.clone()];
                for i in 2..(1 << CONFIG_WINDOW_SIZE) {
                    let mut ai = self.add(ctx, &mut candidates[i - 1], a)?;
                    self.curvature(ctx, &mut ai)?;
                    candidates.push(ai)
                }
                Ok(candidates)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let pick_candidate = |ctx: &mut Context<N>,
                              pi: usize,
                              bits_in_le: &[AssignedCondition<N>; CONFIG_WINDOW_SIZE]|
         -> Result<AssignedPoint<C, N>, Error> {
            let mut curr_candidates: Vec<AssignedPoint<_, _>> = point_candidates[pi].clone();
            for bit in bits_in_le {
                let mut next_candidates = vec![];
                let len = curr_candidates.len() / 2;
                let mut it = curr_candidates.iter_mut();

                for _ in 0..len {
                    let a0 = it.next().ok_or(Error::Synthesis)?;
                    let a1 = it.next().ok_or(Error::Synthesis)?;

                    let cell = self.bisec_point_with_curvature(ctx, bit, a1, a0)?;
                    next_candidates.push(cell);
                }
                curr_candidates = next_candidates;
            }

            Ok(curr_candidates.first().unwrap().clone())
        };


        /* for adjacent points, we pre calculate the sum of two points $c_a * p_a + c_b * p_b$ */
        let point_sum_groups = point_candidates.chunks(2); // we group the adjacent points by pairs

        let point_pair_candidate: Vec<Vec<AssignedPoint<_, _>>> = point_sum_groups
            .into_iter()
            .map(|pair| {
                let mut cache = pair[0].clone();
                for d in 1..(1 << CONFIG_WINDOW_SIZE) {
                    for r in 0..(1<<CONFIG_WINDOW_SIZE) {
                        if pair.len() == 2 {
                            let mut ai = self.add(ctx, &mut cache[r], &pair[1][d])?;
                            self.curvature(ctx, &mut ai)?;
                            cache.push(ai)
                        }
                    }
                };
                Ok(cache)
            })
            .collect::<Result<Vec<_>, Error>>()?;


        //println!("size of calculate cache:{:?}", *ctx.offset - start_offset);

        let pick_candidate_of_pair = |ctx: &mut Context<N>,
                              pi: usize,
                              lbits_in_le: &[AssignedCondition<N>; CONFIG_WINDOW_SIZE],
                              hbits_in_le: &[AssignedCondition<N>; CONFIG_WINDOW_SIZE]|
         -> Result<AssignedPoint<C, N>, Error> {
            let mut curr_candidates: Vec<AssignedPoint<_, _>> = point_pair_candidate[pi].clone();
            for bit in lbits_in_le {
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
            for bit in hbits_in_le {
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


        let mut acc: Option<AssignedPoint<C, N>> = None;

        let mut round_size = None;

        let start_offset = *ctx.offset;

        for wi in 0..windows_in_be[0].len() {
            let mut get_inner =
                |round_size: Option<usize>| -> Result<(usize, AssignedPoint<C, N>), Error> {
                    match (round_size, ctx.in_shape_mode()) {
                        (Some(rsize), true) => {
                            ctx.expand(
                                rsize,
                                acc.as_ref().unwrap().z.cell,
                                acc.as_ref().unwrap().z.value,
                            )?;
                            // Hack: acc is not accurate but we depends on overflow bits
                            Ok((rsize, acc.clone().unwrap())) //Hack: In shape phase we dont care the result
                        }
                        _ => {
                            let c = *ctx.offset;
                            let mut inner_acc = None;
                            for pi in 0..points.len()/2 {
                                let mut ci = pick_candidate_of_pair(ctx, pi,
                                  &windows_pair_in_be[pi][0][wi],
                                  &windows_pair_in_be[pi][1][wi])?;
                                match inner_acc {
                                    None => inner_acc = Some(ci),
                                    Some(_inner_acc) => {
                                        let p = self.add_unsafe(ctx, &mut ci, &_inner_acc)?;
                                        //let p = self.add(ctx, &mut ci, &_inner_acc)?;
                                        inner_acc = Some(p);
                                    }
                                }
                            }
                            if points.len() % 2 == 1 {
                                let pi = points.len() - 1;
                                let mut ci = pick_candidate(ctx, pi, &windows_in_be[pi][wi])?;
                                match inner_acc {
                                    None => inner_acc = Some(ci),
                                    Some(_inner_acc) => {
                                        let p = self.add_unsafe(ctx, &mut ci, &_inner_acc)?;
                                        //let p = self.add(ctx, &mut ci, &_inner_acc)?;
                                        inner_acc = Some(p);
                                    }
                                }
                            }
                            let rsize = *ctx.offset - c;
                            // Record the size of each around so that we can skip them in shape mode.
                            Ok((rsize, inner_acc.unwrap()))
                        }
                    }
                };

            let (rsize, mut inner_acc) = get_inner(round_size)?;
            if wi != 0 {
                round_size = Some(rsize);
            }

            match acc {
                None => acc = Some(inner_acc),
                Some(mut _acc) => {
                    for _ in 0..CONFIG_WINDOW_SIZE {
                        //_acc = self.double_unsafe(ctx, &mut _acc)?;
                        _acc = self.double(ctx, &mut _acc)?;
                    }
                    _acc = self.add(ctx, &mut inner_acc, &_acc)?;
                    acc = Some(_acc);
                }
            }
        }

        let total_offset = *ctx.offset - start_offset;
        println!("roundsize is {:?}", total_offset);

        Ok(acc.unwrap())
    }
    fn constant_mul(
        &self,
        ctx: &mut Context<N>,
        a: C::CurveExt,
        s: &Self::AssignedScalar,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let bits_be = self.decompose_scalar::<2usize>(ctx, s)?;
        let mut identity =
            self.assign_constant_point_with_curvature(ctx, C::CurveExt::identity())?;
        let mut acc = None;
        let mut base = a;
        for bit_le in bits_be.iter().rev() {
            let candidate00 = &mut identity;
            let candidate01 = &mut self.assign_constant_point_with_curvature(ctx, base + base)?;
            let candidate10 = &mut self.assign_constant_point_with_curvature(ctx, base)?;
            let candidate11 =
                &mut self.assign_constant_point_with_curvature(ctx, base + base + base)?;

            let candidate0 =
                &mut self.bisec_point_with_curvature(ctx, &bit_le[0], candidate10, candidate00)?;
            let candidate1 =
                &mut self.bisec_point_with_curvature(ctx, &bit_le[0], candidate11, candidate01)?;

            let mut slot =
                self.bisec_point_with_curvature(ctx, &bit_le[1], candidate1, candidate0)?;

            match acc {
                None => acc = Some(slot),
                Some(acc_) => acc = Some(self.add(ctx, &mut slot, &acc_)?),
            }
            base = base + base + base + base;
        }

        Ok(acc.unwrap())
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
                let integer_chip = self.integer_chip();
                let mut x_square = integer_chip.square(ctx, &mut a.x)?;
                let mut numerator = integer_chip.mul_small_constant(ctx, &mut x_square, 3usize)?;
                let mut denominator = integer_chip.mul_small_constant(ctx, &mut a.y, 2usize)?;

                let (z, v) = integer_chip.div(ctx, &mut numerator, &mut denominator)?;
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
        let integer_chip = self.integer_chip();
        let v = integer_chip.bisec(ctx, cond, &a.v, &b.v)?;
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
        let integer_chip = self.integer_chip();
        let x = integer_chip.bisec(ctx, cond, &a.x, &b.x)?;
        let y = integer_chip.bisec(ctx, cond, &a.y, &b.y)?;
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
        let integer_chip = self.integer_chip();
        let x = integer_chip.bisec(ctx, cond, &a.x, &b.x)?;
        let y = integer_chip.bisec(ctx, cond, &a.y, &b.y)?;
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
        let integer_chip = self.integer_chip();

        let l = &mut lambda.v;

        // cx = lambda ^ 2 - a.x - b.x
        let cx = {
            let l_square = integer_chip.square(ctx, l)?;
            let t = integer_chip.sub(ctx, &l_square, &a.x)?;

            integer_chip.sub(ctx, &t, &b.x)?
        };

        let cy = {
            let mut t = integer_chip.sub(ctx, &a.x, &cx)?;
            let t = integer_chip.mul(ctx, &mut t, l)?;

            integer_chip.sub(ctx, &t, &a.y)?
        };
        Ok(AssignedPoint::new(cx, cy, lambda.z))
    }

    /* special addition which assumes that a and b are not equal and not zero */
    fn add_unsafe (
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_chip = self.integer_chip();

        let mut diff_x = integer_chip.sub(ctx, &a.x, &b.x)?;
        let mut diff_y = integer_chip.sub(ctx, &a.y, &b.y)?;
        let (x_eq, tangent) = integer_chip.div(ctx, &mut diff_y, &mut diff_x)?;

        /* Assert non-eq diff_y thus no zero is produced and no curvative case */
        let is_zero = integer_chip.is_zero(ctx, &mut diff_x)?;
        base_gate.assert_constant(ctx, &is_zero.into(), N::one())?;

        /* Not necessary to compute curvature for the case of a=b */
        let tangent = AssignedCurvature::new(tangent, x_eq);
        let mut lambda = tangent;

        let p = self.lambda_to_point(ctx, &mut lambda, a, b)?;
        /* The idea is that we make sure the rhs=accumulator is not identity */
        let p = self.bisec_point(ctx, &a.z, b, &p)?;
        let p = self.bisec_point(ctx, &b.z, a, &p)?;
        Ok(p)
    }

    fn add(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
        b: &AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let base_gate = self.base_gate();
        let integer_chip = self.integer_chip();

        let mut diff_x = integer_chip.sub(ctx, &a.x, &b.x)?;
        let mut diff_y = integer_chip.sub(ctx, &a.y, &b.y)?;
        let (x_eq, tangent) = integer_chip.div(ctx, &mut diff_y, &mut diff_x)?;

        let y_eq = integer_chip.is_zero(ctx, &mut diff_y)?;
        let eq = base_gate.and(ctx, &x_eq, &y_eq)?;

        let tangent = AssignedCurvature::new(tangent, x_eq);
        let curvature = self.curvature(ctx, a)?;
        let mut lambda = self.bisec_curvature(ctx, &eq, curvature, &tangent)?;

        let p = self.lambda_to_point(ctx, &mut lambda, a, b)?;
        let p = self.bisec_point(ctx, &a.z, b, &p)?;
        let p = self.bisec_point(ctx, &b.z, a, &p)?;

        Ok(p)
    }

    fn double_unsafe(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let curvature = self.curvature(ctx, a)?;
        let p = self.lambda_to_point(ctx, &mut curvature.clone(), a, a)?;
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
        let x = coordinates.map(|v| *v.x()).unwrap_or(C::Base::zero());
        let y = coordinates.map(|v| *v.y()).unwrap_or(C::Base::zero());
        let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());

        let base_gate = self.base_gate();
        let integer_chip = self.integer_chip();
        let x = integer_chip.assign_constant(ctx, x)?;
        let y = integer_chip.assign_constant(ctx, y)?;
        let z = base_gate.assign_constant(ctx, z)?;

        Ok(AssignedPoint::new(x, y, z.into()))
    }
    fn assign_constant_point_with_curvature(
        &self,
        ctx: &mut Context<N>,
        c: C::CurveExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let coordinates = c.to_affine().coordinates();
        let x = coordinates.map(|v| *v.x()).unwrap_or(C::Base::zero());
        let y = coordinates.map(|v| *v.y()).unwrap_or(C::Base::zero());
        let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());

        let base_gate = self.base_gate();
        let integer_chip = self.integer_chip();

        let curvature_v =
            integer_chip.assign_constant(ctx, y * x.invert().unwrap_or(C::Base::zero()))?;
        let curvature_z = base_gate.assign_constant(
            ctx,
            if x == C::Base::zero() {
                N::one()
            } else {
                N::zero()
            },
        )?;

        let x = integer_chip.assign_constant(ctx, x)?;
        let y = integer_chip.assign_constant(ctx, y)?;
        let z = base_gate.assign_constant(ctx, z)?;

        Ok(AssignedPoint::new_with_curvature(
            x,
            y,
            z.into(),
            Some(AssignedCurvature::new(curvature_v, curvature_z.into())),
        ))
    }
    fn assign_point(
        &self,
        ctx: &mut Context<N>,
        c: C::CurveExt,
    ) -> Result<AssignedPoint<C, N>, Error> {
        let coordinates = c.to_affine().coordinates();
        let x = coordinates.map(|v| *v.x()).unwrap_or(C::Base::zero());
        let y = coordinates.map(|v| *v.y()).unwrap_or(C::Base::zero());
        let z = N::conditional_select(&N::zero(), &N::one(), c.to_affine().is_identity());

        let base_gate = self.base_gate();
        let integer_chip = self.integer_chip();
        let mut x = integer_chip.assign_w(ctx, &x)?;
        let mut y = integer_chip.assign_w(ctx, &y)?;
        let z = base_gate.assign(ctx, z)?;

        // Constrain y^2 = x^3 + b
        let b = integer_chip.assign_constant(ctx, C::b())?;
        let mut y2 = integer_chip.square(ctx, &mut y)?;
        let mut x2 = integer_chip.square(ctx, &mut x)?;
        let x3 = integer_chip.mul(ctx, &mut x2, &mut x)?;
        let mut right = integer_chip.add(ctx, &x3, &b)?;
        let eq = integer_chip.is_equal(ctx, &mut y2, &mut right)?;
        let eq_or_identity = base_gate.or(ctx, &eq, &z.into())?;
        base_gate.assert_true(ctx, &eq_or_identity)?;

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
        let zero = self.integer_chip().assign_constant(ctx, C::Base::zero())?;
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
        let integer_chip = self.integer_chip();
        let eq_x = integer_chip.is_equal(ctx, &mut a.x, &mut b.x)?;
        let eq_y = integer_chip.is_equal(ctx, &mut a.y, &mut b.y)?;
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
        let y = self.integer_chip().neg(ctx, &a.y)?;
        let z = a.z;

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
    fn reduce(
        &self,
        ctx: &mut Context<N>,
        a: &mut AssignedPoint<C, N>,
    ) -> Result<AssignedPoint<C, N>, Error> {
        self.integer_chip().reduce(ctx, &mut a.x)?;
        self.integer_chip().reduce(ctx, &mut a.y)?;
        let z = a.z;

        let identity = self.assign_identity(ctx)?;
        self.bisec_point(ctx, &z, &identity, a)
    }
}
