use super::{AssignedInteger, IntegerGate, IntegerGateOps};
use crate::{
    gates::base_gate::{
        five::{MUL_COLUMNS, VAR_COLUMNS},
        AssignedCondition, AssignedValue, RegionAux,
    },
    pair, pair_empty,
    utils::{bn_to_field, decompose_bn, field_to_bn},
    PREREQUISITE_CHECK,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use num_bigint::BigUint;
use num_integer::Integer;

const LIMBS: usize = 4usize;
const LIMB_COMMON_WIDTH_OF_COMMON_RANGE: usize = 4usize;
const COMMON_RANGE_BITS: usize = 17usize;
const LIMB_COMMON_WIDTH: usize = LIMB_COMMON_WIDTH_OF_COMMON_RANGE * COMMON_RANGE_BITS; // 68

const OVERFLOW_LIMIT_SHIFT: usize = 6usize;
const OVERFLOW_LIMIT: usize = 1usize << OVERFLOW_LIMIT_SHIFT;

const OVERFLOW_THRESHOLD_SHIFT: usize = OVERFLOW_LIMIT_SHIFT - 1;
const OVERFLOW_THRESHOLD: usize = 1usize << OVERFLOW_THRESHOLD_SHIFT;

pub type FiveColumnIntegerGate<'a, 'b, W, N> = IntegerGate<
    'a,
    'b,
    W,
    N,
    VAR_COLUMNS,
    MUL_COLUMNS,
    COMMON_RANGE_BITS,
    LIMBS,
    LIMB_COMMON_WIDTH,
>;

impl<'a, 'b, W: FieldExt, N: FieldExt> FiveColumnIntegerGate<'a, 'b, W, N> {
    fn find_w_modulus_ceil(&self, a: &AssignedInteger<W, N, LIMBS>) -> [BigUint; LIMBS] {
        let max_a = (a.overflows + 1) * (BigUint::from(1u64) << self.helper.w_ceil_bits);
        let (n, rem) = max_a.div_rem(&self.helper.w_modulus);
        let n = if rem.gt(&BigUint::from(0u64)) {
            n + 1u64
        } else {
            n
        };

        let mut upper = n * &self.helper.w_modulus;

        let mut limbs = vec![];
        for _ in 0..LIMBS - 1 {
            let rem = upper.mod_floor(&self.helper.limb_modulus)
                + (a.overflows + 1) * &self.helper.limb_modulus;
            upper = (upper - &rem).div_floor(&self.helper.limb_modulus);
            limbs.push(rem);
        }
        limbs.push(upper);
        limbs.try_into().unwrap()
    }

    fn is_pure_zero(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let sum = self.base_gate.sum_with_constant(
            r,
            a.limbs_le.iter().map(|v| (v, one)).collect(),
            zero,
        )?;
        let is_zero = self.base_gate.is_zero(r, &sum)?;
        Ok(is_zero)
    }

    fn is_pure_w_modulus(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedCondition<N>, Error> {
        let one = N::one();
        let native_a = self.native(r, a)?;

        if PREREQUISITE_CHECK {
            let bn_one = BigUint::from(1u64);
            let limb_modulus = &bn_one << LIMB_COMMON_WIDTH;
            let lcm = self.helper.n_modulus.lcm(&limb_modulus);
            let w_ceil_modulus = &bn_one << self.helper.w_ceil_bits;
            assert!(lcm >= w_ceil_modulus);
        }

        // TO OPTIMIZE: the two can be merged.
        let native_diff =
            self.base_gate
                .sum_with_constant(r, vec![(&native_a, one)], -self.helper.w_native)?;
        let is_native_eq = self.base_gate.is_zero(r, &native_diff)?;

        // TO OPTIMIZE: the two can be merged.
        let limb0_diff = self.base_gate.sum_with_constant(
            r,
            vec![(&a.limbs_le[0], one)],
            -bn_to_field::<N>(&self.helper.w_modulus_limbs_le[0]),
        )?;
        let is_limb0_eq = self.base_gate.is_zero(r, &limb0_diff)?;

        self.base_gate.and(r, &is_native_eq, &is_limb0_eq)
    }
}

impl<'a, 'b, W: FieldExt, N: FieldExt>
    IntegerGateOps<W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS, LIMBS, LIMB_COMMON_WIDTH>
    for FiveColumnIntegerGate<'a, 'b, W, N>
{
    fn assign_nonleading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        let bn = field_to_bn(&n);
        let chunks = decompose_bn::<N>(&bn, COMMON_RANGE_BITS, LIMB_COMMON_WIDTH_OF_COMMON_RANGE);
        let mut schema: Vec<_> = chunks.into_iter().rev().map(|(a, b)| pair!(a, b)).collect();
        schema.push(pair!(n, -one));

        let cells = self
            .range_gate
            .one_line_in_common_range(r, schema, zero, (vec![], zero))?;
        Ok(cells[VAR_COLUMNS - 1])
    }

    fn assign_n_floor_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error> {
        let leading_limb_bits = self.helper.n_floor_bits as usize % LIMB_COMMON_WIDTH;
        if leading_limb_bits == 0 {
            self.assign_nonleading_limb(r, n)
        } else {
            let zero = N::zero();
            let one = N::one();

            let bn = field_to_bn(&n);
            let nchunks = leading_limb_bits.div_ceil(&COMMON_RANGE_BITS);
            assert!(nchunks < VAR_COLUMNS);
            let chunks = decompose_bn::<N>(&bn, COMMON_RANGE_BITS, nchunks);

            let mut schema: Vec<_> = chunks.into_iter().rev().map(|(a, b)| pair!(a, b)).collect();
            schema.resize_with(VAR_COLUMNS - 1, || pair_empty!(N));
            schema.push(pair!(n, -one));

            let cells = self.range_gate.one_line_in_n_floor_leading_range(
                r,
                schema,
                zero,
                (vec![], zero),
            )?;
            Ok(cells[VAR_COLUMNS - 1])
        }
    }

    fn assign_w_ceil_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error> {
        let leading_limb_bits = self.helper.w_ceil_bits as usize % LIMB_COMMON_WIDTH;
        if leading_limb_bits == 0 {
            self.assign_nonleading_limb(r, n)
        } else {
            let zero = N::zero();
            let one = N::one();

            let bn = field_to_bn(&n);
            let nchunks = leading_limb_bits.div_ceil(&COMMON_RANGE_BITS);
            assert!(nchunks < VAR_COLUMNS);
            let chunks = decompose_bn::<N>(&bn, COMMON_RANGE_BITS, nchunks);
            let mut schema: Vec<_> = chunks.into_iter().rev().map(|(a, b)| pair!(a, b)).collect();
            schema.resize_with(VAR_COLUMNS - 1, || pair_empty!(N));
            schema.push(pair!(n, -one));

            let cells = self.range_gate.one_line_in_w_ceil_leading_range(
                r,
                schema,
                zero,
                (vec![], zero),
            )?;
            Ok(cells[VAR_COLUMNS - 1])
        }
    }

    fn assign_d_leading_limb(&self, r: &mut RegionAux<N>, n: N) -> Result<AssignedValue<N>, Error> {
        let leading_limb_bits = self.helper.d_bits as usize % LIMB_COMMON_WIDTH;
        if leading_limb_bits == 0 {
            self.assign_nonleading_limb(r, n)
        } else {
            let zero = N::zero();
            let one = N::one();

            let leading_cell_bits = leading_limb_bits % COMMON_RANGE_BITS;
            let chunks = (leading_limb_bits / COMMON_RANGE_BITS)
                + if leading_cell_bits == 0 { 0 } else { 1 };
            let bn = field_to_bn(&n);
            let chunks = decompose_bn::<N>(&bn, COMMON_RANGE_BITS, chunks);
            let mut schema: Vec<_> = chunks.into_iter().rev().map(|(a, b)| pair!(a, b)).collect();
            schema.resize_with(VAR_COLUMNS - 1, || pair_empty!(N));
            schema.push(pair!(n, -one));

            let cells =
                self.range_gate
                    .one_line_in_d_leading_range(r, schema, zero, (vec![], zero))?;
            Ok(cells[VAR_COLUMNS - 1])
        }
    }

    fn assign_d(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<[AssignedValue<N>; LIMBS], Error> {
        let limbs_value_le = self.helper.bn_to_limb_n_le(v);

        let mut limbs = vec![];

        for (i, limb) in limbs_value_le.into_iter().rev().enumerate() {
            let cell = if i == 0 {
                self.assign_d_leading_limb(r, limb)?
            } else {
                self.assign_nonleading_limb(r, limb)?
            };
            limbs.push(cell);
        }

        limbs.reverse();

        Ok(limbs.try_into().unwrap())
    }

    fn assign_w(&self, r: &mut RegionAux<N>, v: &W) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let limbs_value_le = self.helper.w_to_limb_n_le(v);

        let mut limbs = vec![];

        for (i, limb) in limbs_value_le.into_iter().rev().enumerate() {
            let cell = if i == 0 {
                self.assign_w_ceil_leading_limb(r, limb)?
            } else {
                self.assign_nonleading_limb(r, limb)?
            };
            limbs.push(cell);
        }

        limbs.reverse();

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0usize))
    }

    fn assign_integer(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<[AssignedValue<N>; LIMBS], Error> {
        let limbs_value_le = self.helper.bn_to_limb_n_le(v);

        let mut limbs = vec![];

        for limb in limbs_value_le {
            let cell = self.assign_nonleading_limb(r, limb)?;
            limbs.push(cell);
        }

        Ok(limbs.try_into().unwrap())
    }

    fn reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        if a.overflows == 0 {
            return Ok(a.clone());
        }

        assert!(a.overflows < OVERFLOW_LIMIT);

        let zero = N::zero();
        let one = N::one();

        if PREREQUISITE_CHECK {
            // We will first find (d, rem) that a = d * w_modulus + rem and add following constraints
            // 1. d is limited by RANGE_BITS, e.g. 1 << 17
            // 2. rem is limited by LIMBS, e.g. 1 << w_max_bits
            // 3. d * w_modulus + rem - a = 0 on native
            // 4. d * w_modulus + rem - a = 0 on LIMB_MODULUS (2 ^ 68)
            // so d * w_modulus + rem - a = 0 on LCM(native, LIMB_MODULUS)

            // assert for configurations
            // 1. max d * w_modulus + rem < LCM(native, LIMB_MODULUS)
            // 2. max a < LCM(native, LIMB_MODULUS)
            // 3. max a < max d * w_modulus + rem
            let lcm = self.helper.n_modulus.lcm(&self.helper.limb_modulus);
            let max_assigned_integer_unit = BigUint::from(1u64) << self.helper.w_ceil_bits;
            let max_l = &max_assigned_integer_unit * OVERFLOW_LIMIT;
            let max_r =
                &self.helper.w_modulus * (1u64 << COMMON_RANGE_BITS) + &max_assigned_integer_unit;
            assert!(lcm >= max_l);
            assert!(lcm >= max_r);
            assert!(max_r >= max_l);

            // We know,
            // 1. d * w_modulus + rem - a = 0 on LIMB_MODULUS <-> d * w_modulus[0] + rem[0] - a[0] = 0 on LIMB_MODULUS.
            // 2. because a[0] < OVERFLOW_LIMIT * LIMB_MODULUS,
            // 3. d < OVERFLOW_LIMIT * 2 (because a < OVERFLOW_LIMIT * max_assigned_integer_unit < OVERFLOW_LIMIT * w * 2)

            // let u = d * w_modulus[0] + rem[0] + OVERFLOW_LIMIT * LIMB_MODULUS - a[0]
            // u < OVERFLOW_LIMIT * 2 * LIMB_MODULUS + LIMB_MODULUS + OVERFLOW_LIMIT * LIMB_MODULUS
            // -> u < (OVERFLOW_LIMIT * 3 + 1 + OVERFLOW_LIMIT) * LIMB_MODULUS
            assert!((OVERFLOW_LIMIT * 3 + 1 + OVERFLOW_LIMIT) < 1 << COMMON_RANGE_BITS);
            // -> u < (1 << COMMON_RANGE_BITS) * LIMB_MODULUS
            // So, we can find a v in [0..1 << COMMON_RANGE_BITS) that v * LIMB_MODULUS = u
        }

        let a_bn = a.bn(&self.helper.limb_modulus);
        let (d, rem) = a_bn.div_rem(&self.helper.w_modulus);
        let u = &d * &self.helper.w_modulus_limbs_le[0]
            + &self.helper.bn_to_limb_le(&rem)[0]
            + &self.helper.limb_modulus * OVERFLOW_LIMIT
            - field_to_bn(&a.limbs_le[0].value);

        let v = u.div_floor(&self.helper.limb_modulus);

        // 1. Add range check for (d, v).
        let mut rem = self.assign_w(r, &bn_to_field(&rem))?;
        let (d, v) = {
            let cells = self.range_gate.one_line_in_common_range(
                r,
                vec![
                    pair!(bn_to_field::<N>(&d), zero),
                    pair!(bn_to_field::<N>(&v), zero),
                ],
                zero,
                (vec![], zero),
            )?;
            (cells[0], cells[1])
        };

        // 2. Add constrains native.
        let rem_native = self.native(r, &mut rem)?;
        let a_native = self.native(r, a)?;
        self.base_gate.one_line_add(
            r,
            vec![
                pair!(a_native, -one),
                pair!(&d, self.helper.w_native),
                pair!(rem_native, one),
            ],
            zero,
        )?;

        // 3. Add constrains on limb[0].
        self.base_gate.one_line_add(
            r,
            vec![
                pair!(&d, bn_to_field(&self.helper.w_modulus_limbs_le[0])),
                pair!(&rem.limbs_le[0], one),
                pair!(&a.limbs_le[0], -one),
                pair!(&v, -bn_to_field::<N>(&self.helper.limb_modulus)),
            ],
            bn_to_field(&(&self.helper.limb_modulus * OVERFLOW_LIMIT)),
        )?;

        Ok(rem)
    }

    fn conditionally_reduce(
        &self,
        r: &mut RegionAux<N>,
        mut a: AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        if a.overflows >= OVERFLOW_THRESHOLD {
            self.reduce(r, &mut a)
        } else {
            Ok(a)
        }
    }

    fn native<'c>(
        &self,
        r: &mut RegionAux<N>,
        a: &'c mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<&'c AssignedValue<N>, Error> {
        let new_native = match &mut a.native {
            Some(_) => None,
            None => {
                let zero = N::zero();
                let schemas = a.limbs_le.iter().zip(self.helper.limb_modulus_exps);
                let cell = self
                    .base_gate
                    .sum_with_constant(r, schemas.collect(), zero)?;
                Some(cell)
            }
        };

        match new_native {
            None => (),
            Some(native) => a.set_native(native),
        }

        match &a.native {
            Some(n) => Ok(n),
            None => Err(Error::Synthesis),
        }
    }

    fn assert_equal(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<(), Error> {
        // TODO: can be optimized.
        let zero = N::zero();
        let mut diff = self.sub(r, a, b)?;
        let mut diff = self.reduce(r, &mut diff)?;

        let diff_native = self.native(r, &mut diff)?;
        self.base_gate.assert_constant(r, diff_native, zero)?;
        self.base_gate.assert_constant(r, &diff.limbs_le[0], zero)?;
        Ok(())
    }

    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let mut limbs = vec![];

        for i in 0..LIMBS {
            let value = self.base_gate.add(r, &a.limbs_le[i], &b.limbs_le[i])?;
            limbs.push(value)
        }

        let res = AssignedInteger::new(limbs.try_into().unwrap(), a.overflows + b.overflows + 1);
        self.conditionally_reduce(r, res)
    }

    fn sub(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let one = N::one();
        let upper_limbs = self.find_w_modulus_ceil(b);

        let mut limbs = vec![];
        for i in 0..LIMBS {
            let cell = self.base_gate.sum_with_constant(
                r,
                vec![(&a.limbs_le[i], one), (&b.limbs_le[i], -one)],
                bn_to_field(&upper_limbs[i]),
            )?;
            limbs.push(cell);
        }

        let overflow = a.overflows + (b.overflows + 1) + 1;
        let res = AssignedInteger::new(limbs.try_into().unwrap(), overflow);
        self.conditionally_reduce(r, res)
    }

    fn neg(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let one = N::one();
        let upper_limbs = self.find_w_modulus_ceil(a);

        let mut limbs = vec![];
        for i in 0..LIMBS {
            let cell = self.base_gate.sum_with_constant(
                r,
                vec![(&a.limbs_le[i], -one)],
                bn_to_field(&upper_limbs[i]),
            )?;
            limbs.push(cell);
        }

        let overflow = a.overflows + 1;
        let res = AssignedInteger::new(limbs.try_into().unwrap(), overflow);
        self.conditionally_reduce(r, res)
    }

    fn mul(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
        b: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let zero = N::zero();
        let one = N::one();
        let bn_one = BigUint::from(1u64);

        if PREREQUISITE_CHECK {
            // Find (d, rem), that a * b = d * w_modulus + r
            // 1. limit r in [0..1 << w_ceil_bits), e.g. 248
            // 2. limit d in [0..1 << LIMBS * LIMB_COMMON_WIDTH], e.g. 4 * 68 = 272
            // 3. Add constraints to ensure the equation on native, and 1 << LIMBS * LIMB_COMMON_WIDTH

            let lcm = self.helper.integer_modulus.lcm(&self.helper.n_modulus);
            let max_a = (&bn_one << self.helper.w_ceil_bits) * OVERFLOW_LIMIT;
            let max_b = (&bn_one << self.helper.w_ceil_bits) * OVERFLOW_LIMIT;
            let max_l = max_a * max_b;

            let max_d = &bn_one << &self.helper.d_bits;
            let max_w = &self.helper.w_modulus;
            let max_rem = &bn_one << self.helper.w_ceil_bits;
            let max_r = max_d * max_w + max_rem;

            assert!(max_l <= lcm);
            assert!(max_r <= lcm);
            assert!(max_l <= max_r);
        }

        let a_bn = a.bn(&self.helper.limb_modulus);
        let b_bn = b.bn(&self.helper.limb_modulus);
        let (d, rem) = (a_bn * b_bn).div_rem(&self.helper.w_modulus);

        let mut rem = self.assign_w(r, &bn_to_field(&rem))?;
        let d = self.assign_d(r, &d)?;

        // 1. Add contraints on integer modulus
        let neg_w = &self.helper.integer_modulus - &self.helper.w_modulus;
        let neg_w_limbs_le = self
            .helper
            .bn_to_limb_le(&neg_w)
            .map(|v| bn_to_field::<N>(&v));

        let mut limbs = vec![];
        for pos in 0..LIMBS {
            // e.g. l0 = a0 * b0 - d0 * w0
            // e.g. l1 = a1 * b0 + a0 * b1 - d1 * w0 - d0 * w1
            // ...
            let l = self.base_gate.mul_add_with_next_line(
                r,
                (0..pos + 1)
                    .map(|i| {
                        (
                            &a.limbs_le[i],
                            &b.limbs_le[pos - i],
                            &d[i],
                            neg_w_limbs_le[pos - i].clone(),
                        )
                    })
                    .collect(),
            )?;

            limbs.push(l);
        }

        if PREREQUISITE_CHECK {
            // each limbs[i] = sum(a[j] * b[i - j] + d[i] * neg_w[i - j]), 0 <= j <= i, 0 <= i < LIMBS
            // -> limbs[i] < LIMBS * max(a[j] * b[i - j] + d[i] * neg_w[i - j])
            // -> limbs[i] < LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) * LIMB_MODULUS^2

            // To avoid minus overflow,
            // let u0 = limb0 - rem0 + (limb1 - rem1) * limb_modulus + limb_modulus * limb_modulus
            // -> u < limb0 + limb1 * LIMB_MODULUS + LIMB_MODULUS * LIMB_MODULUS
            // -> u < LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) * LIMB_MODULUS^3
            //      + LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) * LIMB_MODULUS^2
            //      + LIMB_MODULUS ^ 2
            // let v = u / LIMB_MODULUS^2
            // -> v < LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) * LIMB_MODULUS
            //      + LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) + 1
            let max_v = &self.helper.limb_modulus * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1) * LIMBS
                + LIMBS * (OVERFLOW_LIMIT * OVERFLOW_LIMIT + 1)
                + 1usize;

            // Ensure we can v in with a n_floor_leading limb and a common limb
            assert!(max_v < &bn_one << (self.helper.n_floor_bits - LIMB_COMMON_WIDTH * 2));
        }

        let u0 = (limbs[1].value - rem.limbs_le[1].value) * self.helper.limb_modulus_on_n
            + limbs[0].value
            - rem.limbs_le[0].value
            + self.helper.limb_modulus_exps[2];
        let v0 = u0 * self.helper.limb_modulus_exps[2].invert().unwrap();
        let (v0_h, v0_l) = field_to_bn(&v0).div_rem(&self.helper.limb_modulus);

        let u1 = v0 - one + limbs[2].value - rem.limbs_le[2].value
            + (limbs[3].value - rem.limbs_le[3].value) * self.helper.limb_modulus_on_n;
        let v1 = u1 * self.helper.limb_modulus_exps[2].invert().unwrap();
        let (v1_h, v1_l) = field_to_bn(&v1).div_rem(&self.helper.limb_modulus);

        let v0_h = self.assign_n_floor_leading_limb(r, bn_to_field(&v0_h))?;
        let v0_l = self.assign_nonleading_limb(r, bn_to_field(&v0_l))?;
        let v1_h = self.assign_n_floor_leading_limb(r, bn_to_field(&v1_h))?;
        let v1_l = self.assign_nonleading_limb(r, bn_to_field(&v1_l))?;

        let u0 = self.base_gate.sum_with_constant(
            r,
            vec![
                (&limbs[0], one),
                (&limbs[1], self.helper.limb_modulus_on_n.clone()),
                (&rem.limbs_le[0], -one),
                (&rem.limbs_le[1], -self.helper.limb_modulus_on_n.clone()),
            ],
            self.helper.limb_modulus_exps[2],
        )?;

        self.base_gate.one_line_add(
            r,
            vec![
                pair!(&u0, -one),
                pair!(&v0_l, self.helper.limb_modulus_exps[2]),
                pair!(&v0_h, self.helper.limb_modulus_exps[3]),
            ],
            zero,
        )?;

        let u1 = self.base_gate.sum_with_constant(
            r,
            vec![
                (&limbs[2], one),
                (&limbs[3], self.helper.limb_modulus_on_n.clone()),
                (&rem.limbs_le[2], -one),
                (&rem.limbs_le[3], -self.helper.limb_modulus_on_n.clone()),
            ],
            zero,
        )?;
        self.base_gate.one_line_add(
            r,
            vec![
                pair!(&u1, one),
                pair!(&v0_l, self.helper.limb_modulus_exps[0]),
                pair!(&v0_h, self.helper.limb_modulus_exps[1]),
                pair!(&v1_l, -self.helper.limb_modulus_exps[2]),
                pair!(&v1_h, -self.helper.limb_modulus_exps[3]),
            ],
            -one,
        )?;

        // Add constrains on native modulus
        let a_native = self.native(r, a)?;
        let b_native = self.native(r, b)?;
        let d_native = self.base_gate.sum_with_constant(
            r,
            d.iter().zip(self.helper.limb_modulus_exps).collect(),
            zero,
        )?;
        let rem_native = self.native(r, &mut rem)?;

        self.base_gate.one_line(
            r,
            vec![
                pair!(a_native, zero),
                pair!(b_native, zero),
                pair!(&d_native, -self.helper.w_native),
                pair!(rem_native, -one),
            ],
            zero,
            (vec![one], zero),
        )?;

        Ok(rem)
    }

    fn assigned_constant(
        &self,
        r: &mut RegionAux<N>,
        w: W,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let limbs_value = self.helper.w_to_limb_n_le(&w);

        let mut limbs = vec![];
        for limb in limbs_value {
            let cell = self.base_gate.assign_constant(r, limb)?;
            limbs.push(cell);
        }

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0usize))
    }

    fn is_zero(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedCondition<N>, Error> {
        let mut a = self.reduce(r, a)?;
        let is_zero = self.is_pure_zero(r, &a)?;
        let is_w_modulus = self.is_pure_w_modulus(r, &mut a)?;

        self.base_gate.or(r, &is_zero, &is_w_modulus)
    }
}
