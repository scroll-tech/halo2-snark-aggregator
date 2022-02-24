use crate::{
    gates::{
        base_gate::{AssignedValue, BaseGate, RegionAux},
        range_gate::RangeGate,
    },
    utils::{bn_to_field, field_to_bn, get_d_range_bits_in_mul},
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use num_bigint::BigUint;
use std::{marker::PhantomData, vec};

pub mod five;

#[derive(Clone)]
pub struct AssignedInteger<W: FieldExt, N: FieldExt, const LIMBS: usize> {
    limbs_le: [AssignedValue<N>; LIMBS],
    native: Option<AssignedValue<N>>,
    overflows: usize,

    _phantom: PhantomData<W>,
}

impl<W: FieldExt, N: FieldExt, const LIMBS: usize> AssignedInteger<W, N, LIMBS> {
    pub fn new(limbs_le: [AssignedValue<N>; LIMBS], overflows: usize) -> Self {
        Self {
            limbs_le,
            native: None,
            overflows,
            _phantom: PhantomData,
        }
    }

    pub fn set_native(&mut self, native: AssignedValue<N>) {
        self.native = Some(native);
    }

    pub fn bn(&self, limb_modulus: &BigUint) -> BigUint {
        self.limbs_le
            .iter()
            .rev()
            .fold(BigUint::from(0u64), |acc, v| {
                acc * limb_modulus + field_to_bn(&v.value)
            })
    }
}

pub struct IntegerGateHelper<W: FieldExt, N: FieldExt, const LIMBS: usize, const LIMB_WIDTH: usize>
{
    pub limb_modulus: BigUint,
    pub integer_modulus: BigUint,
    pub limb_modulus_on_n: N,
    pub limb_modulus_exps: [N; LIMBS],
    pub w_modulus: BigUint,
    pub w_modulus_limbs_le: [BigUint; LIMBS],
    pub n_modulus: BigUint,
    pub w_native: N,
    pub w_ceil_bits: usize,
    pub n_floor_bits: usize,
    pub d_bits: usize,
    pub _phantom_w: PhantomData<W>,
}

impl<W: FieldExt, N: FieldExt, const LIMBS: usize, const LIMB_WIDTH: usize>
    IntegerGateHelper<W, N, LIMBS, LIMB_WIDTH>
{
    pub fn w_to_limb_n_le(&self, w: &W) -> [N; LIMBS] {
        let bn = field_to_bn(w);
        self.bn_to_limb_n_le(&bn)
    }

    fn _bn_to_limb_le(bn: &BigUint, limb_modulus: &BigUint) -> [BigUint; LIMBS] {
        let mut ret = vec![];
        let mut n = bn.clone();

        for _ in 0..LIMBS - 1 {
            ret.push(&n % limb_modulus);
            n = n >> LIMB_WIDTH;
        }
        ret.push(n);
        ret.try_into().unwrap()
    }

    pub fn bn_to_limb_n_le(&self, bn: &BigUint) -> [N; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus).map(|v| bn_to_field(&v))
    }

    pub fn bn_to_limb_le(&self, bn: &BigUint) -> [BigUint; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus)
    }

    pub fn new() -> Self {
        let limb_modulus = BigUint::from(1u64) << LIMB_WIDTH;
        let integer_modulus = BigUint::from(1u64) << (LIMB_WIDTH * LIMBS);
        let limb_modulus_on_n: N = bn_to_field(&limb_modulus);
        let w_modulus = field_to_bn(&-W::one()) + 1u64;
        let n_modulus = field_to_bn(&-N::one()) + 1u64;
        let w_native = bn_to_field(&(&w_modulus % &n_modulus));
        let w_modulus_limbs_le = Self::_bn_to_limb_le(&w_modulus, &limb_modulus);
        let w_ceil_bits = w_modulus.bits() as usize + 1;
        let n_floor_bits = n_modulus.bits() as usize;

        let mut limb_modulus_exps = vec![];
        let mut acc = N::one();
        for _ in 0..LIMBS {
            limb_modulus_exps.push(acc);
            acc = acc * limb_modulus_on_n;
        }

        let d_bits = get_d_range_bits_in_mul::<W, N>(&integer_modulus);

        Self {
            _phantom_w: PhantomData,
            limb_modulus,
            integer_modulus,
            limb_modulus_on_n,
            limb_modulus_exps: limb_modulus_exps.try_into().unwrap(),
            w_modulus,
            n_modulus,
            w_native,
            w_modulus_limbs_le,
            w_ceil_bits,
            n_floor_bits,
            d_bits,
        }
    }
}

pub struct IntegerGate<
    'a,
    'b,
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
    pub helper: IntegerGateHelper<W, N, LIMBS, LIMB_WIDTH>,
}

pub trait IntegerGateOps<
    W: FieldExt,
    N: FieldExt,
    const VAR_COLUMNS: usize,
    const MUL_COLUMNS: usize,
    const COMMON_RANGE_BITS: usize,
    const LIMBS: usize,
    const LIMB_WIDTH: usize,
>
{
    fn assign_nonleading_limb(&self, r: &mut RegionAux<N>, n: N)
        -> Result<AssignedValue<N>, Error>;
    fn assign_w_ceil_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error>;
    fn assign_n_floor_leading_limb(
        &self,
        r: &mut RegionAux<N>,
        n: N,
    ) -> Result<AssignedValue<N>, Error>;
    fn assign_d_leading_limb(&self, r: &mut RegionAux<N>, n: N) -> Result<AssignedValue<N>, Error>;
    fn assign_w(&self, r: &mut RegionAux<N>, w: &W) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn assign_d(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<[AssignedValue<N>; LIMBS], Error>;
    fn assign_integer(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<[AssignedValue<N>; LIMBS], Error>;

    fn conditionally_reduce(
        &self,
        r: &mut RegionAux<N>,
        a: AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;

    fn native<'a>(
        &self,
        r: &mut RegionAux<N>,
        a: &'a mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<&'a AssignedValue<N>, Error>;
    fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn sub(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn neg(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn mul(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
        b: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn assigned_constant(
        &self,
        r: &mut RegionAux<N>,
        w: W,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error>;
    fn assert_equal(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<(), Error>;
}

impl<
        'a,
        'b,
        W: FieldExt,
        N: FieldExt,
        const VAR_COLUMNS: usize,
        const MUL_COLUMNS: usize,
        const COMMON_RANGE_BITS: usize,
        const LIMBS: usize,
        const LIMB_WIDTH: usize,
    > IntegerGate<'a, 'b, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS, LIMBS, LIMB_WIDTH>
{
    pub fn new(
        range_gate: &'b RangeGate<'a, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS>,
    ) -> Self {
        Self {
            base_gate: range_gate.base_gate,
            range_gate,
            helper: IntegerGateHelper::new(),
        }
    }
}

/*
    fn assign_limb(&self, r: &mut RegionAux<N>, n: N) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let one = N::one();

        let modulus = BigUint::from(1u64) << RANGE_BITS;

        let mut bn = field_to_bn(&n);
        let mut schemas = vec![];
        let mut coeff = N::one();
        for _ in 0..VAR_COLUMNS {
            let rem = bn_to_field::<N>(&(&bn % &modulus));
            bn = bn / &modulus;

            schemas.push(pair!(rem, coeff));
            coeff = coeff * bn_to_field::<N>(&modulus);
        }

        self.range_gate
            .one_line_ranged(r, schemas, zero, (vec![], -one))?;
        let cells = self.base_gate.one_line_with_last_base(
            r,
            vec![],
            pair!(n, zero),
            zero,
            (vec![], zero),
        )?;
        Ok(cells[VAR_COLUMNS - 1])
    }

    pub fn assign_integer(
        &self,
        r: &mut RegionAux<N>,
        v: &W,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let limbs_value = self.helper.w_to_limb_n_le(v);

        let mut limbs = vec![];
        for limb in limbs_value {
            let cell = self.assign_limb(r, limb)?;
            limbs.push(cell);
        }

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0u32))
    }

    pub fn assign_integer_bn(
        &self,
        r: &mut RegionAux<N>,
        v: &BigUint,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let limbs_value = self.helper.bn_to_limb_n_le(v);

        let mut limbs = vec![];
        for limb in limbs_value {
            let cell = self.assign_limb(r, limb)?;
            limbs.push(cell);
        }

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0u32))
    }

    pub fn reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        assert!(a.overflows < OVERFLOW_LIMIT);

        // We will first find (d, rem) that a = d * w_modulus + rem and add following constraints
        // 1. d is limited by RANGE_BITS, e.g. 1 << 16
        // 2. rem is limited by LIMBS, e.g. 1 << 256
        // 3. d * w_modulus + rem - a = 0 on native
        // 4. d * w_modulus + rem - a = 0 on LIMB_MODULUS
        // so d * w_modulus + rem - a = 0 on LCM(native, LIMB_MODULUS)

        // assert for configurations
        // 1. max d * w_modulus + rem < LCM(native, LIMB_MODULUS)
        // 2. max a < LCM(native, LIMB_MODULUS)
        let lcm = self.helper.n_modulus.lcm(&self.helper.limb_modulus);
        assert!(
            lcm >= &self.helper.w_modulus * RANGE_BITS
                + (BigUint::from(1u64) << LIMBS * LIMB_WIDTH)
        );
        assert!(lcm >= &self.helper.w_modulus * OVERFLOW_LIMIT);

        // To guarantee d * w_modulus + rem - a = 0 on LIMB_MODULUS
        // we find limb_d, that d * w_modulus[0] + rem[0] - a[0] + OVERFLOW_LIMIT * LIMB_MODULUS = limb_d * LIMB_MODULUS:
        // 1. limb_d is limited by RANGE_BITS, e.g. 1 << 16
        // Guarantee max(d * w_modulus[0] + rem[0] - a[0] + OVERFLOW_LIMIT * LIMB_MODULUS) < MAX_RANGE * LIMB_MODULUS
        let max_a = BigUint::from(OVERFLOW_LIMIT as u32) << (LIMB_WIDTH * LIMBS);
        let max_d = max_a.div(&self.helper.w_modulus) + 1u64;
        assert!(max_d + 1u64 + OVERFLOW_LIMIT < (BigUint::from(1u64) << RANGE_BITS));

        let total = a.limbs_le.iter().rev().fold(BigUint::from(0u64), |acc, v| {
            acc * &self.helper.limb_modulus + field_to_bn(&v.value)
        });

        let (d, rem) = total.div_rem(&self.helper.w_modulus);

        let (limb_d, limb_rem) = (&d * &self.helper.w_modulus_limbs_le[0]
            + &self.helper.bn_to_limb_le(&rem)[0]
            + &self.helper.limb_modulus * OVERFLOW_LIMIT
            - &self.helper.bn_to_limb_le(&total)[0])
            .div_rem(&self.helper.limb_modulus);
        assert!(limb_rem == BigUint::from(0u64));

        let zero = N::zero();
        let one = N::one();

        let mut rem = self.assign_integer_bn(r, &rem)?;
        let (d, limb_d) = {
            let cells = self.range_gate.one_line_ranged(
                r,
                vec![
                    pair!(bn_to_field::<N>(&d), zero),
                    pair!(bn_to_field::<N>(&limb_d), zero),
                ],
                zero,
                (vec![], zero),
            )?;
            (cells[0], cells[1])
        };

        // Add constrains on limb[0] and native for
        // a = d * w_modulus + rem

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

        self.base_gate.one_line_add(
            r,
            vec![
                pair!(&d, bn_to_field(&self.helper.w_modulus_limbs_le[0])),
                pair!(&rem.limbs_le[0], one),
                pair!(&a.limbs_le[0], -one),
                pair!(&limb_d, bn_to_field(&self.helper.limb_modulus)),
            ],
            -bn_to_field::<N>(&(&self.helper.limb_modulus * OVERFLOW_LIMIT)),
        )?;

        Ok(rem)
    }

    pub fn conditionally_reduce(
        &self,
        r: &mut RegionAux<N>,
        mut a: AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        if a.overflows > OVERFLOW_THRESHOLD {
            self.reduce(r, &mut a)
        } else {
            Ok(a)
        }
    }

    pub fn native(
        &self,
        r: &mut RegionAux<N>,
        a: &'a mut AssignedInteger<W, N>,
    ) -> Result<&'a AssignedValue<N>, Error> {
        let new_native = match &mut a.native {
            Some(native) => None,
            None => {
                let zero = N::zero();
                let one = N::one();
                let limb_modulus: N = bn_to_field(&self.helper.limb_modulus);

                let mut schemas = vec![];
                let mut coeff = one;
                let mut v = zero;
                for i in 0..LIMBS {
                    v = v + a.limbs_le[i].value * coeff;
                    schemas.push(pair!(&a.limbs_le[i], coeff));
                    coeff = coeff * limb_modulus;
                }

                self.base_gate.one_line(r, schemas, zero, (vec![], -one))?;
                let cells = self.base_gate.one_line_with_last_base(
                    r,
                    vec![],
                    pair!(v, zero),
                    zero,
                    (vec![], zero),
                )?;
                Some(cells[VAR_COLUMNS - 1])
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

    pub fn add(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let mut limbs = vec![];

        for i in 0..LIMBS {
            let value = self.base_gate.add(r, &a.limbs_le[i], &b.limbs_le[i])?;
            limbs.push(value)
        }

        let res = AssignedInteger::new(limbs.try_into().unwrap(), a.overflows + b.overflows + 1);
        self.conditionally_reduce(r, res)
    }

    fn find_w_modulus_ceil(&self, a: &AssignedInteger<W, N>) -> [BigUint; LIMBS] {
        let max_a = (a.overflows + 1) * (&self.helper.limb_modulus << LIMBS);
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
                + a.overflows * &self.helper.limb_modulus;
            upper = (upper - &rem).div_floor(&self.helper.limb_modulus);
            limbs.push(rem);
        }
        limbs.push(upper);
        limbs.try_into().unwrap()
    }

    pub fn neg(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
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

    pub fn sub(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
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

    pub fn assigned_constant(
        &self,
        r: &mut RegionAux<N>,
        w: W,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let limbs_value = self.helper.w_to_limb_n_le(&w);

        let mut limbs = vec![];
        for limb in limbs_value {
            let cell = self.base_gate.assign_constant(r, limb)?;
            limbs.push(cell);
        }

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0u32))
    }

    pub fn mul(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N>,
        b: &mut AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let bn_one = BigUint::from(1u64);

        // Let's assume LIMBS = 4, LIMB_WIDTH = 64, RANGE_BITS = 16, OVERFLOW_LIMITS = 32 (2 ^ 5)
        // to help understand the algorithm.
        // We choose a `_t`, that `t = 2 ^ (LIMB_WIDTH * _t)`, e.g. t = 2 ^ (LIMB_WIDTH * (LIMBS + 1)) = 320

        // We calculate `(d, rem)`, that `a * b = d * w_modulus + rem`.
        // We add constraints that d < 2 ^ (LIMBS * LIMB_WIDTH + RANGE_BITS) = 2 ^ 272, r < 2 ^ 256
        // Then we add constraints forthe equation both on t and native modulus.
        // So the equation is established in range (0..lcm(T, native_modulus)).

        // Assert that max of each side is less than lcm(T, native_modulus)
        let _t = LIMBS + 1;
        let t = &bn_one << (LIMB_WIDTH * _t);
        let lcm = t.lcm(&self.helper.n_modulus);
        let max_ab = (&bn_one << (LIMB_WIDTH * LIMBS * 2)) * OVERFLOW_LIMIT * OVERFLOW_LIMIT;
        assert!(max_ab <= lcm);
        let max_d_w_r = (&bn_one << (RANGE_BITS + LIMB_WIDTH * LIMBS)) * &self.helper.n_modulus
            + (&bn_one << (LIMB_WIDTH * LIMBS));
        assert!(max_d_w_r <= lcm);
        // Assert max_d_w_r >= max_ab, so we can always found such (d, rem)
        assert!(max_ab <= max_d_w_r);

        let a_total = a.limbs_le.iter().rev().fold(BigUint::from(0u64), |acc, v| {
            acc * &self.helper.limb_modulus + field_to_bn(&v.value)
        });
        let b_total = b.limbs_le.iter().rev().fold(BigUint::from(0u64), |acc, v| {
            acc * &self.helper.limb_modulus + field_to_bn(&v.value)
        });
        let a_b = a_total * b_total;
        let (d, rem) = a_b.div_rem(&self.helper.w_modulus);

        let (d_overflow, d) = d.div_rem(&(&bn_one << (LIMBS * LIMB_WIDTH)));
        let mut rem = self.assign_integer_bn(r, &rem)?;
        let mut d = self.assign_integer_bn(r, &d)?;
        let d_overflow = self.range_gate.assign_value(r, bn_to_field(&d_overflow))?;

        let neg_w = t - &self.helper.w_modulus;
        let (neg_w_overflow, neg_w) = neg_w.div_rem(&(&bn_one << (LIMBS * LIMB_WIDTH)));
        let neg_w = self.helper.bn_to_limb_le(&neg_w);

        let mut limbs = vec![];
        // we calculate each limbs after a * b - d * w_modulus, and ignore the limbs overflow the t
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
                            &d.limbs_le[i],
                            bn_to_field(&neg_w[pos - i]),
                        )
                    })
                    .collect(),
            )?;

            // TODO: this can be merged into the last line of mul_add_with_next_line
            let l = self.base_gate.sum_with_constant(
                r,
                vec![(&l, one), (&rem.limbs_le[pos], -one)],
                zero,
            )?;
            limbs.push(l);
        }

        {
            // e.g. (a1 * b3 + a2 * b2 + a3 * b1 - d1 * w3 - d2 * w2 - d3 * w3) - d0 * w_overflow - d_overflow * w0
            let l = self.base_gate.mul_add_with_next_line(
                r,
                (1..LIMBS)
                    .map(|i| {
                        (
                            &a.limbs_le[i],
                            &b.limbs_le[LIMBS - i],
                            &d.limbs_le[i],
                            bn_to_field(&neg_w[LIMBS - i]),
                        )
                    })
                    .collect(),
            )?;
            let l = self.base_gate.sum_with_constant(
                r,
                vec![
                    (&l, one),
                    (&d.limbs_le[0], bn_to_field(&neg_w_overflow)),
                    (&d_overflow, bn_to_field(&neg_w[0])),
                ],
                zero,
            )?;

            limbs.push(l);
        }

        // each limbs is sum of n's `ai * bj` and m's `di * wj`,
        // we know that
        // 1. n <= LIMBS
        // 2. m <= LIMBS + 1
        // 3. ai * bj < (OVERFLOW_LIMIT * limb_modulus) ^ 2
        // 4. di * wj < limb_modulus ^ 2
        // thus the sum < (LIMBS * OVERFLOW_LIMIT ^ 2 + LIMBS + 1) * limb_modulus ^ 2
        // For convenience, we assert (LIMBS * OVERFLOW_LIMIT ^ 2 + LIMBS + 1) < 1 << RANGE_BIS
        assert!(
            (LIMBS as u32) * OVERFLOW_LIMIT * (LIMBS as u32) * OVERFLOW_LIMIT + (LIMBS as u32) + 1
                < 1 << RANGE_BITS
        );

        // To avoid overflow when combine two limbs, it requires (1 << RANGE_BIS)  * limb_modulus ^ 3 <= n_modulus
        // To avoid overflow when combine two limbs with overflow, it requires (1 << RANGE_BIS)  * (limb_modulus ^ 3 + limb_modulus ^ 2 + limb_modulus + 1) <= n_modulus
        // For convenience, we assert (1 << RANGE_BIS)  * (limb_modulus ^ 3) * 2 <= n_modulus
        assert!(
            (&bn_one << RANGE_BITS)
                * self.helper.limb_modulus.clone().pow(3u32)
                * BigUint::from(2u64)
                <= self.helper.n_modulus
        );

        let mut carry = vec![];
        let limb_modulus = bn_to_field(&self.helper.limb_modulus);
        let limb_modulus_sqr = self.helper.limb_modulus.clone().pow(2u32);
        for i in 0..(LIMBS + 1) / 2 {
            let i = i * 2;
            let mut elems = vec![(&limbs[i], one), (&limbs[i + 1], limb_modulus)];
            elems.append(&mut carry.iter().map(|x| (x, one)).collect());
            let total = self.base_gate.sum_with_constant(r, elems, zero)?;

            let (t_d, t_rem) = field_to_bn(&total.value).div_rem(&limb_modulus_sqr);
            println!("{:?}", t_rem);
            // sanity check
            assert!(t_rem.eq(&BigUint::from(0u64)));

            let (t_overflow, t_d) = t_d.div_rem(&self.helper.limb_modulus);
            let o = self.range_gate.assign_value(r, bn_to_field(&t_overflow))?;
            let d = self.assign_limb(r, bn_to_field(&t_d))?;

            let _carry =
                self.base_gate
                    .sum_with_constant(r, vec![(&o, limb_modulus), (&d, one)], zero)?;
            self.base_gate.one_line(
                r,
                vec![
                    pair!(&_carry, limb_modulus * limb_modulus),
                    pair!(&total, -one),
                ],
                zero,
                (vec![], zero),
            )?;

            carry = vec![_carry];
        }

        if LIMBS.is_even() {
            let mut elems = vec![(&limbs[LIMBS], one)];
            elems.append(&mut carry.iter().map(|x| (x, one)).collect());

            let total = self.base_gate.sum_with_constant(r, elems, zero)?;
            let (t_d, t_rem) = field_to_bn(&total.value).div_rem(&self.helper.limb_modulus);
            // sanity check
            assert!(t_rem.eq(&BigUint::from(0u64)));
            let (t_overflow, t_d) = t_d.div_rem(&self.helper.limb_modulus);
            let o = self.range_gate.assign_value(r, bn_to_field(&t_overflow))?;
            let d = self.assign_limb(r, bn_to_field(&t_d))?;

            let _carry =
                self.base_gate
                    .sum_with_constant(r, vec![(&o, limb_modulus), (&d, one)], zero)?;
            self.base_gate.one_line(
                r,
                vec![pair!(&_carry, limb_modulus), pair!(&total, -one)],
                zero,
                (vec![], zero),
            )?;
        }

        // check a * b - d * w - rem = 0 on native;
        let a_native = self.native(r, a)?;
        let b_native = self.native(r, b)?;
        let d_native = self.native(r, &mut d)?;
        let rem_native = self.native(r, &mut rem)?;

        self.base_gate.one_line(
            r,
            vec![
                pair!(a_native, zero),
                pair!(b_native, zero),
                pair!(d_native, -self.helper.w_native),
                pair!(rem_native, -one),
            ],
            zero,
            (vec![one], zero),
        )?;

        Ok(rem)
    }

    pub fn div(
        &self,
        r: &mut RegionAux<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        unimplemented!()
    }

    pub fn div_unsafe() -> Result<AssignedInteger<W, N>, Error> {
        unimplemented!()
    }

    pub fn invert_unsafe() -> Result<AssignedInteger<W, N>, Error> {
        unimplemented!()
    }

    pub fn invert() -> Result<AssignedInteger<W, N>, Error> {
        unimplemented!()
    }
}
*/
