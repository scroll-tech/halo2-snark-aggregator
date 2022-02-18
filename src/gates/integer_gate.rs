use crate::{
    gates::{
        base_gate::{AssignedValue, BaseGate, BaseRegion},
        range_gate::RangeGate,
    },
    pair,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use num_bigint::BigUint;
use num_integer::Integer;
use std::{marker::PhantomData, ops::Div, vec};

const LIMBS: usize = 4usize;
const OVERFLOW_LIMIT: u32 = 32u32;
const OVERFLOW_THRESHOLD: u32 = 16u32;

pub struct AssignedInteger<W: FieldExt, N: FieldExt> {
    pub limbs_le: [AssignedValue<N>; LIMBS],
    pub w_value: W,
    native: Option<AssignedValue<N>>,
    overflows: u32,
}

impl<W: FieldExt, N: FieldExt> AssignedInteger<W, N> {
    pub fn new(limbs_le: [AssignedValue<N>; LIMBS], w_value: W, overflows: u32) -> Self {
        Self {
            limbs_le,
            native: None,
            w_value,
            overflows,
        }
    }

    pub fn set_native(&mut self, native: AssignedValue<N>) {
        self.native = Some(native);
    }
}

pub struct IntegerGateHelper<const LIMB_WIDTH: usize, W: FieldExt, N: FieldExt> {
    _phantom_w: PhantomData<W>,
    _phantom_n: PhantomData<N>,
    limb_modulus: BigUint,
    w_modulus: BigUint,
    w_modulus_limbs_le: [BigUint; LIMBS],
    n_modulus: BigUint,
    w_native: N,
}

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    F::from_str_vartime(&bn.to_str_radix(10)[..]).unwrap()
}

impl<const LIMB_WIDTH: usize, W: FieldExt, N: FieldExt> IntegerGateHelper<LIMB_WIDTH, W, N> {
    pub fn w_to_limb_n_le(&self, w: &W) -> [N; LIMBS] {
        let bn = field_to_bn(w);
        self.bn_to_limb_n_le(&bn)
    }

    fn _bn_to_limb_le(bn: &BigUint, limb_modulus: &BigUint) -> [BigUint; LIMBS] {
        (0..LIMBS)
            .map(|i| ((bn >> (i * LIMB_WIDTH)) % limb_modulus))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    pub fn bn_to_limb_n_le(&self, bn: &BigUint) -> [N; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus).map(|v| bn_to_field(&v))
    }

    pub fn bn_to_limb_le(&self, bn: &BigUint) -> [BigUint; LIMBS] {
        Self::_bn_to_limb_le(bn, &self.limb_modulus)
    }

    pub fn new() -> Self {
        let limb_modulus = BigUint::from(1u64) << LIMB_WIDTH;
        let w_modulus = field_to_bn(&-W::one()) + 1u64;
        let n_modulus = field_to_bn(&-N::one()) + 1u64;
        let w_native = bn_to_field(&(&w_modulus % &n_modulus));
        let w_modulus_limbs_le = Self::_bn_to_limb_le(&w_modulus, &limb_modulus);
        Self {
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
            limb_modulus,
            w_modulus,
            n_modulus,
            w_native,
            w_modulus_limbs_le,
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
    const LIMB_WIDTH: usize,
    const RANGE_BITS: usize,
> {
    base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>,
    range_gate: &'b RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS, RANGE_BITS>,
    helper: IntegerGateHelper<LIMB_WIDTH, W, N>,
    _phantom: PhantomData<W>,
}

impl<
        'a,
        'b,
        W: FieldExt,
        N: FieldExt,
        const VAR_COLUMNS: usize,
        const MUL_COLUMNS: usize,
        const LIMB_WIDTH: usize,
        const RANGE_BITS: usize,
    > IntegerGate<'a, 'b, W, N, VAR_COLUMNS, MUL_COLUMNS, LIMB_WIDTH, RANGE_BITS>
{
    pub fn new(range_gate: &'b RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS, RANGE_BITS>) -> Self {
        assert!(VAR_COLUMNS * RANGE_BITS >= LIMB_WIDTH);
        Self {
            base_gate: range_gate.base_gate,
            range_gate,
            helper: IntegerGateHelper::new(),
            _phantom: PhantomData,
        }
    }

    fn assign_limb(&self, r: &mut BaseRegion<N>, n: N) -> Result<AssignedValue<N>, Error> {
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

        self.range_gate.one_line_ranged(r, schemas, zero, (vec![], -one))?;
        let cells = self
            .base_gate
            .one_line_with_last_base(r, vec![], pair!(n, zero), zero, (vec![], zero))?;
        Ok(cells[VAR_COLUMNS - 1])
    }

    pub fn assign_integer(&self, r: &mut BaseRegion<N>, w: W) -> Result<AssignedInteger<W, N>, Error> {
        let limbs_value = self.helper.w_to_limb_n_le(&w);

        let mut limbs = vec![];
        for limb in limbs_value {
            let cell = self.assign_limb(r, limb)?;
            limbs.push(cell);
        }

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), w, 0u32))
    }

    pub fn reduce(&self, r: &mut BaseRegion<N>, a: &mut AssignedInteger<W, N>) -> Result<AssignedInteger<W, N>, Error> {
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
        assert!(lcm >= &self.helper.w_modulus * RANGE_BITS + (BigUint::from(1u64) << LIMBS * LIMB_WIDTH));
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
        assert!(field_to_bn(&a.w_value) == rem);

        let (limb_d, limb_rem) = (&d * &self.helper.w_modulus_limbs_le[0]
            + &self.helper.bn_to_limb_le(&rem)[0]
            + &self.helper.limb_modulus * OVERFLOW_LIMIT
            - &self.helper.bn_to_limb_le(&total)[0])
            .div_rem(&self.helper.limb_modulus);
        assert!(limb_rem == BigUint::from(0u64));

        let zero = N::zero();
        let one = N::one();

        let mut rem = self.assign_integer(r, bn_to_field(&rem))?;
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
        r: &mut BaseRegion<N>,
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
        r: &mut BaseRegion<N>,
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
                let cells = self
                    .base_gate
                    .one_line_with_last_base(r, vec![], pair!(v, zero), zero, (vec![], zero))?;
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
        r: &mut BaseRegion<N>,
        a: &AssignedInteger<W, N>,
        b: &AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        let mut limbs = vec![];

        for i in 0..LIMBS {
            let value = self.base_gate.add(r, &a.limbs_le[i], &b.limbs_le[i])?;
            limbs.push(value)
        }

        let res = AssignedInteger::new(
            limbs.try_into().unwrap(),
            a.w_value + b.w_value,
            a.overflows + b.overflows + 1,
        );
        self.conditionally_reduce(r, res)
    }

    fn find_w_modulus_ceil(&self, a: &AssignedInteger<W, N>) -> [BigUint; LIMBS] {
        let max_a = (a.overflows + 1) * (&self.helper.limb_modulus << LIMBS);
        let (n, rem) = max_a.div_rem(&self.helper.w_modulus);
        let n = if rem.gt(&BigUint::from(0u64)) { n + 1u64 } else { n };
        let mut upper = n * &self.helper.w_modulus;

        let mut limbs = vec![];
        for _ in 0..LIMBS - 1 {
            let rem = upper.mod_floor(&self.helper.limb_modulus) + a.overflows * &self.helper.limb_modulus;
            upper = (upper - &rem).div_floor(&self.helper.limb_modulus);
            limbs.push(rem);
        }
        limbs.push(upper);
        limbs.try_into().unwrap()
    }

    pub fn neg(&self, r: &mut BaseRegion<N>, a: &AssignedInteger<W, N>) -> Result<AssignedInteger<W, N>, Error> {
        let one = N::one();
        let upper_limbs = self.find_w_modulus_ceil(a);

        let mut limbs = vec![];
        for i in 0..LIMBS {
            let cell =
                self.base_gate
                    .sum_with_constant(r, vec![(&a.limbs_le[i], -one)], bn_to_field(&upper_limbs[i]))?;
            limbs.push(cell);
        }

        let overflow = a.overflows + 1;
        let res = AssignedInteger::new(limbs.try_into().unwrap(), -a.w_value, overflow);
        self.conditionally_reduce(r, res)
    }

    pub fn sub(
        &self,
        r: &mut BaseRegion<N>,
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
        let res = AssignedInteger::new(limbs.try_into().unwrap(), -a.w_value, overflow);
        self.conditionally_reduce(r, res)
    }
}
