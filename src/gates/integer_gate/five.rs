use super::{AssignedInteger, IntegerGate, IntegerGateOps};
use crate::{
    gates::base_gate::{
        five::{MUL_COLUMNS, VAR_COLUMNS},
        AssignedValue, RegionAux,
    },
    pair, pair_empty,
    utils::{bn_to_field, decompose_bn, field_to_bn},
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use num_bigint::BigUint;
use num_integer::Integer;

const LIMBS: usize = 4usize;
const LIMB_WIDTH_OF_COMMON_RANGE: usize = 4usize;
const COMMON_RANGE_BITS: usize = 17usize;
const LIMB_WIDTH: usize = LIMB_WIDTH_OF_COMMON_RANGE * COMMON_RANGE_BITS; // 68

const OVERFLOW_THRESHOLD_SHIFT: usize = 4usize;
const OVERFLOW_THRESHOLD: usize = 1usize << OVERFLOW_THRESHOLD_SHIFT;

const OVERFLOW_LIMIT_SHIFT: usize = 5usize;
const OVERFLOW_LIMIT: usize = 1usize << OVERFLOW_LIMIT_SHIFT;

type FiveColumnIntegerGate<'a, 'b, W, N> =
    IntegerGate<'a, 'b, W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS, LIMBS, LIMB_WIDTH>;

impl<'a, 'b, W: FieldExt, N: FieldExt> FiveColumnIntegerGate<'a, 'b, W, N> {
    fn find_w_modulus_ceil(&self, a: &AssignedInteger<W, N, LIMBS>) -> [BigUint; LIMBS] {
        let max_a = (a.overflows + 1) * (BigUint::from(1u64) << self.helper.w_bits);
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
}

impl<'a, 'b, W: FieldExt, N: FieldExt>
    IntegerGateOps<W, N, VAR_COLUMNS, MUL_COLUMNS, COMMON_RANGE_BITS, LIMBS, LIMB_WIDTH>
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
        let chunks = decompose_bn::<N>(&bn, COMMON_RANGE_BITS, LIMB_WIDTH_OF_COMMON_RANGE);
        let mut schema: Vec<_> = chunks.into_iter().rev().map(|(a, b)| pair!(a, b)).collect();
        schema.push(pair!(n, -one));

        let cells = self
            .range_gate
            .one_line_in_common_range(r, schema, zero, (vec![], -one))?;
        Ok(cells[VAR_COLUMNS - 1])
    }

    fn assign_leading_limb(&self, r: &mut RegionAux<N>, n: N) -> Result<AssignedValue<N>, Error> {
        let leading_limb_bits = self.helper.w_bits as usize % LIMB_WIDTH;
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
            schema.resize_with(LIMB_WIDTH_OF_COMMON_RANGE, || pair_empty!(N));
            schema.push(pair!(n, -one));

            let cells =
                self.range_gate
                    .one_line_in_leading_range(r, schema, zero, (vec![], -one))?;
            Ok(cells[VAR_COLUMNS - 1])
        }
    }

    fn assign_w(&self, r: &mut RegionAux<N>, v: &W) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        let limbs_value_le = self.helper.w_to_limb_n_le(v);

        let mut limbs = vec![];

        for (i, limb) in limbs_value_le.into_iter().rev().enumerate() {
            let cell = if i == 0 {
                self.assign_leading_limb(r, limb)?
            } else {
                self.assign_nonleading_limb(r, limb)?
            };
            limbs.push(cell);
        }

        limbs.reverse();

        Ok(AssignedInteger::new(limbs.try_into().unwrap(), 0usize))
    }

    fn reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        assert!(a.overflows < OVERFLOW_LIMIT);

        let a_bn = a.bn(&self.helper.limb_modulus);

        // We will first find (d, rem) that a = d * w_modulus + rem and add following constraints
        // 1. d is limited by RANGE_BITS, e.g. 1 << 17
        // 2. rem is limited by LIMBS, e.g. 1 << w_max_bits
        // 3. d * w_modulus + rem - a = 0 on native
        // 4. d * w_modulus + rem - a = 0 on LIMB_MODULUS (2 ^ 68)
        // so d * w_modulus + rem - a = 0 on LCM(native, LIMB_MODULUS)
        let (d, rem) = a_bn.div_rem(&self.helper.w_modulus);

        // assert for configurations
        // 1. max d * w_modulus + rem < LCM(native, LIMB_MODULUS)
        // 2. max a < LCM(native, LIMB_MODULUS)
        // 3. max a < max d * w_modulus + rem
        let lcm = self.helper.n_modulus.lcm(&self.helper.limb_modulus);
        let max_assigned_integer_unit = BigUint::from(1u64) << self.helper.w_bits;
        let max_l = &max_assigned_integer_unit * OVERFLOW_LIMIT;
        let max_r = &self.helper.w_modulus * (1u64 << COMMON_RANGE_BITS) + &max_assigned_integer_unit;
        assert!(lcm >= max_l);
        assert!(lcm >= max_r);
        assert!(max_r >= max_l);

        // We know,
        // 1. d * w_modulus + rem - a = 0 on LIMB_MODULUS <-> d * w_modulus[0] + rem[0] - a[0] = 0 on LIMB_MODULUS.
        // 2. because a[0] < OVERFLOW_LIMIT * LIMB_MODULUS,
        // 3. d < OVERFLOW_LIMIT * 2 (because a < OVERFLOW_LIMIT * max_assigned_integer_unit < OVERFLOW_LIMIT * w * 2)

        // let u = d * w_modulus[0] + rem[0] + OVERFLOW_LIMIT * LIMB_MODULUS - a[0]
        let u = &d * &self.helper.w_modulus_limbs_le[0]
            + &self.helper.bn_to_limb_le(&rem)[0]
            + &self.helper.limb_modulus * OVERFLOW_LIMIT
            - &self.helper.bn_to_limb_le(&a_bn)[0];
        // We add constraints that u can be divided by LIMB_MODULUS

        // u < OVERFLOW_LIMIT * 2 * LIMB_MODULUS + LIMB_MODULUS + OVERFLOW_LIMIT * LIMB_MODULUS
        // -> u < (OVERFLOW_LIMIT * 3 + 1) * LIMB_MODULUS
        assert!((OVERFLOW_LIMIT * 3 + 1 + OVERFLOW_LIMIT) < 1 << COMMON_RANGE_BITS);
        // -> u < (1 << COMMON_RANGE_BITS) * LIMB_MODULUS
        // So, we can find a v in [0..1 << COMMON_RANGE_BITS) that v * LIMB_MODULUS = u
        let v = u.div_floor(&self.helper.limb_modulus);

        let zero = N::zero();
        let one = N::one();

        // Let's add the constraints.

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
            bn_to_field::<N>(&(&self.helper.limb_modulus * OVERFLOW_LIMIT)),
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
                let schemas = a.limbs_le.iter().zip(self.helper.limbs_le_modulus_list);
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
        a: &AssignedInteger<W, N, LIMBS>,
        b: &AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedInteger<W, N, LIMBS>, Error> {
        todo!()
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
}
