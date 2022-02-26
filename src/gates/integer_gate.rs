use crate::FieldExt;
use crate::{
    gates::{
        base_gate::{AssignedValue, BaseGate, RegionAux},
        range_gate::RangeGate,
    },
    utils::{bn_to_field, field_to_bn, get_d_range_bits_in_mul},
};
use halo2_proofs::plonk::Error;
use num_bigint::BigUint;
use num_integer::Integer;
use std::{marker::PhantomData, vec};

use super::base_gate::AssignedCondition;

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

    pub fn w(&self, limb_modulus: &BigUint, w_modulus: &BigUint) -> W {
        let v = self.bn(limb_modulus);
        let (_, rem) = v.div_rem(w_modulus);
        bn_to_field(&rem)
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
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<(), Error>;
    fn reduce(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<(), Error>;

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
    fn div(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
        b: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<(AssignedCondition<N>, AssignedInteger<W, N, LIMBS>), Error>;
    fn is_zero(
        &self,
        r: &mut RegionAux<N>,
        a: &mut AssignedInteger<W, N, LIMBS>,
    ) -> Result<AssignedCondition<N>, Error>;
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
