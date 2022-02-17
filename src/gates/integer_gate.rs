use crate::{
    gates::{
        base_gate::{AssignedValue, BaseGate, BaseRegion},
        range_gate::RangeGate,
    },
    pair,
};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};
use num_bigint::BigUint;
use std::marker::PhantomData;

const LIMBS: usize = 4usize;

pub struct AssignedInteger<W: FieldExt, N: FieldExt> {
    pub limbs_le: [AssignedValue<N>; LIMBS],
    pub value: W,
    native: Option<AssignedValue<N>>,
    overflows: u32,
}

impl<W: FieldExt, N: FieldExt> AssignedInteger<W, N> {
    pub fn new(limbs_le: [AssignedValue<N>; LIMBS], w: W, overflows: u32) -> Self {
        Self {
            limbs_le,
            native: None,
            value: w,
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
    limb_modulus: N,
}

impl<const LIMB_WIDTH: usize, W: FieldExt, N: FieldExt> IntegerGateHelper<LIMB_WIDTH, W, N> {
    pub fn new() -> Self {
        Self {
            _phantom_w: PhantomData,
            _phantom_n: PhantomData,
            limb_modulus: N::from_u128(1u128 << LIMB_WIDTH),
        }
    }
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
        let modulus = BigUint::from(1u64) << LIMB_WIDTH;
        (0..LIMBS)
            .map(|i| bn_to_field(&((&bn >> (i * LIMB_WIDTH)) % &modulus)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
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

    pub fn conditionally_reduce(
        &self,
        r: &mut BaseRegion<N>,
        a: AssignedInteger<W, N>,
    ) -> Result<AssignedInteger<W, N>, Error> {
        //unimplemented!()
        Ok(a)
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

                let mut schemas = vec![];
                let mut coeff = one;
                let mut v = zero;
                for i in 0..LIMBS {
                    v = v + a.limbs_le[i].value * coeff;
                    schemas.push(pair!(&a.limbs_le[i], coeff));
                    coeff = coeff * self.helper.limb_modulus;
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

        let assigned_integer = AssignedInteger::new(
            limbs.try_into().unwrap(),
            a.value + b.value,
            a.overflows + b.overflows + 1,
        );

        self.conditionally_reduce(r, assigned_integer)
    }
}
