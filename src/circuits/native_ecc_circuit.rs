use super::{
    ecc_circuit::{EccGate, EccGateOps},
    integer_circuit::IntegerGateOps,
};
use crate::{
    field::{bn_to_field, field_to_bn},
    gates::base_gate::{AssignedCondition, AssignedValue, RegionAux},
    pair,
};
use group::ff::{Field, PrimeField};
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::Error,
};
use num_bigint::BigUint;

pub struct NativeEccGate<'a, C: CurveAffine, N: FieldExt>(EccGate<'a, C, N>);

impl<'a, C: CurveAffine, N: FieldExt> NativeEccGate<'a, C, N> {
    pub fn new(integer_gate: &'a dyn IntegerGateOps<C::Base, N>) -> Self {
        NativeEccGate(EccGate::new(integer_gate))
    }
}

impl<'a, C: CurveAffine, N: FieldExt> NativeEccGate<'a, C, N> {
    fn decompose_bits<const WINDOW_SIZE: usize>(
        &self,
        r: &mut RegionAux<N>,
        s: BigUint,
    ) -> (Vec<N>, BigUint) {
        let zero = N::zero();
        let one = N::one();
        (
            (0..WINDOW_SIZE)
                .map(|i| if s.bit(i as u64) { one } else { zero })
                .collect(),
            s >> WINDOW_SIZE,
        )
    }
}

const WINDOW_SIZE: usize = 4usize;

impl<'a, C: CurveAffine> EccGateOps<C, C::ScalarExt, WINDOW_SIZE>
    for NativeEccGate<'a, C, C::ScalarExt>
{
    fn integer_gate(&self) -> &dyn IntegerGateOps<C::Base, C::ScalarExt> {
        self.0.integer_gate
    }

    fn decompose_scalar(
        &self,
        r: &mut RegionAux<C::ScalarExt>,
        s: &AssignedValue<C::ScalarExt>,
    ) -> Result<Vec<[AssignedCondition<C::ScalarExt>; WINDOW_SIZE]>, Error> {
        let zero = C::ScalarExt::zero();
        let one = C::ScalarExt::one();
        let base_gate = self.base_gate();
        let windows = (<C::ScalarExt as PrimeField>::NUM_BITS - 1 + WINDOW_SIZE as u32)
            / (WINDOW_SIZE as u32);
        let mut ret = vec![];

        let s_bn = field_to_bn(&s.value);

        let (bits, s_bn) = self.decompose_bits::<WINDOW_SIZE>(r, s_bn);
        let bits = bits
            .into_iter()
            .enumerate()
            .map(|(i, v)| pair!(v, C::ScalarExt::from(1u64 << i)))
            .collect();
        let cells = base_gate.one_line_with_last_base(
            r,
            bits,
            pair!(s, -one),
            zero,
            (vec![], C::ScalarExt::from(1u64 << WINDOW_SIZE)),
        )?;
        ret.push(
            cells[0..4]
                .iter()
                .map(|v| -> AssignedCondition<C::ScalarExt> { v.into() })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        let mut s_bn = s_bn;
        for _ in 1..windows - 1 {
            let s_n: C::ScalarExt = bn_to_field(&s_bn);
            let (bits, _s_bn) = self.decompose_bits::<WINDOW_SIZE>(r, s_bn);
            let bits = bits
                .into_iter()
                .enumerate()
                .map(|(i, v)| pair!(v, C::ScalarExt::from(1u64 << i)))
                .collect();
            let cells = base_gate.one_line_with_last_base(
                r,
                bits,
                pair!(s_n, -one),
                zero,
                (vec![], C::ScalarExt::from(1u64 << WINDOW_SIZE)),
            )?;
            ret.push(
                cells[0..4]
                    .iter()
                    .map(|v| -> AssignedCondition<C::ScalarExt> { v.into() })
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
            );
            s_bn = _s_bn;
        }

        let s_n: C::ScalarExt = bn_to_field(&s_bn);
        let (bits, _) = self.decompose_bits::<WINDOW_SIZE>(r, s_bn);
        let bits = bits
            .into_iter()
            .enumerate()
            .map(|(i, v)| pair!(v, C::ScalarExt::from(1u64 << i)))
            .collect();
        let cells =
            base_gate.one_line_with_last_base(r, bits, pair!(s_n, -one), zero, (vec![], zero))?;
        ret.push(
            cells[0..4]
                .iter()
                .map(|v| -> AssignedCondition<C::ScalarExt> { v.into() })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
        );

        ret.reverse();

        for window in &ret {
            for bit in window {
                base_gate.assert_bit(r, &AssignedValue::from(bit))?;
            }
        }

        Ok(ret)
    }

    type AssignedScalar = AssignedValue<C::ScalarExt>;
}
