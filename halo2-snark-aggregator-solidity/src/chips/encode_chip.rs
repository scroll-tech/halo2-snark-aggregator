use std::marker::PhantomData;

use super::ecc_chip::SolidityEccChip;
use halo2_proofs::{
    arithmetic::{CurveAffine, Field, FieldExt},
    halo2curves::group::ff::PrimeField,
};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    mock::transcript_encode::{bn_to_field, field_to_bn},
    transcript::encode::Encode,
};

pub struct PoseidonEncode<A: ArithEccChip> {
    _phantom: PhantomData<A>,
}

fn base_to_scalar<B: FieldExt, S: FieldExt>(base: &B) -> S {
    let bn = field_to_bn(base);
    let modulus = field_to_bn(&-B::one()) + 1u64;
    let bn = bn % modulus;
    bn_to_field(&bn)
}

impl<C: CurveAffine, E> Encode<SolidityEccChip<C, E>> for PoseidonEncode<SolidityEccChip<C, E>>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::ScalarExt: PrimeField<Repr = [u8; 32]>,
{
    fn encode_point(
        ctx: &mut <SolidityEccChip<C, E> as ArithCommonChip>::Context,
        nchip: &<SolidityEccChip<C, E> as ArithEccChip>::NativeChip,
        _: &<SolidityEccChip<C, E> as ArithEccChip>::ScalarChip,
        pchip: &SolidityEccChip<C, E>,
        v: &<SolidityEccChip<C, E> as ArithEccChip>::AssignedPoint,
    ) -> Result<Vec<<SolidityEccChip<C, E> as ArithEccChip>::AssignedNative>, E> {
        let p = pchip.to_value(v)?;
        let c = p.coordinates();
        let x = c.map(|v| *v.x()).unwrap_or(
            <<SolidityEccChip<C, E> as ArithEccChip>::Point as CurveAffine>::Base::zero(),
        );
        let y = c.map(|v| *v.y()).unwrap_or(
            <<SolidityEccChip<C, E> as ArithEccChip>::Point as CurveAffine>::Base::zero(),
        );

        let px = nchip.assign_var(ctx, base_to_scalar(&x))?;
        let py = nchip.assign_var(ctx, base_to_scalar(&y))?;

        Ok(vec![px, py])
    }

    fn encode_scalar(
        _: &mut <SolidityEccChip<C, E> as ArithCommonChip>::Context,
        _: &<SolidityEccChip<C, E> as ArithEccChip>::NativeChip,
        _: &<SolidityEccChip<C, E> as ArithEccChip>::ScalarChip,
        v: &<SolidityEccChip<C, E> as ArithEccChip>::AssignedScalar,
    ) -> Result<Vec<<SolidityEccChip<C, E> as ArithEccChip>::AssignedNative>, E> {
        Ok(vec![v.clone()])
    }

    fn decode_scalar(
        _: &mut <SolidityEccChip<C, E> as ArithCommonChip>::Context,
        _: &<SolidityEccChip<C, E> as ArithEccChip>::NativeChip,
        _: &<SolidityEccChip<C, E> as ArithEccChip>::ScalarChip,
        v: &[<SolidityEccChip<C, E> as ArithEccChip>::AssignedNative],
    ) -> Result<<SolidityEccChip<C, E> as ArithEccChip>::AssignedScalar, E> {
        Ok(v[0].clone())
    }
}
