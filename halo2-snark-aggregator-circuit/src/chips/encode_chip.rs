use super::ecc_chip::EccChip;
use ff::PrimeField;
use halo2_proofs::{halo2curves::CurveAffineExt, plonk::Error};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    transcript::encode::Encode,
};
use std::marker::PhantomData;

pub struct PoseidonEncodeChip<A: ArithEccChip> {
    _phantom: PhantomData<A>,
}

impl<'a, C: CurveAffineExt> Encode<EccChip<'a, C>> for PoseidonEncodeChip<EccChip<'a, C>>
where
    C::Base: PrimeField<Repr = [u8; 32]>,
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    fn encode_point(
        _ctx: &mut <EccChip<'a, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, C> as ArithEccChip>::ScalarChip,
        _pchip: &EccChip<'a, C>,
        v: &<EccChip<'a, C> as ArithEccChip>::AssignedPoint,
    ) -> Result<Vec<<EccChip<'a, C> as ArithEccChip>::AssignedNative>, Error> {
        let x_native = v.x.native.clone();
        let y_native = v.y.native.clone();
        Ok(vec![x_native, y_native])
    }

    fn encode_scalar(
        _: &mut <EccChip<'a, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, C> as ArithEccChip>::ScalarChip,
        v: &<EccChip<'a, C> as ArithEccChip>::AssignedScalar,
    ) -> Result<Vec<<EccChip<'a, C> as ArithEccChip>::AssignedNative>, Error> {
        Ok(vec![v.clone()])
    }

    fn decode_scalar(
        _: &mut <EccChip<'a, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, C> as ArithEccChip>::ScalarChip,
        v: &[<EccChip<'a, C> as ArithEccChip>::AssignedNative],
    ) -> Result<<EccChip<'a, C> as ArithEccChip>::AssignedScalar, Error> {
        Ok(v[0].clone())
    }
}
