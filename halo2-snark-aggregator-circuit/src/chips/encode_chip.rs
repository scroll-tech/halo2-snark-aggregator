use super::ecc_chip::EccChip;
use super::scalar_chip::AssignedValue;
use ff::PrimeField;
use halo2_proofs::{arithmetic::CurveAffine, plonk::Error};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    transcript::encode::Encode,
};
use std::marker::PhantomData;

pub struct PoseidonEncodeChip<A: ArithEccChip> {
    _phantom: PhantomData<A>,
}

impl<'a, 'b, C: CurveAffine> Encode<EccChip<'a, 'b, C>> for PoseidonEncodeChip<EccChip<'a, 'b, C>>
where
    C::Base: PrimeField,
{
    fn encode_point(
        _ctx: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        _pchip: &EccChip<'a, 'b, C>,
        v: &<EccChip<'a, 'b, C> as ArithEccChip>::AssignedPoint,
    ) -> Result<Vec<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative>, Error> {
        let mut px = v.x.clone();
        let mut py = v.y.clone();
        let x_native = EccChipOps::integer_chip(pchip.chip).native(ctx, &mut px)?;
        let y_native = if true {
            pchip.chip.integer_chip().native(ctx, &mut py)?
        } else {
            &py.limbs_le[0]
        };

        Ok(vec![*x_native, *y_native])
    }

    fn encode_scalar(
        _: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        v: &<EccChip<'a, 'b, C> as ArithEccChip>::AssignedScalar,
    ) -> Result<Vec<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative>, Error> {
        Ok(vec![*v])
    }

    fn decode_scalar(
        _: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        v: &[<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative],
    ) -> Result<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedScalar, Error> {
        Ok(v[0])
    }
}
