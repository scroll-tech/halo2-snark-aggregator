use super::ecc_chip::EccChip;
use halo2_ecc_circuit_lib::chips::ecc_chip::EccChipOps;
use halo2_proofs::{arithmetic::CurveAffine, plonk::Error};
use halo2_snark_aggregator_api::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    transcript::encode::Encode,
};
use std::marker::PhantomData;

pub struct PoseidonEncode<A: ArithEccChip> {
    _phantom: PhantomData<A>,
}

impl<'a, 'b, C: CurveAffine> Encode<EccChip<'a, 'b, C>> for PoseidonEncode<EccChip<'a, 'b, C>> {
    fn encode_point(
        ctx: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        pchip: &EccChip<'a, 'b, C>,
        v: &<EccChip<'a, 'b, C> as ArithEccChip>::AssignedPoint,
    ) -> Result<Vec<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative>, Error> {
        let mut px = v.x.clone();
        let mut py = v.y.clone();
        let x_native = EccChipOps::integer_chip(&pchip.chip).native(ctx, &mut px)?;
        let y_native = if true {
            pchip.chip.integer_chip().native(ctx, &mut py)?
        } else {
            &py.limbs_le[0]
        };

        Ok(vec![x_native.clone(), y_native.clone()])
    }

    fn encode_scalar(
        _: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        v: &<EccChip<'a, 'b, C> as ArithEccChip>::AssignedScalar,
    ) -> Result<Vec<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative>, Error> {
        Ok(vec![v.clone()])
    }

    fn decode_scalar(
        _: &mut <EccChip<'a, 'b, C> as ArithCommonChip>::Context,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::NativeChip,
        _: &<EccChip<'a, 'b, C> as ArithEccChip>::ScalarChip,
        v: &[<EccChip<'a, 'b, C> as ArithEccChip>::AssignedNative],
    ) -> Result<<EccChip<'a, 'b, C> as ArithEccChip>::AssignedScalar, Error> {
        Ok(v[0].clone())
    }
}
