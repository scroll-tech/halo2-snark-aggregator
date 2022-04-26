use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    transcript::encode::Encode,
};
use halo2_proofs::{
    arithmetic::{BaseExt, CurveAffine, Field, FieldExt},
    transcript::{bn_to_field, field_to_bn},
};

fn base_to_scalar<B: BaseExt, S: FieldExt>(base: &B) -> S {
    let bn = field_to_bn(base);
    let modulus = field_to_bn(&-B::one()) + 1u64;
    let bn = bn % modulus;
    bn_to_field(&bn)
}

pub struct PoseidonEncode();

impl<F: FieldExt, A: ArithEccChip<Scalar = F, Native = F>> Encode<A> for PoseidonEncode {
    fn encode_point(
        ctx: &mut <A>::Context,
        nchip: &<A as ArithEccChip>::NativeChip,
        _schip: &<A as ArithEccChip>::ScalarChip,
        pchip: &A,
        v: &<A as ArithEccChip>::AssignedPoint,
    ) -> Result<Vec<<A as ArithEccChip>::AssignedNative>, <A>::Error> {
        let p = pchip.to_value(v)?;
        let c = p.coordinates();
        let x = c
            .map(|v| v.x().clone())
            .unwrap_or(<A::Point as CurveAffine>::Base::zero());
        let y = c
            .map(|v| v.y().clone())
            .unwrap_or(<A::Point as CurveAffine>::Base::zero());

        let px = nchip.assign_var(ctx, base_to_scalar(&x))?;
        let py = nchip.assign_var(ctx, base_to_scalar(&y))?;

        Ok(vec![px, py])
    }

    fn encode_scalar(
        ctx: &mut <A>::Context,
        nchip: &<A as ArithEccChip>::NativeChip,
        schip: &<A as ArithEccChip>::ScalarChip,
        v: &<A as ArithEccChip>::AssignedScalar,
    ) -> Result<Vec<<A as ArithEccChip>::AssignedNative>, <A>::Error> {
        let value = schip.to_value(v)?;
        let v = nchip.assign_var(ctx, value)?;
        Ok(vec![v])
    }

    fn decode_scalar(
        ctx: &mut <A>::Context,
        nchip: &<A as ArithEccChip>::NativeChip,
        schip: &<A as ArithEccChip>::ScalarChip,
        v: &[<A as ArithEccChip>::AssignedNative],
    ) -> Result<<A as ArithEccChip>::AssignedScalar, <A>::Error> {
        let v = nchip.to_value(&v[0])?;
        let v = schip.assign_var(ctx, v)?;
        Ok(v)
    }
}
