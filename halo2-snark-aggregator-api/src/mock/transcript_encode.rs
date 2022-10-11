use crate::{
    arith::{common::ArithCommonChip, ecc::ArithEccChip},
    transcript::encode::Encode,
};
use halo2_proofs::arithmetic::{CurveAffine, Field, FieldExt};
use num_bigint::BigUint;

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

/// Input a big integer `bn`, compute a field element `f`
/// such that `f == bn % F::MODULUS`.
pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    let mut buf = bn.to_bytes_le();
    buf.resize(64, 0u8);

    let mut buf_array = [0u8; 64];
    buf_array.copy_from_slice(buf.as_ref());
    F::from_bytes_wide(&buf_array)
}

fn base_to_scalar<B: FieldExt, S: FieldExt>(base: &B) -> S {
    let bn = field_to_bn(base);
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
            .map(|v| *v.x())
            .unwrap_or(<A::Point as CurveAffine>::Base::zero());
        let y = c
            .map(|v| *v.y())
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
