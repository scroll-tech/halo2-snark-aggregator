use super::{ecc_circuit::AssignedPoint, native_ecc_circuit::NativeEccCircuit};
use crate::circuits::ecc_circuit::EccCircuitOps;
use crate::{
    gates::{
        base_gate::{AssignedValue, RegionAux},
        five::base_gate::FiveColumnBaseGate,
    },
    verify::halo2::verify::transcript::Encode,
};
use halo2_proofs::{arithmetic::CurveAffine, plonk::Error};

pub struct PoseidonEncode();

impl<'a, 'b, 'c, C: CurveAffine>
    Encode<
        RegionAux<'a, 'b, <C as CurveAffine>::ScalarExt>,
        AssignedValue<<C as CurveAffine>::ScalarExt>,
        AssignedPoint<C, <C as CurveAffine>::ScalarExt>,
        Error,
        <C as CurveAffine>::ScalarExt,
        C,
        FiveColumnBaseGate<C::ScalarExt>,
        NativeEccCircuit<'c, C>,
    > for PoseidonEncode
{
    fn encode_point(
        ctx: &mut RegionAux<'a, 'b, <C as CurveAffine>::ScalarExt>,
        _: &FiveColumnBaseGate<C::ScalarExt>,
        pgate: &NativeEccCircuit<'c, C>,
        p: &AssignedPoint<C, <C as CurveAffine>::ScalarExt>,
    ) -> Result<Vec<AssignedValue<<C as CurveAffine>::ScalarExt>>, Error> {
        let mut px = p.x.clone();
        let mut py = p.y.clone();
        let x_native = pgate.integer_gate().native(ctx, &mut px)?;
        let y_native = if true {
            pgate.integer_gate().native(ctx, &mut py)?
        } else {
            &py.limbs_le[0]
        };

        Ok(vec![x_native.clone(), y_native.clone()])
    }

    fn encode_scalar(
        _: &mut RegionAux<'a, 'b, <C as CurveAffine>::ScalarExt>,
        _: &FiveColumnBaseGate<C::ScalarExt>,
        v: &AssignedValue<<C as CurveAffine>::ScalarExt>,
    ) -> Result<Vec<AssignedValue<<C as CurveAffine>::ScalarExt>>, Error> {
        Ok(vec![v.clone()])
    }
}
