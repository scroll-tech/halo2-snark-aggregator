use super::api::{ContextGroup, ContextRing};
use crate::{
    circuits::{
        ecc_circuit::{AssignedPoint, EccCircuitOps},
        native_ecc_circuit::NativeEccCircuit,
    },
    field::bn_to_field,
    gates::{
        base_gate::{AssignedValue, BaseGateOps, RegionAux},
        five::base_gate::FiveColumnBaseGate,
    },
};
use group::ff::Field;
use group::{Curve, GroupEncoding};
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::Error,
};
use num_bigint::BigUint;

impl<'a, 'b, 'c, C: CurveAffine>
    ContextGroup<
        RegionAux<'a, 'b, C::ScalarExt>,
        AssignedValue<C::ScalarExt>,
        AssignedPoint<C, C::ScalarExt>,
        C::CurveExt,
        Error,
    > for NativeEccCircuit<'c, C>
{
    fn add(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        lhs: &AssignedPoint<C, C::ScalarExt>,
        rhs: &AssignedPoint<C, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::add(self, ctx, &mut lhs.clone(), rhs)
    }

    fn minus(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        lhs: &AssignedPoint<C, C::ScalarExt>,
        rhs: &AssignedPoint<C, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::sub(self, ctx, &mut lhs.clone(), rhs)
    }

    fn scalar_mul(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        lhs: &AssignedValue<C::ScalarExt>,
        rhs: &AssignedPoint<C, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::mul(self, ctx, &mut rhs.clone(), lhs)
    }

    fn one(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_point_from_constant_scalar(self, ctx, C::ScalarExt::from(0u64))
    }

    fn zero(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_point_from_constant_scalar(self, ctx, C::ScalarExt::from(1u64))
    }

    fn from_constant(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        c: C::CurveExt,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_point_from_constant(self, ctx, c)
    }

    fn generator(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_point_from_constant_scalar(self, ctx, C::ScalarExt::from(1u64))
    }
}

impl<'a, 'b, N: FieldExt>
    ContextGroup<RegionAux<'a, 'b, N>, AssignedValue<N>, AssignedValue<N>, N, Error>
    for FiveColumnBaseGate<N>
{
    fn add(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::add(self, ctx, lhs, rhs)
    }

    fn minus(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::sub(self, ctx, lhs, rhs)
    }

    fn scalar_mul(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::mul(self, ctx, lhs, rhs)
    }

    fn one(&self, ctx: &mut RegionAux<'a, 'b, N>) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::assign_constant(self, ctx, N::one())
    }

    fn zero(&self, ctx: &mut RegionAux<'a, 'b, N>) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::assign_constant(self, ctx, N::zero())
    }

    fn from_constant(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        c: N,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::assign_constant(self, ctx, c)
    }

    fn generator(&self, ctx: &mut RegionAux<'a, 'b, N>) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::assign_constant(self, ctx, N::one())
    }
}

impl<'a, 'b, 'c, N: FieldExt>
    ContextRing<RegionAux<'a, 'b, N>, AssignedValue<N>, AssignedValue<N>, Error>
    for FiveColumnBaseGate<N>
{
    fn mul(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::mul(self, ctx, lhs, rhs)
    }

    fn div(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::div_unsafe(self, ctx, lhs, rhs)
    }

    fn square(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::mul(self, ctx, lhs, lhs)
    }
}
