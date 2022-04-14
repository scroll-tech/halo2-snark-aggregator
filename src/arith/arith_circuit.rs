use super::api::{ContextGroup, ContextRing};
use crate::{
    circuits::{
        ecc_circuit::{AssignedPoint, EccCircuitOps},
        native_ecc_circuit::NativeEccCircuit,
    },
    gates::{
        base_gate::{AssignedValue, BaseGateOps, RegionAux},
        five::base_gate::FiveColumnBaseGate,
    },
};
use group::ff::Field;
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    plonk::Error,
};

impl<'a, 'b, 'c, C: CurveAffine>
    ContextGroup<
        RegionAux<'a, 'b, C::ScalarExt>,
        AssignedValue<C::ScalarExt>,
        AssignedPoint<C, C::ScalarExt>,
        C,
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
        EccCircuitOps::assign_constant_point_from_scalar(self, ctx, C::ScalarExt::from(0u64))
    }

    fn zero(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_constant_point_from_scalar(self, ctx, C::ScalarExt::from(1u64))
    }

    fn from_constant(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        c: C,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_constant_point(self, ctx, c.to_curve())
    }

    fn generator(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_constant_point_from_scalar(self, ctx, C::ScalarExt::from(1u64))
    }

    fn to_value(&self, p: &AssignedPoint<C, C::ScalarExt>) -> Result<C, Error> {
        if p.z.value == C::ScalarExt::zero() {
            Ok(C::identity())
        } else {
            let x = self.0.integer_gate.get_w(&p.x)?;
            let y = self.0.integer_gate.get_w(&p.y)?;
            Ok(C::from_xy(x, y).unwrap())
        }
    }

    fn from_var(
        &self,
        ctx: &mut RegionAux<'a, 'b, C::ScalarExt>,
        c: C,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        EccCircuitOps::assign_point(self, ctx, c.to_curve())
    }

    fn mul_add_constant(
        &self,
        _: &mut RegionAux<'a, 'b, C::ScalarExt>,
        _: &AssignedValue<C::ScalarExt>,
        _: &AssignedPoint<C, C::ScalarExt>,
        _: C,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        unreachable!()
    }

    fn sum_with_constant(
        &self,
        _: &mut RegionAux<'a, 'b, C::ScalarExt>,
        _: Vec<(&AssignedValue<C::ScalarExt>, C)>,
        _: C,
    ) -> Result<AssignedPoint<C, C::ScalarExt>, Error> {
        unreachable!()
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

    fn to_value(&self, a: &AssignedValue<N>) -> Result<N, Error> {
        Ok(a.value.clone())
    }

    fn from_var(&self, ctx: &mut RegionAux<'a, 'b, N>, c: N) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::assign(self, ctx, c)
    }

    fn mul_add_constant(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        lhs: &AssignedValue<N>,
        rhs: &AssignedValue<N>,
        c: N,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::mul_add_constant(self, ctx, lhs, rhs, c)
    }

    fn sum_with_constant(
        &self,
        ctx: &mut RegionAux<'a, 'b, N>,
        a: Vec<(&AssignedValue<N>, N)>,
        c: N,
    ) -> Result<AssignedValue<N>, Error> {
        BaseGateOps::sum_with_constant(self, ctx, a, c)
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
