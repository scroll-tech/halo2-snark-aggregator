use super::scalar_chip::ScalarChip;
use halo2_ecc_circuit_lib::{
    chips::{
        ecc_chip::{AssignedPoint, EccChipOps},
        native_ecc_chip::NativeEccChip,
    },
    gates::base_gate::{AssignedValue, Context},
};
use halo2_proofs::arithmetic::Field;
use halo2_proofs::{arithmetic::CurveAffine, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use std::marker::PhantomData;

pub struct EccChip<'a, 'b, C: CurveAffine> {
    pub chip: &'a NativeEccChip<'a, C>,
    _phantom: PhantomData<&'b C>,
}

impl<'a, 'b, C: CurveAffine> EccChip<'a, 'b, C> {
    pub fn new(chip: &'a NativeEccChip<'a, C>) -> Self {
        EccChip {
            chip,
            _phantom: PhantomData,
        }
    }
}

impl<'a, 'b, C: CurveAffine> ArithCommonChip for EccChip<'a, 'b, C> {
    type Context = Context<'b, C::ScalarExt>;
    type Value = C;
    type AssignedValue = AssignedPoint<C, C::ScalarExt>;
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.add(ctx, &mut a.clone(), &mut b.clone())
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.sub(ctx, &mut a.clone(), b)
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.assign_identity(ctx)
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        self.chip
            .assign_constant_point_from_scalar(ctx, C::ScalarExt::from(1u64))
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.assign_constant_point(ctx, c.to_curve())
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.assign_point(ctx, v.to_curve())
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        if v.z.value == C::ScalarExt::one() {
            Ok(C::identity())
        } else {
            let x = self.chip.integer_chip().get_w(&v.x)?;
            let y = self.chip.integer_chip().get_w(&v.y)?;
            Ok(C::from_xy(x, y).unwrap())
        }
    }
}

impl<'a, 'b, C: CurveAffine> ArithEccChip for EccChip<'a, 'b, C> {
    type Point = C;
    type AssignedPoint = AssignedPoint<C, C::ScalarExt>;
    type Scalar = C::ScalarExt;
    type AssignedScalar = AssignedValue<C::ScalarExt>;
    type Native = C::ScalarExt;
    type AssignedNative = AssignedValue<C::ScalarExt>;

    type ScalarChip = ScalarChip<'a, 'b, C::ScalarExt>;
    type NativeChip = ScalarChip<'a, 'b, C::ScalarExt>;

    fn print_debug_info(&self, c: &Self::Context, desc: &'static str) {
        println!("EccChip: {}, current offset: {}", desc, *c.offset);
    }
    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        self.chip.mul(ctx, &mut rhs.clone(), lhs)
    }
}
