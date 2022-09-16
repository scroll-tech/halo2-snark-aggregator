use super::scalar_chip::ScalarChip;
use ff::PrimeField;
use halo2_ecc::{
    bigint::CRTInteger,
    ecc,
    fields::{fp, FieldChip},
    gates::Context,
};
use halo2_proofs::{arithmetic::CurveAffine, circuit::AssignedCell, plonk::Error};
use halo2_snark_aggregator_api::arith::{common::ArithCommonChip, ecc::ArithEccChip};
use std::marker::PhantomData;

pub type FpChip<C> = fp::FpConfig<<C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>;
pub type FpPoint<C> = CRTInteger<<C as CurveAffine>::ScalarExt>;

// We're assuming that the scalar field of C actually happens to be the native field F of the proving system
// There used to be a 'b lifetime, I don't know why it's needed so I removed
// We need this struct because you can't implement traits if you don't own either the struct or the trait...
pub struct EccChip<'a, 'b, C: CurveAffine>
where
    C::Base: PrimeField,
{
    pub chip: ecc::EccChip<'a, C::ScalarExt, FpChip<C>>,
    // More succinctly, if F = C::ScalarExt && Fp = C::Base, then
    // chip: ecc::EccChip<'a, F, FpChip<F>>

    // the 'b lifetime is needed for Context<'b, F> below
    pub _marker: PhantomData<&'b C>,
}

impl<'a, 'b, C: CurveAffine> EccChip<'a, 'b, C>
where
    C::Base: PrimeField,
{
    pub fn new(field_chip: &'a FpChip<C>) -> Self {
        EccChip {
            chip: ecc::EccChip::construct(field_chip),
            _marker: PhantomData,
        }
    }
}

impl<'a, 'b, C: CurveAffine> ArithCommonChip for EccChip<'a, 'b, C>
where
    C::Base: PrimeField,
{
    type Context = Context<'b, C::ScalarExt>;
    type Value = C;
    type AssignedValue = ecc::EccPoint<C::ScalarExt, FpPoint<C>>;
    type Error = Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        // TODO: change this to either constrain a.x != b.x or change to a general addition
        self.chip.add_unequal(ctx, a, b)
    }

    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        // TODO: change this to either constrain a.x != b.x or change to a general addition
        self.chip.sub_unequal(ctx, a, b)
    }

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        unimplemented!()
    }

    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        let g1 = C::generator();
        self.assign_const(ctx, g1)
    }

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        let c_fixed = ecc::fixed::FixedEccPoint::from_g1(
            &c,
            self.chip.field_chip.num_limbs,
            self.chip.field_chip.limb_bits,
        );
        c_fixed.assign(self.chip.field_chip, ctx)
    }

    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        self.chip.load_private(
            ctx,
            (
                Some(v.coordinates().unwrap().x().clone()),
                Some(v.coordinates().unwrap().y().clone()),
            ),
        )
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        let x = FpChip::<C>::get_assigned_value(&v.x).expect("x should not be None");
        let y = FpChip::<C>::get_assigned_value(&v.y).expect("y should not be None");
        Ok(C::from_xy(x, y).unwrap())
    }

    fn normalize(
        &self,
        ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        // identity (?)
        Ok(v.clone())
    }
}

impl<'a, 'b, C: CurveAffine> ArithEccChip for EccChip<'a, 'b, C>
where
    C::Base: PrimeField,
{
    type Point = C;
    type AssignedPoint = ecc::EccPoint<C::ScalarExt, FpPoint<C>>;
    type Scalar = C::ScalarExt;
    type AssignedScalar = AssignedCell<C::ScalarExt, C::ScalarExt>;
    type Native = C::ScalarExt;
    type AssignedNative = AssignedCell<C::ScalarExt, C::ScalarExt>;

    type ScalarChip = ScalarChip<'a, 'b, C::ScalarExt>;
    type NativeChip = ScalarChip<'a, 'b, C::ScalarExt>;

    fn scalar_mul(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: &Self::AssignedPoint,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        // only works if C::b(), which is an element of C::Base, actually fits into C::ScalarExt
        let b_base = halo2_ecc::utils::fe_to_biguint(&C::b());
        let b = halo2_ecc::utils::biguint_to_fe::<C::ScalarExt>(&b_base);
        self.chip.scalar_mult(
            ctx,
            rhs,
            &vec![lhs.clone()],
            b,
            <C::Scalar as PrimeField>::NUM_BITS as usize,
            4,
        )
    }

    fn scalar_mul_constant(
        &self,
        ctx: &mut Self::Context,
        lhs: &Self::AssignedScalar,
        rhs: Self::Point,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        // only works if C::b(), which is an element of C::Base, actually fits into C::ScalarExt
        let b_base = halo2_ecc::utils::fe_to_biguint(&C::b());
        let b = halo2_ecc::utils::biguint_to_fe::<C::ScalarExt>(&b_base);

        let fixed_point = ecc::fixed::FixedEccPoint::from_g1(
            &rhs,
            self.chip.field_chip.num_limbs,
            self.chip.field_chip.limb_bits,
        );
        self.chip.fixed_base_scalar_mult(
            ctx,
            &fixed_point,
            &vec![lhs.clone()],
            b,
            <C::Scalar as PrimeField>::NUM_BITS as usize,
            4,
        )
    }

    fn multi_exp(
        &self,
        ctx: &mut Self::Context,
        mut points: Vec<Self::AssignedPoint>,
        scalars: Vec<Self::AssignedScalar>,
    ) -> Result<Self::AssignedPoint, Self::Error> {
        // only works if C::b(), which is an element of C::Base, actually fits into C::ScalarExt
        let b_base = halo2_ecc::utils::fe_to_biguint(&C::b());
        let b = halo2_ecc::utils::biguint_to_fe::<C::ScalarExt>(&b_base);

        self.chip.multi_scalar_mult::<C>(
            ctx,
            &points,
            &scalars.iter().map(|scalar| vec![scalar.clone()]).collect(),
            b,
            <C::Scalar as PrimeField>::NUM_BITS as usize,
            4,
        )
    }
}
