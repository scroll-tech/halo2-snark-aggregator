use super::api::{ContextGroup, ContextRing};
use group::Group;
use pairing_bn256::arithmetic::{CurveAffine, FieldExt};

pub struct FieldCode<F: FieldExt> {
    pub one: F,
    pub zero: F,
    pub generator: F,
}

impl<F: FieldExt> Default for FieldCode<F> {
    fn default() -> Self {
        Self {
            one: F::one(),
            zero: F::zero(),
            generator: F::one(),
        }
    }
}

pub struct PointCode<C: CurveAffine> {
    pub one: C::CurveExt,
    pub zero: C::CurveExt,
    pub generator: C::CurveExt,
}

impl<C: CurveAffine> Default for PointCode<C> {
    fn default() -> Self {
        Self {
            one: <C as CurveAffine>::CurveExt::generator(),
            zero: <C as CurveAffine>::CurveExt::identity(),
            generator: <C as CurveAffine>::CurveExt::generator(),
        }
    }
}

impl<C: CurveAffine> ContextGroup<(), C::ScalarExt, C::CurveExt, C, ()> for PointCode<C> {
    fn add(&self, _ctx: &mut (), lhs: &C::CurveExt, rhs: &C::CurveExt) -> Result<C::CurveExt, ()> {
        let t = (*lhs) + (*rhs);
        Ok(t)
    }

    fn minus(
        &self,
        _ctx: &mut (),
        lhs: &C::CurveExt,
        rhs: &C::CurveExt,
    ) -> Result<C::CurveExt, ()> {
        let t = *lhs - *rhs;
        Ok(t)
    }

    fn scalar_mul(
        &self,
        _ctx: &mut (),
        lhs: &C::ScalarExt,
        rhs: &C::CurveExt,
    ) -> Result<C::CurveExt, ()> {
        let t = (*rhs) * (*lhs);
        Ok(t)
    }

    fn one(&self, _ctx: &mut ()) -> Result<C::CurveExt, ()> {
        Ok(self.one)
    }

    fn zero(&self, _ctx: &mut ()) -> Result<C::CurveExt, ()> {
        Ok(self.zero)
    }

    fn from_constant(&self, _ctx: &mut (), c: C) -> Result<C::CurveExt, ()> {
        let c = c.to_curve();
        Ok(c)
    }

    fn generator(&self, _ctx: &mut ()) -> Result<C::CurveExt, ()> {
        Ok(self.generator)
    }

    fn to_value(&self, _: &C::CurveExt) -> Result<C, ()> {
        unimplemented!()
    }

    fn from_var(&self, _: &mut (), c: C) -> Result<C::CurveExt, ()> {
        let c = c.to_curve();
        Ok(c)
    }
}

impl<F: FieldExt> ContextGroup<(), F, F, F, ()> for FieldCode<F> {
    fn add(&self, _ctx: &mut (), lhs: &F, rhs: &F) -> Result<F, ()> {
        let t = *lhs + *rhs;
        Ok(t)
    }

    fn minus(&self, _ctx: &mut (), lhs: &F, rhs: &F) -> Result<F, ()> {
        let t = *lhs - *rhs;
        Ok(t)
    }

    fn scalar_mul(&self, _ctx: &mut (), lhs: &F, rhs: &F) -> Result<F, ()> {
        let t = (*lhs) * (*rhs);
        Ok(t)
    }

    fn one(&self, _ctx: &mut ()) -> Result<F, ()> {
        Ok(self.one)
    }

    fn zero(&self, _ctx: &mut ()) -> Result<F, ()> {
        Ok(self.zero)
    }

    fn from_constant(&self, _ctx: &mut (), c: F) -> Result<F, ()> {
        Ok(c)
    }

    fn generator(&self, _ctx: &mut ()) -> Result<F, ()> {
        Ok(self.generator)
    }

    fn to_value(&self, v: &F) -> Result<F, ()> {
        Ok(v.clone())
    }

    fn from_var(&self, ctx: &mut (), c: F) -> Result<F, ()> {
        Ok(c)
    }
}

impl<F: FieldExt> ContextRing<(), F, F, ()> for FieldCode<F> {
    fn mul(&self, _ctx: &mut (), lhs: &F, rhs: &F) -> Result<F, ()> {
        let t = (*lhs) * (*rhs);
        Ok(t)
    }

    fn div(&self, _ctx: &mut (), lhs: &F, rhs: &F) -> Result<F, ()> {
        let t = (*lhs) * (rhs.invert().unwrap());
        Ok(t)
    }

    fn square(&self, _ctx: &mut (), lhs: &F) -> Result<F, ()> {
        Ok((*lhs) * (*lhs))
    }
}
