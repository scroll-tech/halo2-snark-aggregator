use crate::arith::{common::ArithCommonChip, field::ArithFieldChip};
use halo2_proofs::arithmetic::FieldExt;
use std::{collections::HashMap, marker::PhantomData};

#[derive(Default)]
pub struct MockEccChipCtx {
    pub point_list: Vec<String>,
    pub tag: String,
}

impl MockEccChipCtx {
    pub fn print(&self) {
        log::debug!("===== BEGIN: Halo2VerifierCircuit rows cost estimation ========");
        let n = self.point_list.len();
        let rows = n * 79322;
        let mut k = 18;
        loop {
            if 1 << k > rows {
                break;
            }
            k += 1;
        }
        log::debug!("total ecmul: {}", n);
        log::debug!(
            "rows needed by ecmul: {} = {} * 79322 = {:.2} * 2**{}",
            rows,
            n,
            (rows as f64) / ((1 << k) as f64),
            k
        );
        log::debug!("at least need k: {}", k);
        let counter = self
            .point_list
            .iter()
            .cloned()
            .fold(HashMap::new(), |mut map, val| {
                let tag = val.split("_").next().unwrap_or("unknown").to_string();
                map.entry(tag).and_modify(|frq| *frq += 1).or_insert(1);
                map
            });
        for (k, v) in counter {
            log::debug!(
                "circuit {}: num {}, percentage {:.2}%",
                k,
                v,
                (v as f64 / n as f64) * 100f64
            );
        }
        log::trace!("all point list: {:?}", self.point_list);
        log::debug!("===== END: Halo2VerifierCircuit rows cost estimation ========");
    }
}

pub struct MockFieldChip<F: FieldExt, E> {
    zero: F,
    one: F,
    _data: PhantomData<E>,
}

impl<F: FieldExt, E> Default for MockFieldChip<F, E> {
    fn default() -> Self {
        Self {
            zero: F::zero(),
            one: F::one(),
            _data: PhantomData,
        }
    }
}

impl<F: FieldExt, E> ArithCommonChip for MockFieldChip<F, E> {
    type Context = MockEccChipCtx;
    type Value = F;
    type AssignedValue = F;
    type Error = E;

    fn add(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(*a + *b)
    }

    fn sub(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(*a - *b)
    }

    fn assign_zero(&self, _ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.zero)
    }

    fn assign_one(&self, _ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error> {
        Ok(self.one)
    }

    fn assign_const(
        &self,
        _ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(c)
    }

    fn assign_var(
        &self,
        _ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error> {
        Ok(v)
    }

    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error> {
        Ok(*v)
    }
}

impl<F: FieldExt, E> ArithFieldChip for MockFieldChip<F, E> {
    type Field = F;
    type AssignedField = F;

    fn mul(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *b)
    }

    fn div(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * b.invert().unwrap())
    }

    fn square(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *a)
    }

    fn sum_with_coeff_and_constant(
        &self,
        _ctx: &mut Self::Context,
        a_with_coeff: Vec<(&Self::AssignedField, Self::Value)>,
        b: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        let mut acc = b;
        for (x, coeff) in a_with_coeff {
            acc = acc + *x * coeff
        }
        Ok(acc)
    }

    fn mul_add_constant(
        &self,
        _ctx: &mut Self::Context,
        a: &Self::AssignedField,
        b: &Self::AssignedField,
        c: Self::Field,
    ) -> Result<Self::AssignedField, Self::Error> {
        Ok(*a * *b + c)
    }
}
