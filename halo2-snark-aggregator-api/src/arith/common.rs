use std::fmt::{Debug, Display};

pub trait ArithCommonChip {
    type Context: Display;
    type Value: Clone + PartialEq + Debug;
    type AssignedValue: Clone + Debug;
    type Error;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::AssignedValue,
        b: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error>;
    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::AssignedValue, Self::Error>;

    fn assign_const(
        &self,
        ctx: &mut Self::Context,
        c: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn assign_var(
        &self,
        ctx: &mut Self::Context,
        v: Self::Value,
    ) -> Result<Self::AssignedValue, Self::Error>;
    fn to_value(&self, v: &Self::AssignedValue) -> Result<Self::Value, Self::Error>;

    fn normalize(
        &self,
        ctx: &mut Self::Context,
        v: &Self::AssignedValue,
    ) -> Result<Self::AssignedValue, Self::Error>;
}
