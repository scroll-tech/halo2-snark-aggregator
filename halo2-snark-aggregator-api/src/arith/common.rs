use std::fmt::Debug;

pub trait ArithCommon<Value: Clone + PartialEq + Debug, Error> {
    type Context;
    type Assigned: Clone + Debug;

    fn add(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
        b: &Self::Assigned,
    ) -> Result<Self::Assigned, Error>;
    fn sub(
        &self,
        ctx: &mut Self::Context,
        a: &Self::Assigned,
        b: &Self::Assigned,
    ) -> Result<Self::Assigned, Error>;

    fn assign_zero(&self, ctx: &mut Self::Context) -> Result<Self::Assigned, Error>;
    fn assign_one(&self, ctx: &mut Self::Context) -> Result<Self::Assigned, Error>;

    fn assign_const(&self, ctx: &mut Self::Context, c: &Value) -> Result<Self::Assigned, Error>;
    fn assign_var(&self, ctx: &mut Self::Context, v: &Value) -> Result<Self::Assigned, Error>;
    fn to_value(&self, v: &Self::Assigned) -> Result<Value, Error>;
}
