use std::fmt::Debug;

pub trait ArithCommonChip<
    Context,
    Value: Clone + PartialEq + Debug,
    AssignedValue: Clone + Debug,
    Error,
>
{
    fn add(
        &self,
        ctx: &mut Context,
        a: &AssignedValue,
        b: &AssignedValue,
    ) -> Result<AssignedValue, Error>;
    fn sub(
        &self,
        ctx: &mut Context,
        a: &AssignedValue,
        b: &AssignedValue,
    ) -> Result<AssignedValue, Error>;

    fn assign_zero(&self, ctx: &mut Context) -> Result<AssignedValue, Error>;
    fn assign_one(&self, ctx: &mut Context) -> Result<AssignedValue, Error>;

    fn assign_const(&self, ctx: &mut Context, c: Value) -> Result<AssignedValue, Error>;
    fn assign_var(&self, ctx: &mut Context, v: Value) -> Result<AssignedValue, Error>;
    fn to_value(&self, v: &AssignedValue) -> Result<Value, Error>;
}
