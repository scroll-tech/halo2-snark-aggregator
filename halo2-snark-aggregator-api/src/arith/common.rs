use std::fmt::Debug;

pub trait ArithCommon<Context, Value: Clone + PartialEq + Debug, Assigned: Clone + Debug, Error> {
    fn add(&self, ctx: &mut Context, a: &Assigned, b: &Assigned) -> Result<Assigned, Error>;
    fn sub(&self, ctx: &mut Context, a: &Assigned, b: &Assigned) -> Result<Assigned, Error>;

    fn assign_zero(&self, ctx: &mut Context) -> Result<Assigned, Error>;
    fn assign_one(&self, ctx: &mut Context) -> Result<Assigned, Error>;

    fn assign_const(&self, ctx: &mut Context, c: Value) -> Result<Assigned, Error>;
    fn assign_var(&self, ctx: &mut Context, v: Value) -> Result<Assigned, Error>;
    fn to_value(&self, v: &Assigned) -> Result<Value, Error>;
}
