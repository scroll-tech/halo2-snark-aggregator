use super::field::ArithFieldChip;
use std::ops::{Add, Div, Mul, Sub};

pub enum FieldArithHelper<A: ArithFieldChip> {
    Value(A::AssignedValue),
    Add(Box<FieldArithHelper<A>>, Box<FieldArithHelper<A>>),
    Sub(Box<FieldArithHelper<A>>, Box<FieldArithHelper<A>>),
    Mul(Box<FieldArithHelper<A>>, Box<FieldArithHelper<A>>),
    Div(Box<FieldArithHelper<A>>, Box<FieldArithHelper<A>>),
}

impl<A: ArithFieldChip> FieldArithHelper<A> {
    pub fn eval(self, ctx: &mut A::Context, schip: &A) -> Result<A::AssignedValue, A::Error> {
        match self {
            FieldArithHelper::Value(v) => Ok(v),
            FieldArithHelper::Add(a, b) => {
                let a = a.eval(ctx, schip)?;
                let b = b.eval(ctx, schip)?;
                schip.add(ctx, &a, &b)
            }
            FieldArithHelper::Sub(a, b) => {
                let a = a.eval(ctx, schip)?;
                let b = b.eval(ctx, schip)?;
                schip.sub(ctx, &a, &b)
            }
            FieldArithHelper::Mul(a, b) => {
                let a = a.eval(ctx, schip)?;
                let b = b.eval(ctx, schip)?;
                schip.mul(ctx, &a, &b)
            }
            FieldArithHelper::Div(a, b) => {
                let a = a.eval(ctx, schip)?;
                let b = b.eval(ctx, schip)?;
                schip.div(ctx, &a, &b)
            }
        }
    }
}

impl<A: ArithFieldChip> From<&A::AssignedValue> for FieldArithHelper<A> {
    fn from(v: &A::AssignedValue) -> Self {
        FieldArithHelper::Value(v.clone())
    }
}

impl<A: ArithFieldChip> Add<FieldArithHelper<A>> for FieldArithHelper<A> {
    type Output = Self;

    fn add(self, rhs: FieldArithHelper<A>) -> Self::Output {
        FieldArithHelper::Add(Box::new(self), Box::new(rhs))
    }
}

impl<A: ArithFieldChip> Sub<FieldArithHelper<A>> for FieldArithHelper<A> {
    type Output = Self;

    fn sub(self, rhs: FieldArithHelper<A>) -> Self::Output {
        FieldArithHelper::Sub(Box::new(self), Box::new(rhs))
    }
}

impl<A: ArithFieldChip> Mul<FieldArithHelper<A>> for FieldArithHelper<A> {
    type Output = Self;

    fn mul(self, rhs: FieldArithHelper<A>) -> Self::Output {
        FieldArithHelper::Mul(Box::new(self), Box::new(rhs))
    }
}

impl<A: ArithFieldChip> Div<FieldArithHelper<A>> for FieldArithHelper<A> {
    type Output = Self;

    fn div(self, rhs: FieldArithHelper<A>) -> Self::Output {
        FieldArithHelper::Div(Box::new(self), Box::new(rhs))
    }
}

#[macro_export]
macro_rules! arith_ast {
    ($postfix:tt + $($tail:tt)*) => { arith_ast!($postfix) + arith_ast!($($tail)*) };
    ($postfix:tt - $($tail:tt)*) => { arith_ast!($postfix) - arith_ast!($($tail)*) };
    ($postfix:tt * $($tail:tt)*) => { arith_ast!($postfix) * arith_ast!($($tail)*) };
    ($postfix:tt / $($tail:tt)*) => { arith_ast!($postfix) / arith_ast!($($tail)*) };
    (($($inner:tt)*)) => { (arith_ast!($($inner)*)) };
    ($inner:tt) => { FieldArithHelper::from($inner) };
}
/*
// Group operations Wll not work in general since we have context dependence when
// performing group/ring operations
#[macro_export]
macro_rules! arith_in_ctx {
  //arith_in_ctx! { @ pfx [h, r] (r,) () }`
  (@pfx [$s:tt, $c:tt] ($result:expr,) ()) => {
      {$s.ok($result.clone())}
  };
//note: to `arith_in_ctx! (@ pfx [h, r] (a a) (+ a +))`
  (@pfx [$s:tt, $c:tt] ($a:expr, $b:expr, $($stack:tt,)*) (+ $($tail:tt)*)) => {
      {
        let r = &$s.add($c, $a, $b)?;
        arith_in_ctx! (@pfx [$s, $c] (r, $($stack,)*) ($($tail)*))
      }
  };
  (@pfx [$s:tt, $c:tt] ($a:expr, $b:expr, $($stack:tt,)*) (- $($tail:tt)*)) => {
      {
        let r = &$s.minus($c, $b, $a)?;
        arith_in_ctx!(@pfx [$s, $c] (r, $($stack,)*) ($($tail)*))
      }
  };
  (@pfx [$s:tt, $c:tt] ($a:expr, $b:expr, $($stack:tt,)*) (* $($tail:tt)*)) => {
      {
        let eval = &$s.mul($c, $b, $a)?;
        arith_in_ctx!(@pfx [$s, $c] (eval, $($stack,)*) ($($tail)*))
      }
  };
  (@pfx [$s:tt, $c:tt] ($a:expr, $b:expr, $($stack:tt,)*) (/ $($tail:tt)*)) => {
      {
        let eval = &$s.div($c, $b, $a)?;
        arith_in_ctx!(@pfx [$s, $c] (eval, $($stack,)*) ($($tail)*))
      }
  };

  (@pfx [$s:tt, $c:tt] ($($stack:tt,)*) ($head:tt $($tail:tt)*)) => {
      arith_in_ctx!(@pfx [$s, $c] ($head, $($stack,)*) ($($tail)*))
  };

  ([$s:tt, $c:tt] $($rhs:tt)*) => {
    infix2postfix!([$s, $c] () () $($rhs)*)
  };
}
*/
