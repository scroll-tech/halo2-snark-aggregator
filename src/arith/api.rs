//#![feature(trace_macros)]
//trace_macros!(true);
// Context Arithment Group under Context C, Scalar Group S and Base Group B
pub trait ContextGroup<C, S, B, Error> {
    fn add(&self, cxt:&mut C, lhs: &B, rhs: &B) -> Result<B, Error>;
    fn minus(&self, cxt:&mut C, lhs: &B, rhs: &B) -> Result<B, Error>;
    fn scalar_mul(&self, cxt:&mut C, lhs: &S, rhs: &B) -> Result<B, Error>;
    fn one(&self) -> &B;
    fn zero(&self) -> &B;
    fn from_constant(&self, c: u32) -> Result<B, Error>;
    fn ok(&self, v:B) -> Result<B, Error> {
        Ok(v)
    }
}

// Context Arithment Group under Context C, Scalar Group S and Base Group B
pub trait ContextRing<C, S, B, Error> {
   fn mul(&self, cxt:&mut C, lhs: &B, rhs: &B) -> Result<B, Error>;
   fn square(&self, cxt:&mut C, lhs: &B) -> Result<B, Error>;
   fn generator(&self) -> &B;
}

pub trait PowConstant<C, S, G, Error> {
    fn pow_constant(
        &self,
        ctx: &mut C,
        base: &G,
        exponent: u32,
    ) -> Result<G, Error>;
}

impl<C, S, G:Clone, Error, T:ContextRing<C, S, G, Error>> PowConstant<C, S, G, Error> for T
{
    fn pow_constant(
        &self,
        ctx: &mut C,
        base: &G,
        exponent: u32,
    ) -> Result<G, Error> {
       assert!(exponent >= 1);
        let mut acc = base.clone();
        let mut second_bit = 1;
        while second_bit <= exponent {
            second_bit <<= 1;
        }
        second_bit >>= 2;
        while second_bit > 0 {
            acc = self.square(ctx, &acc)?;
            if exponent & second_bit == 1 {
                acc = self.mul(ctx, &acc, base)?;
            }
            second_bit >>= 1;
        }
        Ok(acc)
    }
}

#[macro_export]
macro_rules! infix2postfix {
    (@cvt [$s:tt, $c:tt] () $postfix:tt) => { arith_in_ctx!(@pfx [$s, $c] () $postfix) };

    // infix to postfix conversion using the rules at the bottom of this page: http://csis.pace.edu/~wolf/CS122/infix-postfix.htm

    // at end of input, flush the operators to postfix
    (@cvt [$s:tt, $c:tt] ($ophead:tt $($optail:tt)*) ($($postfix:tt)*)) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* $ophead)) };

    // 2. push an operator onto the stack if it's empty or has a left-paren on top
    (@cvt [$s:tt, $c:tt] (                 ) $postfix:tt + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (+               ) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (                 ) $postfix:tt - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (-               ) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (                 ) $postfix:tt * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (*               ) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (                 ) $postfix:tt / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/               ) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (LP $($optail:tt)*) $postfix:tt + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (+ LP $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (LP $($optail:tt)*) $postfix:tt - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (- LP $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (LP $($optail:tt)*) $postfix:tt * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (* LP $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (LP $($optail:tt)*) $postfix:tt / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/ LP $($optail)*) $postfix $($tail)*) };

    // 3. push a left-paren onto the stack
    (@cvt [$s:tt, $c:tt] ($($operator:tt)*) $postfix:tt ($($inner:tt)*) $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (LP $($operator)*) $postfix $($inner)* RP $($tail)*) };

    // 4. see right-paren, pop operators to postfix until left-paren
    (@cvt [$s:tt, $c:tt] (LP         $($optail:tt)*) $postfix:tt       RP $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) $postfix               $($tail)*)    };
    (@cvt [$s:tt, $c:tt] ($ophead:tt $($optail:tt)*) ($($postfix:tt)*) RP $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* $ophead) RP $($tail)*) };

    // 5. if an operator w/ lower precedence is on top, just push
    (@cvt [$s:tt, $c:tt] (+ $($optail:tt)*) $postfix:tt * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (* + $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (- $($optail:tt)*) $postfix:tt * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (* - $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (+ $($optail:tt)*) $postfix:tt / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/ + $($optail)*) $postfix $($tail)*) };
    (@cvt [$s:tt, $c:tt] (- $($optail:tt)*) $postfix:tt / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/ - $($optail)*) $postfix $($tail)*) };

    // 6. if an operator w/ equal precedence is on top, pop and push
    (@cvt [$s:tt, $c:tt] (+ $($optail:tt)*) ($($postfix:tt)*) + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (+ $($optail)*) ($($postfix)* +) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (- $($optail:tt)*) ($($postfix:tt)*) - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (- $($optail)*) ($($postfix)* -) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (+ $($optail:tt)*) ($($postfix:tt)*) - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (- $($optail)*) ($($postfix)* +) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (- $($optail:tt)*) ($($postfix:tt)*) + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (+ $($optail)*) ($($postfix)* -) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (* $($optail:tt)*) ($($postfix:tt)*) * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (* $($optail)*) ($($postfix)* *) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (/ $($optail:tt)*) ($($postfix:tt)*) / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/ $($optail)*) ($($postfix)* /) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (* $($optail:tt)*) ($($postfix:tt)*) / $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (/ $($optail)*) ($($postfix)* *) $($tail)*) };
    (@cvt [$s:tt, $c:tt] (/ $($optail:tt)*) ($($postfix:tt)*) * $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] (* $($optail)*) ($($postfix)* /) $($tail)*) };

    // 7. if an operator w/ higher precedence is on top, pop it to postfix
    (@cvt [$s:tt, $c:tt] (* $($optail:tt)*) ($($postfix:tt)*) + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* *) + $($tail)*) };
    (@cvt [$s:tt, $c:tt] (* $($optail:tt)*) ($($postfix:tt)*) - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* *) - $($tail)*) };
    (@cvt [$s:tt, $c:tt] (/ $($optail:tt)*) ($($postfix:tt)*) + $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* /) + $($tail)*) };
    (@cvt [$s:tt, $c:tt] (/ $($optail:tt)*) ($($postfix:tt)*) - $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] ($($optail)*) ($($postfix)* /) - $($tail)*) };

    // 1. operands go to the postfix output
    (@cvt [$s:tt, $c:tt] $operators:tt ($($postfix:tt)*) $head:tt $($tail:tt)*) => { infix2postfix!(@cvt [$s, $c] $operators ($($postfix)* $head) $($tail)*) };
}

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
  (@pfx [$s:tt, $c:tt] ($($stack:tt,)*) ($head:tt $($tail:tt)*)) => {
      arith_in_ctx!(@pfx [$s, $c] ($head, $($stack,)*) ($($tail)*))
  };

  ([$s:tt, $c:tt] $($rhs:tt)*) => {
    infix2postfix!(@cvt [$s, $c] () () $($rhs)*)
  };

}

#[cfg(test)]
mod test_marco {
  use crate::carith::ContextGroup;
  use crate::carith::ContextRing;

  #[derive(Debug, Default, Clone)]
  struct W {
    pub t: i32,
  }

  impl ContextGroup<W, W, W, ()> for W {
    fn add(&self, _ctx:&mut W, lhs:&W, rhs:&W) -> W {
      println!("(add {:?} {:?})", lhs, rhs);
      let t = lhs.t + rhs.t;
      Ok(W {t})
    }
    fn minus(&self, _ctx:&mut W, lhs:&W, rhs:&W) -> W {
      let t = lhs.t - rhs.t;
      Ok(W {t})
    }
    fn scalar_mul(&self, _ctx:&mut W, lhs:&W, rhs:&W) -> W {
      let t = lhs.t * rhs.t;
      Ok(W {t})
    }
  }

  impl ContextRing <W, W, W> for W {
    fn mul(&self, _ctx:&mut W, lhs:&W, rhs:&W) -> W {
      let t = lhs.t * rhs.t;
      Ok(W {t})
    }
    fn power (&self, _ctx:&mut W, lhs:&W, rhs:&W) -> W {
      let t = lhs.t ^ rhs.t;
      Ok(W {t})
    }
  }

  #[test]
  fn test_singleton() {
    let mut i = W {t:1};
    let h = W {t:1};
    let r = &mut i;
    let a = W {t:1};
    let a = &a;
    let b = W {t:2};
    let b = &b;
    let c = W {t:3};
    let c = &c;
    let d = W {t:4};
    let d = &d;
    let a1 = arith_in_ctx!([h, r] a);
    assert_eq!(a1.t, 1);
    let a1 = arith_in_ctx!([h, r] a + a + a);
    assert_eq!(a1.t, 3);
    let a1 = arith_in_ctx!([h, r] a - a);
    assert_eq!(a1.t, 0);
    let a1 = arith_in_ctx!([h, r] b - (b * b));
    assert_eq!(a1.t, -2);
    let a1 = arith_in_ctx!([h, r] b - b * b);
    assert_eq!(a1.t, -2);
    let a1 = arith_in_ctx!([h, r] (b - b) * b);
    assert_eq!(a1.t, 0);
    let a1 = arith_in_ctx!([h, r] (b - b * b + b) * b + b * b);
    assert_eq!(a1.t, 4);
/*
    let a1 = under_context!([h, r] (a - a) * a);
    assert_eq!(a1, 0);
    let a2 = under_context!([h, r] 1 + 2 + 3);
    assert_eq!(a2, 6);
*/
/*
    let a3 = under_context!([()] 1 + (2 + 3) + b);
    assert_eq!(a3, 9);
    let a4 = under_context!([()] 1 * (2 + 3) * b);
    assert_eq!(a4, 15);
*/
  }
}
