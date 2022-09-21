use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Cell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};

use std::marker::PhantomData;

#[derive(Clone, Copy, Debug)]
pub struct AssignedCondition<N: FieldExt> {
    pub cell: Cell,
    pub value: N,
}

#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<N: FieldExt> {
    pub cell: Cell,
    pub value: N,
}

impl<N: FieldExt> From<&AssignedCondition<N>> for AssignedValue<N> {
    fn from(v: &AssignedCondition<N>) -> Self {
        AssignedValue {
            cell: v.cell,
            value: v.value,
        }
    }
}

impl<N: FieldExt> From<&AssignedValue<N>> for AssignedCondition<N> {
    fn from(v: &AssignedValue<N>) -> Self {
        AssignedCondition {
            cell: v.cell,
            value: v.value,
        }
    }
}

impl<N: FieldExt> From<AssignedCondition<N>> for AssignedValue<N> {
    fn from(v: AssignedCondition<N>) -> Self {
        AssignedValue {
            cell: v.cell,
            value: v.value,
        }
    }
}

impl<N: FieldExt> From<AssignedValue<N>> for AssignedCondition<N> {
    fn from(v: AssignedValue<N>) -> Self {
        AssignedCondition {
            cell: v.cell,
            value: v.value,
        }
    }
}

#[derive(Debug)]
pub enum ValueSchema<'a, N: FieldExt> {
    Assigned(&'a AssignedValue<N>),
    Unassigned(N),
}

impl<'a, N: FieldExt> From<N> for ValueSchema<'a, N> {
    fn from(v: N) -> Self {
        Self::Unassigned(v)
    }
}

impl<'a, N: FieldExt> From<&'a AssignedValue<N>> for ValueSchema<'a, N> {
    fn from(v: &'a AssignedValue<N>) -> Self {
        Self::Assigned(v)
    }
}

impl<'a, N: FieldExt> ValueSchema<'a, N> {
    pub fn value(&self) -> N {
        match self {
            ValueSchema::Assigned(cell) => cell.value,
            ValueSchema::Unassigned(n) => *n,
        }
    }

    pub fn constrain_equal_conditionally(
        &self,
        region: &mut Region<'_, N>,
        new_cell: Cell,
    ) -> Result<(), Error> {
        match self {
            ValueSchema::Assigned(c) => region.constrain_equal(c.cell, new_cell),
            _ => Ok(()),
        }
    }
}

#[macro_export]
macro_rules! pair {
    ($x: expr, $y: expr) => {
        ($crate::gates::base_gate::ValueSchema::from($x), ($y))
    };
}

#[macro_export]
macro_rules! pair_empty {
    ($N: tt) => {
        (
            $crate::gates::base_gate::ValueSchema::from($N::zero()),
            $N::zero(),
        )
    };
}

pub struct Context<'a, N: FieldExt> {
    pub region: Box<Region<'a, N>>,
    pub offset: Box<usize>,
    pub in_shape_mode: bool,
}

impl<'a, N: FieldExt> Context<'a, N> {
    pub fn new(region: Region<'a, N>, offset: usize) -> Context<'a, N> {
        Context {
            region: Box::new(region),
            offset: Box::new(offset),
            in_shape_mode: false,
        }
    }
    pub fn in_shape_mode(&self) -> bool {
        self.in_shape_mode
    }
    pub fn expand(&mut self, size:usize, v: Cell, value: N) -> Result<(), Error> {
        self.region.as_mut().assign_advice(|| "expand", v.column.try_into().unwrap(), *self.offset + size - 1, || Value::known(value))?;
        *self.offset += size;
        Ok(())
    }
}


impl<'a, N: FieldExt> std::fmt::Display for Context<'a, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "(total offset: {})", self.offset)
    }
}

#[derive(Clone, Debug)]
pub struct BaseGateConfig<const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> {
    pub base: [Column<Advice>; VAR_COLUMNS],
    pub coeff: [Column<Fixed>; VAR_COLUMNS],
    pub mul_coeff: [Column<Fixed>; MUL_COLUMNS],
    pub next_coeff: Column<Fixed>,
    pub constant: Column<Fixed>,
}

pub trait BaseGateOps<N: FieldExt> {
    fn var_columns(&self) -> usize;
    fn mul_columns(&self) -> usize;

    fn one_line(
        &self,
        ctx: &mut Context<'_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error>;

    fn one_line_add(
        &self,
        ctx: &mut Context<'_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        self.one_line(ctx, base_coeff_pairs, constant, (vec![], N::zero()))
    }

    fn one_line_with_last_base<'a>(
        &self,
        ctx: &mut Context<'_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<'a, N>, N)>,
        last: (ValueSchema<'a, N>, N),
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<Vec<AssignedValue<N>>, Error> {
        assert!(base_coeff_pairs.len() < self.var_columns());

        base_coeff_pairs.resize_with(self.var_columns() - 1, || pair_empty!(N));
        base_coeff_pairs.push(last);
        self.one_line(ctx, base_coeff_pairs, constant, mul_next_coeffs)
    }

    fn sum_with_constant(
        &self,
        ctx: &mut Context<'_, N>,
        elems: Vec<(&AssignedValue<N>, N)>,
        constant: N,
    ) -> Result<AssignedValue<N>, Error> {
        let columns = self.var_columns();
        let zero = N::zero();
        let one = N::one();
        let mut acc: Option<N> = None;
        let mut curr = 0;

        // Util `rest size + acc cell + sum cell` can be placed into one line.
        while elems.len() - curr + acc.map_or(0usize, |_| 1usize) + 1usize > columns {
            // The first line doesn't have acc cell.
            let line_len = self.var_columns() - acc.map_or(0usize, |_| 1usize);
            let line = &elems[curr..curr + line_len];
            curr += line_len;

            let line_sum = line
                .iter()
                .fold(zero, |acc, (v, coeff)| acc + v.value * coeff);

            if acc.is_none() {
                self.one_line(
                    ctx,
                    line.iter().map(|(v, coeff)| pair!(*v, *coeff)).collect(),
                    zero,
                    (vec![], -one),
                )?;
            } else {
                self.one_line_with_last_base(
                    ctx,
                    line.iter().map(|(v, coeff)| pair!(*v, *coeff)).collect(),
                    pair!(acc.unwrap(), one),
                    zero,
                    (vec![], -one),
                )?;
            }

            acc = Some(acc.unwrap_or(zero) + line_sum);
        }

        let sum = elems[curr..]
            .iter()
            .fold(constant, |acc, (v, coeff)| acc + v.value * coeff)
            + acc.unwrap_or(zero);

        let mut schemas_pairs = vec![pair!(sum, -one)];
        schemas_pairs.append(
            &mut elems[curr..]
                .iter()
                .map(|(v, coeff)| pair!(*v, *coeff))
                .collect(),
        );

        let cells = if acc.is_none() {
            self.one_line(ctx, schemas_pairs, constant, (vec![], zero))?
        } else {
            self.one_line_with_last_base(
                ctx,
                schemas_pairs,
                pair!(acc.unwrap(), one),
                constant,
                (vec![], zero),
            )?
        };

        Ok(cells[0])
    }

    fn add(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);

        let zero = N::zero();
        let one = N::one();
        self.sum_with_constant(ctx, vec![(a, one), (b, one)], zero)
    }

    fn add_constant(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        c: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);

        let one = N::one();
        self.sum_with_constant(ctx, vec![(a, one)], c)
    }

    fn sub(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);

        let zero = N::zero();
        let one = N::one();
        self.sum_with_constant(ctx, vec![(a, one), (b, -one)], zero)
    }

    fn mul(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 3);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let c = a.value * b.value;

        let cells = self.one_line(
            ctx,
            vec![pair!(a, zero), pair!(b, zero), pair!(c, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[2])
    }

    fn mul_add_constant(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        c: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 4);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let d = a.value * b.value + c;

        let cells = self.one_line(
            ctx,
            vec![pair!(a, zero), pair!(b, zero), pair!(d, -one)],
            c,
            (vec![one], zero),
        )?;

        Ok(cells[2])
    }

    fn mul_add(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        c: &AssignedValue<N>,
        c_coeff: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 4);
        assert!(self.mul_columns() >= 1);

        let one = N::one();
        let zero = N::zero();

        let d = a.value * b.value + c.value * c_coeff;

        let cells = self.one_line(
            ctx,
            vec![
                pair!(a, zero),
                pair!(b, zero),
                pair!(c, c_coeff),
                pair!(d, -one),
            ],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[3])
    }

    fn mul_add_with_next_line(
        &self,
        ctx: &mut Context<'_, N>,
        ls: Vec<(&AssignedValue<N>, &AssignedValue<N>, &AssignedValue<N>, N)>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(self.var_columns() >= 4);
        assert!(self.mul_columns() >= 1);
        assert!(!ls.is_empty());

        if ls.len() == 1 {
            let (a, b, c, c_coeff) = ls[0];
            self.mul_add(ctx, a, b, c, c_coeff)
        } else {
            let one = N::one();
            let zero = N::zero();

            let mut t = zero;

            for (a, b, c, c_coeff) in ls {
                self.one_line_with_last_base(
                    ctx,
                    vec![pair!(a, zero), pair!(b, zero), pair!(c, c_coeff)],
                    pair!(t, one),
                    zero,
                    (vec![one], -one),
                )?;

                t = a.value * b.value + c.value * c_coeff + t;
            }

            let cells =
                self.one_line_with_last_base(ctx, vec![], pair!(t, zero), zero, (vec![], zero))?;

            Ok(cells[self.var_columns() - 1])
        }
    }

    fn invert_unsafe(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let b = a.value.invert().unwrap();

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            ctx,
            vec![pair!(a, zero), pair!(b, zero)],
            -one,
            (vec![one], zero),
        )?;

        Ok(cells[1])
    }

    fn invert(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
    ) -> Result<(AssignedCondition<N>, AssignedValue<N>), Error> {
        let zero = N::zero();
        let one = N::one();
        let b = a.value.invert().unwrap_or(zero);
        let c = one - a.value * b;

        // a * c = 0, one of them must be zero
        let cells = self.one_line(
            ctx,
            vec![pair!(a, zero), pair!(c, zero)],
            zero,
            (vec![one], zero),
        )?;
        let c = &cells[1];

        // a * b + c = 1
        let cells = self.one_line(
            ctx,
            vec![pair!(a, zero), pair!(b, zero), pair!(c, one)],
            -one,
            (vec![one], zero),
        )?;

        Ok(((&cells[2]).into(), cells[1]))
    }

    fn is_zero(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let (res, _) = self.invert(ctx, a)?;
        Ok(res)
    }

    fn div_unsafe(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let c = b.value.invert().unwrap() * a.value;

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            ctx,
            vec![pair!(b, zero), pair!(c, zero), pair!(a, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[1])
    }

    fn assign_constant(&self, ctx: &mut Context<'_, N>, v: N) -> Result<AssignedValue<N>, Error> {
        let one = N::one();

        let cells = self.one_line_add(ctx, vec![pair!(v, -one)], v)?;

        Ok(cells[0])
    }

    fn assign(&self, ctx: &mut Context<'_, N>, v: N) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let cells = self.one_line_add(ctx, vec![pair!(v, zero)], zero)?;
        Ok(cells[0])
    }

    fn assert_equal(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<(), Error> {
        let one = N::one();
        let zero = N::zero();

        self.one_line_add(ctx, vec![pair!(a, -one), pair!(b, one)], zero)?;

        Ok(())
    }

    fn assert_constant(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedValue<N>,
        b: N,
    ) -> Result<(), Error> {
        let one = N::one();

        self.one_line_add(ctx, vec![pair!(a, -one)], b)?;

        Ok(())
    }

    fn assert_bit(&self, ctx: &mut Context<'_, N>, a: &AssignedValue<N>) -> Result<(), Error> {
        let zero = N::zero();
        let one = N::one();

        self.one_line(
            ctx,
            vec![pair!(a, one), pair!(a, zero)],
            zero,
            (vec![-one], zero),
        )?;

        Ok(())
    }

    fn and(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let res = self.mul(ctx, &a.into(), &b.into())?;

        Ok((&res).into())
    }

    fn not(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let one = N::one();
        let res = self.sum_with_constant(ctx, vec![(&a.into(), -one)], one)?;

        Ok((&res).into())
    }

    fn or(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let c = a.value + b.value - a.value * b.value;
        let a: AssignedValue<N> = a.into();
        let b: AssignedValue<N> = b.into();
        let cells = self.one_line(
            ctx,
            vec![pair!(&a, one), pair!(&b, one), pair!(c, -one)],
            zero,
            (vec![-one], zero),
        )?;

        Ok((&cells[2]).into())
    }

    fn xor(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let two = one + one;
        let c = a.value + b.value - two * a.value * b.value;
        let a: AssignedValue<N> = a.into();
        let b: AssignedValue<N> = b.into();
        let cells = self.one_line(
            ctx,
            vec![pair!(&a, one), pair!(&b, one), pair!(c, -one)],
            zero,
            (vec![-two], zero),
        )?;

        Ok((&cells[2]).into())
    }

    fn xnor(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let zero = N::zero();
        let one = N::one();
        let two = one + one;
        let c = one - a.value - b.value + two * a.value * b.value;
        let a: AssignedValue<N> = a.into();
        let b: AssignedValue<N> = b.into();
        let cells = self.one_line(
            ctx,
            vec![pair!(&a, -one), pair!(&b, -one), pair!(c, -one)],
            one,
            (vec![two], zero),
        )?;

        Ok((&cells[2]).into())
    }

    fn bisec(
        &self,
        ctx: &mut Context<'_, N>,
        cond: &AssignedCondition<N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error>;

    fn bisec_cond(
        &self,
        ctx: &mut Context<'_, N>,
        cond: &AssignedCondition<N>,
        a: &AssignedCondition<N>,
        b: &AssignedCondition<N>,
    ) -> Result<AssignedCondition<N>, Error> {
        let a = a.into();
        let b = b.into();
        let c = self.bisec(ctx, cond, &a, &b)?;
        Ok(c.into())
    }

    fn assert_true(&self, ctx: &mut Context<'_, N>, a: &AssignedCondition<N>) -> Result<(), Error> {
        self.assert_constant(ctx, &a.into(), N::one())
    }

    fn assert_false(
        &self,
        ctx: &mut Context<'_, N>,
        a: &AssignedCondition<N>,
    ) -> Result<(), Error> {
        self.assert_constant(ctx, &a.into(), N::zero())
    }
}

pub struct BaseGate<N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> {
    config: BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
    _phantom: PhantomData<N>,
}

impl<N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize>
    BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>
{
    pub fn new(
        config: BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
    ) -> BaseGate<N, VAR_COLUMNS, MUL_COLUMNS> {
        BaseGate {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>) -> BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS> {
        let base = [(); VAR_COLUMNS].map(|_| meta.advice_column());
        let coeff = [(); VAR_COLUMNS].map(|_| meta.fixed_column());
        let mul_coeff = [(); MUL_COLUMNS].map(|_| meta.fixed_column());
        let next_coeff = meta.fixed_column();
        let constant = meta.fixed_column();

        base.iter().for_each(|c| meta.enable_equality(*c));

        meta.create_gate("base_gate", |meta| {
            let _constant = meta.query_fixed(constant, Rotation::cur());
            let _next = meta.query_advice(base[VAR_COLUMNS - 1], Rotation::next());
            let _next_coeff = meta.query_fixed(next_coeff, Rotation::cur());

            let mut acc = _constant + _next * _next_coeff;
            for i in 0..VAR_COLUMNS {
                let _base = meta.query_advice(base[i], Rotation::cur());
                let _coeff = meta.query_fixed(coeff[i], Rotation::cur());
                acc = acc + _base * _coeff;
            }
            for i in 0..MUL_COLUMNS {
                let _base_l = meta.query_advice(base[i * 2], Rotation::cur());
                let _base_r = meta.query_advice(base[i * 2 + 1], Rotation::cur());
                let _mul_coeff = meta.query_fixed(mul_coeff[i], Rotation::cur());
                acc = acc + _base_l * _base_r * _mul_coeff;
            }

            vec![acc]
        });

        BaseGateConfig::<VAR_COLUMNS, MUL_COLUMNS> {
            base,
            coeff,
            mul_coeff,
            constant,
            next_coeff,
        }
    }

    pub fn var_columns(&self) -> usize {
        VAR_COLUMNS
    }

    pub fn mul_columns(&self) -> usize {
        MUL_COLUMNS
    }

    pub fn one_line(
        &self,
        ctx: &mut Context<'_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<(Vec<AssignedValue<N>>, Vec<Value<N>>), Error> {
        assert!(base_coeff_pairs.len() <= VAR_COLUMNS);
        assert!(mul_next_coeffs.0.len() <= MUL_COLUMNS);

        let zero = N::zero();
        let mut cells = vec![];
        let mut values = vec![];

        base_coeff_pairs.resize_with(VAR_COLUMNS, || pair_empty!(N));
        for (i, (base, coeff)) in base_coeff_pairs.into_iter().enumerate() {
            let fixed_cell = ctx.region
                .as_mut()
                .assign_fixed(
                    || format!("coeff_{}", i),
                    self.config.coeff[i],
                    *ctx.offset,
                    || Value::known(coeff),
                )?;

            let assign_cell = ctx
                .region
                .as_mut()
                .assign_advice(
                    || format!("base_{}", i),
                    self.config.base[i],
                    *ctx.offset,
                    || Value::known(base.value()),
                )?;

            let cell = assign_cell.cell();

            base.constrain_equal_conditionally(ctx.region.as_mut(), cell)?;
            cells.push(AssignedValue {
                cell,
                value: base.value(),
            });
            values.push(fixed_cell.value().map(|x| *x));
            values.push(assign_cell.value().map(|x| *x));
        }

        let (mut mul_coeffs, next) = mul_next_coeffs;
        mul_coeffs.resize_with(MUL_COLUMNS, || zero);
        for (i, mul_coeff) in mul_coeffs.into_iter().enumerate() {
            ctx.region.as_mut().assign_fixed(
                || format!("mul_coeff_{}", i),
                self.config.mul_coeff[i],
                *ctx.offset,
                || Value::known(mul_coeff),
            )?;
        }

        ctx.region.as_mut().assign_fixed(
            || "constant",
            self.config.constant,
            *ctx.offset,
            || Value::known(constant),
        )?;
        ctx.region.as_mut().assign_fixed(
            || "next_coeff",
            self.config.next_coeff,
            *ctx.offset,
            || Value::known(next),
        )?;

        *ctx.offset += 1;

        Ok((cells.try_into().unwrap(), values))
    }
}
