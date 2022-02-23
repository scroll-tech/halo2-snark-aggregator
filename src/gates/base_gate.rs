use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Cell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use std::marker::PhantomData;

pub mod five;

#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<N: FieldExt> {
    cell: Cell,
    pub value: N,
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
            ValueSchema::Assigned(cell) => cell.value.clone(),
            ValueSchema::Unassigned(n) => n.clone(),
        }
    }

    pub fn constrain_equal_conditionally(
        &self,
        region: &mut Region<'_, N>,
        new_cell: Cell,
    ) -> Result<(), Error> {
        match self {
            ValueSchema::Assigned(c) => region.constrain_equal(c.cell.clone(), new_cell),
            _ => Ok(()),
        }
    }

    pub fn is_unassigned(&self) -> bool {
        match self {
            ValueSchema::Unassigned(_) => true,
            ValueSchema::Assigned(_) => false,
        }
    }

    pub fn to_assigned_value(&self) -> Option<&'a AssignedValue<N>> {
        match self {
            ValueSchema::Assigned(v) => Some(v),
            ValueSchema::Unassigned(_) => None,
        }
    }
}

#[macro_export]
macro_rules! pair {
    ($x: expr, $y: expr) => {
        (($x).into(), ($y))
    };
}

#[macro_export]
macro_rules! pair_empty {
    ($N: tt) => {
        ($N::zero().into(), $N::zero())
    };
}

pub struct RegionAux<'a, 'b, N: FieldExt> {
    pub region: &'a mut Region<'b, N>,
    pub offset: &'a mut usize,
}

impl<'a, 'b, N: FieldExt> RegionAux<'a, 'b, N> {
    pub fn new(region: &'a mut Region<'b, N>, offset: &'a mut usize) -> RegionAux<'a, 'b, N> {
        RegionAux { region, offset }
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

        base.iter().for_each(|c| meta.enable_equality(c.clone()));

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

    pub fn one_line(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        assert!(base_coeff_pairs.len() <= VAR_COLUMNS);
        assert!(mul_next_coeffs.0.len() <= MUL_COLUMNS);

        let zero = N::zero();
        let mut cells = vec![];

        base_coeff_pairs.resize_with(VAR_COLUMNS, || pair_empty!(N));
        for (i, (base, coeff)) in base_coeff_pairs.into_iter().enumerate() {
            r.region
                .assign_fixed(
                    || format!("coeff_{}", i),
                    self.config.coeff[i],
                    *r.offset,
                    || Ok(coeff),
                )?
                .cell();

            let cell = r
                .region
                .assign_advice(
                    || format!("base_{}", i),
                    self.config.base[i],
                    *r.offset,
                    || Ok(base.value()),
                )?
                .cell();

            base.constrain_equal_conditionally(r.region, cell)?;
            cells.push(AssignedValue {
                cell,
                value: base.value(),
            });
        }

        let (mut mul_coeffs, next) = mul_next_coeffs;
        mul_coeffs.resize_with(MUL_COLUMNS, || zero);
        for (i, mul_coeff) in mul_coeffs.into_iter().enumerate() {
            r.region.assign_fixed(
                || format!("mul_coeff_{}", i),
                self.config.mul_coeff[i],
                *r.offset,
                || Ok(mul_coeff),
            )?;
        }

        r.region.assign_fixed(
            || "constant",
            self.config.constant,
            *r.offset,
            || Ok(constant),
        )?;
        r.region.assign_fixed(
            || "next_coeff",
            self.config.next_coeff,
            *r.offset,
            || Ok(next),
        )?;

        *r.offset += 1;

        Ok(cells.try_into().unwrap())
    }

    pub fn one_line_add(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        self.one_line(r, base_coeff_pairs, constant, (vec![], N::zero()))
    }

    pub fn one_line_with_last_base<'a>(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<'a, N>, N)>,
        last: (ValueSchema<'a, N>, N),
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        assert!(base_coeff_pairs.len() <= VAR_COLUMNS - 1);

        let zero = N::zero();

        base_coeff_pairs.resize_with(VAR_COLUMNS - 1, || pair_empty!(N));
        base_coeff_pairs.push(last);
        self.one_line(r, base_coeff_pairs, constant, mul_next_coeffs)
    }

    pub fn sum_with_constant(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        elems: Vec<(&AssignedValue<N>, N)>,
        constant: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(elems.len() <= VAR_COLUMNS - 1);

        let one = N::one();
        let zero = N::zero();

        let sum = elems
            .iter()
            .fold(constant, |acc, (v, coeff)| acc + v.value * coeff);
        let mut schemas_pairs = vec![pair!(sum, -one)];
        schemas_pairs.append(
            &mut elems
                .into_iter()
                .map(|(v, coeff)| pair!(v, coeff))
                .collect(),
        );

        let cells = self.one_line(r, schemas_pairs, constant, (vec![], zero))?;

        Ok(cells[0])
    }

    pub fn add(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS >= 3);

        let zero = N::zero();
        let one = N::one();
        self.sum_with_constant(r, vec![(a, one), (b, one)], zero)
    }

    pub fn mul(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS >= 3);
        assert!(MUL_COLUMNS >= 1);

        let one = N::one();
        let zero = N::zero();

        let c = a.value * b.value;

        let cells = self.one_line(
            r,
            vec![pair!(a, zero), pair!(b, zero), pair!(c, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[2])
    }

    pub fn mul_add(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
        c: &AssignedValue<N>,
        c_coeff: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS >= 4);
        assert!(MUL_COLUMNS >= 1);

        let one = N::one();
        let zero = N::zero();

        let d = a.value * b.value + c.value * c_coeff;

        let cells = self.one_line(
            r,
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

    pub fn mul_add_with_next_line(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        ls: Vec<(&AssignedValue<N>, &AssignedValue<N>, &AssignedValue<N>, N)>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS >= 4);
        assert!(MUL_COLUMNS >= 1);
        assert!(ls.len() > 0);

        if ls.len() == 1 {
            let (a, b, c, c_coeff) = ls[0];
            self.mul_add(r, a, b, c, c_coeff)
        } else {
            let one = N::one();
            let zero = N::zero();

            let mut t = zero;

            for (a, b, c, c_coeff) in ls {
                self.one_line_with_last_base(
                    r,
                    vec![pair!(a, zero), pair!(b, zero), pair!(c, c_coeff)],
                    pair!(t, one),
                    zero,
                    (vec![one], -one),
                )?;

                t = a.value * b.value + c.value * c_coeff + t;
            }

            let cells =
                self.one_line_with_last_base(r, vec![], pair!(t, zero), zero, (vec![], zero))?;

            Ok(cells[VAR_COLUMNS - 1])
        }
    }

    pub fn invert_unsafe(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let b = a.value.invert().unwrap();

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            r,
            vec![pair!(a, zero), pair!(b, zero)],
            -one,
            (vec![one], zero),
        )?;

        Ok(cells[1])
    }

    pub fn div_unsafe(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let c = b.value.invert().unwrap() * a.value;

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            r,
            vec![pair!(b, zero), pair!(c, zero), pair!(a, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[1])
    }

    pub fn assign_constant(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        v: N,
    ) -> Result<AssignedValue<N>, Error> {
        let one = N::one();

        let cells = self.one_line_add(r, vec![pair!(v, -one)], v)?;

        Ok(cells[0])
    }

    pub fn assert_equal(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<(), Error> {
        let one = N::one();
        let zero = N::zero();

        self.one_line_add(r, vec![pair!(a, -one), pair!(b, one)], zero)?;

        Ok(())
    }

    pub fn assert_constant(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        a: &AssignedValue<N>,
        b: N,
    ) -> Result<(), Error> {
        let one = N::one();
        let zero = N::zero();

        self.one_line_add(r, vec![pair!(a, -one)], b)?;

        Ok(())
    }
}
