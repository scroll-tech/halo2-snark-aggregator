use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Cell, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};

pub mod five;
pub mod four;
pub mod ops;

#[derive(Clone, Debug)]
pub struct BaseGateConfig<const VAR_VAR_COLUMNS: usize, const MUL_VAR_COLUMNS: usize> {
    pub base: [Column<Advice>; VAR_VAR_COLUMNS],
    pub coeff: [Column<Fixed>; VAR_VAR_COLUMNS],
    pub mul_coeff: [Column<Fixed>; MUL_VAR_COLUMNS],
    pub next_coeff: Column<Fixed>,
    pub constant: Column<Fixed>,
}

pub struct BaseGate<N: FieldExt, const VAR_VAR_COLUMNS: usize, const MUL_VAR_COLUMNS: usize> {
    config: BaseGateConfig<VAR_VAR_COLUMNS, MUL_VAR_COLUMNS>,
    _phantom: PhantomData<N>,
}

impl<N: FieldExt, const VAR_VAR_COLUMNS: usize, const MUL_VAR_COLUMNS: usize>
    BaseGate<N, VAR_VAR_COLUMNS, MUL_VAR_COLUMNS>
{
    pub fn new(
        config: BaseGateConfig<VAR_VAR_COLUMNS, MUL_VAR_COLUMNS>,
    ) -> BaseGate<N, VAR_VAR_COLUMNS, MUL_VAR_COLUMNS> {
        BaseGate {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<N>) -> BaseGateConfig<VAR_VAR_COLUMNS, MUL_VAR_COLUMNS> {
        let base = [(); VAR_VAR_COLUMNS].map(|_| meta.advice_column());
        let coeff = [(); VAR_VAR_COLUMNS].map(|_| meta.fixed_column());
        let mul_coeff = [(); MUL_VAR_COLUMNS].map(|_| meta.fixed_column());
        let next_coeff = meta.fixed_column();
        let constant = meta.fixed_column();

        base.iter().for_each(|c| meta.enable_equality(c.clone()));

        meta.create_gate("base_gate", |meta| {
            let _constant = meta.query_fixed(constant, Rotation::cur());
            let _next = meta.query_advice(base[VAR_VAR_COLUMNS - 1], Rotation::next());
            let _next_coeff = meta.query_fixed(next_coeff, Rotation::cur());

            let mut acc = _constant + _next * _next_coeff;
            for i in 0..VAR_VAR_COLUMNS {
                let _base = meta.query_advice(base[i], Rotation::cur());
                let _coeff = meta.query_fixed(coeff[i], Rotation::cur());
                acc = acc + _base * _coeff;
            }
            for i in 0..MUL_VAR_COLUMNS {
                let _base_l = meta.query_advice(base[i * 2], Rotation::cur());
                let _base_r = meta.query_advice(base[i * 2 + 1], Rotation::cur());
                let _mul_coeff = meta.query_fixed(mul_coeff[i], Rotation::cur());
                acc = acc + _base_l * _base_r * _mul_coeff;
            }

            vec![acc]
        });

        BaseGateConfig::<VAR_VAR_COLUMNS, MUL_VAR_COLUMNS> {
            base,
            coeff,
            mul_coeff,
            constant,
            next_coeff,
        }
    }
}

pub struct BaseRegion<'a, 'b, N: FieldExt> {
    pub region: &'a mut Region<'b, N>,
    pub offset: &'a mut usize,
}

impl<'a, 'b, N: FieldExt> BaseRegion<'a, 'b, N> {
    pub fn new(region: &'a mut Region<'b, N>, offset: &'a mut usize) -> BaseRegion<'a, 'b, N> {
        BaseRegion { region, offset }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AssignedValue<N: FieldExt> {
    cell: Cell,
    value: N,
}

#[derive(Debug)]
pub enum ValueSchema<'a, N: FieldExt> {
    Assigned(&'a AssignedValue<N>),
    Unassigned(N),
    Empty,
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
            ValueSchema::Empty => N::zero(),
        }
    }

    pub fn constrain_equal_conditionally(&self, region: &mut Region<'_, N>, new_cell: Cell) -> Result<(), Error> {
        match self {
            ValueSchema::Assigned(c) => region.constrain_equal(c.cell.clone(), new_cell),
            _ => Ok(()),
        }
    }
}
