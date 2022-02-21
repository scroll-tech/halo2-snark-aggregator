use std::marker::PhantomData;

use crate::{gates::base_gate::{AssignedValue, BaseGate, BaseGateConfig, RegionAux, ValueSchema}, pair};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct RangeGateConfig {
    selector: Selector,
    table_column: TableColumn,
}

pub struct RangeGate<'a, N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize, const RANGE_BITS: usize> {
    config: RangeGateConfig,
    pub base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>,
    _phantom: PhantomData<N>,
}

impl<'a, N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize, const RANGE_BITS: usize>
    RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS, RANGE_BITS>
{
    pub fn new(config: RangeGateConfig, base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>) -> Self {
        RangeGate {
            config,
            base_gate,
            _phantom: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<N>,
        base_gate_config: &'a BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
    ) -> RangeGateConfig {
        let selector = meta.complex_selector();
        let table_column = meta.lookup_table_column();

        base_gate_config.base.iter().for_each(|column| {
            meta.lookup(|meta| {
                let exp = meta.query_advice(column.clone(), Rotation::cur());
                let s = meta.query_selector(selector);
                vec![(exp * s, table_column)]
            });
        });

        RangeGateConfig { selector, table_column }
    }

    pub fn init_table(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for i in 0..1 << RANGE_BITS {
                    table.assign_cell(|| "range table", self.config.table_column, i, || Ok(N::from(i as u64)))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn one_line_ranged(
        &self,
        r: &mut RegionAux<'_, '_, N>,
        base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        self.config.selector.enable(r.region, *r.offset)?;
        let assigned_values = self
            .base_gate
            .one_line(r, base_coeff_pairs, constant, mul_next_coeffs)?;

        Ok(assigned_values)
    }

    pub fn assign_value(&self,
        r: &mut RegionAux<'_, '_, N>,
        v: N,
    ) -> Result<AssignedValue<N>, Error> {
        let zero = N::zero();
        let cells = self.one_line_ranged(r, vec![pair!(v, zero)], zero, (vec![], zero))?;
        Ok(cells[0])
    }
}
