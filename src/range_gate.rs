use std::marker::PhantomData;

use crate::{
    base_gate::{AssignedValue, BaseGate, BaseGateConfig, BaseRegion},
    pair,
};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{layouter::RegionLayouter, Layouter},
    plonk::{ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct RangeConfig<const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> {
    bits: usize,
    selector: Selector,
    table_column: TableColumn,
}

pub struct RangeGate<'a, N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> {
    config: RangeConfig<VAR_COLUMNS, MUL_COLUMNS>,
    base_gate: &'a BaseGate<N, VAR_COLUMNS, MUL_COLUMNS>,
    _phantom: PhantomData<N>,
}

impl<'a, N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> RangeGate<'a, N, VAR_COLUMNS, MUL_COLUMNS> {
    pub fn configuration(
        meta: &mut ConstraintSystem<N>,
        base_gate_config: &'a BaseGateConfig<VAR_COLUMNS, MUL_COLUMNS>,
        bits: usize,
    ) -> RangeConfig<VAR_COLUMNS, MUL_COLUMNS> {
        let selector = meta.complex_selector();
        let table_column = meta.lookup_table_column();

        base_gate_config.base.iter().for_each(|column| {
            meta.lookup(|meta| {
                let exp = meta.query_advice(column.clone(), Rotation::cur());
                let s = meta.query_selector(selector);
                vec![(exp * s, table_column)]
            });
        });

        RangeConfig {
            bits,
            selector,
            table_column,
        }
    }

    fn init_table(&self, layouter: &mut impl Layouter<N>) -> Result<(), Error> {
        layouter.assign_table(
            || "",
            |mut table| {
                for i in 0..1 << self.config.bits {
                    table.assign_cell(|| "range table", self.config.table_column, i, || Ok(N::from(i as u64)))?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }

    pub fn assign_ranged_values(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        values: Vec<N>,
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        let zero = N::zero();
        self.config.selector.enable(r.region, *r.offset)?;

        let assigned_values = self.base_gate.one_line(
            r,
            values.into_iter().map(|v| pair!(v, zero)).collect(),
            zero,
            (vec![], zero),
        )?;

        Ok(assigned_values)
    }
}
