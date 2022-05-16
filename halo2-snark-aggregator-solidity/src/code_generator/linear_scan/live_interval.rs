use super::memory_pool::MemoryBlock;
use crate::code_generator::ctx::{Expression, Statement, Type};
use std::{collections::HashMap, rc::Rc};

#[derive(Hash, PartialEq, Eq, Clone)]
pub(crate) struct Interval {
    pub(crate) expr: usize,
    pub(crate) t: Type,
    pub(crate) mem_block: Option<MemoryBlock>,
    pub(crate) start: usize,
    pub(crate) end: usize,
}

pub(crate) fn build_intervals(statements: &Vec<Statement>) -> Vec<Interval> {
    let mut intervals: Vec<Interval> = vec![];
    // from memory offset to statement array offset
    let lookup = &mut HashMap::<Rc<Expression>, usize>::new();
    let mut idx = 0;

    statements
        .iter()
        .enumerate()
        .for_each(|(current, s)| match s {
            Statement::Assign(l, r) => {
                let offset = match **l {
                    Expression::Memory(o, _) => o,
                    _ => unreachable!(),
                };

                let interval = Interval {
                    start: current,
                    end: current,
                    expr: offset,
                    t: l.get_type(),
                    mem_block: None,
                };

                intervals.push(interval);
                lookup.insert(l.clone(), idx);
                idx = idx + 1;

                r.iter(&mut |e| {
                    let expr = lookup.get(e);
                    if expr.is_some() {
                        intervals[*expr.unwrap()].end = current;
                    }
                });
            }
            Statement::UpdateHash(e) => {
                e.iter(&mut |e| {
                    let expr = lookup.get(e);
                    if expr.is_some() {
                        intervals[*expr.unwrap()].end = current;
                    }
                });
            }
        });

    intervals
}
