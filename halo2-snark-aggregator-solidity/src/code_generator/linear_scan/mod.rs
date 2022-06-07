pub(crate) mod live_interval;
pub(crate) mod memory_pool;

use self::{
    live_interval::{build_intervals, Interval},
    memory_pool::MemoryPool,
};
use super::ctx::{CodeGeneratorCtx, Statement, Type};
use std::collections::{HashMap, HashSet};

fn linear_scan(
    intervals: &mut Vec<Interval>,
    old_statements: &Vec<Statement>,
    pool: &mut MemoryPool,
) -> (Vec<Statement>, usize, HashMap<usize, usize>) {
    let active = &mut HashSet::<Interval>::new();
    let mut statements = vec![];
    let mut replaced_expr = HashMap::<usize, usize>::new();

    intervals
        .into_iter()
        .zip(old_statements.iter())
        .for_each(|(i, s)| {
            expire_old_intervals(active, &i, pool);

            let mem_block = match i.t {
                Type::Scalar => {
                    if pool.free_256_block.is_empty() {
                        pool.expand();
                    }
                    pool.alloc_scalar()
                }
                Type::Point => {
                    if pool.free_512_block.is_empty() {
                        pool.expand();
                    }
                    pool.alloc_point()
                }
            };

            replaced_expr.insert(i.expr.clone(), mem_block.pos);

            statements.push(s.substitute(&replaced_expr));

            i.mem_block = Some(mem_block);
            active.insert(i.clone());
        });
    (statements, pool.capability, replaced_expr)
}

fn expire_old_intervals(active: &mut HashSet<Interval>, i: &Interval, pool: &mut MemoryPool) {
    let active_vec = &mut active.clone().into_iter().collect::<Vec<_>>();
    active_vec.sort_by(|i1, i2| i1.end.cmp(&i2.end));

    active_vec.iter().for_each(|j| {
        if j.end < i.start {
            pool.free(j.mem_block.clone().unwrap());
            active.remove(j);
        }
    })
}

pub(crate) fn memory_optimize(ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let intervals = &mut build_intervals(&ctx.assignments);
    let empty_pool = &mut MemoryPool::default();
    let (replaced_statement, memory_offset, replaced_expr) =
        linear_scan(intervals, &ctx.assignments, empty_pool);

    CodeGeneratorCtx {
        wx: ctx.wx.substitute(&replaced_expr),
        wg: ctx.wg.substitute(&replaced_expr),
        s_g2: ctx.s_g2,
        n_g2: ctx.n_g2,
        assignments: replaced_statement,
        memory_size: memory_offset,
        absorbing_length: ctx.absorbing_length
    }
}
