use std::collections::HashMap;

use super::ctx::{CodeGeneratorCtx, Expression, Statement, Type};

pub(crate) fn linearize_memory(ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let mut lookup = HashMap::<usize, usize>::new();
    let mut offset = 0;

    let assignments = ctx
        .assignments
        .iter()
        .map(|statement| {
            match statement {
                Statement::Assign(l, _r) => match **l {
                    Expression::Memory(o, Type::Scalar) => {
                        lookup.insert(o, offset);
                        offset = offset + 1;
                    }
                    Expression::Memory(o, Type::Point) => {
                        lookup.insert(o, offset);
                        offset = offset + 2;
                    }
                    _ => {}
                },
                _ => {}
            };

            statement.substitute(&lookup)
        })
        .collect::<Vec<_>>();

    CodeGeneratorCtx {
        wx: ctx.wx.substitute(&lookup),
        wg: ctx.wg.substitute(&lookup),
        s_g2: ctx.s_g2,
        n_g2: ctx.n_g2,
        assignments,
        memory_size: offset,
        absorbing_length: ctx.absorbing_length,
    }
}
