use std::rc::Rc;

use crate::code_generator::ctx::Expression;

use super::ctx::{CodeGeneratorCtx, Statement, Type};

struct Merge {
    memory_offset_start: usize,
    memory_offset_end: usize,
    absorbing_start: usize,
    absorbing_end: usize,
    step_memory_offset: usize,
    step_absorbing_offset: usize,
    in_processing: bool,
}

impl Default for Merge {
    fn default() -> Self {
        Self {
            memory_offset_start: Default::default(),
            memory_offset_end: Default::default(),
            absorbing_start: Default::default(),
            absorbing_end: Default::default(),
            step_memory_offset: Default::default(),
            step_absorbing_offset: Default::default(),
            in_processing: false,
        }
    }
}
impl Merge {
    fn try_start(statement: &Statement) -> Self {
        match statement {
            Statement::UpdateHash(e, absorbing_offset) => match **e {
                super::ctx::Expression::TransciprtOffset(memory_offset, _) => Self {
                    memory_offset_start: memory_offset,
                    memory_offset_end: memory_offset,
                    absorbing_start: *absorbing_offset,
                    absorbing_end: *absorbing_offset,
                    step_memory_offset: 1,
                    step_absorbing_offset: 2,
                    in_processing: false,
                },
                _ => Self::default(),
            },
            _ => Self::default(),
        }
    }

    fn try_merge(&mut self, statement: &Statement) -> bool {
        if let super::ctx::Statement::UpdateHash(e, absorbing_offset) = statement {
            if let Expression::Memory(memory_offset, _ty) = &*(e.clone()) {
                if memory_offset - self.memory_offset_end == self.step_memory_offset
                    && absorbing_offset - self.absorbing_end == self.step_absorbing_offset
                {
                    self.memory_offset_end = *memory_offset;
                    self.absorbing_end = *absorbing_offset;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        }
    }

    fn to_statement(&self) -> Statement {
        if self.memory_offset_start == self.memory_offset_end {
            Statement::UpdateHash(
                Rc::new(Expression::TransciprtOffset(
                    self.memory_offset_start,
                    Type::Scalar,
                )),
                self.absorbing_start,
            )
        } else {
            println!("xixi");
            Statement::For {
                memory_start: self.memory_offset_start,
                memory_end: self.memory_offset_end,
                memory_step: self.step_memory_offset,
                absorbing_start: self.absorbing_start,
                absorbing_end: self.absorbing_end,
                absorbing_step: self.step_absorbing_offset,
            }
        }
    }
}

pub(crate) fn aggregate(mut ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let mut statements = vec![];
    let mut merge = Merge::default();

    macro_rules! flush_merge {
        () => {
            if merge.in_processing {
                statements.push(merge.to_statement());

                merge = Merge::default();
            }
        };
    }

    ctx.assignments
        .iter()
        .for_each(|statement| match statement {
            super::ctx::Statement::Assign(..) => {
                flush_merge!();

                statements.push(statement.clone())
            }
            super::ctx::Statement::UpdateHash(e, _t) => match e.get_type() {
                super::ctx::Type::Scalar => {
                    if merge.in_processing && merge.try_merge(statement) {
                        // do nothing
                    } else {
                        flush_merge!();
                        merge = Merge::try_start(statement);
                    }
                }
                super::ctx::Type::Point => {
                    flush_merge!();

                    statements.push(statement.clone())
                }
            },
            super::ctx::Statement::For { .. } => unreachable!(),
        });

    flush_merge!();

    ctx.assignments = statements;

    ctx
}
