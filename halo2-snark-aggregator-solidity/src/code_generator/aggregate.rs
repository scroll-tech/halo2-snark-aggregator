use std::{ops::Deref, rc::Rc};

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
    t: Type,
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
            t: Type::Scalar,
        }
    }
}
impl Merge {
    fn try_start(statement: &Statement) -> Option<Self> {
        match statement {
            Statement::UpdateHash(e, absorbing_offset) => match e.deref() {
                super::ctx::Expression::TransciprtOffset(memory_offset, t) => Some(Self {
                    memory_offset_start: *memory_offset,
                    memory_offset_end: *memory_offset,
                    absorbing_start: *absorbing_offset,
                    absorbing_end: *absorbing_offset,
                    step_memory_offset: if *t == Type::Scalar { 1 } else { 2 },
                    step_absorbing_offset: if *t == Type::Scalar { 2 } else { 3 },
                    in_processing: true,
                    t: t.clone(),
                }),
                _ => None,
            },
            _ => None,
        }
    }

    fn try_merge(&mut self, statement: &Statement) -> bool {
        println!("try merge");
        if let super::ctx::Statement::UpdateHash(e, absorbing_offset) = statement {
            if let Expression::TransciprtOffset(memory_offset, ty) = &*(e.clone()) {
                if memory_offset - self.memory_offset_end == self.step_memory_offset
                    && absorbing_offset - self.absorbing_end == self.step_absorbing_offset
                    && *ty == self.t
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
            Statement::For {
                memory_start: self.memory_offset_start,
                memory_end: self.memory_offset_end,
                memory_step: self.step_memory_offset,
                absorbing_start: self.absorbing_start,
                absorbing_step: self.step_absorbing_offset,
                t: self.t.clone(),
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
            super::ctx::Statement::UpdateHash(e, _t) => {
                if merge.in_processing && merge.try_merge(statement) {
                    // do nothing
                } else {
                    flush_merge!();
                    let merge_opt = Merge::try_start(statement);
                    match merge_opt {
                        Some(m) => merge = m,
                        None => statements.push(statement.clone()),
                    }
                }
            }
            super::ctx::Statement::For { .. } => unreachable!(),
        });

    flush_merge!();

    ctx.assignments = statements;

    ctx
}
