use crate::code_generator::ctx::{Expression, Statement};

use super::{Action, GroupOptimizer};

const CAPABILITY: usize = 1;

pub(crate) struct MultiInstOpcode {
    unresolved_statements: Vec<Statement>,
    target: Option<Expression>,
    byte_pairs: Vec<(usize, usize)>,
    capability: usize,
}

impl Default for MultiInstOpcode {
    fn default() -> Self {
        Self {
            target: None,
            byte_pairs: Default::default(),
            capability: CAPABILITY,
            unresolved_statements: vec![],
        }
    }
}

impl MultiInstOpcode {
    fn is_complete(&self) -> bool {
        self.byte_pairs.len() == self.capability
    }
}

fn extract_fr_mul_add(statement: &Statement) -> Option<(usize, usize, Expression)> {
    match statement {
        Statement::Assign(l, r, _) => match r {
            crate::code_generator::ctx::Expression::MulAdd(a, b, c, _) => {
                if a.is_transcript() && b.is_memory() && c == l {
                    Some((
                        a.try_get_offset().unwrap(),
                        b.try_get_offset().unwrap(),
                        c.as_ref().clone(),
                    ))
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    }
}

impl GroupOptimizer for MultiInstOpcode {
    type Optimizer = Self;

    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((proof_offset, memory_offset, target)) = extract_fr_mul_add(statement) {
            self.byte_pairs.push((proof_offset, memory_offset));

            self.target = Some(target);
            Action::Continue
        } else {
            Action::Skip
        }
    }

    fn try_merge(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if self.is_complete() {
            return Action::Complete;
        }

        if let Some((proof_offset, memory_offset, target)) = extract_fr_mul_add(statement) {
            if target == *self.target.as_ref().unwrap() {
                self.byte_pairs.push((proof_offset, memory_offset));
                Action::Continue
            } else {
                Action::Terminate
            }
        } else {
            Action::Terminate
        }
    }

    fn to_statement(&self) -> crate::code_generator::ctx::Statement {
        todo!()
    }

    fn unresolved_statements(&self) -> Vec<Statement> {
        self.unresolved_statements.clone()
    }

    fn reset(&mut self) {
        self.byte_pairs = vec![];
        self.target = None;
        self.unresolved_statements = vec![];
    }

    fn can_complete(&self) -> bool {
        self.is_complete()
    }
}
