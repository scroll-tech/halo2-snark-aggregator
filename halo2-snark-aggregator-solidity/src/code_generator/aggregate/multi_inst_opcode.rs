use std::rc::Rc;

use num_bigint::BigUint;

use super::{Action, GroupOptimizer};
use crate::code_generator::ctx::{Expression, Statement, Type};

const CAPABILITY: usize = 16;

pub(crate) struct MultiInstOpcode {
    unresolved_statements: Vec<Statement>,
    target: Option<Expression>,
    byte_pairs: Vec<(usize, usize)>,
    capability: usize,
    t: Type,
    samples: Vec<BigUint>,
}

impl Default for MultiInstOpcode {
    fn default() -> Self {
        Self {
            target: None,
            byte_pairs: Default::default(),
            capability: CAPABILITY,
            unresolved_statements: vec![],
            t: Type::Scalar,
            samples: vec![],
        }
    }
}

impl MultiInstOpcode {
    fn is_complete(&self) -> bool {
        self.byte_pairs.len() == self.capability
    }
}

fn extract_fr_mul_add(statement: &Statement) -> Option<(usize, usize, Expression, Vec<BigUint>)> {
    match statement {
        Statement::Assign(l, r, samples) => match r {
            crate::code_generator::ctx::Expression::MulAdd(a, b, c, Type::Scalar) => {
                if a.is_transcript() && b.is_memory() && c.is_temp() && l.is_temp() {
                    Some((
                        a.try_get_offset().unwrap(),
                        b.try_get_offset().unwrap(),
                        c.as_ref().clone(),
                        samples.clone(),
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
    fn try_start(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if let Some((proof_offset, memory_offset, target, samples)) = extract_fr_mul_add(statement)
        {
            self.byte_pairs.push((proof_offset, memory_offset));
            self.target = Some(target);
            self.samples = samples;
            println!("start!");
            Action::Continue
        } else {
            Action::Skip
        }
    }

    fn try_merge(&mut self, statement: &crate::code_generator::ctx::Statement) -> super::Action {
        if self.is_complete() {
            return Action::Complete;
        }

        if let Some((proof_offset, memory_offset, target, samples)) = extract_fr_mul_add(statement)
        {
            if target == *self.target.as_ref().unwrap() {
                println!("merge!");
                self.byte_pairs.push((proof_offset, memory_offset));
                self.samples = samples;
                Action::Continue
            } else {
                Action::Abort
            }
        } else {
            Action::Abort
        }
    }

    fn to_statement(&self) -> crate::code_generator::ctx::Statement {
        let opcode = self
            .byte_pairs
            .iter()
            .rev()
            .fold(0xffff, |acc, (p, m)| (acc << 16) | (m << 8) | p);
        Statement::Assign(
            Rc::new(Expression::Temp(self.t.clone())),
            Expression::MulAddPM(
                Rc::new(self.target.clone().unwrap()),
                opcode,
                self.t.clone(),
            ),
            self.samples.clone(),
        )
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
        self.byte_pairs.len() > 1
    }
}
