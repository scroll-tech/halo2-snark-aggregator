use crate::code_generator::aggregate::multi_inst_opcode::MultiInstOpcode;

use self::update_hash::UpdateHashMerger;
use super::ctx::{CodeGeneratorCtx, Statement};
use std::{cell::RefCell, rc::Rc};

mod multi_inst_opcode;
mod update_hash;

#[derive(PartialEq)]
pub(crate) enum Status {
    Disabled,
    Active,
    Terminated,
}

#[derive(PartialEq)]
pub(crate) enum Action {
    // Failed to merge
    Skip,
    // Merged
    Continue,
    // Failed, should re-dump feeded statements
    Terminate,
    // Success
    Complete,
}

trait GroupOptimizer: Default {
    type Optimizer: Sized;

    fn try_start(&mut self, statement: &Statement) -> Action;
    fn try_merge(&mut self, statement: &Statement) -> Action;
    fn to_statement(&self) -> Statement;
    fn unresolved_statements(&self) -> Vec<Statement>;
    fn reset(&mut self);
    fn can_complete(&self) -> bool;
}

pub(crate) fn aggregate(mut ctx: CodeGeneratorCtx) -> CodeGeneratorCtx {
    let mut statements = vec![];

    let update_hash_merger = Rc::new(RefCell::new(UpdateHashMerger::default()));
    let multi_inst_opcode_merger = Rc::new(RefCell::new(MultiInstOpcode::default()));

    // Replace todo! with multi_inst_opcode_merger
    let optimizer: Vec<Rc<RefCell<_>>> = vec![update_hash_merger, todo!()];
    /*
     * Status of optimizer
     *
     *  +-------------------+
     *  |  Skip             |
     *  |                   v
     *  +-----------------  Disabled(try to start for each statement)  <-+
     *                                                                   |
     *                      |    Continue                                |
     *                                                                   |
     *  +---------------->  Active(opt_in_processing.is_some())          | Terminate(stage 2)
     *  | Continue                                                       |
     *  +-----------------  |    Terminate/Complete                      |
     *                                                                   |
     *                      Terminated ----------------------------------+
     *
     * Action for state transition
     *
     *   + Skip: (Disabled -> Disabled) failed to merge in, processing statement should be output
     *   + Continue: (Disabled/Active -> Active) merged, statement should be fed into optimizer
     *   + Complete: Successfully group a batch of instructions, HOWEVER the current instruction is not included, so you should
     *               not move iterator forward
     *   + Terminate: (Active -> Terminated -> Disabled) Unmergeable statement, optimizer should be flushed and try to enable a new optimizer
     */
    let mut it = ctx.assignments.iter();
    let mut cursor: Option<_> = it.next();
    let mut status = Status::Disabled;
    let mut opt_in_processing = None;

    loop {
        match cursor {
            Some(statement) => {
                match statement {
                    // Only the following statements can be optimized
                    super::ctx::Statement::Assign(..) | super::ctx::Statement::UpdateHash(..) => {
                        if status == Status::Disabled {
                            let mut action = Action::Skip;

                            for candidate_opt in optimizer.iter() {
                                if candidate_opt.borrow_mut().try_start(statement)
                                    == Action::Continue
                                {
                                    opt_in_processing = Some(candidate_opt);
                                    action = Action::Continue;
                                    break;
                                }
                            }

                            // Disable -> Disable
                            if action == Action::Skip {
                                statements.push(statement.clone());
                                cursor = it.next();
                                continue;
                            }

                            // Disable -> Active
                            if action == Action::Continue {
                                status = Status::Active;
                                cursor = it.next();
                                continue;
                            }

                            unreachable!();
                        }

                        if status == Status::Active {
                            let action =
                                opt_in_processing.unwrap().borrow_mut().try_merge(statement);

                            // active -> active
                            if action == Action::Continue {
                                cursor = it.next();

                                status = Status::Active;
                                continue;
                            }

                            if action == Action::Complete {
                                statements.push(opt_in_processing.unwrap().borrow().to_statement());

                                status = Status::Terminated;
                                // should NOT move iterator
                                continue;
                            }

                            // active -> terminated
                            if action == Action::Terminate {
                                statements.append(
                                    &mut opt_in_processing
                                        .unwrap()
                                        .borrow()
                                        .unresolved_statements(),
                                );
                                status = Status::Terminated;
                                // should NOT move iterator
                                continue;
                            }
                        }

                        // terminated -> disabled
                        if status == Status::Terminated {
                            // flush opt
                            opt_in_processing.unwrap().borrow_mut().reset();
                            opt_in_processing = None;

                            status = Status::Disabled;
                            continue;
                        }
                    }
                    // Other statements cannot be genenated before this pass
                    _ => unreachable!(),
                }
            }
            None => {
                if status != Status::Disabled {
                    if opt_in_processing.unwrap().borrow().can_complete() {
                        statements.push(opt_in_processing.unwrap().borrow().to_statement());
                    } else {
                        statements.append(
                            &mut opt_in_processing.unwrap().borrow().unresolved_statements(),
                        );
                    }

                    opt_in_processing = None;
                    status = Status::Disabled;
                }
                break;
            }
        }
    }

    assert!(status == Status::Disabled);
    assert!(opt_in_processing.is_none());

    ctx.assignments = statements;

    ctx
}
