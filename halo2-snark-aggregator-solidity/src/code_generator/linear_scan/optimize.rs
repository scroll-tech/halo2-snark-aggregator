use super::live_interval::Interval;
use crate::code_generator::ctx::{Expression, Statement, Type};
use num_bigint::BigUint;
use std::{collections::HashMap, rc::Rc};

pub(crate) fn optimize(
    statements: Vec<Statement>,
    intervals: &Vec<Interval>,
    lookup: &HashMap<Rc<Expression>, usize>,
) -> Vec<Statement> {
    let statements = combine_mul_add(statements, intervals, lookup);
    let statements = combine_fr_pow(statements, intervals, lookup);
    statements
}

fn combine_mul_add(
    statements: Vec<Statement>,
    intervals: &Vec<Interval>,
    lookup: &HashMap<Rc<Expression>, usize>,
) -> Vec<Statement> {
    let mut new_statements = vec![];
    let mut candidate_statement_opt: Option<Statement> = None;

    for (i, statement) in statements.into_iter().enumerate() {
        let able_to_be_optimized = statement.able_to_be_optimized(i, intervals, lookup);

        match candidate_statement_opt {
            None => {
                if able_to_be_optimized {
                    candidate_statement_opt = Some(statement);
                } else {
                    new_statements.push(statement);
                }
            }
            Some(candidate_statement) => {
                let mul_add = candidate_statement.combine_mul_add(&statement);
                match mul_add {
                    Some(statement) => {
                        new_statements.push(statement);
                        candidate_statement_opt = None;
                    }
                    _ => {
                        new_statements.push(candidate_statement);
                        if able_to_be_optimized {
                            candidate_statement_opt = Some(statement);
                        } else {
                            new_statements.push(statement);
                            candidate_statement_opt = None;
                        }
                    }
                }
            }
        }
    }

    if candidate_statement_opt.is_some() {
        new_statements.push(candidate_statement_opt.unwrap());
    }

    new_statements
}

fn record_to_pow(
    record: Option<(
        Rc<Expression>,
        Option<Rc<Expression>>,
        Rc<Expression>,
        usize,
        Vec<BigUint>,
    )>,
) -> Vec<Statement> {
    let mut ret = vec![];
    if let Some((assignee, extra, base, exp, samples)) = record {
        ret.push(Statement::Assign(
            assignee.clone(),
            Expression::Pow(base, exp, Type::Scalar),
            samples.clone(),
        ));
        if extra.is_some() {
            ret.push(Statement::Assign(
                assignee.clone(),
                Expression::Mul(extra.unwrap(), assignee.clone(), Type::Scalar),
                samples.clone(),
            ));
        }
    };
    ret
}

fn combine_fr_pow(
    statements: Vec<Statement>,
    intervals: &Vec<Interval>,
    lookup: &HashMap<Rc<Expression>, usize>,
) -> Vec<Statement> {
    let mut new_statements = vec![];
    let mut candidate_statement_opt: Option<Statement> = None;
    let mut record: Option<(
        Rc<Expression>,
        Option<Rc<Expression>>,
        Rc<Expression>,
        usize,
        Vec<BigUint>,
    )> = None;

    for (i, statement) in statements.into_iter().enumerate() {
        let able_to_be_optimized = statement.able_to_be_optimized(i, intervals, lookup);
        match record {
            Some((assignee, extra, base, exp, samples)) => {
                let res = statement.combine_fr_pow_more(&assignee, &base, exp.clone());
                match res {
                    Some((assignee, exp, samples)) => {
                        if able_to_be_optimized {
                            record = Some((assignee, extra, base, exp, samples));
                        } else {
                            new_statements.append(&mut record_to_pow(Some((
                                assignee, extra, base, exp, samples,
                            ))));
                            candidate_statement_opt = None;
                            record = None;
                        }
                    }
                    None => {
                        new_statements.append(&mut record_to_pow(Some((
                            assignee, extra, base, exp, samples,
                        ))));
                        record = None;
                        if able_to_be_optimized {
                            candidate_statement_opt = Some(statement);
                        } else {
                            candidate_statement_opt = None;
                            new_statements.push(statement);
                        }
                    }
                }
            }
            None => match candidate_statement_opt {
                None => {
                    if able_to_be_optimized {
                        candidate_statement_opt = Some(statement)
                    } else {
                        new_statements.push(statement)
                    }
                }
                Some(candidate_statement) => {
                    record = candidate_statement.combine_fr_pow(&statement);
                    if record.is_none() {
                        new_statements.push(candidate_statement);
                        if able_to_be_optimized {
                            candidate_statement_opt = Some(statement);
                        } else {
                            candidate_statement_opt = None;
                            new_statements.push(statement);
                        }
                    } else {
                        candidate_statement_opt = None;
                        if !able_to_be_optimized {
                            new_statements.append(&mut record_to_pow(record));
                            record = None;
                        }
                    }
                }
            },
        }
    }

    if candidate_statement_opt.is_some() {
        new_statements.push(candidate_statement_opt.unwrap());
    } else if record.is_some() {
        new_statements.append(&mut record_to_pow(record));
    }

    new_statements
}

impl Statement {
    pub fn able_to_be_optimized(
        &self,
        index: usize,
        intervals: &Vec<Interval>,
        lookup: &HashMap<Rc<Expression>, usize>,
    ) -> bool {
        if let Some(assignee) = self.get_assignee() {
            // Only optimize intermediate value
            intervals[*lookup.get(&assignee).unwrap()].end == index + 1
        } else {
            false
        }
    }

    pub fn get_assignee(&self) -> Option<Rc<Expression>> {
        match self {
            Statement::Assign(assignee, _, _) => Some(assignee.clone()),
            _ => None,
        }
    }

    pub fn combine_mul_add(&self, next: &Statement) -> Option<Statement> {
        let curr = match self {
            Statement::Assign(assignee, Expression::Mul(l, r, t), _) => Some((assignee, l, r, t)),
            _ => None,
        };

        match curr {
            None => None,
            Some((assignee, l, r, t)) => match next {
                Statement::Assign(new_assignee, Expression::Add(new_l, new_r, new_t), samples) => {
                    if new_l == assignee && t == new_t {
                        Some(Statement::Assign(
                            new_assignee.clone(),
                            Expression::MulAdd(r.clone(), l.clone(), new_r.clone(), t.clone()),
                            samples.clone(),
                        ))
                    } else if new_r == assignee && t == new_t {
                        Some(Statement::Assign(
                            new_assignee.clone(),
                            Expression::MulAdd(r.clone(), l.clone(), new_l.clone(), t.clone()),
                            samples.clone(),
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
        }
    }

    pub fn combine_fr_pow(
        &self,
        next: &Statement,
    ) -> Option<(
        Rc<Expression>,
        Option<Rc<Expression>>,
        Rc<Expression>,
        usize,
        Vec<BigUint>,
    )> {
        let curr = match self {
            Statement::Assign(assignee, Expression::Mul(l, r, Type::Scalar), _) => {
                Some((assignee, l, r))
            }
            _ => None,
        };

        match curr {
            None => None,
            Some((assignee, l, r)) => match next {
                Statement::Assign(
                    new_assignee,
                    Expression::Mul(new_l, new_r, Type::Scalar),
                    samples,
                ) => {
                    if new_l == assignee && new_r == assignee && l == r {
                        Some((new_assignee.clone(), None, r.clone(), 4, samples.clone()))
                    } else if new_l == assignee && new_r == r && r == l {
                        Some((new_assignee.clone(), None, r.clone(), 3, samples.clone()))
                    } else if new_r == assignee && new_l == r && r == l {
                        Some((new_assignee.clone(), None, r.clone(), 3, samples.clone()))
                    } else if new_l == assignee && new_r == r {
                        Some((
                            new_assignee.clone(),
                            Some(l.clone()),
                            r.clone(),
                            2,
                            samples.clone(),
                        ))
                    } else if new_l == assignee && new_r == l {
                        Some((
                            new_assignee.clone(),
                            Some(r.clone()),
                            l.clone(),
                            2,
                            samples.clone(),
                        ))
                    } else if new_r == assignee && new_l == l {
                        Some((
                            new_assignee.clone(),
                            Some(r.clone()),
                            l.clone(),
                            2,
                            samples.clone(),
                        ))
                    } else if new_r == assignee && new_l == r {
                        Some((
                            new_assignee.clone(),
                            Some(l.clone()),
                            r.clone(),
                            2,
                            samples.clone(),
                        ))
                    } else {
                        None
                    }
                }
                _ => None,
            },
        }
    }

    pub fn combine_fr_pow_more(
        &self,
        assignee: &Rc<Expression>,
        base: &Rc<Expression>,
        exp: usize,
    ) -> Option<(Rc<Expression>, usize, Vec<BigUint>)> {
        match self {
            Statement::Assign(
                new_assignee,
                Expression::Mul(new_l, new_r, Type::Scalar),
                samples,
            ) => {
                if new_l == assignee && new_r == base {
                    Some((new_assignee.clone(), exp + 1, samples.clone()))
                } else if new_r == assignee && new_l == base {
                    Some((new_assignee.clone(), exp + 1, samples.clone()))
                } else if new_r == assignee && new_l == assignee {
                    Some((new_assignee.clone(), exp * 2, samples.clone()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}
