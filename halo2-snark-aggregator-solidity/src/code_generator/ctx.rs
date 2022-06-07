use num_bigint::BigUint;
use std::{collections::HashMap, rc::Rc};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    Scalar,
    Point,
}

impl Type {
    fn to_length(&self) -> usize {
        match &self {
            Type::Scalar => 1,
            Type::Point => 2,
        }
    }

    fn to_libstring(&self) -> String {
        match &self {
            Type::Scalar => "LibFr".to_owned(),
            Type::Point => "LibEcc".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expression {
    Memory(usize, Type),
    TransciprtOffset(usize, Type),
    InstanceOffset(usize, Type),
    // TODO: Remove
    TmpBufOffset(usize, Type),
    Point(BigUint, BigUint),
    Scalar(BigUint),
    Add(Rc<Expression>, Rc<Expression>, Type),
    Sub(Rc<Expression>, Rc<Expression>, Type),
    Mul(Rc<Expression>, Rc<Expression>, Type),
    Div(Rc<Expression>, Rc<Expression>, Type),
    MulAddConstant(Rc<Expression>, Rc<Expression>, Rc<Expression>, Type),
    Hash(usize),
}

impl Expression {
    pub(crate) fn get_type(&self) -> Type {
        match &self {
            Expression::Memory(_, t)
            | Expression::TransciprtOffset(_, t)
            | Expression::InstanceOffset(_, t)
            | Expression::TmpBufOffset(_, t)
            | Expression::Add(_, _, t)
            | Expression::Sub(_, _, t)
            | Expression::Mul(_, _, t)
            | Expression::Div(_, _, t)
            | Expression::MulAddConstant(_, _, _, t) => (*t).clone(),
            Expression::Point(_, _) => Type::Point,
            Expression::Scalar(_) => Type::Scalar,
            Expression::Hash(_) => Type::Scalar,
        }
    }

    pub fn to_untyped_string(&self) -> String {
        match self {
            Expression::Memory(idx, Type::Scalar) => format!("m[{}]", idx),
            Expression::Memory(idx, Type::Point) => format!("(m[{}], m[{}])", idx, idx + 1),
            _ => unreachable!(),
        }
    }

    pub fn to_typed_string(&self) -> String {
        match self {
            Expression::Scalar(s) => format!("{}", s.to_string()),
            Expression::Point(x, y) => {
                format!("LibEcc.from({}, {})", x.to_string(), y.to_string())
            }
            Expression::Memory(idx, Type::Scalar) => format!("m[{}]", idx),
            Expression::Memory(idx, Type::Point) => {
                format!("LibEcc.from(m[{}], m[{}])", idx, idx + 1)
            }
            Expression::Add(l, r, t) => format!(
                "{}.add({}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Sub(l, r, t) => format!(
                "{}.sub({}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::Mul(s, p, t) => format!(
                "{}.mul({}, {})",
                t.to_libstring(),
                (*p).to_typed_string(),
                (*s).to_typed_string()
            ),
            Expression::Div(l, r, t) => format!(
                "{}.div({}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string()
            ),
            Expression::MulAddConstant(l, r, c, t) => format!(
                "{}.mul_add_constant({}, {}, {})",
                t.to_libstring(),
                (*l).to_typed_string(),
                (*r).to_typed_string(),
                (*c).to_typed_string()
            ),
            Expression::TransciprtOffset(offset, t) => {
                format!("{}.from_bytes(proof, {})", t.to_libstring(), offset)
            }
            Expression::InstanceOffset(offset, t) => {
                format!("{}.from_bytes(instances, {})", t.to_libstring(), offset)
            }
            Expression::TmpBufOffset(offset, t) => {
                format!("{}.from_bytes(vars, {})", t.to_libstring(), offset)
            }
            Expression::Hash(offset) => {
                format!("squeeze_challenge(absorbing, {})", offset)
            }
        }
    }

    pub(crate) fn iter(&self, f: &mut impl FnMut(&Expression) -> ()) {
        match self {
            Expression::Add(l, r, _)
            | Expression::Sub(l, r, _)
            | Expression::Mul(l, r, _)
            | Expression::Div(l, r, _) => {
                l.iter(f);
                r.iter(f);
            }
            Expression::MulAddConstant(l, r, c, _) => {
                l.iter(f);
                r.iter(f);
                c.iter(f);
            }
            t => f(t),
        }
    }

    pub(crate) fn map(&self, f: &impl Fn(&Expression) -> Expression) -> Expression {
        match self {
            Expression::Add(l, r, t) => {
                Expression::Add(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Sub(l, r, t) => {
                Expression::Sub(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Mul(l, r, t) => {
                Expression::Mul(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::Div(l, r, t) => {
                Expression::Div(Rc::new(l.map(f)), Rc::new(r.map(f)), t.clone())
            }
            Expression::MulAddConstant(l, r, c, t) => Expression::MulAddConstant(
                Rc::new(l.map(f)),
                Rc::new(r.map(f)),
                Rc::new(c.map(f)),
                t.clone(),
            ),
            t => f(t),
        }
    }

    pub(crate) fn substitute(&self, lookup: &HashMap<usize, usize>) -> Expression {
        let replace = |expr: &Expression| match expr {
            Expression::Memory(o, t) => Expression::Memory(*lookup.get(o).unwrap(), t.clone()),
            _ => expr.clone(),
        };

        self.map(&replace)
    }
}

#[derive(Clone)]
pub(crate) enum Statement {
    Assign(Rc<Expression>, Expression),
    UpdateHash(Rc<Expression>, usize),
}

impl Statement {
    pub fn to_solidity_string(&self) -> String {
        match self {
            Statement::Assign(l, r) => {
                format!(
                    "{} = {}({});",
                    (*l).to_untyped_string(),
                    if r.get_type() == Type::Point {
                        "LibEcc.to_tuple"
                    } else {
                        ""
                    },
                    (*r).to_typed_string()
                )
            }
            Statement::UpdateHash(e, offset) => match e.get_type() {
                Type::Point => {
                    format!(
                        "update_hash_point({}, absorbing, {});",
                        e.to_typed_string(),
                        offset
                    )
                }
                Type::Scalar => {
                    format!(
                        "update_hash_scalar({}, absorbing, {});",
                        e.to_typed_string(),
                        offset
                    )
                }
            },
        }
    }

    pub fn substitute(&self, lookup: &HashMap<usize, usize>) -> Statement {
        match self {
            Statement::Assign(l, r) => {
                Statement::Assign(Rc::new(l.substitute(lookup)), r.substitute(lookup))
            }
            Statement::UpdateHash(e, offset) => Statement::UpdateHash(Rc::new(e.substitute(lookup)), *offset),
        }
    }
}

struct Cache {
    cache_assign: HashMap<Expression, Rc<Expression>>,
}

pub struct SolidityCodeGeneratorContext {
    pub(crate) absorbing_offset: usize,
    pub(crate) memory_offset: usize,
    transcript_offset: usize,
    instance_offset: usize,
    tmp_offset: usize,
    pub(crate) var_buf: Vec<u8>,
    pub(crate) statements: Vec<Statement>,
    cache: Cache,
    mock_hash: bool,
    pub(crate) transcript_context: bool,
    pub(crate) instance_context: bool,
}

impl SolidityCodeGeneratorContext {
    pub(crate) fn enter_hash(&mut self) {
        self.mock_hash = true;
    }

    pub(crate) fn enter_transcript(&mut self) {
        self.transcript_context = true;
    }

    pub(crate) fn exit_transcript(&mut self) {
        self.transcript_context = false;
    }

    pub(crate) fn enter_instance(&mut self) {
        self.instance_context = true;
    }

    pub(crate) fn exit_instance(&mut self) {
        self.instance_context = false;
    }

    pub(crate) fn squeeze_challenge_scalar(&mut self, offset: usize) -> Rc<Expression> {
        self.mock_hash = false;
        let l = self.allocate(Type::Scalar);
        let r = Expression::Hash(offset);
        self.statements.push(Statement::Assign(l.clone(), r));

        l
    }

    pub(crate) fn update(&mut self, expr: &Rc<Expression>, offset: usize) {
        self.statements.push(Statement::UpdateHash(expr.clone(), offset))
    }
}

impl SolidityCodeGeneratorContext {
    pub fn new() -> Self {
        SolidityCodeGeneratorContext {
            absorbing_offset: 0,
            transcript_offset: 0,
            instance_offset: 0,
            tmp_offset: 0,
            memory_offset: 0,
            var_buf: vec![],
            statements: vec![],
            cache: Cache {
                // scalar_constant: HashMap::<BigUint, Rc<Expression>>::new(),
                // point_constant: HashMap::<(BigUint, BigUint), Rc<Expression>>::new(),
                cache_assign: HashMap::<Expression, Rc<Expression>>::new(),
            },
            mock_hash: false,
            transcript_context: false,
            instance_context: false,
        }
    }

    pub(crate) fn allocate(&mut self, t: Type) -> Rc<Expression> {
        let u256_cnt = t.to_length();
        let e = Expression::Memory(self.memory_offset, t);
        self.memory_offset = self.memory_offset + u256_cnt;
        Rc::new(e)
    }

    pub(crate) fn assign_memory(&mut self, v: Expression) -> Rc<Expression> {
        match self.cache.cache_assign.get(&v) {
            Some(e) => e.clone(),
            None => {
                let mem = self.allocate(v.get_type());
                if !self.mock_hash {
                    self.cache.cache_assign.insert(v.clone(), mem.clone());
                    self.statements.push(Statement::Assign(mem.clone(), v));
                }
                mem
            }
        }
    }

    pub(crate) fn new_transcript_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::TransciprtOffset(self.transcript_offset, t);
        self.transcript_offset = self.transcript_offset + delta;
        Rc::new(e)
    }

    pub(crate) fn new_instance_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::InstanceOffset(self.instance_offset, t);
        self.instance_offset = self.instance_offset + delta;
        Rc::new(e)
    }

    pub(crate) fn new_tmp_var(&mut self, t: Type, delta: usize) -> Rc<Expression> {
        let e = Expression::TmpBufOffset(self.tmp_offset, t);
        self.tmp_offset = self.tmp_offset + delta;
        Rc::new(e)
    }

    pub(crate) fn extend_var_buf(&mut self, data: &[u8]) {
        self.var_buf.extend_from_slice(data)
    }
}

pub(crate) struct G2Point {
    pub(crate) x: (BigUint, BigUint),
    pub(crate) y: (BigUint, BigUint),
}

pub(crate) struct CodeGeneratorCtx {
    pub(crate) wx: Expression,
    pub(crate) wg: Expression,
    pub(crate) s_g2: G2Point,
    pub(crate) n_g2: G2Point,
    pub(crate) assignments: Vec<Statement>,
    pub(crate) memory_size: usize,
    pub(crate) absorbing_length: usize,
}
