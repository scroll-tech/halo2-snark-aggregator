use crate::arith::ecc::ArithECC;

pub struct Committed<P> {
    permutation_product_commitments: Vec<P>,
}

#[derive(Debug)]
pub struct EvaluatedSet<S, P> {
    pub(in crate::systems::halo2) permutation_product_commitment: P,
    pub(in crate::systems::halo2) permutation_product_eval: S,
    pub(in crate::systems::halo2) permutation_product_next_eval: S,
    pub(in crate::systems::halo2) permutation_product_last_eval: Option<S>,
    pub(in crate::systems::halo2) chunk_len: usize,
}

#[derive(Debug)]
pub struct CommonEvaluated<'a, S, P> {
    pub permutation_evals: &'a Vec<S>,
    pub permutation_commitments: &'a Vec<P>,
}

#[derive(Debug)]
pub struct Evaluated<A: ArithECC> {
    pub(in crate::systems::halo2) x: A::AssignedScalar,
    pub(in crate::systems::halo2) sets: Vec<EvaluatedSet<A::AssignedScalar, A::AssignedPoint>>,
    pub(in crate::systems::halo2) evals: Vec<A::AssignedScalar>,
    pub(in crate::systems::halo2) chunk_len: usize,
}
