use halo2_proofs::plonk::Expression;

use crate::arith::ecc::ArithECC;

#[derive(Debug)]
pub struct PermutationCommitments<P> {
    pub(in crate::systems::halo2) permuted_input_commitment: P,
    pub(in crate::systems::halo2) permuted_table_commitment: P,
}

#[derive(Debug)]
pub struct Committed<P> {
    pub(in crate::systems::halo2) permuted: PermutationCommitments<P>,
    pub(in crate::systems::halo2) product_commitment: P,
}

#[derive(Debug)]
pub struct Evaluated<A: ArithECC> {
    pub(in crate::systems::halo2) input_expressions: Vec<Expression<A::AssignedScalar>>,
    pub(in crate::systems::halo2) table_expressions: Vec<Expression<A::AssignedScalar>>,
    pub(in crate::systems::halo2) committed: Committed<A::AssignedPoint>,
    pub(in crate::systems::halo2) product_eval: A::AssignedScalar, // X
    pub(in crate::systems::halo2) product_next_eval: A::AssignedScalar, // ωX
    pub(in crate::systems::halo2) permuted_input_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permuted_input_inv_eval: A::AssignedScalar,
    pub(in crate::systems::halo2) permuted_table_eval: A::AssignedScalar,
}
