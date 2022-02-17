use std::fmt::Debug;
use std::marker::PhantomData;

use crate::{commit, scalar, eval};

use crate::schema::ast::{
    SchemaItem,
    CommitQuery,
};

use crate::schema::utils::{
    RingUtils,
};


use crate::arith::api::{
    ContextGroup,
    ContextRing,
    PowConstant,
};

use crate::schema::{
    EvaluationProof,
    SchemaGenerator,
};

use crate::{arith_in_ctx, infix2postfix};

pub struct ParamsPreprocessed<'a, P> {
    q_m: &'a P,
    q_l: &'a P,
    q_r: &'a P,
    q_o: &'a P,
    q_c: &'a P,
    sigma1: &'a P,
    sigma2: &'a P,
    sigma3: &'a P,
}

pub struct VerifyCommitments<'a, P> {
    a: &'a P,
    b: &'a P,
    c: &'a P,
    z: &'a P,
    tl: &'a P,
    tm: &'a P,
    th: &'a P,
    w_z: &'a P,
    w_zw: &'a P,

}

pub struct VerifyEvals<'a, S> {
    pub a_xi: &'a S,
    pub b_xi: &'a S,
    pub c_xi: &'a S,
    pub sigma1_xi: &'a S,
    pub sigma2_xi: &'a S,
    pub z_xiw: &'a S,
}

pub struct PlonkCommonSetup<'a, S> {
    pub l: u32,
    pub n: u32,
    pub k: Vec<&'a S>,
    pub w: &'a S, //TODO the unit root of 2^n = 1
    pub one: &'a S,
    pub zero: &'a S,
}


pub struct PlonkVerifierParams <
    'a, C, S, P, Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate: ContextGroup<C, S, P, Error>,
> {
    //public_wit: Vec<C::ScalarExt>,
    common: PlonkCommonSetup<'a, S>,
    params: ParamsPreprocessed<'a, P>,
    commits: VerifyCommitments<'a, P>,
    evals: VerifyEvals<'a, S>,
    beta: &'a S,
    gamma: &'a S,
    alpha: &'a S,
    u: &'a S,
    v: &'a S,
    xi: &'a S,
    xi_n: &'a S,
    sgate: &'a SGate,
    pgate: &'a PGate,
    _ctx: PhantomData<C>,
    _error: PhantomData<Error>
}

impl<'a, C, S:Clone, P:Clone, Error:Debug, SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>, PGate:ContextGroup<C, S, P, Error>>
    PlonkVerifierParams<'a, C, S, P, Error, SGate, PGate> {

    fn get_common_evals(
        &self,
        ctx: &mut C,
    ) -> Result<[SchemaItem<'a, S, P>; 6], Error> {
        let sgate = self.sgate;
        let n = &sgate.from_constant(self.common.n)?;
        let one = self.sgate.one();
        let xi = self.xi;

        let xi_n = &self.sgate.pow_constant(ctx, self.xi, self.common.n)?;
        let xi_2n = &self.sgate.pow_constant(ctx, xi_n, 2)?;

        // zh_xi = xi ^ n - 1
        let zh_xi = &self.sgate.minus(ctx, xi_n, self.sgate.one())?;

        // l1_xi = w * (xi ^ n - 1) / (n * (xi - w))
        let l1_xi = &{
            let w = self.common.w;
            arith_in_ctx!([sgate, ctx] w * (xi_n - one) / (n * (xi - w)))
        }?;

        let pi_xi = &{
            let w_vec = sgate.pow_constant_vec(ctx, self.common.w, self.common.l)?;
            let mut pi_vec = vec![];
            for i in 0..self.common.l {
                let wi = &w_vec[i as usize];
                // li_xi = (w ^ i) * (xi ^ n - 1) / (n * (xi - w ^ i))
                let li_xi = arith_in_ctx!([sgate, ctx] wi * (xi_n - one) / (n * (xi - wi))).unwrap();
                pi_vec.push(li_xi);
            }

            let mut pi_xi = (&pi_vec)[0].clone();
            for i in 1..self.common.l {
                let next = &(pi_vec)[i as usize];
                let curr = &pi_xi;
                pi_xi = arith_in_ctx!([sgate, ctx] curr + next).unwrap()
            }
            pi_xi.clone()
        };
        Ok([scalar!(xi), scalar!(xi_n), scalar!(xi_2n), scalar!(zh_xi), scalar!(l1_xi), scalar!(pi_xi)])
    }

    fn get_proof_xi (
        &self,
        ctx: &mut C,
    ) -> Result<EvaluationProof<'a, S, P>, Error> {
        let zero = self.sgate.zero();
        let one = self.sgate.one();
        let a = CommitQuery{c: Some(self.commits.a), v: Some(self.evals.a_xi)};
        let b = CommitQuery{c: Some(self.commits.b), v: Some(self.evals.b_xi)};
        let c = CommitQuery{c: Some(self.commits.c), v: Some(self.evals.c_xi)};
        let qm = CommitQuery::<S, P> {c: Some(self.params.q_m), v: None};
        let ql = CommitQuery::<S, P> {c: Some(self.params.q_l), v: None};
        let qr = CommitQuery::<S, P> {c: Some(self.params.q_r), v: None};
        let qo = CommitQuery::<S, P> {c: Some(self.params.q_o), v: None};
        let qc = CommitQuery::<S, P> {c: Some(self.params.q_c), v: None};
        let z = CommitQuery::<S, P> {c: Some(self.commits.z), v: None};
        let zxi = CommitQuery::<S, P> {c: Some(self.commits.z), v: Some(self.evals.z_xiw)};
        let sigma1 = CommitQuery::<S, P> {c: None, v: Some(self.evals.sigma1_xi)};
        let sigma2 = CommitQuery::<S, P> {c: None, v: Some(self.evals.sigma2_xi)};
        let sigma3 = CommitQuery::<S, P> {c: Some(self.params.sigma3), v: None};
        let tl = CommitQuery::<S, P> {c: Some(self.commits.tl), v: None};
        let tm = CommitQuery::<S, P> {c: Some(self.commits.tm), v: None};
        let th = CommitQuery::<S, P> {c: Some(self.commits.th), v: None};
        let [xi, xi_n, xi_2n, zh_xi, l1_xi, pi_xi] = self.get_common_evals(ctx)?;
        let neg_one = &(self.sgate.minus(ctx, zero, one)?);
        let r = eval!(a) * eval!(b) * commit!(qm) + eval!(a) * commit!(ql)
            + eval!(b) * commit!(qr) + eval!(c) * commit!(qo) + pi_xi + commit!(qc)
            + scalar!(self.alpha) * (
                  (eval!(a) + (scalar!(self.beta) * xi.clone()) + scalar!(self.gamma))
                * (eval!(b) + (scalar!(self.beta) * xi.clone()) + scalar!(self.gamma))
                * (eval!(c) + (scalar!(self.beta) * xi) + scalar!(self.gamma))
                * commit!(z)
                + (eval!(a) + (scalar!(self.beta) * eval!(sigma1)) + scalar!(self.gamma))
                * (eval!(b) + (scalar!(self.beta) * eval!(sigma2)) + scalar!(self.gamma))
                * (eval!(c) + (scalar!(self.beta) * commit!(sigma3)) + scalar!(self.gamma))
                * eval!(zxi)
              )
            + scalar!(self.alpha) * scalar!(self.alpha) * l1_xi * (commit!(z) + scalar!(neg_one))
            + zh_xi * (commit!(tl) + xi_n * commit!(tm) + xi_2n * commit!(th))
            + scalar!(self.v) * (
                commit!(a) + scalar!(self.v) * (
                    commit!(b) + scalar!(self.v) * (
                        commit!(c) + scalar!(self.v) * (
                            commit!(sigma1) + scalar!(self.v) * commit!(sigma2)
                        )
                    )
                )
            )
            + scalar!(self.v) * (
                eval!(a) + scalar!(self.v) * (
                    eval!(b) + scalar!(self.v) * (
                        eval!(c) + scalar!(self.v) * (
                            eval!(sigma1) + scalar!(self.v) * eval!(sigma2)
                        )
                    )
                )
            );
        Ok(EvaluationProof {s:r, point:self.xi.clone(), w: self.commits.w_z.clone()})
    }

    fn get_proof_wxi (
        &self,
        ctx: &mut C,
    ) -> Result<EvaluationProof<'a, S, P>, Error> {
        let sgate = self.sgate;
        let zxi = CommitQuery::<S, P> {c: Some(self.commits.z), v: Some(self.evals.z_xiw)};
        let s = commit!(zxi) + eval!(zxi);
        let point = {
            let xi = self.xi;
            let w = self.common.w;
            arith_in_ctx!([sgate, ctx] w * xi)?
        };
        Ok(EvaluationProof {s, point, w: self.commits.w_zw.clone()})
    }
}

impl<'a, C:Clone, S:Clone, P:Clone,
    Error:Debug,
    SGate: ContextGroup<C, S, S, Error> + ContextRing<C, S, S, Error>,
    PGate:ContextGroup<C, S, P, Error>>
    SchemaGenerator<'a, C, S, P, Error> for
    PlonkVerifierParams<'a, C, S, P, Error, SGate, PGate> {
    fn get_point_schemas(&self, ctx: &mut C) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let proof_xi = self.get_proof_xi(ctx)?;
        let proof_wxi = self.get_proof_wxi(ctx)?;
        Ok(vec![proof_xi, proof_wxi])
    }
}


