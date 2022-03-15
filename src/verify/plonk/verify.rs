use crate::arith::api::{ContextGroup, ContextRing, PowConstant};
use crate::schema::ast::{CommitQuery, MultiOpenProof, SchemaItem};
use crate::schema::utils::RingUtils;
use crate::schema::{EvaluationProof, SchemaGenerator};
use crate::{arith_in_ctx, infix2postfix};
use crate::{commit, eval, scalar};
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;
use std::marker::PhantomData;

pub struct ParamsPreprocessed<'a, P> {
    pub q_m: &'a P,
    pub q_l: &'a P,
    pub q_r: &'a P,
    pub q_o: &'a P,
    pub q_c: &'a P,
    pub sigma1: &'a P,
    pub sigma2: &'a P,
    pub sigma3: &'a P,
}

pub struct VerifyCommitments<'a, P> {
    pub a: &'a P,
    pub b: &'a P,
    pub c: &'a P,
    pub z: &'a P,
    pub tl: &'a P,
    pub tm: &'a P,
    pub th: &'a P,
    pub w_z: &'a P,
    pub w_zw: &'a P,
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

pub struct PlonkVerifierParams<'a, C, S, P, Error: Debug> {
    //public_wit: Vec<C::ScalarExt>,
    pub common: PlonkCommonSetup<'a, S>,
    pub params: ParamsPreprocessed<'a, P>,
    pub commits: VerifyCommitments<'a, P>,
    pub evals: VerifyEvals<'a, S>,
    pub beta: &'a S,
    pub gamma: &'a S,
    pub alpha: &'a S,
    pub u: &'a S,
    pub v: &'a S,
    pub xi: &'a S,
    pub _ctx: PhantomData<C>,
    pub _error: PhantomData<Error>,
}

impl<'a, C, S: Clone, P: Clone, Error: Debug> PlonkVerifierParams<'a, C, S, P, Error> {
    fn get_common_evals<
        T: FieldExt,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    >(
        &self,
        ctx: &mut C,
        sgate: &SGate,
    ) -> Result<[SchemaItem<'a, S, P>; 6], Error> {
        let n = &sgate.from_constant(ctx, T::from(self.common.n as u64))?;
        let _one = sgate.one(ctx)?;
        let one = &_one;
        let xi = self.xi;

        let xi_n = &sgate.pow_constant(ctx, self.xi, self.common.n)?;
        let xi_2n = &sgate.pow_constant(ctx, xi_n, 2)?;

        // zh_xi = xi ^ n - 1
        let zh_xi = &sgate.minus(ctx, xi_n, one)?;

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
                let li_xi =
                    arith_in_ctx!([sgate, ctx] wi * (xi_n - one) / (n * (xi - wi))).unwrap();
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
        Ok([
            scalar!(xi),
            scalar!(xi_n),
            scalar!(xi_2n),
            scalar!(zh_xi),
            scalar!(l1_xi),
            scalar!(pi_xi),
        ])
    }

    fn get_proof_xi<
        T: FieldExt,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    >(
        &self,
        ctx: &mut C,
        sgate: &SGate,
    ) -> Result<EvaluationProof<'a, S, P>, Error> {
        let _zero = sgate.zero(ctx)?;
        let _one = sgate.one(ctx)?;
        let zero = &_zero;
        let one = &_one;
        let a = CommitQuery {
            c: Some(self.commits.a),
            v: Some(self.evals.a_xi),
        };
        let b = CommitQuery {
            c: Some(self.commits.b),
            v: Some(self.evals.b_xi),
        };
        let c = CommitQuery {
            c: Some(self.commits.c),
            v: Some(self.evals.c_xi),
        };
        let qm = CommitQuery::<S, P> {
            c: Some(self.params.q_m),
            v: None,
        };
        let ql = CommitQuery::<S, P> {
            c: Some(self.params.q_l),
            v: None,
        };
        let qr = CommitQuery::<S, P> {
            c: Some(self.params.q_r),
            v: None,
        };
        let qo = CommitQuery::<S, P> {
            c: Some(self.params.q_o),
            v: None,
        };
        let qc = CommitQuery::<S, P> {
            c: Some(self.params.q_c),
            v: None,
        };
        let z = CommitQuery::<S, P> {
            c: Some(self.commits.z),
            v: None,
        };
        let zxi = CommitQuery::<S, P> {
            c: Some(self.commits.z),
            v: Some(self.evals.z_xiw),
        };
        let sigma1 = CommitQuery::<S, P> {
            c: None,
            v: Some(self.evals.sigma1_xi),
        };
        let sigma2 = CommitQuery::<S, P> {
            c: None,
            v: Some(self.evals.sigma2_xi),
        };
        let sigma3 = CommitQuery::<S, P> {
            c: Some(self.params.sigma3),
            v: None,
        };
        let tl = CommitQuery::<S, P> {
            c: Some(self.commits.tl),
            v: None,
        };
        let tm = CommitQuery::<S, P> {
            c: Some(self.commits.tm),
            v: None,
        };
        let th = CommitQuery::<S, P> {
            c: Some(self.commits.th),
            v: None,
        };
        let [xi, xi_n, xi_2n, zh_xi, l1_xi, pi_xi] = self.get_common_evals(ctx, sgate)?;
        let neg_one = &(sgate.minus(ctx, zero, one)?);
        let r = eval!(a) * eval!(b) * commit!(qm)
            + eval!(a) * commit!(ql)
            + eval!(b) * commit!(qr)
            + eval!(c) * commit!(qo)
            + pi_xi
            + commit!(qc)
            + scalar!(self.alpha)
                * ((eval!(a) + (scalar!(self.beta) * xi.clone()) + scalar!(self.gamma))
                    * (eval!(b)
                        + (scalar!(self.beta) * scalar!(self.common.k[0]) * xi.clone())
                        + scalar!(self.gamma))
                    * (eval!(c)
                        + (scalar!(self.beta) * scalar!(self.common.k[1]) * xi)
                        + scalar!(self.gamma))
                    * commit!(z)
                    + (eval!(a) + (scalar!(self.beta) * eval!(sigma1)) + scalar!(self.gamma))
                        * (eval!(b) + (scalar!(self.beta) * eval!(sigma2)) + scalar!(self.gamma))
                        * (eval!(c)
                            + (scalar!(self.beta) * commit!(sigma3))
                            + scalar!(self.gamma))
                        * eval!(zxi))
            + scalar!(self.alpha) * scalar!(self.alpha) * l1_xi * (commit!(z) + scalar!(neg_one))
            + zh_xi * (commit!(tl) + xi_n * commit!(tm) + xi_2n * commit!(th))
            + scalar!(self.v)
                * (commit!(a)
                    + scalar!(self.v)
                        * (commit!(b)
                            + scalar!(self.v)
                                * (commit!(c)
                                    + scalar!(self.v)
                                        * (commit!(sigma1) + scalar!(self.v) * commit!(sigma2)))))
            + scalar!(self.v)
                * (eval!(a)
                    + scalar!(self.v)
                        * (eval!(b)
                            + scalar!(self.v)
                                * (eval!(c)
                                    + scalar!(self.v)
                                        * (eval!(sigma1) + scalar!(self.v) * eval!(sigma2)))));
        Ok(EvaluationProof {
            s: r,
            point: self.xi.clone(),
            w: self.commits.w_z,
        })
    }

    fn get_proof_wxi<
        T: FieldExt,
        SGate: ContextGroup<C, S, S, T, Error> + ContextRing<C, S, S, Error>,
    >(
        &self,
        ctx: &mut C,
        sgate: &SGate,
    ) -> Result<EvaluationProof<'a, S, P>, Error> {
        let zxi = CommitQuery::<S, P> {
            c: Some(self.commits.z),
            v: Some(self.evals.z_xiw),
        };
        let s = commit!(zxi) + eval!(zxi);
        let point = {
            let xi = self.xi;
            let w = self.common.w;
            arith_in_ctx!([sgate, ctx] w * xi)?
        };
        Ok(EvaluationProof {
            s,
            point,
            w: self.commits.w_zw,
        })
    }
}

impl<
        'a,
        C: Clone,
        S: Clone,
        P: Clone,
        TS: FieldExt,
        TP,
        Error: Debug,
        SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, TP, Error>,
    > SchemaGenerator<'a, C, S, P, TS, TP, Error, SGate, PGate>
    for PlonkVerifierParams<'a, C, S, P, Error>
{
    fn get_point_schemas(
        &self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let proof_xi = self.get_proof_xi(ctx, sgate)?;
        let proof_wxi = self.get_proof_wxi(ctx, sgate)?;
        Ok(vec![proof_xi, proof_wxi])
    }

    fn batch_multi_open_proofs(
        &self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let mut proofs = self.get_point_schemas(ctx, sgate, pgate)?;
        proofs.reverse();
        let (mut w_x, mut w_g) = {
            let s = &proofs[0].s;
            let w = CommitQuery {
                c: Some(proofs[0].w),
                v: None,
            };
            (
                commit!(w),
                scalar!(proofs[0].point) * commit!(w) + s.clone(),
            )
        };
        let _ = proofs[1..].iter().map(|p| {
            let s = &p.s;
            let w = CommitQuery {
                c: Some(p.w),
                v: None,
            };
            w_x = scalar!(self.u) * w_x.clone() + commit!(w);
            w_g = scalar!(self.u) * w_g.clone() + scalar!(p.point) * commit!(w) + s.clone();
        });
        Ok(MultiOpenProof { w_x, w_g })
    }
}
