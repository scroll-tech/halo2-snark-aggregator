
use crate::schema::ast::{
    SchemeItem,
    CommitQuery,
    //SingleOpeningProof,
    //MultiOpeningProof,
};

use crate::{eval, commit, scalar};

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
    a_xi: &'a S,
    b_xi: &'a S,
    c_xi: &'a S,
    sigma1_xi: &'a S,
    sigma2_xi: &'a S,
    z_xiw: &'a S,
    zh_xi: Option<S>,
    l1_xi: Option<S>,
    pi_xi: Option<S>,
}

pub struct PlonkVerifierParams<'a, S, P> {
    l: u32,
    n: u32,
    //public_wit: Vec<C::ScalarExt>,
    params: ParamsPreprocessed<'a, P>,
    commits: VerifyCommitments<'a, P>,
    evals: VerifyEvals<'a, S>,
    one: &'a S,
    beta: &'a S,
    gamma: &'a S,
    alpha: &'a S,
    xi: &'a S,
    xi_n: Option<S>,
    u: &'a S,
    v: &'a S,
    k1: &'a S,
    k2: &'a S,
    w: &'a S, //TODO the unit root of 2^n = 1
}

/*

impl<C: CurveAffine> PlonkVerifierParams<'_, S, P> {
    fn pow_vec(
        &self,
        main_gate: &MainGate<C::ScalarExt>,
        base: &S,
        exponent: u32,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<Vec<S>, Error> {
        let mut ret = vec![];
        let mut curr = base.clone();

        for _ in 0..exponent {
            let next = main_gate.mul2(region, &curr, offset)?;
            ret.push(curr);
            curr = next;
        }

        ret.push(curr);
        Ok(ret)
    }

    fn pow(
        &self,
        main_gate: &MainGate<C::ScalarExt>,
        base: &S,
        exponent: u32,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        assert!(exponent >= 1);

        let mut acc = base.clone();

        let mut second_bit = 1;
        while second_bit <= exponent {
            second_bit <<= 1;
        }
        second_bit >>= 2;

        while second_bit > 0 {
            acc = main_gate.mul2(region, &acc, offset)?;
            if exponent & second_bit == 1 {
                acc = main_gate.mul(region, &acc, base, offset)?;
            }
            second_bit >>= 1;
        }

        Ok(acc)
    }

    fn get_xi_n(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        match &self.xi_n {
            None => {
                let xi_n = self.pow(main_gate, &self.xi, self.n, region, offset)?;
                self.xi_n = Some(xi_n.clone());
                Ok(xi_n.clone())
            }
            Some(xi_n) => Ok(xi_n.clone()),
        }
    }

    fn get_xi_2n(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        let xi_n = self.get_xi_n(main_gate, region, offset)?;

        Ok(main_gate.mul(region, &xi_n, &xi_n, offset)?)
    }

    fn get_zh_xi(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        match &self.evals.zh_xi {
            None => {
                // zh_xi = xi ^ n - 1
                let xi_n = self.get_xi_n(main_gate, region, offset)?;
                let zh_xi = main_gate.add_constant(region, &xi_n, -C::ScalarExt::one(), offset)?;
                self.evals.zh_xi = Some(zh_xi.clone());
                Ok(zh_xi)
            }
            Some(zh_xi) => Ok(zh_xi.clone()),
        }
    }

    fn get_l1_xi(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        match &self.evals.l1_xi {
            None => {
                let n = C::ScalarExt::from(self.n as u64);
                let one = C::ScalarExt::one();
                let zero = C::ScalarExt::zero();

                // l1_xi = w * (xi ^ n - 1) / (n * (xi - w))
                let n_xi_sub_w_value = self.xi.value.and_then(|xi| self.w.value.map(|w| (xi - w) * n));
                let (_, _, n_xi_sub_w, _, _) = main_gate.combine(
                    region,
                    [
                        Term::Assigned(self.xi, n),
                        Term::Assigned(self.w, -n),
                        Term::Unassigned(n_xi_sub_w_value, -one),
                        Term::Zero,
                        Term::Zero,
                    ],
                    zero,
                    offset,
                    CombinationOptionCommon::OneLinerAdd.into(),
                )?;

                let zh_xi = self.get_zh_xi(main_gate, region, offset)?;
                let w_zh_xi = main_gate.mul(region, self.w, &zh_xi, offset)?;
                let l1_xi = main_gate.div_unsafe(region, &w_zh_xi, &n_xi_sub_w, offset)?;

                Ok(l1_xi)
            }
            Some(l1_xi) => Ok(l1_xi.clone()),
        }
    }

    fn get_pi_xi(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        match &self.evals.pi_xi {
            None => {
                let n = C::ScalarExt::from(self.n as u64);
                let one = C::ScalarExt::one();
                let zero = C::ScalarExt::zero();

                let w_vec = self.pow_vec(main_gate, self.w, self.l, region, offset)?;

                let mut pi_vec = vec![];
                for i in 0..self.l {
                    let wi = &w_vec[i as usize];
                    // li_xi = (w ^ i) * (xi ^ n - 1) / (n * (xi - w ^ i))
                    let n_xi_sub_w_i_value = self.xi.value.and_then(|xi| self.w.value.map(|wi| (xi - wi) * n));
                    let (_, _, n_xi_sub_w, _, _) = main_gate.combine(
                        region,
                        [
                            Term::Assigned(self.xi, n),
                            Term::Assigned(wi, -n),
                            Term::Unassigned(n_xi_sub_w_i_value, -one),
                            Term::Zero,
                            Term::Zero,
                        ],
                        zero,
                        offset,
                        CombinationOptionCommon::OneLinerAdd.into(),
                    )?;

                    let zh_xi = self.get_zh_xi(main_gate, region, offset)?;
                    let wi_zh_xi = main_gate.mul(region, wi, &zh_xi, offset)?;
                    let li_xi = main_gate.div_unsafe(region, &wi_zh_xi, &n_xi_sub_w, offset)?;

                    pi_vec.push(li_xi);
                }

                let mut pi_xi = (&pi_vec)[0].clone();
                for i in 1..self.l {
                    pi_xi = main_gate.add(region, pi_xi, (&pi_vec)[i as usize].clone(), offset)?;
                }
                self.evals.pi_xi = Some(pi_xi.clone());
                Ok(pi_xi)
            }
            Some(l1_xi) => Ok(l1_xi.clone()),
        }
    }


    fn get_r (
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<SchemeItem<C>, Error> {
        let a = CommitQuery{c: Some(self.commits.a), v: Some(self.evals.a_xi)};
        let b = CommitQuery{c: Some(self.commits.b), v: Some(self.evals.b_xi)};
        let c = CommitQuery{c: Some(self.commits.c), v: Some(self.evals.c_xi)};
        let qm = CommitQuery{c: Some(self.params.q_m), v: None};
        let ql = CommitQuery{c: Some(self.params.q_l), v: None};
        let qr = CommitQuery{c: Some(self.params.q_r), v: None};
        let qo = CommitQuery{c: Some(self.params.q_o), v: None};
        let qc = CommitQuery{c: Some(self.params.q_c), v: None};
        let z = CommitQuery{c: Some(self.commits.z), v: None};
        let zxi = CommitQuery{c: Some(self.commits.z), v: None};
        let sigma1 = CommitQuery{c: None, v: Some(self.evals.sigma1_xi)};
        let sigma2 = CommitQuery{c: None, v: Some(self.evals.sigma2_xi)};
        let sigma3 = CommitQuery{c: Some(self.params.sigma3), v: None};
        let tl = CommitQuery{c: Some(self.commits.tl), v: None};
        let tm = CommitQuery{c: Some(self.commits.tm), v: None};
        let th = CommitQuery{c: Some(self.commits.th), v: None};
        let pi_xi = self.get_pi_xi(main_gate, region, offset)?;
        let l1_xi = self.get_l1_xi(main_gate, region, offset)?;
        let xi_n = self.get_xi_n(main_gate, region, offset)?;
        let xi_2n = self.get_xi_2n(main_gate, region, offset)?;
        let zh_xi = self.get_zh_xi(main_gate, region, offset)?;
        let neg_one = main_gate.neg_with_constant(region, self.one, C::ScalarExt::zero(), offset)?;
        Ok(eval!(a) * eval!(b) * commit!(qm) + eval!(a) * commit!(ql)
            + eval!(b) * commit!(qr) + eval!(c) * commit!(qo) + scalar!(pi_xi) + commit!(qc)
            + scalar!(self.alpha) * (
                  (eval!(a) + (scalar!(self.beta) * scalar!(self.xi)) + scalar!(self.gamma))
                * (eval!(b) + (scalar!(self.beta) * scalar!(self.xi)) + scalar!(self.gamma))
                * (eval!(c) + (scalar!(self.beta) * scalar!(self.xi)) + scalar!(self.gamma))
                * commit!(z)
                + (eval!(a) + (scalar!(self.beta) * eval!(sigma1)) + scalar!(self.gamma))
                * (eval!(b) + (scalar!(self.beta) * eval!(sigma2)) + scalar!(self.gamma))
                * (eval!(c) + (scalar!(self.beta) * commit!(sigma3)) + scalar!(self.gamma))
                * eval!(zxi)
              )
            + scalar!(self.alpha) * scalar!(self.alpha) * scalar!(l1_xi) * (commit!(z) + scalar!(neg_one))
            + scalar!(zh_xi) * (
                  commit!(tl)
                + scalar!(xi_n) * commit!(tm)
                + scalar!(xi_2n) * commit!(th)
            )
        )
    }

    fn get_e1(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<S, Error> {
        let r0_xi = self.get_r0(main_gate, region, offset)?;
        let v0 = SPE(
            [
                self.evals.sigma2_xi,
                self.evals.sigma1_xi,
                self.evals.c_xi,
                self.evals.b_xi,
                self.evals.a_xi,
                &r0_xi,
            ]
            .to_vec(),
            self.v,
        );
        let v1 = SPE([self.evals.z_xiw].to_vec(), self.one);
        MPE([&v0 as &dyn EvalAggregator<C>, &v1].to_vec(), self.u).aggregate(main_gate, region, self.one, offset)
    }

    fn get_f1(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        ecc_gate: &BaseFieldEccChip<C>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<AssignedPoint<C::ScalarExt>, Error> {
        let r1 = self.get_r1(main_gate, ecc_gate, region, offset)?;
        let v0 = SPC(
            [self.params.sigma2, self.params.sigma1, self.commits.c, self.commits.b, self.commits.a, &r1].to_vec(),
            self.v,
        );
        let v1 = SPC([self.commits.z].to_vec(), self.one);
        MPC([&v0 as &dyn MSMAggregator<C>, &v1].to_vec(), self.u).aggregate(ecc_gate, region, self.one, offset)
    }

    fn get_wx(
        &mut self,
        main_gate: &MainGate<C::ScalarExt>,
        ecc_gate: &BaseFieldEccChip<C>,
        ws: Vec<SingleOpeningProof<C>>,
        region: &mut Region<'_, C::ScalarExt>,
        offset: &mut usize,
    ) -> Result<MultiOpeningProof<C>, Error> {
        let e1 = self.get_e1(main_gate, region, offset)?;
        let f1 = self.get_f1(main_gate, ecc_gate, region, offset)?;
        let mut wxs = Vec::new();
        ws.iter().for_each(|w| {
            wxs.push(w.w.clone());
        });
        let wxs = SPC(wxs.iter().collect(), self.u).aggregate(ecc_gate, region, self.one, offset)?;
        Ok(MultiOpeningProof{w_x: wxs.clone(), w_g: wxs, e: e1, f :f1})

    }
}
*/
