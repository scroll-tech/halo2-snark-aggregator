use crate::arith::api::{ContextGroup, ContextRing};
use crate::schema::ast::SchemaItem;
use crate::schema::ast::{CommitQuery, MultiOpenProof};
use crate::schema::EvaluationProof;
use crate::verify::halo2::verify::query::IVerifierParams;
use crate::verify::halo2::verify::SchemaGenerator;
use crate::{commit, scalar};
use halo2_proofs::arithmetic::FieldExt;
use std::fmt::Debug;

use super::VerifierParams;
impl<
        'a,
        C,
        S: Clone + Debug + PartialEq,
        P: Clone + Debug,
        TS: FieldExt,
        TP,
        Error: Debug,
        SGate: ContextGroup<C, S, S, TS, Error> + ContextRing<C, S, S, Error>,
        PGate: ContextGroup<C, S, P, TP, Error>,
    > SchemaGenerator<'a, C, S, P, TS, TP, Error, SGate, PGate> for VerifierParams<C, S, P, Error>
{
    fn get_point_schemas(
        &'a self,
        ctx: &mut C,
        sgate: &SGate,
        _pgate: &PGate,
    ) -> Result<Vec<EvaluationProof<'a, S, P>>, Error> {
        let queries = self.queries(sgate, ctx)?;
        let mut points: Vec<(S, Vec<_>)> = vec![];
        for query in queries.into_iter() {
            let mut found = None;
            for point in points.iter_mut() {
                if point.0 == query.point {
                    found = Some(&mut point.1);
                }
            }
            match found {
                Some(v) => v.push(query.s),
                _ => points.push((query.point, vec![query.s])),
            }
        }

        assert_eq!(self.w.len(), points.len());

        points
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let point = p.0;
                let queries = p.1;
                let mut acc = None;

                for q in queries.into_iter() {
                    acc = match acc {
                        Some(acc) => Some(scalar!(self.v) * acc + q),
                        _ => Some(q),
                    };
                }

                Ok(EvaluationProof {
                    s: acc.unwrap(),
                    point,
                    w: &self.w[i],
                })
            })
            .collect()
    }

    fn batch_multi_open_proofs(
        &'a self,
        ctx: &mut C,
        sgate: &SGate,
        pgate: &PGate,
    ) -> Result<MultiOpenProof<'a, S, P>, Error> {
        let proofs = self.get_point_schemas(ctx, sgate, pgate)?;

        let mut w_x = None;
        let mut w_g = None;

        for (i, p) in proofs.into_iter().enumerate() {
            let s = &p.s;
            let w = CommitQuery {
                key: format!("w{}", i),
                c: Some(p.w),
                v: None,
            };
            w_x = w_x.map_or(Some(commit!(w)), |w_x| {
                Some(scalar!(self.u) * w_x + commit!(w))
            });
            w_g = w_g.map_or(Some(scalar!(p.point) * commit!(w) + s.clone()), |w_g| {
                Some(scalar!(self.u) * w_g + scalar!(p.point) * commit!(w) + s.clone())
            });
        }

        Ok(MultiOpenProof {
            w_x: w_x.unwrap(),
            w_g: w_g.unwrap(),
        })
    }
}
