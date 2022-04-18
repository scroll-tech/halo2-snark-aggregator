use crate::{
    arith::ecc::ArithEccChip, commit, scalar, systems::halo2::evaluation::EvaluationQuerySchema,
};

use super::{
    evaluation::{CommitQuery, EvaluationProof},
    params::VerifierParams,
};

pub struct MultiOpenProof<A: ArithEccChip> {
    pub w_x: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    pub w_g: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
}

impl<A: ArithEccChip> VerifierParams<A> {
    fn get_point_schemas<'a>(
        &'a self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<Vec<EvaluationProof<A>>, A::Error> {
        let queries = self.queries(ctx, schip)?;
        let mut points: Vec<(String, A::AssignedScalar, Vec<_>)> = vec![];
        for query in queries {
            let p = points.iter_mut().find(|p| p.0 == query.key);
            match p {
                Some(v) => v.2.push(query.s),
                _ => points.push((query.key, query.point, vec![query.s])),
            }
        }

        assert_eq!(self.w.len(), points.len());

        points
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let point = p.1;
                let queries = p.2;

                let acc = queries
                    .into_iter()
                    .reduce(|acc, q| scalar!(self.v) * acc + q);

                Ok(EvaluationProof {
                    s: acc.unwrap(),
                    point,
                    w: &self.w[i],
                })
            })
            .collect()
    }

    pub fn batch_multi_open_proofs(
        &self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
    ) -> Result<MultiOpenProof<A>, A::Error> {
        let proofs = self.get_point_schemas(ctx, schip)?;

        let mut w_x = None;
        let mut w_g = None;

        for (i, p) in proofs.into_iter().enumerate() {
            let s = &p.s;
            let w = CommitQuery {
                key: format!("w{}", i),
                commitment: Some(p.w.clone()),
                eval: None,
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
