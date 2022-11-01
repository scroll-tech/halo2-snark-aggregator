use crate::{
    arith::ecc::ArithEccChip, commit, scalar, systems::halo2::evaluation::EvaluationQuerySchema,
};

use super::{
    evaluation::{CommitQuery, EvaluationProof},
    params::VerifierParams,
};

#[derive(Debug)]
pub struct MultiOpenProof<A: ArithEccChip> {
    pub w_x: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
    pub w_g: EvaluationQuerySchema<A::AssignedPoint, A::AssignedScalar>,
}

impl<A: ArithEccChip> std::fmt::Display for MultiOpenProof<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nb_points = self.w_x.estimate(None) + self.w_g.estimate(None);
        write!(f, "(estimated scalar mult of points: {})", nb_points)
    }
}

impl<A: ArithEccChip> VerifierParams<A> {
    fn get_point_schemas<'a>(
        &'a self,
        ctx: &mut A::Context,
        schip: &A::ScalarChip,
        _pchip: &A,
    ) -> Result<Vec<EvaluationProof<A>>, A::Error> {
        let queries = self.queries(ctx, schip)?;

        let mut points: Vec<(i32, (_, Vec<_>))> = Vec::new();

        for query in queries {
            if let Some(pos) = points
                .iter()
                .position(|(rotation, _)| *rotation == query.rotation)
            {
                let (_, schemas) = &mut points[pos];
                schemas.1.push(query.s);
            } else {
                points.push((query.rotation, (query.point, vec![query.s])));
            }
        }

        // update 2020.10.14(zzhang): self.w here is not sorted by rotation
        // check https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_proofs/src/poly/kzg/multiopen/gwc/prover.rs
        // for more details
        assert_eq!(self.w.len(), points.len());

        points
            .into_iter()
            .enumerate()
            .map(|(i, p)| {
                let point = p.1 .0;

                let acc =
                    p.1 .1
                        .into_iter()
                        .rev()
                        .reduce(|acc, q| scalar!(self.v) * acc + q);
                assert!(acc.is_none() == false);

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
        pchip: &A,
    ) -> Result<MultiOpenProof<A>, A::Error> {
        let proofs = self.get_point_schemas(ctx, schip, pchip)?;

        let mut w_x = None;
        let mut w_g = None;

        for (i, p) in proofs.into_iter().enumerate().rev() {
            let s = &p.s;
            let w = CommitQuery {
                key: format!("{}_w{}", self.key, i),
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
