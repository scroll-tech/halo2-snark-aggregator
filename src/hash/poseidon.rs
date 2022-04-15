use crate::arith::api::{ContextGroup, ContextRing};
use halo2_proofs::arithmetic::FieldExt;
use poseidon::{SparseMDSMatrix, Spec, State};
use std::fmt::Debug;
use std::marker::PhantomData;

struct PoseidonState<
    C,
    S,
    Error,
    F: FieldExt,
    SGate: ContextGroup<C, S, S, F, Error> + ContextRing<C, S, S, Error>,
    const T: usize,
    const RATE: usize,
> {
    s: [S; T],
    _phantom: PhantomData<(C, (F, Error, SGate))>,
}

impl<
        C,
        S: Debug,
        Error,
        F: FieldExt,
        SGate: ContextGroup<C, S, S, F, Error> + ContextRing<C, S, S, Error>,
        const T: usize,
        const RATE: usize,
    > PoseidonState<C, S, Error, F, SGate, T, RATE>
{
    fn sbox_full(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        constants: &[F; T],
    ) -> Result<(), Error> {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            let x2 = sgate.mul(ctx, x, x)?;
            let x4 = sgate.mul(ctx, &x2, &x2)?;
            *x = sgate.mul_add_constant(ctx, &x, &x4, constant.clone())?;
        }
        Ok(())
    }

    fn sbox_part(&mut self, ctx: &mut C, sgate: &SGate, constant: &F) -> Result<(), Error> {
        let x = &mut self.s[0];
        let x2 = sgate.mul(ctx, x, x)?;
        let x4 = sgate.mul(ctx, &x2, &x2)?;
        *x = sgate.mul_add_constant(ctx, &x, &x4, constant.clone())?;

        Ok(())
    }

    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        inputs: Vec<S>,
        pre_constants: &[F; T],
    ) -> Result<(), Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;

        self.s[0] = sgate.sum_with_constant(ctx, vec![(&self.s[0], F::one())], pre_constants[0])?;

        for ((x, constant), input) in self
            .s
            .iter_mut()
            .skip(1)
            .zip(pre_constants.iter().skip(1))
            .zip(inputs.iter())
        {
            *x =
                sgate.sum_with_constant(ctx, vec![(&x, F::one()), (input, F::one())], *constant)?;
        }

        for (i, (x, constant)) in self
            .s
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            *x = sgate.sum_with_constant(
                ctx,
                vec![(x, F::one())],
                if i == 0 {
                    *constant + F::one()
                } else {
                    *constant
                },
            )?;
        }

        Ok(())
    }

    fn apply_mds(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        mds: &[[F; T]; T],
    ) -> Result<(), Error> {
        let res = mds
            .iter()
            .map(|row| {
                let a = self
                    .s
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| (e, *word))
                    .collect::<Vec<_>>();

                sgate.sum_with_constant(ctx, a, F::zero())
            })
            .collect::<Result<Vec<_>, Error>>()?;

        self.s = res.try_into().unwrap();

        Ok(())
    }

    fn apply_sparse_mds(
        &mut self,
        ctx: &mut C,
        sgate: &SGate,
        mds: &SparseMDSMatrix<F, T, RATE>,
    ) -> Result<(), Error> {
        let a = self
            .s
            .iter()
            .zip(mds.row.iter())
            .map(|(e, word)| (e, *word))
            .collect::<Vec<_>>();

        let mut res = vec![sgate.sum_with_constant(ctx, a, F::zero())?];

        for (e, x) in mds.col_hat.iter().zip(self.s.iter().skip(1)) {
            res.push(sgate.sum_with_constant(
                ctx,
                vec![(&self.s[0], *e), (&x, F::one())],
                F::zero(),
            )?);
        }

        for (x, new_x) in self.s.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }

        Ok(())
    }
}

pub struct Poseidon<
    C,
    S,
    Error,
    F: FieldExt,
    SGate: ContextGroup<C, S, S, F, Error> + ContextRing<C, S, S, Error>,
    const T: usize,
    const RATE: usize,
> {
    state: PoseidonState<C, S, Error, F, SGate, T, RATE>,
    spec: Spec<F, T, RATE>,
    absorbing: Vec<S>,
}

impl<
        C,
        S: Debug + Clone,
        Error,
        F: FieldExt,
        SGate: ContextGroup<C, S, S, F, Error> + ContextRing<C, S, S, Error>,
        const T: usize,
        const RATE: usize,
    > Poseidon<C, S, Error, F, SGate, T, RATE>
{
    pub fn new(ctx: &mut C, sgate: &SGate, r_f: usize, r_p: usize) -> Result<Self, Error> {
        let init_state = State::<F, T>::default()
            .words()
            .iter()
            .map(|x| sgate.from_constant(ctx, *x))
            .collect::<Result<Vec<S>, _>>()?;

        Ok(Self {
            spec: Spec::new(r_f, r_p),
            state: PoseidonState {
                s: init_state.try_into().unwrap(),
                _phantom: PhantomData,
            },
            absorbing: Vec::new(),
        })
    }

    pub fn update(&mut self, elements: &[S]) {
        self.absorbing.extend_from_slice(elements);
    }

    pub fn squeeze(&mut self, ctx: &mut C, sgate: &SGate) -> Result<S, Error> {
        let mut input_elements = vec![];
        input_elements.append(&mut self.absorbing);

        let mut padding_offset = 0;

        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, sgate, chunk.to_vec())?;
        }

        if padding_offset == 0 {
            self.permutation(ctx, sgate, vec![])?;
        }

        Ok(self.state.s[1].clone())
    }

    fn permutation(&mut self, ctx: &mut C, sgate: &SGate, inputs: Vec<S>) -> Result<(), Error> {
        let r_f = self.spec.r_f / 2;
        let mds = &self.spec.mds_matrices.mds.rows();

        let constants = &self.spec.constants.start;
        self.state
            .absorb_with_pre_constants(ctx, sgate, inputs, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(ctx, sgate, constants)?;
            self.state.apply_mds(ctx, sgate, mds)?;
        }

        let pre_sparse_mds = &self.spec.mds_matrices.pre_sparse_mds.rows();
        self.state
            .sbox_full(ctx, sgate, constants.last().unwrap())?;
        self.state.apply_mds(ctx, sgate, &pre_sparse_mds)?;

        let sparse_matrices = &self.spec.mds_matrices.sparse_matrices;
        let constants = &self.spec.constants.partial;
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(ctx, sgate, constant)?;
            self.state.apply_sparse_mds(ctx, sgate, sparse_mds)?;
        }

        let constants = &self.spec.constants.end;
        for constants in constants.iter() {
            self.state.sbox_full(ctx, sgate, constants)?;
            self.state.apply_mds(ctx, sgate, mds)?;
        }
        self.state.sbox_full(ctx, sgate, &[F::zero(); T])?;
        self.state.apply_mds(ctx, sgate, mds)?;

        Ok(())
    }
}
