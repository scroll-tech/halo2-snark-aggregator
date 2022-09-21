use crate::arith::field::ArithFieldChip;
use halo2_proofs::arithmetic::Field;
use poseidon::{SparseMDSMatrix, Spec, State};

struct PoseidonState<A: ArithFieldChip, const T: usize, const RATE: usize> {
    s: [A::AssignedValue; T],
}

impl<A: ArithFieldChip, const T: usize, const RATE: usize> PoseidonState<A, T, RATE> {
    fn x_power5_with_constant(
        ctx: &mut A::Context,
        chip: &A,
        x: &A::AssignedValue,
        constant: A::Value,
    ) -> Result<A::AssignedValue, A::Error> {
        let x2 = chip.mul(ctx, x, x)?;
        let x4 = chip.mul(ctx, &x2, &x2)?;
        chip.mul_add_constant(ctx, x, &x4, constant)
    }

    fn sbox_full(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        constants: &[A::Value; T],
    ) -> Result<(), A::Error> {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, chip, x, *constant)?;
        }
        Ok(())
    }

    fn sbox_part(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        constant: &A::Value,
    ) -> Result<(), A::Error> {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, chip, x, *constant)?;

        Ok(())
    }

    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        inputs: Vec<A::AssignedValue>,
        pre_constants: &[A::Value; T],
    ) -> Result<(), A::Error> {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;

        self.s[0] = chip.sum_with_constant(ctx, vec![&self.s[0]], pre_constants[0])?;

        for ((x, constant), input) in self
            .s
            .iter_mut()
            .skip(1)
            .zip(pre_constants.iter().skip(1))
            .zip(inputs.iter())
        {
            *x = chip.sum_with_constant(ctx, vec![x, input], *constant)?;
        }

        for (i, (x, constant)) in self
            .s
            .iter_mut()
            .skip(offset)
            .zip(pre_constants.iter().skip(offset))
            .enumerate()
        {
            *x = chip.sum_with_constant(
                ctx,
                vec![x],
                if i == 0 {
                    *constant + A::Value::one()
                } else {
                    *constant
                },
            )?;
        }

        Ok(())
    }

    fn apply_mds(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        mds: &[[A::Value; T]; T],
    ) -> Result<(), A::Error> {
        let res = mds
            .iter()
            .map(|row| {
                let a = self
                    .s
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| (e, *word))
                    .collect::<Vec<_>>();

                chip.sum_with_coeff_and_constant(ctx, a, A::Value::zero())
            })
            .collect::<Result<Vec<_>, A::Error>>()?;

        self.s = res.try_into().unwrap();

        Ok(())
    }

    fn apply_sparse_mds(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        mds: &SparseMDSMatrix<A::Field, T, RATE>,
    ) -> Result<(), A::Error> {
        let a = self
            .s
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| (e, *word))
            .collect::<Vec<_>>();

        let mut res = vec![chip.sum_with_coeff_and_constant(ctx, a, A::Value::zero())?];

        for (e, x) in mds.col_hat().iter().zip(self.s.iter().skip(1)) {
            res.push(chip.sum_with_coeff_and_constant(
                ctx,
                vec![(&self.s[0], *e), (x, A::Value::one())],
                A::Value::zero(),
            )?);
        }

        for (x, new_x) in self.s.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }

        Ok(())
    }
}

pub struct PoseidonChip<A: ArithFieldChip, const T: usize, const RATE: usize> {
    state: PoseidonState<A, T, RATE>,
    spec: Spec<A::Field, T, RATE>,
    absorbing: Vec<A::AssignedValue>,
}

impl<A: ArithFieldChip, const T: usize, const RATE: usize> PoseidonChip<A, T, RATE> {
    pub fn new(ctx: &mut A::Context, chip: &A, r_f: usize, r_p: usize) -> Result<Self, A::Error> {
        let init_state = State::<A::Value, T>::default()
            .words()
            .into_iter()
            .map(|x| chip.assign_const(ctx, x))
            .collect::<Result<Vec<A::AssignedValue>, _>>()?;

        Ok(Self {
            spec: Spec::new(r_f, r_p),
            state: PoseidonState {
                s: init_state.try_into().unwrap(),
            },
            absorbing: Vec::new(),
        })
    }

    pub fn update(&mut self, elements: &[A::AssignedValue]) {
        self.absorbing.extend_from_slice(elements);
    }

    pub fn squeeze(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
    ) -> Result<A::AssignedValue, A::Error> {
        let mut input_elements = vec![];
        input_elements.append(&mut self.absorbing);

        let mut padding_offset = 0;

        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(ctx, chip, chunk.to_vec())?;
        }

        if padding_offset == 0 {
            self.permutation(ctx, chip, vec![])?;
        }

        Ok(self.state.s[1].clone())
    }

    fn permutation(
        &mut self,
        ctx: &mut A::Context,
        chip: &A,
        inputs: Vec<A::AssignedValue>,
    ) -> Result<(), A::Error> {
        let r_f = self.spec.r_f() / 2;
        let mds = &self.spec.mds_matrices().mds().rows();

        let constants = &self.spec.constants().start();
        self.state
            .absorb_with_pre_constants(ctx, chip, inputs, &constants[0])?;
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(ctx, chip, constants)?;
            self.state.apply_mds(ctx, chip, mds)?;
        }

        let pre_sparse_mds = &self.spec.mds_matrices().pre_sparse_mds().rows();
        self.state.sbox_full(ctx, chip, constants.last().unwrap())?;
        self.state.apply_mds(ctx, chip, pre_sparse_mds)?;

        let sparse_matrices = &self.spec.mds_matrices().sparse_matrices();
        let constants = &self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(ctx, chip, constant)?;
            self.state.apply_sparse_mds(ctx, chip, sparse_mds)?;
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            self.state.sbox_full(ctx, chip, constants)?;
            self.state.apply_mds(ctx, chip, mds)?;
        }
        self.state.sbox_full(ctx, chip, &[A::Value::zero(); T])?;
        self.state.apply_mds(ctx, chip, mds)?;

        Ok(())
    }
}
