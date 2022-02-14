use super::{AssignedValue, BaseGate, BaseRegion, ValueSchema};
use halo2_proofs::{arithmetic::FieldExt, plonk::Error};

macro_rules! pair {
    ($x: expr, $y: expr) => {
        (($x).into(), ($y))
    };
}

impl<N: FieldExt, const VAR_COLUMNS: usize, const MUL_COLUMNS: usize> BaseGate<N, VAR_COLUMNS, MUL_COLUMNS> {
    pub fn one_line(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        mut base_coeff_pairs: Vec<(ValueSchema<N>, N)>,
        constant: N,
        mul_next_coeffs: (Vec<N>, N),
    ) -> Result<[AssignedValue<N>; VAR_COLUMNS], Error> {
        let mut cells = vec![];

        let zero = N::zero();

        base_coeff_pairs.resize_with(VAR_COLUMNS, || (ValueSchema::Empty, zero));
        for (i, (base, coeff)) in base_coeff_pairs.into_iter().enumerate() {
            r.region
                .assign_fixed(|| format!("coeff_{}", i), self.config.coeff[i], *r.offset, || Ok(coeff))?
                .cell();

            let cell = r
                .region
                .assign_advice(
                    || format!("base_{}", i),
                    self.config.base[i],
                    *r.offset,
                    || Ok(base.value()),
                )?
                .cell();

            base.constrain_equal_conditionally(r.region, cell)?;
            cells.push(AssignedValue {
                cell,
                value: base.value(),
            });
        }

        let (mut mul_coeffs, next) = mul_next_coeffs;
        mul_coeffs.resize_with(MUL_COLUMNS, || zero);
        for (i, mul_coeff) in mul_coeffs.into_iter().enumerate() {
            r.region.assign_fixed(
                || format!("mul_coeff_{}", i),
                self.config.mul_coeff[i],
                *r.offset,
                || Ok(mul_coeff),
            )?;
        }

        r.region
            .assign_fixed(|| "constant", self.config.constant, *r.offset, || Ok(constant))?;
        r.region
            .assign_fixed(|| "next_coeff", self.config.next_coeff, *r.offset, || Ok(next))?;

        *r.offset += 1;

        Ok(cells.try_into().unwrap())
    }

    pub fn sum_with_constant(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        elems: Vec<(&AssignedValue<N>, N)>,
        constant: N,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(elems.len() < VAR_COLUMNS);

        let one = N::one();
        let zero = N::zero();

        let sum = elems.iter().fold(constant, |acc, (v, coeff)| acc + v.value * coeff);
        let mut schemas_pairs = vec![pair!(sum, -one)];
        schemas_pairs.append(&mut elems.into_iter().map(|(v, coeff)| pair!(v, coeff)).collect());

        let cells = self.one_line(r, schemas_pairs, constant, (vec![], zero))?;

        Ok(cells[0])
    }

    pub fn add(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS > 2);

        let zero = N::zero();
        let one = N::one();
        self.sum_with_constant(r, vec![(a, one), (b, one)], zero)
    }

    pub fn mul(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        assert!(VAR_COLUMNS > 2);
        assert!(MUL_COLUMNS > 0);

        let one = N::one();
        let zero = N::zero();

        let c = a.value * b.value;

        let cells = self.one_line(
            r,
            vec![pair!(a, zero), pair!(b, zero), pair!(c, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[2])
    }

    pub fn invert_unsafe(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        a: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let b = a.value.invert().unwrap();

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(r, vec![pair!(a, zero), pair!(b, zero)], one, (vec![one], zero))?;

        Ok(cells[1])
    }

    pub fn div_unsafe(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<AssignedValue<N>, Error> {
        let c = b.value.invert().unwrap() * a.value;

        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(
            r,
            vec![pair!(b, zero), pair!(c, zero), pair!(a, -one)],
            zero,
            (vec![one], zero),
        )?;

        Ok(cells[1])
    }

    pub fn assign_constant(&self, r: &mut BaseRegion<'_, '_, N>, v: N) -> Result<AssignedValue<N>, Error> {
        let one = N::one();
        let zero = N::zero();

        let cells = self.one_line(r, vec![pair!(v, -one)], v, (vec![], zero))?;

        Ok(cells[0])
    }

    pub fn assert_equal(
        &self,
        r: &mut BaseRegion<'_, '_, N>,
        a: &AssignedValue<N>,
        b: &AssignedValue<N>,
    ) -> Result<(), Error> {
        let one = N::one();
        let zero = N::zero();

        self.one_line(r, vec![pair!(a, -one), pair!(b, one)], zero, (vec![], zero))?;

        Ok(())
    }
}
