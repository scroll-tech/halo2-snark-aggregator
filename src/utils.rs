use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    F::from_str_vartime(&bn.to_str_radix(10)[..]).unwrap()
}

pub fn decompose_bn<F: FieldExt>(v: &BigUint, modulus_shift: usize, chunks: usize) -> Vec<(F, F)> {
    let modulus = BigUint::from(1u64) << modulus_shift;
    let modulus_mask = &modulus - 1u64;

    let mut ret = vec![];
    for i in 0..chunks {
        let rem = (v >> (i * modulus_shift)) & &modulus_mask;
        let coeff = BigUint::from(1u64) << (i * modulus_shift);
        ret.push((rem, coeff))
    }

    ret.iter()
        .map(|(a, b)| (bn_to_field(&a), bn_to_field(&b)))
        .collect()
}
