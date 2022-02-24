use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;
use num_integer::Integer;

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

pub fn get_d_range_bits_in_mul<W: FieldExt, N: FieldExt>(integer_modulus: &BigUint) -> usize {
    let w_ceil_bits = field_to_bn(&-W::one()).bits() as usize + 1;
    let n_modulus = field_to_bn(&-N::one()) + 1usize;
    let lcm = integer_modulus.lcm(&n_modulus);
    let d_range_bits = ((lcm >> w_ceil_bits) - 1u64).bits() as usize;

    d_range_bits
}
