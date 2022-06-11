use halo2_proofs::arithmetic::{BaseExt, FieldExt};
use num_bigint::BigUint;
use num_integer::Integer;

pub fn field_to_bn<F: BaseExt>(f: &F) -> BigUint {
    let mut bytes: Vec<u8> = Vec::new();
    f.write(&mut bytes).unwrap();
    BigUint::from_bytes_le(&bytes[..])
}

pub fn bn_to_field<F: BaseExt>(bn: &BigUint) -> F {
    let mut bytes = bn.to_bytes_le();
    bytes.resize(32, 0);
    let mut bytes = &bytes[..];
    F::read(&mut bytes).unwrap()
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

// What is d range bits?
// First we define w_ceil bits by k, where 2 ^ k >= w > 2 ^ (k - 1), w_ceil = 2 ^ k.
//
// To prove r = a * b (mod w), where a < w_ceil * overflows (e.g. w * 64)
// <- exists d, a * b = w * d + r (mod lcm(n, 2 ^ t)), where lcm(n, 2 ^ t) > max(a) * max(b) = w * w * overflows * overflows
// <-> a * b = w * d + r (mod n_modulus) && a * b = w * d + r (mod 2 ^ t, e.g. 2 ^ (4 * 68)),
//
// let's limit d by d_bits, where d < 2 ^ d_bits to guarantee w * d + r < lcm(n, 2 ^ t).
// Pick d_bits = bits_of((lcm(n, 2 ^ t) - w_ceil) / w_ceil) - 1.
// 2 ^ d_bits < (lcm(n, 2 ^ t) - w_ceil) / w_ceil
// -> 2 ^ d_bits * w_ceil + w_ceil < lcm(n, 2 ^ t)
// -> d * w + r < 2 ^ d_bits * w_ceil + w_ceil < lcm(n, 2 ^ t)
pub fn get_d_range_bits_in_mul<W: BaseExt, N: FieldExt>(integer_modulus: &BigUint) -> usize {
    let w_ceil_bits = field_to_bn(&-W::one()).bits();
    let w_modulus = field_to_bn(&-W::one()) + 1usize;
    let n_modulus = field_to_bn(&-N::one()) + 1usize;
    let lcm = integer_modulus.lcm(&n_modulus);
    let d_range_bits = ((&lcm >> w_ceil_bits) - 1u64).bits() as usize - 1;
    assert!((BigUint::from(1u64) << d_range_bits) * &w_modulus + &w_modulus <= lcm);

    d_range_bits
}
