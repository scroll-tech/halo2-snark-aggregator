use halo2_proofs::arithmetic::FieldExt;
use num_bigint::BigUint;
use num_integer::Integer;

pub fn field_to_bn<F: FieldExt>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

/// Input a big integer `bn`, compute a field element `f`
/// such that `f == bn % F::MODULUS`.
pub fn bn_to_field<F: FieldExt>(bn: &BigUint) -> F {
    let mut buf = bn.to_bytes_le();
    buf.resize(64, 0u8);

    let mut buf_array = [0u8; 64];
    buf_array.copy_from_slice(buf.as_ref());
    F::from_bytes_wide(&buf_array)
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
pub fn get_d_range_bits_in_mul<W: FieldExt, N: FieldExt>(integer_modulus: &BigUint) -> usize {
    let w_ceil_bits = field_to_bn(&-W::one()).bits();
    let w_modulus = field_to_bn(&-W::one()) + 1usize;
    let n_modulus = field_to_bn(&-N::one()) + 1usize;
    let lcm = integer_modulus.lcm(&n_modulus);
    let d_range_bits = ((&lcm >> w_ceil_bits) - 1u64).bits() as usize - 1;
    assert!((BigUint::from(1u64) << d_range_bits) * &w_modulus + &w_modulus <= lcm);

    d_range_bits
}
