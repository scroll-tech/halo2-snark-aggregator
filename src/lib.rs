#![allow(dead_code)]
#![feature(trait_alias)]
mod gates;
mod utils;

mod arith;
mod schema;
mod verify;

#[cfg(test)]
mod tests;

pub const PREREQUISITE_CHECK: bool = true;

pub trait FieldExt = halo2_proofs::arithmetic::FieldExt;