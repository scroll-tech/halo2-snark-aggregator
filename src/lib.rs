#![allow(dead_code)]
#![feature(trait_alias)]
mod gates;
mod utils;

mod arith;
mod schema;
mod plonk;

#[cfg(test)]
mod tests;

pub const PREREQUISITE_CHECK: bool = true;
