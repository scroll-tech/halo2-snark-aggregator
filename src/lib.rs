#![allow(dead_code)]
#![feature(trait_alias)]
#![feature(const_generics_defaults)]
mod circuits;
mod field;
mod gates;

mod arith;
mod schema;
pub mod verify;

#[cfg(test)]
mod tests;

pub const PREREQUISITE_CHECK: bool = true;
