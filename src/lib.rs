#![allow(dead_code)]
#![feature(trait_alias)]
mod circuits;
mod field;
mod gates;

mod arith;
mod schema;
mod verify;

#[cfg(test)]
mod tests;

pub const PREREQUISITE_CHECK: bool = true;
