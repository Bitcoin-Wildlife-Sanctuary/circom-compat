//! Arkworks - Circom Compatibility layer
//!
//! Provides bindings to Circom's R1CS, for Groth16 Proof and Witness generation in Rust.

pub mod circuit;
pub mod r1cs_reader;

pub use crate::r1cs_reader::{R1CSFile, R1CS};

pub use crate::circuit::CircomCircuit;

pub type Constraints<F> = (ConstraintVec<F>, ConstraintVec<F>, ConstraintVec<F>);
pub type ConstraintVec<F> = Vec<(usize, F)>;
