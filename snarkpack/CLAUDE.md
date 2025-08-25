# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a Rust implementation of Snarkpack, a scheme for aggregating Groth16 proofs. It's a port of the original bellperson implementation to the arkworks framework. The library implements the inner pairing product argument (IPP) for proof aggregation.

## Development Commands

### Build and Test
- `cargo build --workspace --release` - Build the entire workspace in release mode
- `cargo test --workspace --verbose` - Run all tests with verbose output
- `cargo test aggregation` - Run specific aggregation tests
- `cargo clippy --workspace --all-targets` - Run clippy lints
- `cargo fmt --all -- --check` - Check code formatting (requires nightly toolchain)

### Benchmarks
- `cargo bench` - Run benchmarks using criterion
- `cargo bench --bench bench_aggregation` - Run specific aggregation benchmarks

### Toolchain Requirements
- Uses nightly Rust toolchain for formatting and builds
- clippy runs on stable toolchain

## Architecture

### Core Components

**Proof Aggregation Pipeline:**
- `srs.rs` - Structured Reference String setup and specialization
- `prover.rs` - Proof aggregation logic using inner pairing product arguments
- `verifier.rs` - Aggregate proof verification
- `transcript.rs` - Fiat-Shamir transcript management using Merlin

**Supporting Modules:**
- `commitment.rs` - Polynomial commitment scheme utilities
- `ip.rs` - Inner product argument implementation
- `pairing_check.rs` - Optimized pairing operations for verification
- `proof.rs` - Proof data structures and serialization

### Key Data Flow

1. **Setup Phase**: Generate fake SRS for testing/development using `setup_fake_srs`
2. **Specialization**: Adapt SRS to specific number of proofs with `srs.specialize()`
3. **Aggregation**: Use `aggregate_proofs()` with prover SRS and transcript
4. **Verification**: Call `verify_aggregate_proof()` with verifier SRS and prepared verification key

### Dependencies
- Built on arkworks ecosystem (v0.5.0) for elliptic curves and cryptographic primitives
- Uses BLS12-381 curve for testing and examples
- Merlin transcripts for Fiat-Shamir transforms
- Rayon for parallel computation (feature-gated)

### Testing Pattern
Main aggregation test in `tests/aggregation.rs` demonstrates complete flow:
- Generate multiple Groth16 proofs
- Prepare verification keys and SRS
- Aggregate proofs and verify the result

The test creates benchmark circuits with configurable constraint counts for realistic testing scenarios.