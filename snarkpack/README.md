![example workflow](https://github.com/nikkolasg/snarkpack/actions/workflows/check.yml/badge.svg)


# Snarpack-onchain

This is a port in the arkwork framework of the original [implementation in bellperson](https://github.com/filecoin-project/bellperson/tree/master/src/groth16/aggregate) of [Snarkpack](https://eprint.iacr.org/2021/529.pdf). Note both works are derived from the original arkwork implementation of the inner pairing product argument (IPP) [paper](https://eprint.iacr.org/2019/1177.pdf).

## Dependency

Add the following to your `Cargo.toml`
```
snarkpack = { git = "https://github.com/PostSiliconDev/snarpack-onchain" }
```

## Usage

See the straightforward example in [`tests/aggregation.rs`](./tests/aggregation.rs).

## Contribution

There are plenty of issues to tackle so you're more than welcome to contribute.


