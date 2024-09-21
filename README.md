![Logo](./logo.svg)

# ikebuster

[![Crates.io License](https://img.shields.io/crates/l/MIT)](https://github.com/myOmikron/ikebuster/blob/main/LICENSE)
[![Crates.io Version](https://img.shields.io/crates/v/ikebuster)](https://crates.io/crates/ikebuster)
[![crates io downloads](https://img.shields.io/crates/d/ikebuster)](https://crates.io/crates/ikebuster)
[![docs.rs](https://img.shields.io/docsrs/ikebuster)](https://docs.rs/ikebuster/latest/ikebuster/)
[![ci](https://img.shields.io/github/actions/workflow/status/myOmikron/ikebuster/linux.yml?label=Backend)](https://github.com/myOmikron/ikebuster/actions/workflows/linux.yml)

A simple utility to report insecure configurations on IKE.

## Installation

```bash
cargo install ikebuster -F bin
```

## Usage

By default, `ikebuster` will try to bruteforce all combinations of:

- encryption algorithm
- hash algorithm
- authentication method
- group description

![img.png](./img.png)

## Honorable mentions

This project originated from [here](https://github.com/trufflebee33/bike-scan),
but I had to rewrite too many of the parts in there to be feasibly via PRs.
