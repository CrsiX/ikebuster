![Logo](./logo.svg)

# ikebuster

A simple utility to report insecure configurations on IKE.

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
