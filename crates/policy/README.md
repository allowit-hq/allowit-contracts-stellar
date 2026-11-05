# Stellar policy bindings

This crate supplies native Soroban types, contract codecs, parameter reads, buffered state writes and abort semantics.
It compiles the exact shared rule source exported by Core. Rule algorithms and common policy types remain in Core.

Contracts use the workspace dependency alias `allowit`, so authored policy source retains its portable namespace.
The offchain rail uses Core's `std` types. SDK engine composes shared authoring and execution workflows.
The server retains trusted admission and publication authority.
See the [canonical responsibility diagram](https://github.com/allowit-hq/allowit-project/blob/main/wiki/allowit/architecture.md#dependency-direction).

The [manifest](Cargo.toml) records the native backend's source provenance.
The native binding and embedded portable rule source retain their `UNLICENSED` terms.
