# Custom policy on the wallet kernel

A Custom wallet is the shared wallet kernel (`crates/policy-wallet`) with one compiled policy. The
owner writes and signs one policy source. The on-chain policy is derived from it, compiled into the
contract and run by the kernel on every agent operation. This page states what that compiled
policy may call, which figures the wallet keeps for it, and how the contract is built.

## Build rule

The contract `contracts/allowit-custom-policy` compiles two files:

| File | Content | Who writes it |
| --- | --- | --- |
| `policy/policy.rs` | The on-chain policy, compiled verbatim as a module | The host builder, or `scripts/build-custom-policy.sh POLICY.rs OUT_DIR [SOURCE.rs]` |
| `policy/source.rs` | The owner's full source, from which `policy.rs` is derived | The same builder, when the policy is derived. Without it the build treats `policy.rs` as the full source |

`build.rs` derives two constants:

- `SOURCE_HASH`: the SHA-256 of `policy/source.rs`, or of `policy/policy.rs` when there is no
  `source.rs`. The owner's policy signature binds this hash. The wallet stores it, and the
  constructor and every `execute` refuse a stored hash that differs from the compiled one.
- `FIGURES`: the cumulated figures that the compiled policy's checks read (see below).

The build refuses a `policy.rs` that contains `unsafe`, `include!`, `include_str!`,
`include_bytes!` or `#[path`: the policy is one safe file. Core's source gate
(`scripts/check-policy-bindings.py`) applies its own checks as well.

The owner's deployment signature names the code hash. The owner's client compares it with the
build of the reviewed sources, so a different build registered between upload and creation cannot
use the owner's signature.

## The policy's entry point

```rust
use allowit::prelude::*;
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;
    Ok(())
}
```

`execute` returns `Ok(())` to admit the operation. A returned error denies it: the transaction
fails with that `AllowitError` code. A panic, such as a missing param in `ctx.params[key]`, also
denies it.

The policy may read:

- the owner's params: `ctx.params[key]` and `allowit::param(ctx, key)`, up to `MAX_PARAMS` (32)
  keys with values within Core's bounds;
- the request facts: `ctx.request.operation`, `asset`, `recipient`, `amount`, `token_in`,
  `amount_in`, `token_out`, `min_out`, `now`, `expires_at`, `spent_units`, `gas_units`,
  `unpriced`;
- the agent's execution params: `allowit::arg(ctx, key)` and `ctx.request.args`, up to
  `MAX_ARGS` (16) keys;
- the canonical rules: `payment_limit`, `lifetime_spending_limit`, `daily_spending_limit`,
  `daily_volume_limit`, `call_limit`, `destinations`, `tokens`, `expires_at` and `operations`.

The wallet runs all four operations: `transfer`, `swap`, `deposit` and `redeem`. The policy
selects among them, for example with `allowit::operations`.

The policy cannot write state. A call of `allowit::set_state` makes the operation fail with
`UnsupportedOperation`: the wallet stores no free-form state.

## Figures

The wallet keeps only cumulated figures, and only those that a check reads. The canonical rules
read them:

| Figure | Read by | Stored in |
| --- | --- | --- |
| `spent`, `unpriced` | `lifetime_spending_limit` | `t`, persistent |
| `calls` | `call_limit` | `t`, persistent |
| `day_spent`, `day_unpriced` | `daily_spending_limit` | `d`, temporary |
| `day_total`, `day_unpriced` | `daily_volume_limit` | `d`, temporary |

`build.rs` finds the figures in the compiled `policy.rs`. It reads whole words and leaves out the
lines that start with `//`:

- each rule name above keeps its figure;
- any word that contains `state`, and the words `preflight`, `RULES`, `AllowitRule`,
  `AllowitStandardState` and `evaluate`, keep every figure.

A derived policy calls its rules by name and contains no state read, so it keeps exactly the
figures of its rules. A word in a trailing comment or a string literal can only add a figure.

`t` is created by the constructor and paid for 2,073,600 ledgers (the Mainnet minimum lifetime of a
persistent entry, about 120 days). Nothing extends it; after it lapses, the next operation restores
it with its values. `d` opens at the first operation after the last window ended and holds its own
end ledger, 17,279 ledgers later (the Mainnet minimum lifetime of a temporary entry, about one
day). The daily figures of the policy are the figures of that window, not of a UTC day. A window
whose end ledger has passed reads as zero, even if someone paid to keep the entry alive.

## Errors

A Custom policy's denial fails the call with the policy's own `AllowitError` code (101 and up), so
the caller learns which rule denied. Wallet errors keep their codes below 100: `InvalidParam` (2),
`InvalidState` (1), `Overflow` (11) and `UnsupportedOperation` (16).
