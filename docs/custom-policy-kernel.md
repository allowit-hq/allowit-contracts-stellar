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

`build.rs` derives three constants:

- `SOURCE_HASH`: the SHA-256 of `policy/source.rs`, or of `policy/policy.rs` when there is no
  `source.rs`. The owner's policy signature binds this hash. The wallet stores it, and the
  constructor and every `execute` refuse a stored hash that differs from the compiled one.
- `FIGURES`: the cumulated figures that the compiled policy's checks read (see below).
- `STATE`: the policy's own state entries, one for each key of its `get_state` and `set_state`
  calls (see [Policy state](#policy-state)).

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

- its own state: `allowit::get_state(ctx, "key")` and `allowit::set_state(ctx, "key", value)`
  (see [Policy state](#policy-state)).

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
- a `get_state` read of a standard figure keeps that figure;
- any other word that contains `state`, such as `ctx.state`, and the words `preflight`, `RULES`,
  `AllowitRule`, `AllowitStandardState` and `evaluate`, keep every figure.

A derived policy calls its rules by name and reads its own state through `get_state`, so it keeps
exactly the figures of its rules. A word in a trailing comment or a string literal can only add a figure.

`t` is created by the constructor and paid for 2,073,600 ledgers (the Mainnet minimum lifetime of a
persistent entry, about 120 days). Nothing extends it; after it lapses, the next operation restores
it with its values. `d` opens at the first operation after the last window ended and holds its own
end ledger, 17,279 ledgers later (the Mainnet minimum lifetime of a temporary entry, about one
day). The daily figures of the policy are the figures of that window, not of a UTC day. A window
whose end ledger has passed reads as zero, even if someone paid to keep the entry alive.

## Policy state

A Custom policy can keep its own state when its checks need it. Generation prefers, in order: no
state; a figure that a canonical rule already keeps or that the request derives; then the
smallest packed state. The wallet itself still writes only the figures that the installed checks
read (`d`, `t`): no receipts and no lifetime paid ahead.

### Calls

```rust
use allowit::prelude::*;
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    let payments: u64 = allowit::get_state(ctx, "day_payments")?.unwrap_or(0);
    if payments >= 2 {
        return Err(AllowitError::CallLimitExceeded);
    }
    allowit::set_state(ctx, "day_payments", payments + 1)?;
    Ok(())
}
```

- `allowit::get_state::<V>(ctx, "key")` returns the value that the last admitted operation wrote,
  or `None` when the entry holds none or its daily window ended.
- `allowit::set_state(ctx, "key", value)` writes when the operation is admitted. A denied
  operation writes nothing: the transaction fails and the ledger keeps no change.
- A value is a policy value: `Int`, `Bool`, `Str`, `Addr` or a `List` of them.
- Reading a standard figure through `get_state` (`spent`, `unpriced`, `calls`, `day_spent`,
  `day_total`, `day_unpriced`) keeps that figure. A policy never writes one.

### Keys

The build reads every `get_state` and `set_state` call of `policy.rs`:

| Rule | Build result |
| --- | --- |
| The key is a string literal of 1 to 32 ASCII letters, digits or `_` | The key is declared |
| The key is anything else: a variable, a format, a call | The build stops: the wallet must know each key before it runs |
| The key names a standard figure in `set_state` | The build stops |
| More than 8 distinct keys | The build stops |
| Two keys whose storage keys are equal | The build stops; rename one |

The wallet never stores the key name. The storage key of an entry is a `u32`: the first four bytes
of the SHA-256 of the name, big-endian. The same name keeps the same storage key across source
revisions. The wallet's own entries use `Symbol` keys (`c`, `d`, `t`), so no policy key can reach
them.

### Values

An entry's value is one packed policy value, the encoding of the instance's params:

| Value | Bytes |
| --- | --- |
| `Bool` | 1: the type |
| `Int` | 1 + 1 to 19: the type, then a zigzag LEB128 integer (a counter below 64 takes 1) |
| `Str` | 1 + length (LEB128) + UTF-8 bytes |
| `Addr` | 1 + 32: the kind (account or contract), then the key |
| `List` | 1 + count (LEB128) + each item |

A daily entry holds its window's end ledger (4 bytes, big-endian) before the value. A persistent
entry that holds no bytes holds no value.

### Lifetimes

The name of a key states its lifetime:

| Key | Storage | Lifetime |
| --- | --- | --- |
| `day_…` | Temporary | One daily window: 17,280 ledgers (the Mainnet minimum for a temporary entry, about one day) from the write that opens it. Writes in an open window keep its end. After the end ledger the entry reads as absent, even if someone paid to keep it alive; the next write opens a new window |
| Any other | Persistent | 2,073,600 ledgers (the Mainnet minimum for a persistent entry, about 120 days) from its creation |

No read extends an entry, and no write extends it later. A persistent entry that has lapsed is
restored with its value by the next operation that uses it.

### Caps

| Cap | Value | Checked |
| --- | --- | --- |
| Entries per policy | 8 | At build |
| Packed bytes per value | 64 | At write: a larger value fails the operation with `InvalidState` |
| Bytes per wallet | 8 × (64 + 4) = 544 | Follows from the two caps |

### Who pays

The transaction that writes an entry pays for it: the server's sending account pays the fee, and
the wallet repays it as gas in the same transaction. The deployment creates each persistent entry,
empty, so the owner's deployment signature pays its minimum lifetime; a write then pays only for
the bytes that it changes. A daily entry is created by the first write of each window.

## Errors

A Custom policy's denial fails the call with the policy's own `AllowitError` code (101 and up), so
the caller learns which rule denied. Wallet errors keep their codes below 100: `InvalidParam` (2),
`InvalidState` (1), `Overflow` (11) and `UnsupportedOperation` (16).
