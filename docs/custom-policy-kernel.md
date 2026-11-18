# Custom policy on the wallet kernel

A Custom wallet is the shared wallet kernel (`crates/policy-wallet`) with one compiled policy. The
owner writes and signs one policy source. The on-chain policy is derived from it, compiled into the
contract and run by the kernel on every agent operation. This page states what that compiled
policy may call, which figures and state the wallet keeps for it, and how the contract is built.

## One source, two parts

The server evaluates the whole source before it signs. A contract cannot call a server function,
so the contract compiles the on-chain part: the statements that the chain can check by itself.
Core derives that part (`allowit_core::policy_source::derive`). It is a pure function of the source
bytes, so the server and the owner's client build the same code from the same source.

| Source | `policy/policy.rs` | `policy/source.rs` | Server signs |
| --- | --- | --- | --- |
| No server part: the on-chain part equals the source | The source | Absent | After the contract's recording simulation |
| A server part: a server function, owner text read with `as_str()`, or state that the server keeps | The on-chain part | The source | Only after its evaluator passed the whole source |

`policy::custom_parts` gives both parts in the rail. Every place that reads the source of a Custom
wallet uses it: the build hook, the installation binding, the read of the wallet's state entries,
the figures that the wallet keeps and the server's evaluation. A source with a server part is
server policy source; its on-chain part is portable source that names no server function.

## Build rule

The contract `contracts/allowit-custom-policy` compiles two files:

| File | Content | Who writes it |
| --- | --- | --- |
| `policy/policy.rs` | The on-chain policy, compiled verbatim as a module | The build hook (`provider/custom_build.rs`), which derives it from the owner's source, or `scripts/build-custom-policy.sh POLICY.rs OUT_DIR [SOURCE.rs]` |
| `policy/source.rs` | The owner's full source, from which `policy.rs` is derived | The same builder, when the on-chain part differs from the source. Without it the build treats `policy.rs` as the full source |

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

`build.rs` finds the figures in the compiled `policy.rs` (`state_keys::figures`, the scan that the
rail runs too). It reads whole words and leaves out the lines that start with `//`:

- each rule name above keeps its figure;
- a `get_state` read of a standard figure keeps that figure;
- any other word that contains `state`, such as `ctx.state`, and the words `preflight`, `RULES`,
  `AllowitRule`, `AllowitStandardState` and `evaluate`, keep every figure.

A derived policy calls its rules by name and reads its own state through `get_state`, so it keeps
exactly the figures of its rules. A word in a trailing comment or a string literal can only add a figure.

A rule that runs only on the server, such as a rule in a branch that depends on a server function,
is no part of `policy.rs`, so the wallet keeps no figure for it. The server's own accounting gives
that figure to the server's evaluation (`kept_figures`): the wallet's figures for the on-chain
part, the server's for the rest. So an execution of a wallet whose source has a server part needs
the server's accounting, as an execution of a Simple or Standard wallet does.

The two daily figures share one unpriced flag. When the wallet keeps one daily figure and the
server the other, an unpriced operation in either one's day marks the day: the wallet counts its
own window, and the server counts the UTC day.

`t` is created by the constructor and paid for 2,073,600 ledgers (the Mainnet minimum lifetime of a
persistent entry, about 120 days). Nothing extends it; after it lapses, the next operation restores
it with its values. The instance lives as long from its creation, and each call keeps it live: once
it has at most `TOTAL_LEDGERS - RENEWAL_LEDGERS` ledgers left (`RENEWAL_LEDGERS` is 720, about one
hour), the call renews it to `TOTAL_LEDGERS - 1`, so most calls renew nothing. A Custom wallet's code
is built from its policy and is its own: its creation renews the code to the same lifetime, and each
call keeps it live with the instance. The code of a Simple or Standard wallet is shared by every
wallet of its kind, and Allowit keeps it live. The rent is part of the call's network fee, which the
wallet repays as gas within its gas cap. Nothing restores a wallet whose instance or code lapsed. `d` opens at the first operation after the last window ended and holds its own
end ledger, 17,279 ledgers later (the Mainnet minimum lifetime of a temporary entry, about one
day). The daily figures of the policy are the figures of that window, not of a UTC day. A window
whose end ledger has passed reads as zero, even if someone paid to keep the entry alive.

## Policy state

A Custom policy can keep its own state when its checks need it. Generation prefers, in order: no
state; a figure that a canonical rule already keeps or that the request derives; then the
smallest packed state. The wallet itself still writes only the figures that the installed checks
read (`d`, `t`): no receipts and no lifetime paid ahead.

Each key has one keeper, which Core's derivation names (`Derived::state`):

| Keeper | When | Where the value lives |
| --- | --- | --- |
| The contract | Every statement that writes the key is in `policy.rs` | In the wallet, as stated below. The server reads it from the wallet when it evaluates the whole source |
| The server | A statement that writes the key depends on a server function, or only such statements read it | With the server. No statement of `policy.rs` names the key, and the wallet never stores it |

This rail neither reads nor stores a key of the server: a wallet's snapshot holds only the
contract's entries. The host's evaluator gives the server's values to the evaluation and keeps the
values that an admitted operation wrote, with that operation's settlement
(`policy::CustomParts::server_keys`).

The rest of this section is about the keys that the contract keeps: the keys of `policy.rs`.

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

A call in a comment or in a string literal is no call. The scan is
`contracts/allowit-custom-policy/state_keys.rs`; the rail's server evaluation runs the same file on
the on-chain part of the installed source, reads each declared entry with the same lifetimes and
evaluates the policy with the Custom post-flight, so the server decides with the state that the
wallet holds. A write of a key that neither the build declares nor the server keeps is refused.

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

### Bounds

| Bound | Value | Checked |
| --- | --- | --- |
| Entries per policy | 8 | At build |
| Packed bytes per value | 64 | At write: a larger value fails the operation with `InvalidState` |
| Bytes per wallet | 8 × (64 + 4) = 544 | Follows from the two bounds above |

### Who pays

The transaction that writes an entry pays for it: the server's sending account pays the fee, and
the wallet repays it as gas in the same transaction. The deployment creates each persistent entry,
empty, so the owner's deployment signature pays its minimum lifetime; a write then pays only for
the bytes that it changes. A daily entry is created by the first write of each window.

## Errors

A Custom policy's denial fails the call with the policy's own `AllowitError` code (101 and up), so
the caller learns which rule denied. Wallet errors keep their codes below 100: `InvalidParam` (2),
`InvalidState` (1), `Overflow` (11) and `UnsupportedOperation` (16).
