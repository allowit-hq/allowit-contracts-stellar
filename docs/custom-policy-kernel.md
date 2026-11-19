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
the figures that the wallet keeps and the server's evaluation. Core's derivation decides which
statements only the server runs; this rail keeps no list of server functions of its own. A source
with a server part is server policy source, which the server checks against the registry of the
host calls that it links; its on-chain part is portable source that names no server function.

## Build rule

The contract `contracts/allowit-custom-policy` builds from four files, its build inputs. One function
writes all of them from the owner's source, `policy::custom_build_inputs`, which the build hook
(`provider/custom_build.rs`) and `scripts/build-custom-policy.sh SOURCE.rs OUT_DIR` (through
`allowit-stellar-admin custom-build-inputs`) both use. Everything in them comes from Core's
derivation; the build reads no policy decision from the source itself.

| File | Content |
| --- | --- |
| `policy/policy.rs` | The on-chain policy, compiled verbatim as a module |
| `policy/policy.figures` | The keys of the figures that Core names for the on-chain policy (`Derived::figures`), one per line |
| `policy/policy.state` | The state keys that Core gives the chain (`Derived::state`), one per line with `daily` or `lasting` |
| `policy/source.rs` | The owner's full source, when the on-chain part differs from it. Without it the build treats `policy.rs` as the full source |

`build.rs` derives three constants:

- `SOURCE_HASH`: the SHA-256 of `policy/source.rs`, or of `policy/policy.rs` when there is no
  `source.rs`. The owner's policy signature binds this hash. The wallet stores it, and the
  constructor and every `execute` refuse a stored hash that differs from the compiled one.
- `FIGURES`: the wallet entries of the figures in `policy/policy.figures` (see below).
- `STATE`: the policy's own state entries, one for each key in `policy/policy.state` (see
  [Policy state](#policy-state)).

The build refuses a `policy.rs` that contains `unsafe`, `include!`, `include_str!`,
`include_bytes!` or `#[path`, comments included: the policy is one safe file
(`state_keys::one_safe_file`, which the rail's `check` runs too). Core's source gate
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

Core's derivation names the figures of the on-chain policy (`Derived::figures`): those of the kept
canonical rules, and each standard figure that a kept statement reads with `get_state`. The build
reads their keys from `policy/policy.figures`, and `state_keys::packed` gives each key its entry:
`spent` and `unpriced` live in `t` with `SPENT`, `calls` in `t` with `CALLS`, `day_spent` and
`day_total` in `d`, and `day_unpriced` in `d` beside either daily figure. A daily flag without a
daily figure opens `d` with `day_spent`. The rail reads the same keys from Core
(`policy::CustomParts::figures`); it finds no figure in the source itself.

A rule that runs only on the server, such as a rule in a branch that depends on a server function,
is no part of `policy.rs`, so the wallet keeps no figure for it. The server's own accounting gives
that figure to the server's evaluation: the wallet gives exactly the figures that Core names for the
on-chain part, and the server's accounting the rest. An execution needs the server's
accounting whenever the wallet gives fewer than all six standard figures
(`wallet_gives_every_figure`), as an execution of a Simple or Standard wallet does. The
two daily figures share one unpriced flag: the wallet gives it when Core names it for the on-chain
part, and the server's accounting otherwise.

`t` is created by the constructor and paid for 2,073,600 ledgers (the Mainnet minimum lifetime of a
persistent entry, about 120 days). Nothing extends it; after it lapses, the next operation restores
it with its values. The instance lives as long from its creation, and each call keeps it live: once
it has at most `TOTAL_LEDGERS - RENEWAL_LEDGERS` ledgers left (`RENEWAL_LEDGERS` is 720, about one
hour), the call renews it to `TOTAL_LEDGERS - 1`, so most calls renew nothing. A Custom wallet's code
is built from its policy and is its own: its creation renews the code to the same lifetime, and each
call keeps it live with the instance. The code of a Simple or Standard wallet is shared by every
wallet of its kind, and Allowit keeps it live. The rent is part of the call's network fee, which the
wallet repays as gas within its gas cap. Nothing restores a wallet whose instance or code lapsed. `d` opens at the first operation after the last window ended that changes a daily figure that the wallet keeps (an operation that changes only another figure, such as a deposit in a wallet that keeps only the daily spending figures, opens nothing) and holds its own
end ledger, 17,279 ledgers later (the Mainnet minimum lifetime of a temporary entry, about one
day). The daily figures of the policy are the figures of that window, not of a UTC day. A window
whose end ledger has passed reads as zero, even if someone paid to keep the entry alive. The
contract and the rail's host take the window from Core's portable rule (`allowit::daily_window_end`,
`allowit::daily_window_open`; the end ledger is the window's last ledger), as for a daily policy key.

## Policy state

A Custom policy can keep its own state when its checks need it. Generation prefers, in order: no
state; a figure that a canonical rule already keeps or that the request derives; then the
smallest packed state. The wallet itself still writes only the figures that the installed checks
read (`d`, `t`): no receipts and no lifetime paid ahead.

Each key has one keeper, which Core's derivation names (`Derived::state`):

| Keeper | When | Where the value lives |
| --- | --- | --- |
| The contract | A statement that uses the key stays in `policy.rs`, and no statement that writes it leaves | In the wallet, as stated below. The server reads it from the wallet when it evaluates the whole source |
| The server | Any other key: a statement that writes it leaves, or every statement that uses it leaves | With the server. No statement of `policy.rs` names the key, and the wallet never stores it |

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

Core's derivation names each key of the policy's own state and its keeper, and it refuses a key
that is not a string literal of 1 to 32 ASCII letters, digits or `_`, and a write of a standard
figure. The build reads the keys that Core gives the chain from `policy/policy.state`, and
`state_keys::entries` applies Stellar's storage to them:

| Rule | Build result |
| --- | --- |
| The key is a `Symbol`: 1 to 32 ASCII letters, digits or `_` | The key gets its storage key |
| The key names a standard figure | The build stops |
| More than 8 distinct keys | The build stops |
| Two keys whose storage keys are equal | The build stops; rename one |

The rail's server evaluation reads the same Core output through the same file
(`contracts/allowit-custom-policy/state_keys.rs`), reads each entry with the same lifetimes and
evaluates the policy with the Custom post-flight, so the server decides with the state that the
wallet holds. A write of a key that neither the contract nor the server keeps is refused.

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
| `day_…` | Temporary | One daily window: 17,280 ledgers (the Mainnet minimum for a temporary entry, about one day) from the write that opens it. Writes in an open window keep its end. After the end ledger the entry reads as absent, even if someone paid to keep it alive; the next write opens a new window. The contract keeps the window by Core's portable rule (`allowit::daily_window_end`, `allowit::daily_window_open`), which the server applies to the keys that it keeps: the end ledger is the window's last ledger, inclusive |
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
