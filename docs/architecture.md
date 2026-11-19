# Policy wallet engines

This page explains how an Allowit policy wallet is put together on Stellar: the three wallet
implementations, the portable policy source, the canonical rules, the configuration the owner signs,
what happens on every operation, and the operations only the owner can perform. Read the
[README](../README.md) first for the short version and the build steps.

A policy wallet keeps one immutable underlying Stellar Asset Contract (SAC). The owner selects the
wallet code, the agent, an independent server signer and the params. Delegated operations need both
the agent and the server. The owner needs nobody. The server signer is a plain co-signer; it is not
a shared checker contract or that contract's parent administrator. Shared checkers have no custody.

`AllowitSimplePolicyEngine` relies on the agent's and the server's signatures and runs no rule onchain. `AllowitCommonPolicyEngine` is
the standard implementation for an owner-approved initial preflight prefix. `AllowitCustomPolicy`
compiles a complete authored policy into its contract. All three are built from the same custody
core in `crates/policy-wallet`. The `policy_wallet!` macro attaches the complete owner and
delegated-execution interface to an `AllowitPolicy` implementation, so Simple, Common and Custom
expose identical entrypoints and differ only in their `AllowitPolicy` logic.

## Public names

Every public type that authored policy, SDK integrations or contract specs name carries the
`Allowit` prefix: `AllowitContext`, `AllowitEnv`, `AllowitParams`, `AllowitArgs`, `AllowitValue`, `AllowitRule`,
`AllowitError`, `AllowitExecutionRequest`, `AllowitPolicyUpdate`, `AllowitState` and the others. The contract
structs and their generated clients carry it too: `AllowitSimplePolicyEngine`,
`AllowitCommonPolicyEngine`, `AllowitCustomPolicy`, `AllowitEngine`, `AllowitEngineParent`, and
`AllowitEngineClient` and the other `*Client` types. Namespaced items keep their short names, such
as `allowit::Result`, `allowit::lifetime_spending_limit` and `allowit::PAYMENT_LIMIT`.

Encodings carry struct field names and enum variant symbols, not type names. The prefix therefore
leaves signed encodings and the stored layout unchanged. Type names are in the Wasm contract spec,
so rebuilt Wasm has new module hashes.

## One portable policy source

Policy source is ordinary synchronous Rust against the portable `allowit` package from Allowit core. The offchain server and
`AllowitCustomPolicy` compile the file verbatim:

```rust
use allowit::prelude::*;
/// Let my agent pay our invoices. Limit every payment, limit its total spending and pay only vendors
/// I approve.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Limit every payment"
    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;
    // "limit its total spending"
    allowit::lifetime_spending_limit(ctx, &ctx.params[allowit::LIFETIME_SPENDING_LIMIT])?;
    // "pay only vendors I approve"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    Ok(())
}
```

`execute` takes only the context. Each rule call keeps the form
`allowit::<rule>(ctx, &ctx.params[<key>])?`: the policy reads the param by key and the rule
decodes the value. A rule may read any key, such as a custom `vendor_limit`.

The function doc comment keeps the owner's original policy prompt. Each inline comment quotes the
prompt clause that the next call implements.

`AllowitCustomPolicy` and the offchain server call `execute` directly. Only an error that the
policy returns, usually with `?`, denies. A policy may catch a rule error, read it, record it in
its own state and continue. The standard contract runs only its leading canonical calls, supplied
by the owner as `rules`, and skips absent params. The admin binary `allowit-stellar-admin` derives `rules` from the source file. `scripts/policy_source.py` lexes
Rust comments, including nested block comments, and literals first, so they cannot add or hide calls.

Policy source names `allowit` only as the path root `allowit::`. Any other occurrence of the
identifier, such as `mod allowit`, `use core as allowit`, `extern crate`, `macro_rules! allowit` or
`fn allowit`, could rebind the crate that prefix calls name, so the tooling rejects it.

`AllowitCustomPolicy` compiles the file as a module with `#[path]`, and `SOURCE_HASH` covers only that file.
The file must therefore be the whole policy: it must not use `include!`, `include_str!`,
`include_bytes!`, `env!`, `option_env!`, `#[path]`, `cfg_attr` or an out-of-line `mod name;`. The
names of those macros may appear only as the bare context field read `ctx.env`: after a single `.`
and not followed by `.`, `(` or `!`. So `ctx.env.storage()` and a value's Soroban `env()` method
reject. The field is read-only: an assignment such as `c.env = ...` and a `&mut c.env` borrow,
which `core::mem::replace` could use, reject, and so does the name `AllowitEnv`. The host
portability test includes the file, so it must not use inner attributes or inner doc comments.

The same file must also behave the same offchain and onchain, where `usize` is 32 and 64 bits
wide, backend lists differ and code addresses differ. `scripts/policy_source.py` therefore admits
code through an allowlist, not a list of known hazards. Every identifier must be one of:

- an allowed keyword: `fn`, `const`, `let`, `mut`, `ref`, `pub`, `use`, `if`, `else`, `match`,
  `for`, `in`, `while`, `loop`, `break`, `continue`, `return`, `true` and `false`;
- a listed field after `.`: `env`, `params`, `request` and the request fields, including `args`;
- a listed method after `.`: comparisons, `clone`, and the `Option`, `Result`, fixed-width integer,
  `bool` and `Ordering` methods that take and return no pointer-width value, such as `is_some`,
  `unwrap_or`, `checked_add`, `saturating_sub`, `min` and `max`, and `contains` on `params` and
  `args` only;
- a listed path: the `allowit` rules, `param`, `arg`, `get_state`, `set_state`, the canonical key
  constants, the server-only functions and their request types, the `AllowitOperation`,
  `AllowitError`, `AllowitRule` and `AllowitValue` variants, `Option` and `Result` variants,
  `MAX`, `MIN`, `from` and `try_from` of the fixed-width integers, and `core::cmp::{min, max,
  Ordering}`;
- a listed type (`AllowitContext`, `AllowitError`, `AllowitOperation`, `AllowitRequest`,
  `AllowitRule`, `AllowitValue`, `Address`, `Result`, `String`, `Vec`, `Option`, `DAY` and the
  variants `Some`, `None`, `Ok`, `Err`), a canonical key constant, a server request type, a
  constant the file defines or an `allowit` type it imports;
- a field name of a server request struct expression, such as `query:`;
- a lowercase name the file declares: a function or constant name, a function parameter, or a
  `let`, `for` or match-arm binding;
- a fixed-width primitive type: the `i` and `u` integers of 8 to 128 bits, `bool`, `char` and `str`.

`use` admits only `use allowit::prelude::*;` and imports of `allowit` types. The allowlist
therefore rejects, among others: `usize`, `isize` and float types and literals; casts (`as`);
closures and function values, including function pointer types and the `Some`, `Ok`, `Err` and
`AllowitValue` constructors when not called, because they compare by code address; the prelude functions
`size_of`, `size_of_val`, `align_of`, `align_of_val` and `drop`, because type sizes differ
between the backends (a host `Address` is a 24-byte string, onchain an 8-byte handle); raw pointers; qualified (`<T>::`) and generic type paths; modules, traits, impls, structs,
enums, statics, `unsafe`, `extern` and paths into the including crate (`crate`, `super`, `self`);
`ctx.state`, which policy reads only through `allowit::get_state`; and every `core` API outside the
list, such as `NonZeroUsize`, `ilog2`, `count_ones`, `len` or `Utf8Error::valid_up_to`. A local
function name may only be called. Non-ASCII identifiers reject.

Beside the allowlist, the tooling rejects:

- Every macro other than `assert!`, `assert_eq!`, `assert_ne!`, `panic!`, `matches!` and
  `unreachable!`. `core::arch::global_asm!` is safe code without `unsafe` that emits native code.
  Linked into the offchain evaluator, it could run before `main`, while the Soroban compile rejects it.
- A macro message that is not one string literal. The message is optional; the format arguments
  after it are ordinary checked code.
- A macro message whose value holds a brace other than the placeholders `{}` and `{:?}` and the
  escapes `{{` and `}}`. The allowed macros read their message as a format string, and a width or
  precision count, such as `{:1$}`, `{:.*}` or `{:a$}`, is a `usize`: it makes an unsuffixed
  binding a `usize` without naming the type. The check decodes escapes first, so `\x7b` and
  `\u{7b}` cannot spell a brace. Other string literals are data, such as a JSON body, and can hold
  any brace.
- Every attribute other than `allow`, `expect`, `warn`, `deny`, `forbid`, `inline`, `cold` and
  `must_use`, for example `track_caller`, `doc` or `cfg`.
- The map inside `params` and `args`, such as `ctx.params.0`, and the names `AllowitParams` and
  `AllowitArgs`. Soroban maps key by `Symbol` and decode values on read, and heap maps have other
  methods, so params are read only by key, `ctx.params[key]`, and args only with `allowit::arg`.
  The host backend keeps both maps private, so the std-only compile also rejects `.0` on a clone or
  a binding, such as `ctx.params.clone().0`. Indexing passes only on the field access `.params`,
  whose type indexes only by key text; every other index, such as `list[0]` or
  `ctx.request.args["k"]`, rejects. `contains` passes only on the field access `.params` or
  `.args`, and the file may not declare `params` or `args` as a binding or function name: on a
  list, `contains` is a Soroban method that the host list lacks. A struct expression or pattern
  of `AllowitContext`, which would reach `state`, and struct update syntax `..` reject. The host
  list offers authored code no methods (the server reads it with `as_slice`), and Soroban and heap strings have different methods with the same names,
  for example `len` returns `u32` onchain and `usize` on the host, so a list from
  `AllowitValue::List`, and a `Vec` or `String` that `param` or `arg` returns, admits only
  comparison, `clone`, matching and `for`.
- Indexing (`x[i]`), whose index Rust infers as `usize`.

`scripts/policy_source.py` implements these checks; `check-policy-bindings.py` and the owner packet
tooling of every tier apply them.

These checks are lexical, so they cannot see types. Every owner source therefore also passes two
compiles:

- The std-only compile builds the file as a module of a `no_std` crate whose only dependency is
  `allowit` with only the `std` feature, as the offchain server uses it, with overflow checks on
  and `-F unpredictable_function_pointer_comparisons`: a function pointer `==` that the lexical
  checks miss fails there, because its result changes with the optimization level. The lint is
  forbidden, so a source `#[allow]`, `#[expect]` or `#[warn]` on it also fails. A path into `soroban_sdk`, a wallet crate or any other crate fails there. So does a call to a
  Soroban `Env` or `Address` method, also through an alias such as `let e = &ctx.env;`, an
  address comparison with `<`, `min`, `max`, `sort` or `binary_search`, and a `std` prelude item
  such as `vec!`. On the host, `Address` holds the text that its rail supplies, a StrKey on Stellar,
  and compares only for equality: Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while text would
  sort by StrKey. The host `Vec` iterates a borrowed list by clone, as the Soroban `Vec` does, so
  `for item in items` binds an owned item on both backends, also when `items` borrows from
  `ctx.params[key]`, and a dereference `*item` fails both compiles. It has no slice `Deref`.
  `scripts/policy_source.py` runs this compile in `check-policy-bindings.py`, and
  so in `scripts/build-contracts.sh`. `allowit-stellar-admin` and `scripts/contract_admin.py` run the
  same compile for the owner packets of every tier. These tools need `rustc` (from `RUSTC` or `PATH`). The portability test below and the
  `policy` job of `.github/workflows/contracts.yml` also compile `scripts/policy-smoke.rs`, which
  includes the branch sources, the same way.
- The Soroban compile builds the file into `AllowitCustomPolicy`. A host-only item, such as
  `Address::new`, fails there. `scripts/build-contracts.sh` runs it for
  the branch source. Build the reviewed custom Wasm from the owner source before deployment.

The allowlist is lexical: a name passes by spelling. A listed method name therefore also passes on
an unlisted receiver type. No listed path, type or method takes or returns a `usize`, slice,
iterator or pointer on a type that portable code can produce. A name is not the only way to reach a
`usize`: Rust also infers one from a format width or precision count, which the placeholder check
above rejects, and from an index, which rejects too. Extend the allowlist, the macros and the
placeholders only with forms that keep this property.

Integer overflow must behave the same: it panics, so the operation denies. The contract release
profile sets `overflow-checks = true`. The offchain server must build with `overflow-checks = true`
in every profile that evaluates policy, because Cargo's default release profile wraps on overflow.
The std-only compile, the smoke and the portability test pass `-Coverflow-checks=on` explicitly.

Execution must be bounded the same way. Onchain, the Soroban budget stops a policy that loops or
recurses without end, and the operation denies. A host process has no such budget: `loop {}` never
returns, and deep recursion overflows the stack, which aborts the whole process because Rust
cannot catch a stack overflow. For Simple and Common wallets, the host run is the only evaluation
of the full policy. The offchain server must therefore evaluate each policy in an isolated worker
process with CPU-time, wall-clock, stack and memory limits. A timeout, crash, abort or panic of the
worker counts as a denial. `allowit::evaluate` catches a policy panic in process with
`catch_unwind`, which needs `panic = "unwind"`; with `panic = "abort"` the process boundary turns
the panic into a denial. One owner's policy must not be able to stop or slow evaluations for other
wallets.

`allowit` has two backends that share one rule implementation. Feature `soroban` (default) uses
Soroban `Address`, `Vec`, `Map`, `Env` and contract types. Feature `std` uses heap strings, maps
and lists for the host evaluator; addresses are unordered rail-supplied texts and the environment is
a host `AllowitEnv`, which buffers the policy's state writes. The selected backend backs the crate root that authored policy names. The offchain
server depends on `allowit = { default-features = false, features = ["std"] }` and builds with
`overflow-checks = true`. Enabling both backends is a compile error, so a server cannot silently
unify `soroban` through another crate.

The portability test, `crates/policy-wallet/src/portability_tests.rs`, runs one shared vector set,
`scripts/policy-vectors.rs`, through four targets:

1. The host backend: the std-only compile of `scripts/policy-smoke.rs` prints its outcomes.
2. `AllowitCustomPolicy`: the Soroban backend of the same sources must give identical pass values,
   errors and post-flight state. Each Soroban step runs in its own contract frame, so an unset
   `ctx.params[key]` reports its `MissingParam` abort as the host reports its caught panic. The
   real custom Wasm must then return the mapped policy result, or the abort's own error code.
   A fixture Wasm built with the `test-catching` feature compiles `src/catching_policy.rs`
   instead. That policy catches a daily spending limit error, counts it in its own state key and
   continues, at most twice. When the agent's args name an `invoice`, it also limits the payment
   with the custom `invoice_limit` param. The wallet keeps that declared state key, as the
   server's Custom evaluation does.
3. `AllowitCommonPolicyEngine`: the real standard Wasm, bound to the sample policy's prefix, must
   return the mapped first prefix preflight error. It skips absent params.
4. `AllowitSimplePolicyEngine`: the real simple Wasm runs no rules.

Each vector holds the current state before the operation. The test seeds each Wasm with the
vector's params and figures, runs a transfer signed by the agent and the server, and checks that
each success stores exactly the figures of the host's post-flight that the wallet keeps. A vector
whose state no wallet stores (a policy key, a backward day or a total beyond the width of `t`) runs
on the two backends only, as do a deposit, swap or redeem, a negative limit, an invalid
`operations` value or more than 16 args. Kernel violations (another asset, payment to the wallet,
request expiry, stale version, a spent authorization and pause) reject with the same kernel error
in every contract.

`scripts/build-contracts.sh` builds in the Cargo target directory, so a shared target directory
reuses compiled dependencies across worktrees. The tests read every Wasm from `./target`, so the
script copies the deployable Wasm to `target/wasm32v1-none/release` and the test-feature fixtures
(`engine_deny.wasm` and `custom_catching.wasm`) to `target/test-fixtures`. The fixtures build in
their own target directory, so the deployable release paths never hold a test artifact. A lock
directory in the Cargo target directory runs one build at a time per target directory. The mainnet
tooling rejects any artifact whose hash matches a test fixture.

Portable authored code beyond canonical calls uses typed scalar fields, enum comparisons such as
`ctx.request.operation == AllowitOperation::deposit`, matches on `AllowitValue`, and its own
state keys. The host list offers authored code no methods and `String::len` returns `u32` onchain and `usize` on
the host, so the tooling admits no list or text method.

`AllowitContext` is the complete rule input. It is plain data without methods. The wallet or server
computes it:

| Field | Content |
| --- | --- |
| `env` | Backend environment: the contract's Soroban `Env` onchain, an `AllowitEnv` on the host |
| `params` | The owner's constructor params, key => `AllowitValue`. An absent key is unset |
| `state` | Current policy state before this operation: one free-form map of standard and policy-defined keys |
| `request` | Typed general `AllowitOperation` (`transfer`, `swap`, `deposit`, `redeem` or `custom`), immutable asset, recipient (payee, vault or router), amount, `token_in` and `amount_in` that leave the wallet, `token_out` and `min_out` that it receives back, `now`, `expires_at`, `spent_units` and `gas_units` from the validated expense bounds, or `unpriced`, and the agent's `args` |

Params, state and args share one value type, `AllowitValue`: `Int(i128)`, `Bool(bool)`,
`Str(String)`, `Addr(Address)` and `List(Vec<AllowitValue>)`. Onchain a map is
`Map<Symbol, AllowitValue>`, on the host `BTreeMap<String, AllowitValue>`. `params` is
`AllowitParams`. Policy reads a param by key, `ctx.params[allowit::DESTINATIONS]` or
`ctx.params["destinations"]`, which returns `&AllowitValue` on both backends. A Soroban map decodes
a value on every read, so the Soroban `AllowitParams::new` decodes the at most 32 entries once per
run, and indexing returns a reference to the decoded value. Indexing an unset key panics with
`MissingParam`; see [Panics](#panics). `ctx.params.contains(key)` tells whether the owner set a
key. `request.args` is `AllowitArgs`, the contract type of the agent's map, read with
`allowit::arg` and `ctx.request.args.contains(key)`. Both host maps are private; the server
converts with `From`. A key that no map can hold, such as one with a space, is unset on both
backends.

Rules are checks: `allowit::<rule>(ctx, &AllowitValue) -> allowit::Result<T>`. Each decodes the
value, then returns only its passing constraint, or an `allowit::AllowitError`. A value of the
wrong type or range is `InvalidParam`. Policy code reads the param unguarded, so an unset param
stops the run. A rule error that the policy catches denies nothing: the policy decides. Custom
keys reach policy as `&ctx.params["vendor_limit"]` or as a typed read
`let limit: i128 = allowit::param(ctx, "vendor_limit");`, and agent args as
`let amount: i128 = allowit::arg(ctx, "amount");`. A typed read returns the type of its binding:
`i128`, `u64`, `u32`, `bool`, `Address`, `String`, `Vec<AllowitValue>`, `Vec<Address>` or
`AllowitValue`. It panics when the key is unset or the value has another type or range; see
[Panics](#panics).

The owner sets params at install and changes them with `deploy_policy`, without code redeployment.
The canonical keys are `allowit::PAYMENT_LIMIT`, `LIFETIME_SPENDING_LIMIT`, `DAILY_SPENDING_LIMIT`, `DAILY_VOLUME_LIMIT`,
`CALL_LIMIT`, `DESTINATIONS`, `TOKENS`, `EXPIRES_AT` and `OPERATIONS`, each the name of its rule.
`allowit::check_params` checks every owner write. Simple and Common admit only the canonical keys,
each with the type its rule decodes: a nonnegative `Int` limit, an `Int` in the `u64` range for
`call_limit` and `expires_at`, a `List` of `Addr` for `destinations` and `tokens`, and `Str` `*` or a
`List` of `Str` op names for `operations`. Custom admits up to 32 keys, whose meaning its policy
defines. Every value holds at most 64 nested values, and every text at most 256 bytes. Nothing
checks that a rule reads its own key.

Params, args and state also have byte budgets: `MAX_PARAM_BYTES`, `MAX_ARG_BYTES` and
`MAX_STATE_BYTES`, 16 KiB each. Both backends count a map's encoded size the same way: 40 bytes per
key, 80 per value and each text padded to four bytes. This count is at least the XDR size. The
wallet stores params and policy state in its one instance entry, so the two budgets keep that
entry far below the network's contract data entry limit, 64 KiB in current settings. Full
allowlists fit beside every other canonical param and 28 `operations` entries of the longest form;
a larger standard map is `InvalidParam`.

The agent supplies execution params per call in `AllowitExecutionRequest.args`, at most 16 keys
with the same key and value bounds. An empty key, which a Soroban `Symbol` can hold, is
`InvalidParam` in params and args on both backends. The agent and server authorize the whole request, so a changed arg
fails authorization. The wallet passes them to policy as `ctx.request.args` and never stores them.
Canonical rules and the standard contract ignore them; Custom and offchain policy read them with
`allowit::arg(ctx, "key")` and test one with `ctx.request.args.contains("key")`.

The state map holds the standard keys `spent`, `day_spent`, `day_total`, `calls`, `day`,
`unpriced` and `day_unpriced`, and any keys the policy defines, at most `allowit::MAX_STATE_KEYS`
(39) keys and `MAX_STATE_BYTES` in all: the seven standard keys and 32 policy keys. `AllowitStandardState` decodes the
standard keys in one place; an absent key is zero or false, and a value of another type or range,
such as a negative `calls`, is `InvalidState`. Policy code reads a key with
`allowit::get_state::<V>(ctx, key)`, which sees the state before this operation and decodes the
`AllowitValue` as `V`: `i128`, `u64`, `bool`, `Address` or `AllowitValue`. It records a write with
`allowit::set_state(ctx, key, value)`, where the value converts into an `AllowitValue` within the
value bounds; a key is 1 to 32 ASCII letters, digits or underscores. Writes are held in the
environment: in contract temporary storage onchain and in `AllowitEnv` on the host. `ctx` stays
plain data.

`allowit::post_flight(ctx, tier)` computes the state after an approved operation. The wallet and
the server run the same function. It rolls the UTC day over, adds one call, adds `spent_units` to
`spent` and `day_spent`, adds the amount and `gas_units` to `day_total`, and marks `unpriced` and
`day_unpriced` for a request without expense bounds. It then applies the policy's writes, which may
replace a standard key: owner-signed code is trusted, and no key is reserved. A merged state whose
standard keys later operations could not decode, such as `calls` written as a `bool`, a negative
`spent` or a later `day`, is `InvalidState`. So is a merged state with `calls` at `u64::MAX`, or
with `spent`, `day_spent` or `day_total` at `i128::MAX`: the next standard update would overflow
before any repair write applies. So is a merged state with more than `MAX_STATE_KEYS` keys or
`MAX_STATE_BYTES` bytes: no call deletes a state key and `deploy_policy` keeps the state, so
unbounded writes would grow the wallet's entry past the network limit, and the host would approve
a state that the chain cannot store. The operation denies instead, so no policy write makes every
later standard update fail; operations that write no new key and grow no value still pass at the
bound.
`post_flight` consumes the write buffer first, even when it fails.

The server evaluates a policy with `allowit::evaluate(ctx, execute, tier)`. It clears stale
writes, checks `request.args` with `allowit::check_args` as the wallet kernel does, and, for
`AllowitTier::Standard`, checks the params with `allowit::check_params` as the standard contract
does on every admission. Args or params that the wallet rejects are `InvalidParam`. A standard
wallet can hold a custom param after a code change from Custom, because the new code validates the
kept params only at its next admission. `evaluate` then runs `execute`, and runs `post_flight` on
approval; a denial discards the policy's writes.
So no write outlives its evaluation, also when the server reuses an `AllowitEnv`. Onchain, the
buffer is in memory and costs no ledger entry: the wallet clears it before its policy check and runs
`post_flight` after it. Each contract call runs in its own Wasm instance, and a denied transaction
keeps no change.

A Simple or Common wallet stores no policy state of its own: it runs the standard post-flight,
which denies a policy write with `Unsupported`, on the host as onchain. A Custom wallet stores the
state entries that its build declares, and runs the Custom post-flight: the server evaluates its
source with the Custom params check and the Custom post-flight, so the server never approves an
operation whose state the chain would drop. [Custom policy on the wallet kernel](custom-policy-kernel.md#policy-state)
states the calls, keys, values, lifetimes and bounds. The figures and state entries that the wallet
keeps are the server's next `ctx.state`. `allowit-stellar-admin` refuses a Simple or Common source
that calls `allowit::set_state`, also through the raw identifier `allowit::r#set_state`.

The server-only enrichment functions exist only in the host backend. Each takes the context and an
owner-written request and returns its passing constraint:
`price(ctx, &AllowitPrice { from, to, amount, price, slip })` the observed price,
`fetch(ctx, &AllowitFetch { method, url, data, pubkey })` the verified response,
`internet_search(ctx, &AllowitInternetSearch { query })` and
`marketplace_search(ctx, &AllowitMarketplaceSearch { query })` their results,
`request_screening(ctx, &AllowitRequestScreening { query, deny_below })` the passing score,
`decision(ctx, &AllowitDecision { id, query, deny_below, allow_above })` the passing confidence,
and `new_decision_context(ctx, contents)` nothing: it starts a new decision context, empty or with the optional
`contents` as its first contents. `id` names the decision call within the policy. Scores and confidences are basis points. There they are
stubs that return `Unsupported` until the server fills them. A Custom policy that calls one does not
compile, because the Soroban backend has none of them.

| Rule and canonical param key | Param value | Pass value |
| --- | --- | --- |
| `payment_limit` | Nonnegative `Int` gross units for one operation | `limit - amount` |
| `lifetime_spending_limit` | Nonnegative `Int` cumulative irreversible-expense ceiling | `limit - (spent + spent_units)` |
| `daily_spending_limit` | Nonnegative `Int` UTC-day irreversible-expense ceiling | `limit - (today_spent + spent_units)` |
| `daily_volume_limit` | Nonnegative `Int` UTC-day gross amount plus separate gas | `limit - (today_total + amount + gas_units)` |
| `call_limit` | `Int` in the `u64` range: successful operation count ceiling; zero denies | `limit - (calls + 1)` |
| `destinations` | `List` of `Addr`: permitted destinations, including vaults and swap routers; empty denies | Matched recipient |
| `tokens` | `List` of `Addr`: exact permitted token identities, the asset and any token a swap trades against it; empty denies | Matched asset |
| `expires_at` | `Int` in the `u64` range: exclusive Unix timestamp; request expiry cannot exceed it | `expires_at - now` |
| `operations` | `Str` `*` for every op, or `List` of `Str` op names; empty denies | The request's op name |

`today_spent` and `today_total` are the daily values when `state.day == now / 86400`, and zero for
an earlier day. A later day is `InvalidState`. Each rule checks only the facts it reads. A negative
limit is `InvalidParam`, as are a nonpositive `payment_limit` amount and negative request units. A
negative state value that a limit reads is `InvalidState`. Lifetime unpriced state or an unpriced
request denies `lifetime_spending_limit`; unpriced state of the day or an unpriced request denies
both daily limits (`Unpriced`). A sum outside its integer range is `Overflow`. Standard
configuration rejects negative limits.

Stellar admits only the general operations `transfer`, `swap`, `deposit` and `redeem` of
`AllowitOperation`. The wallet maps its native calls onto them: a SEP-41 transfer is `transfer`, a
SEP-56 deposit `deposit`, a router swap `swap` and a SEP-56 redeem `redeem`. The policy core names
no rail operation. Its custom-call entries, described in
[Allowit core](https://github.com/allowit-hq/allowit-core#operations), admit no Stellar request.
`operations` returns the request's op name, so a policy can `match` it; an op outside the list is
`OperationNotAllowed`. Any other value, such as `Str` `transfer` or an unknown name, is
`InvalidParam`. Even transfers need the param: a policy that should only swap leaves `transfer` out.

## Standard prefix

The standard prefix is the consecutive leading top-level statements of exactly the form
`allowit::<rule>(ctx, &ctx.params[allowit::<RULE>])?;`: one canonical rule and its own canonical
key constant. Any other statement ends it, including a rule that reads another key. Later
statements run offchain or in `AllowitCustomPolicy`.
The standard contract receives the exact owner-approved ordered prefix as `rules: Vec<AllowitRule>`, never
caller selectors. `AllowitRule` is a typed enum whose variants are the canonical names. Soroban decodes
vector and map elements when read, so owner configuration decodes every rule and param value before
storing it: an unknown rule name aborts and a malformed element is `InvalidParam`. It runs each call
through `allowit::preflight` as
`if ctx.params.contains(rule.key()) { allowit::<rule>(ctx, &ctx.params[rule.key()])?; }` and
discards pass values. This preflight runner is the only place an absent param skips its rule. The
offchain full policy and `AllowitCustomPolicy` still index it unguarded, so they stop with
`MissingParam`. An absent prefix param is valid configuration: the owner can set or remove params
with `deploy_policy` without code redeployment. `allowit-stellar-admin` warns about it without
rejecting the packet. The preflight runner propagates the first rule error. Repeated rules
read the same current state and only `post_flight` charges, so a rule cannot charge twice.

On Simple and Common, rule denials, including `OperationNotAllowed`, map to `PolicyDenied`.
`AllowitCustomPolicy` compiles the whole policy, so it fails the call with the denying rule's own
`AllowitError` code, for example `PaymentLimitExceeded` (102). These codes start at 101 and never
share a number with a wallet error. The server names the canonical rule of such a code only when
the simulation's diagnostic events show that the wallet itself raised it. A returned `MissingParam` or
`InvalidParam` maps to `InvalidParam` on every tier; a failed read aborts with its own code instead, see
[Panics](#panics). `InvalidState` maps to `InvalidState`, `Overflow` to
`Overflow` and `Unsupported` to `UnsupportedOperation`. The host evaluator returns `Panicked` for a
caught panic. A policy may also return it; onchain it is then a rule denial. A
failed call rolls back its events, so a standard wallet's specific rule error comes only from the
host evaluator and the shared engine.

Besides a Custom policy's declared state entries, a wallet stores only the cumulated figures that
its checks read:
spent and calls in the persistent entry `t`, and the day's spent and total in the temporary entry
`d`. A Standard wallet keeps the figure of each rule that has its param set; a Custom wallet keeps
the figures that its build finds in its source. With cost bounds a figure counts the conservative
expense and gas; without them it counts the raw gross and calls and sets the unpriced flag. No
owner reconciliation or refund method clears a figure. The day is the life of `d`: its first write
sets its end ledger, one day of ledgers later, and the entry expires with it. The kernel checks the
signed expiry, the configuration version and the expense bounds before the rules run; the host's
authorization nonce makes each signed operation run once.

After the policy approves, the wallet writes the figures before it calls the token, the router or
the vault. Soroban transactions are atomic, so a later failed effect check rolls all of it back.
Soroban also refuses a call into a contract that is already on the call stack, so a hostile vault
or router cannot call `execute` or reach the wallet's `__check_auth` while the wallet's operation
runs; the transaction fails and no state changes.

## Debits, re-entry and panics

Two rules from [Allowit core](https://github.com/allowit-hq/allowit-core#operations) hold on every
rail: a custom call never moves wallet funds, and a policy never re-enters the wallet. Stellar
admits no custom call. Each delegated transfer, deposit, swap and redeem runs through `execute`
and authorizes exactly one debit, which the canonical rules check: transfer and deposit one
`transfer` of the asset; swap one `transfer` of the first path token from the wallet to the first
pair for exactly `amount_in`; redeem the vault's own burn of `shares`, which needs no token
authorization.

On Stellar the wallet's authorization enforces both rules:

- `execute` authorizes its debit with `authorize_as_current_contract`: exactly one nested
  `transfer` for a transfer, deposit or swap, and none for a redeem.
- The wallet's `__check_auth` admits only one context: this wallet's own `execute`. Any other
  call that names the wallet's address, such as a plain token transfer or router call, fails
  authorization. The wallet calls `require_auth` on its own address once, at the start of
  `execute`, and the host runs `__check_auth` there. A nested `__check_auth` during the operation
  calls a contract that is already on the call stack, which the host refuses.
- No agent operation approves a spender, so the policy leaves no standing allowance. Tests check
  that no transfer, deposit, swap or redeem leaves an allowance, also for a vault that tries to
  approve itself.
- The owner-signed `invoke(contract, function, args, auth)` passthrough is outside the policy. It
  authorizes the scopes that the owner signs and can call any contract, `token.approve` included.
  An allowance that it leaves is the owner's choice.

Stellar does not implement `allowit::reentry_transfer`, so a policy that calls it does not compile.

### Panics

A rule returns `Err`. The policy may catch it and continue, and only a returned error denies. A
panic is a hard stop: the run denies and its writes are discarded. Indexing an unset param,
`ctx.params[key]`, panics with `MissingParam`. `allowit::param` and `allowit::arg` panic with
`MissingParam` for an unset key and with `InvalidParam` for a value of another type or range.
`panic!`, `assert!`, `unreachable!` and integer overflow panic too.

Onchain a panic aborts the wallet call, which rolls back every write. A failed read aborts with
`panic_with_error` and its `AllowitError` code: 101 for `MissingParam` and 111 for
`InvalidParam`. `AllowitError` codes start at 101 and wallet error codes stay below 100, so a
client never reads one as the other. On the host, `allowit::evaluate` catches the panic, discards
the writes and returns the failed read's error, or `Panicked` for any other panic. The evaluator
process keeps running.

## Source and configuration binding

The wallet stores `source_hash`, the SHA-256 of the owner's whole policy source, for every tier.
The owner signs the configuration that names it, then the deployment that names the code hash; the
owner's client derives and builds the code and compares the hash. A Common wallet also stores the
ordered `Vec<AllowitRule>` of the source's standard prefix. Each unit variant encodes as a
one-symbol vector of its rule name; the param it reads is always its canonical key. The code hash
fixes the operations that the wallet runs.

A Custom wallet compiles `contracts/allowit-custom-policy/policy/policy.rs` verbatim, and its
`build.rs` hashes that file into `SOURCE_HASH`: construction and `deploy_policy` refuse another
`source_hash`. `AllowitCustom::OPERATIONS` lists transfer, swap, deposit and redeem, and the
compiled policy's `operations` rule selects among them. `scripts/check-policy-bindings.py` checks
that the contract compiles and hashes its source verbatim. [The kernel interface for Custom
sources](custom-policy-kernel.md) gives the details.

`deploy_policy` changes the owner configuration at exactly the next `deployment_version`. With
`wasm_hash=None`, params change without code redeployment. The kept figures, pause and asset
remain; `t` follows the totals that the new configuration keeps. The new version refuses earlier
signed requests. A changed prefix or executable needs a new owner signature.

Owner packets bind their exact meaning. Struct decoding ignores extra keys and reads absent
`Option` keys as `None`, so the constructor and `deploy_policy` require owner authorization for
the canonical re-encoding of the decoded packet. A params map decodes as sent, so an absent key is
unset. A Standard wallet stores only the params of its rules; the server holds the rest of the
owner's params, and the source runs over all of them.

Custody layout 5 packs the configuration into the instance value `c`: a fixed header (layout,
flags, deployment version, owner, the agent's and the server's raw Ed25519 keys, asset and source
hash), then the gas cap, the rules and the params. `t` is 12 bytes; `d` holds its end ledger and
the kept daily figures. Execution, `state()` and `set_pause` read only layout 5. `recover` and
`stop` read only the header, which later layouts keep, so a code change never locks recovery. No
layout migrates implicitly: recover funds from an earlier layout and deploy a new wallet.

Earlier code reads the configuration only in its own layout, so a `deploy_policy` code change to
an earlier release locks custody. Each wallet Wasm declares `allowit_custody_layout` metadata equal
to `CONTRACT_VERSION`. `allowit-stellar-admin` refuses a code change to Wasm that declares another
layout or none. Recover funds before any change across layouts.

## Shared engine

`AllowitContext` carries the contract `Env`, so it is not a contract value. The shared engine
exposes each canonical rule as
`<rule>(params: Map<Symbol, AllowitValue>, state: Map<Symbol, AllowitValue>, request: AllowitRequest) -> Result<T, AllowitError>`,
where `state` is the current policy state.
Callers use its generated `AllowitEngineClient`.
It builds the context with its own `Env`, runs `allowit::<rule>(&ctx, &ctx.params[allowit::<RULE>])`
and returns the same pass value or rule error. An unset param aborts the call with `MissingParam`.
It holds no custody, params or policy state. No policy wallet, release tool or server in this repository
calls it; offchain evaluation uses `allowit` directly. It remains the engine parent's administered
checker for onchain callers that cannot bundle `allowit`. Its tests match `AllowitRule` exhaustively, so a
new rule fails to compile until the engine exposes it. The `test-deny` fixture aborts every rule
with contract error `TEST_DENY` (1000), outside `allowit::AllowitError`. `engine_version` 5 marks this ABI:
its methods carry the canonical rule names, and its `AllowitRequest` names the general operations
`transfer`, `swap`, `deposit`, `redeem` and `custom(contract, function)`, and carries `token_in`,
`amount_in`, `token_out` and `min_out`. Release 4 used the earlier rule names. Release 3 named Stellar operations and lacked those facts. It
replaces the shipped release 1 ABI, whose methods take `(request: EngineRequest, state:
EngineState)`. Release 2 was never released. An `upgrade_engine` from a deployed release 1, 3 or 4
engine to release 5 breaks every onchain caller of the earlier methods, so migrate or retire those
callers first.

## Typed operations

`execute` takes one `AllowitExecutionRequest`, a positional tuple: operation id, deployment
version, expiry, operation, expense, gas, gas payee and args. Its `operation` is an
`AllowitStellarOperation`, whose variants carry positional arguments:

| Variant | Arguments | Native call |
| --- | --- | --- |
| `Transfer` | token, to, amount | SEP-41 `token.transfer(wallet, to, amount)` |
| `Swap` | router, amount in, minimum out, path, deadline | `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet, deadline)` |
| `Deposit` | vault, assets, minimum shares | SEP-56 `vault.deposit(assets, wallet, wallet, wallet)` |
| `Redeem` | vault, shares, minimum assets | SEP-56 `vault.redeem(shares, wallet, wallet, wallet)` |

The wallet is the source, owner, receiver and operator of every native call, so no argument names
it. Soroban decodes the request as typed values: a wrong type, a missing argument or an unknown
variant fails before the wallet runs.

`to_core()` maps each variant onto the general `AllowitOperation` that rules read: `transfer`,
`swap`, `deposit` or `redeem`. The rail-neutral policy core never sees a SEP or router name. Each
tier lists the operations it runs in `AllowitPolicy::OPERATIONS`; a request for another operation
is `UnsupportedOperation`. Every tier runs all four.

The agent and the server sign the payload of the wallet's own authorization entry, which covers
the `execute` invocation with the whole request, the host nonce and the signature's expiration
ledger. The entry's signature is `AllowitCosignatures(agent, server)`, two raw Ed25519 signatures,
and `__check_auth` verifies them against the keys that the wallet stores. Neither the agent nor the
server needs an account: the server's sending account is the transaction source and pays the fee.

## Expenses and native effects

An external payment spends principal plus attributable gas. A deposit retains principal as shares.
Its conversion cost plus attributable gas counts toward spent limits. Daily total includes principal
plus separate gas; embedded conversion fees are not counted twice. Underlying units use seven
decimals. Share units retain their independent native scale.

`AllowitExecutionRequest.expense` is `Unpriced` or `Priced(gas units, conversion units, spent
units, observed ledger)`, all in units of the wallet's installed asset. The server approves exact
conservative economic ceilings. The kernel checks the ledger, the operation class, nonnegative
units and the spent identity. It cannot observe final transaction gas. XLM/stroop identity
conversion is intrinsic; other gas conversions need an admitted trusted source.

The request names the gas that the wallet repays in XLM and its payee, the server's sending
account. The repayment is at most the owner-signed gas cap; a wallet without XLM repays zero. For
an XLM wallet the gas units equal the repaid stroops and count against the limits. The rail signs
the fee bound of the simulated resource fee plus the inclusion fee plus a 1% margin as the gas; the
sending account declares that bound as the fee while the final simulation fits it. The server
keeps the part of a repayment above the fee charged and subtracts it from the wallet's next
repayment, down to zero; the wallet counts what it repays. The [rail
guide](../crates/allowit-stellar/README.md) gives the steps.

`execute` checks the operation that the tier runs, the immutable asset, amounts, positive debit,
pause, expiry, configuration version, the gas against the gas cap and the execution args' bounds
independently of business checks. Figures and effects commit atomically; denials and native
failures roll them back. Each `execute` emits one event, `allowit` with the operation id as its
topic and the operation's output as its data: a transfer's amount, a swap's observed output, a
deposit's minted shares or a redeem's paid assets. The wallet stores no receipt; the settled
transaction and its event are the record.

SEP-56 deposits name vault, assets and minimum shares; the wallet is source, operator and share
receiver. Ordinary `destinations` controls destination vaults; no separate vault list or code-hash
pin applies. The vault must report the immutable underlying SAC. Custody authorizes one exact
deeper `transfer(wallet, vault, assets)`. Extra debits, including a second debit later refunded,
lack authority. Returned shares must match the observed balance credit and meet the minimum. Any
conversion-loss ceiling also checks `preview_redeem(actual_shares)`. Foreign reads precede final
balances. The immutable SAC balance read is last. A vault getter cannot mutate already-checked
effects. Vault code can misreport ownership, valuation or redeemability; the wallet bounds SAC
spending and interface observations, and cannot prove investment value. Owner `invoke` can redeem
shares independently, and the agent can redeem them under the policy.

## Swaps and redeems

A swap trades the asset for another token, or back, through an exact-input router such as
Soroswap. A redeem burns SEP-56 vault shares for the asset. Both run through `execute`: the wallet
calls the router or vault itself, observes the effects and emits the event with the output.

### Arguments and invariants

`AllowitStellarOperation::Swap` holds `router`, `amount_in`, `amount_out_min`, `path` and
`deadline`; `Redeem` holds `vault`, `shares` and `min_assets`. The wallet is the swap's receiver
and the redeem's owner, operator and receiver. The kernel checks, before any policy runs:

- Swap: the router is neither the wallet nor the asset; the path holds 2 to `MAX_SWAP_PATH` (4)
  tokens and not the wallet; exactly one endpoint is the asset; the other endpoint is a Stellar
  Asset Contract (`UnsupportedAsset` otherwise); `amount_in` and `amount_out_min` are positive;
  `deadline` is no later than `expires_at`.
- Redeem: the vault is neither the wallet nor the asset; `shares` and `min_assets` are positive.

A forward swap pays the asset; a reverse swap pays the other token and receives the asset. Only the
asset leaves through transfers, deposits and forward swaps. A swap's other endpoint must be a
Stellar Asset Contract, which keeps the `execute` balance reads trusted. Common and Custom can
restrict it with `tokens`; Simple relies on the server.

### Request facts and accounting

| Op | `recipient` | `amount` (asset units) | `token_in` / `amount_in` | `token_out` / `min_out` |
| --- | --- | --- | --- | --- |
| transfer | `to` | amount | asset / amount | `None` / 0 |
| deposit | vault | assets | asset / assets | vault shares / `min_shares` |
| swap, asset to X | router | `amount_in` | asset / `amount_in` | X / `amount_out_min` |
| swap, X to asset | router | `amount_out_min`, a floor | X / `amount_in` | asset / `amount_out_min` |
| redeem | vault | `min_assets`, a floor | vault shares / `shares` | asset / `min_assets` |

`destinations` allows routers and vaults; no separate list applies. `tokens` checks the asset and,
for a swap, its other endpoint. `payment_limit` and `daily_volume_limit` read the gross amount, so
their limits on reverse swaps and redeems are floors. Swaps and redeems follow the deposit expense
model: `conversion_units` is the loss ceiling, and `spent_units` equals it plus `gas_units`. A
forward swap's loss cannot exceed `amount_in`. An `execute` redeem checks its loss against the
vault's `preview_redeem`. The wallet cannot price a swap's other token, so agent and server attest
a swap's `conversion_units`. Custom policy can add its own params, such as a
`swap_limit`, in a `match` arm of `operations`.

### Observed effects in `execute`

An `execute` swap reads `router_pair_for(path[0], path[1])`, authorizes exactly
`path[0].transfer(wallet, pair, amount_in)`, calls the router and requires: one returned amount per
path token, the first equal to `amount_in`, the last at least `amount_out_min`; an exact debit; and
a credit equal to the last returned amount. Both endpoints are Stellar Asset Contracts, so no
untrusted code runs after the router returns.

An `execute` redeem requires the vault to report the asset before the call, the share
balance to fall by exactly `shares`, and the asset credit to equal the returned assets and be at
least `min_assets`. With expense bounds it reads `preview_redeem(shares)` before the call and
requires `preview - min(preview, assets) <= conversion_units`. The final read is the asset balance.

### Limits

- An allowlisted router that misbehaves can lose up to `amount_in`, never more.
- Another contract can move the pool or vault price earlier in the same transaction.
  `amount_out_min` bounds a swap's loss and `min_assets` a redeem's.
- Testnet resets change router and token addresses: update `destinations` and `tokens` with
  `deploy_policy`.

## Owner authority and public metadata

Owner pause, stop, configuration, recovery, upgrades and exact `invoke` bypass agent/server
business checks and never call an engine. Owner authorization binds exact target, arguments and
supplied subtrees. `stop` pauses the wallet at the next version and returns its asset and XLM to
the owner in one call. The owner acts alone: a wallet whose `t` has lapsed restores it in the same
transaction. Each call keeps the wallet's instance live, and a Custom wallet's own code too
(`keep_live`); the rail refuses a step on a wallet whose instance or code lapsed with
`CONTRACT_EXPIRED`, and nothing restores it. `state()` returns the configuration, the kept figure set and the figures. Unknown
stored layouts reject. Upgrades do not migrate state.

The owner creates and funds a wallet with one signature through the stateless deployer contract:
`deploy(owner, wasm_hash, salt, constructor_args, funding)` creates the wallet at the owner's
address and salt and moves each funding amount from the owner to it. The deployer holds no funds
and no authority; the owner's signature covers exactly the creation and its transfers. The server
uploads the wallet code and pays only the fees of what it submits.

Classic G-address multisig has no contract prefix enforcement. Owner-selected signer thresholds
control native transactions. Its policy source and economic checks run offchain before signing.

## Crate boundaries

[Allowit core](https://github.com/allowit-hq/allowit-core) holds the shared rule core (`core.rs`)
and its host backend. The offchain server and the SDK evaluator run policies on the host backend.
`crates/policy` (`allowit-stellar-policy`) is the Soroban backend. Its `build.rs` copies `core.rs`
from the pinned Core release, and `src/lib.rs` includes that copy. The custody core, protocol,
engine and wallet contracts build on this backend. `crates/allowit-stellar` (`allowit-stellar`) is
the offchain rail crate, in its own Cargo workspace. The SDK engine composes it to prepare,
authorize and settle operations. Authored policy names only `allowit::`, so one source builds on
both backends.
