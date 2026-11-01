# Policy wallet engines

This page explains how an Allowit policy wallet is put together on Stellar: the three wallet
implementations, the portable policy source, the canonical rules, the configuration the owner signs,
what happens on every operation, and the operations only the owner can perform. Read the
[README](../README.md) first for the short version and the build steps.

A policy wallet keeps one immutable underlying Stellar Asset Contract (SAC). The owner selects the
wallet code, the agent, an independent server signer and the params. Delegated operations need both
the agent and the server. The owner needs nobody. The server signer is a plain co-signer; it is not
a shared checker contract or that contract's parent administrator. Shared checkers have no custody.

`AllowitSimplePolicyEngine` relies on agent/server authorization. `AllowitCommonPolicyEngine` is
the standard implementation for an owner-approved initial preflight prefix. `AllowitCustomPolicy`
compiles a complete authored policy into its contract. All three are built from the same custody
core in `crates/policy-wallet`. The `policy_wallet!` macro attaches the complete owner and
delegated-execution interface to an `AllowitPolicy` implementation, so Simple, Common and Custom
expose identical entrypoints and differ only in their `AllowitPolicy` logic.

## Public names

Every public type that authored policy, SDK integrations or contract specs name carries the
`Allowit` prefix: `AllowitContext`, `AllowitEnv`, `AllowitParams`, `AllowitValue`, `AllowitRule`,
`AllowitError`, `AllowitExecutionRequest`, `AllowitPolicyDeployment`, `AllowitState` and the others. The contract
structs and their generated clients carry it too: `AllowitSimplePolicyEngine`,
`AllowitCommonPolicyEngine`, `AllowitCustomPolicy`, `AllowitEngine`, `AllowitEngineParent`, and
`AllowitEngineClient` and the other `*Client` types. Namespaced items keep their short names, such
as `allowit::Result`, `allowit::spent_cap` and `allowit::TRANSACTION_CAP`.

Encodings carry struct field names and enum variant symbols, not type names. The prefix therefore
leaves signed encodings, the standard prefix digest and the stored layout unchanged.
Type names are in the Wasm contract spec, so rebuilt Wasm has new module hashes and, because the
standard `source_digest` hashes the module, new prefix-binding digests.

## One portable policy source

Policy source is ordinary synchronous Rust against `crates/allowit`. The offchain server and
`AllowitCustomPolicy` compile the file verbatim:

```rust
use allowit::prelude::*;
/// Let my agent pay our invoices. Cap every payment, cap its total spending and pay only vendors
/// I approve.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Cap every payment"
    allowit::transaction_cap(ctx, ctx.params.get(allowit::TRANSACTION_CAP))?;
    // "cap its total spending"
    allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;
    // "pay only vendors I approve"
    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;
    Ok(())
}
```

`execute` takes only the context. Each rule call keeps the form
`allowit::<rule>(ctx, ctx.params.get(<key>))?`: the policy looks up the param and the rule decodes
the value. A rule may read any key, such as a custom `vendor_cap`.

The function doc comment keeps the owner's original policy prompt. Each inline comment quotes the
prompt clause that the next call implements.

`AllowitCustomPolicy` and the offchain server call `execute` directly. Only an error that the
policy returns, usually with `?`, denies. A policy may catch a rule error, read it, record it in
its own state and continue. The standard contract runs only its leading canonical calls, supplied
by the owner as `rules`, and skips absent params. `scripts/contract_admin.py` derives `rules` from the source file. `scripts/policy_source.py` lexes
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
  `unwrap_or`, `checked_add`, `saturating_sub`, `min` and `max`, and `get` on `params` and `args`
  only;
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
- The map inside `params` and `args`, such as `ctx.params.0`, and the name `AllowitParams`. Soroban
  maps key by `Symbol` and decode values on read, and heap maps have other methods, so params and
  args are read only with `.get(key)`. The host backend keeps that map private, so the std-only
  compile also rejects `.0` on a clone or a binding, such as `ctx.params.clone().0`. `get` passes
  only on the field access `.params` or `.args`, such as `ctx.params.get` or
  `ctx.request.args.get`, and the file may not declare `params` or `args` as a binding or function
  name: on a list or a string, `get` would take a pointer-width index on the host. A struct expression or pattern of
  `AllowitContext`, which would reach `state`, and struct update syntax `..` reject. Soroban and
  heap vectors have different methods with the same names, for example `append` drains its argument
  only on the host, so a list from `AllowitValue::List`, and a `Vec` or `String` that `param` or
  `arg` returns, admits only comparison, `clone`, matching and `for`.
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
  such as `vec!`. On the host, `Address` is a StrKey newtype that compares only for equality:
  Soroban orders addresses by `ScAddress`, so accounts sort before contracts, while text would
  sort by StrKey. `scripts/policy_source.py` runs this compile in `check-policy-bindings.py`, and
  so in `scripts/build-contracts.sh`, and in `scripts/contract_admin.py` for the owner packets of
  every tier. These tools need `rustc` (from `RUSTC` or `PATH`). The portability test below and the
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
and vectors for the host evaluator; addresses are unordered StrKey newtypes and the environment is
a host `AllowitEnv`, which buffers the policy's state writes. The selected backend backs the crate root that authored policy names. The offchain
server depends on `allowit = { default-features = false, features = ["std"] }` and builds with
`overflow-checks = true`. Enabling both backends is a compile error, so a server cannot silently
unify `soroban` through another crate.

The portability test, `crates/policy-wallet/src/portability_tests.rs`, runs one shared vector set,
`scripts/policy-vectors.rs`, through four targets:

1. The host backend: the std-only compile of `scripts/policy-smoke.rs` prints its outcomes.
2. `AllowitCustomPolicy`: the Soroban backend of the same sources must give identical pass values,
   errors and post-flight state. The real custom Wasm must then return the mapped policy result.
   A fixture Wasm built with the `test-catching` feature compiles `src/catching_policy.rs`
   instead, and must return the mapped catching result. That policy catches a daily cap error,
   counts it in its own state key and continues, at most twice. When the agent's args name an
   `invoice`, it also caps the payment with the custom `invoice_cap` param.
3. `AllowitCommonPolicyEngine`: the real standard Wasm, bound to the sample policy's prefix, must
   return the mapped first prefix preflight error. It skips absent params and rejects a custom
   param with `InvalidParam`.
4. `AllowitSimplePolicyEngine`: the real simple Wasm runs no rules and also rejects a custom param.

Every contract then returns the shared post-flight result. Each vector holds the current state
before the operation. The test seeds each Wasm with the vector's params, args and that state, and
checks that each success stores exactly the post-flight state that the host computed. Both backends
also agree that the standard post-flight denies the catching policy's write with `Unsupported`,
that a write past `MAX_STATE_KEYS` keys or `MAX_STATE_BYTES` bytes is `InvalidState`, that
`evaluate` denies more than 16 args with `InvalidParam`, and that a standard `evaluate` rejects a
custom param with `InvalidParam`.
Separate tests check that every tier stores exactly the state that the server's `evaluate`
returned, and that execution params reach the Custom policy, fail authorization when changed after
signing, reject beyond their bounds and leave the standard tiers unaffected. Vectors that the
kernel cannot produce through a transfer `execute`, such as a deposit, swap or redeem, a negative
cap, an invalid `operations` value or more than 16 args, run only on the two backends. The swap and
redeem tests in `src/swap_redeem_tests.rs` run those operations through every contract. Kernel violations
(another asset, payment to the wallet, request expiry, stale nonce, replay and pause) reject with the
same kernel error in every contract.

`scripts/build-contracts.sh` builds the test-feature fixtures (`engine_deny.wasm` and
`custom_catching.wasm`) in their own target directory and copies them to `target/test-fixtures`,
so the deployable release paths never hold a test artifact. The tests read every Wasm from the
default `target/` directory, so the script ignores `CARGO_TARGET_DIR`. Run one build or
`cargo test` at a time in a worktree; a lock directory stops a second concurrent build. Use another
worktree for concurrent runs. The mainnet tooling rejects any artifact whose hash matches a test
fixture.

Portable authored code beyond canonical calls uses typed scalar fields, enum comparisons such as
`ctx.request.operation == AllowitOperation::deposit`, matches on `AllowitValue`, and its own
state keys. Backend list methods differ (`len` returns `u32` onchain and `usize` on the host), so
the tooling admits no list method.

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
`Map<Symbol, AllowitValue>`, on the host `BTreeMap<String, AllowitValue>`. `params` and
`request.args` are `AllowitParams`, which wraps that map and offers authored policy only
`get(key) -> Option<AllowitValue>`. The host map is private; the server converts with `From`. Values are owned on both backends, because Soroban maps decode
them on read; a borrowed host value would bind differently in a `match`. A key that no map can
hold, such as one with a space, is unset on both backends.

Rules are checks: `allowit::<rule>(ctx, Option<AllowitValue>) -> allowit::Result<T>`. Each decodes
the value, then returns only its passing constraint, or an `allowit::AllowitError`. An unset param is
`MissingParam`; a value of the wrong type or range is `InvalidParam`. Policy code calls rules
unguarded, so an unset param denies. A rule error that the policy catches denies nothing: the
policy decides. Custom keys reach policy as `ctx.params.get("vendor_cap")` or as a typed read
`let cap: i128 = allowit::param(ctx, "vendor_cap");`, and agent args as
`let amount: i128 = allowit::arg(ctx, "amount");`. A typed read returns the type of its binding:
`i128`, `u64`, `u32`, `bool`, `Address`, `String`, `Vec<AllowitValue>`, `Vec<Address>` or
`AllowitValue`. It panics when the key is unset or the value has another type or range; see
[Panics](#panics).

The owner sets params at install and changes them with `deploy_policy`, without code redeployment.
The canonical keys are `allowit::TRANSACTION_CAP`, `SPENT_CAP`, `DAY_SPENT_CAP`, `DAY_TOTAL_CAP`,
`CALL_CAP`, `RECIPIENTS`, `TOKENS`, `EXPIRY` and `OPERATIONS`, each the name of its rule.
`allowit::check_params` checks every owner write. Simple and Common admit only the canonical keys,
each with the type its rule decodes: a nonnegative `Int` cap, an `Int` in the `u64` range for
`call_cap` and `expiry`, a `List` of `Addr` for `recipients` and `tokens`, and `Str` `*` or a
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
`ctx.request.args.get("key")`.

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
wallet runs `post_flight` after its own policy check, and a denied transaction rolls the temporary
buffer back.

`AllowitTier` selects what a wallet stores. Custom compiles its whole policy, so its
`AllowitTier::Custom` post-flight applies every write. Simple and Common run only the standard
prefix onchain, which never writes, so they never add or change a policy key. Policy keys left by
earlier Custom code stay unchanged and still count toward the bounds. Their
`AllowitTier::Standard` post-flight therefore denies any policy write with `Unsupported`, on the
host as onchain: the server never approves an operation whose state the chain would drop. For every
tier, the state that `evaluate` returns is exactly the state the wallet stores, and the wallet's
`policy_state` alone is the server's next `ctx.state`. `scripts/contract_admin.py` rejects a Simple
or Common packet whose source calls `allowit::set_state`, also through the raw identifier
`allowit::r#set_state`; such a policy needs Custom.

The server-only enrichment functions exist only in the host backend. Each takes the context and an
owner-written request and returns its passing constraint:
`price(ctx, &AllowitPrice { from, to, amount, price, slip })` the observed price,
`fetch(ctx, &AllowitFetch { method, url, data, pubkey })` the verified response,
`internet_search(ctx, &AllowitInternetSearch { query })` and
`marketplace_search(ctx, &AllowitMarketplaceSearch { query })` their results,
`request_screening(ctx, &AllowitRequestScreening { query, deny_below })` the passing score,
`systemone(ctx, &AllowitSystemOne { id, query, deny_below, allow_above })` the passing confidence,
and `clear_systemone_context(ctx)` nothing. Scores and confidences are basis points. There they are
stubs that return `Unsupported` until the server fills them. A Custom policy that calls one does not
compile, because the Soroban backend has none of them.

| Rule and canonical param key | Param value | Pass value |
| --- | --- | --- |
| `transaction_cap` | Nonnegative `Int` gross units for one operation | `cap - amount` |
| `spent_cap` | Nonnegative `Int` cumulative irreversible-expense ceiling | `cap - (spent + spent_units)` |
| `day_spent_cap` | Nonnegative `Int` UTC-day irreversible-expense ceiling | `cap - (today_spent + spent_units)` |
| `day_total_cap` | Nonnegative `Int` UTC-day gross amount plus separate gas | `cap - (today_total + amount + gas_units)` |
| `call_cap` | `Int` in the `u64` range: successful operation count ceiling; zero denies | `cap - (calls + 1)` |
| `recipients` | `List` of `Addr`: permitted destinations, including vaults and swap routers; empty denies | Matched recipient |
| `tokens` | `List` of `Addr`: exact permitted token identities, the asset and any token a swap trades against it; empty denies | Matched asset |
| `expiry` | `Int` in the `u64` range: exclusive Unix timestamp; request expiry cannot exceed it | `expiry - now` |
| `operations` | `Str` `*` for every op, or `List` of `Str` op names; empty denies | The request's op name |

`today_spent` and `today_total` are the daily values when `state.day == now / 86400`, and zero for
an earlier day. A later day is `InvalidState`. Each rule checks only the facts it reads. A negative
cap is `InvalidParam`, as are a nonpositive `transaction_cap` amount and negative request units. A negative state value that a cap reads is `InvalidState`. Lifetime unpriced state or an
unpriced request denies `spent_cap`; unpriced state of the day or an unpriced request denies both
daily caps (`Unpriced`). A sum outside its integer range is `Overflow`. Standard configuration
rejects negative caps.

The op names are the general operations of `AllowitOperation`: `transfer`, `swap`, `deposit`
and `redeem`, plus three custom-call forms. `custom` admits any custom call, `custom.<function>`
that function on any contract, and `custom:<contract>.<function>` that function on that contract
instance. A function is 1 to 32 ASCII letters, digits or underscores, and a contract a `C` StrKey.
A custom call whose contract and function form no such name is admitted by no entry, not even
`*`. The policy core names no rail operation. The Stellar wallet maps its native calls onto the
general operations: a SEP-41 transfer is `transfer`, a SEP-56 deposit `deposit`, a router swap
`swap` and a SEP-56 redeem `redeem`. `operations` returns the request's op
name, so a policy can `match` it; an op outside the list is `OperationNotAllowed`. Any other value,
such as `Str` `transfer` or an unknown name, is `InvalidParam`. Even transfers need the param: a
policy that should only swap or run custom code leaves `transfer` out.

## Standard prefix

The standard prefix is the consecutive leading top-level statements of exactly the form
`allowit::<rule>(ctx, ctx.params.get(allowit::<RULE>))?;`: one canonical rule and its own canonical
key constant. Any other statement ends it, including a rule that reads another key. Later
statements run offchain or in `AllowitCustomPolicy`.
The standard contract receives the exact owner-approved ordered prefix as `rules: Vec<AllowitRule>`, never
caller selectors. `AllowitRule` is a typed enum whose variants are the canonical names. Soroban decodes
vector and map elements when read, so owner configuration decodes every rule and param value before
storing it: an unknown rule name aborts and a malformed element is `InvalidParam`. It runs each call
through `allowit::preflight` as
`if let Some(value) = ctx.params.get(rule.key()) { allowit::<rule>(ctx, Some(value))?; }` and
discards pass values. This preflight runner is the only place an absent param skips its rule. The
offchain full policy and `AllowitCustomPolicy` still run the unguarded call, so they deny it with
`MissingParam`. An absent prefix param is valid configuration: the owner can set or remove params
with `deploy_policy` without code redeployment. `scripts/contract_admin.py` warns about it without
rejecting the packet. The preflight runner propagates the first rule error. Repeated rules
read the same current state and only `post_flight` charges, so a rule cannot charge twice.

Rule denials, including `OperationNotAllowed`, map to `PolicyDenied`. `MissingParam` and
`InvalidParam` map to `InvalidParam`. `InvalidState` maps to `InvalidState`, `Overflow` to
`Overflow` and `Unsupported` to `UnsupportedOperation`. The host evaluator returns `Panicked` for a
caught panic. A policy may also return it; onchain it then maps to `PolicyDenied`. A
failed call rolls back its events, so only the host evaluator and the shared engine return the
specific rule error.

`AllowitState.policy_state` records every delegated success independently of selected or unset
rules. With cost bounds it records conservative expenses and gas. Without them it records raw gross
and calls plus an unpriced liability. Rollover clears only daily liability. No owner reconciliation
or refund method clears the standard keys. The kernel's single-use `operation_id`, execution nonce
and expense day checks reject replays and changed facts before rules run; a backward ledger day
fails the daily rules and `post_flight` with `InvalidState`.

After the policy approves, the wallet writes the post-flight state, the next nonce and the replay
marker before it calls the token, the router or the vault. Soroban transactions are atomic, so a
later failed effect check rolls all of it back. Soroban also refuses a call into a contract that is
already on the call stack, so a hostile vault or router cannot call `execute` or reach the wallet's
`__check_auth` while the wallet's operation runs; the transaction fails and no state changes.

In an intercepted operation, `__check_auth` writes the post-flight state, nonce and replay marker
when the host verifies the whole signed tree at the wallet's first `require_auth`. For the
Soroswap router and SEP-56 reference vaults, that is before any debit. Atomicity rolls them back on
any later failure, such as a router's minimum-output check.

## Custom calls, re-entry and panics

Two rules hold on every rail:

- A custom call never moves wallet funds. Only the native operations transfer, deposit, swap and
  redeem debit the wallet. Each authorizes exactly one debit, and the canonical rules check it:
  transfer and deposit one `transfer` of the asset; swap one `transfer` of the first path token from
  the wallet to the first pair for exactly `amount_in`. An intercepted redeem authorizes only the
  call `redeem(shares, wallet, wallet, wallet)`; the vault's own code decides the burn and the
  payout, and only `execute` checks the share debit, the underlying asset and `min_assets`.
- A policy never re-enters the wallet, also on a rail that does not block re-entry natively.

On Stellar both rules follow from the wallet's authorization:

- An agent custom call gets no nested authorization from the wallet, so a contract that it reaches
  cannot spend for the wallet. An agent deposit grants exactly one: the asset `transfer` of the
  checked amount from the wallet to the vault. An agent swap grants exactly the signed `transfer`
  sub-invocation. An agent redeem grants only the `redeem` call, and the burn needs no token
  authorization.
- An intercepted transfer, swap or redeem runs the policy in the wallet's `__check_auth`, which the
  host calls while the token, router or vault, not the wallet, is on the call stack. This is not
  re-entry. That `__check_auth` makes no contract call into the router or vault (the host refuses
  re-entry into a contract on the stack); it reads only signed arguments, host functions and its own
  storage. A `__check_auth` that a callee triggers during the wallet's own `execute` is refused.
- A nested `__check_auth` of the wallet during its own operation calls a contract that is already
  on the call stack. The Soroban host refuses that re-entry from a callee, and the transaction
  fails. The host does allow an immediate re-entry: the wallet's own frame calls `require_auth` on
  the wallet's address, and the host runs its `__check_auth`. The rule holds because the wallet
  never does that; it calls `require_auth` only on the owner, agent and server.
- No agent operation approves a spender, so the policy leaves no standing allowance. Each debit is
  one exact `transfer` authorization. Tests check that no transfer, x402 transfer, deposit, swap or
  redeem leaves an allowance, also for a vault that tries to approve itself.
- The owner-signed `invoke(contract, function, args, auth)` passthrough is outside the policy. It
  authorizes the scopes that the owner signs and can call any contract, `token.approve` included.
  An allowance that it leaves is the owner's choice.

`allowit::reentry_transfer` is the only exception. It exists only on rails that implement it.
Stellar has none, so a policy that calls it does not compile. Where it exists, every condition
applies:

- only a Custom wallet has it, and the owner approves it at install;
- it moves one exact amount, which the transfer rules check;
- the wallet stores the policy state, nonce and replay marker before the transfer;
- its authorization is one-shot;
- no other re-entry occurs, and no allowance remains after it.

A policy can check each op with its own params and args:

```rust
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    match allowit::operations(ctx, ctx.params.get(allowit::OPERATIONS))? {
        "custom:CPOOL….swap" => {
            // "at most 50 XLM per swap"
            let amount: i128 = allowit::arg(ctx, "amount");
            let cap: i128 = allowit::param(ctx, "swap_cap");
            if amount > cap { panic!("swap above swap_cap"); }
        }
        "custom:CPOOL….claim" => { /* read claim args */ }
        _ => {}
    }
    Ok(())
}
```

An op that the `operations` param admits but that has no arm runs with no per-op checks.

### Panics

A rule returns `Err`. The policy may catch it and continue, and only a returned error denies. A
panic is a hard stop: the run denies and its writes are discarded. `allowit::param` and
`allowit::arg` panic with `MissingParam` for an unset key and with `InvalidParam` for a value of
another type or range. `panic!`, `assert!`, `unreachable!` and integer overflow panic too.

Onchain a panic aborts the wallet call, which rolls back every write. A failed typed read aborts
with `panic_with_error` and its `AllowitError` code: 101 for `MissingParam` and 111 for
`InvalidParam`. `AllowitError` codes start at 101 and wallet error codes stay below 100, so a
client never reads one as the other. On the host, `allowit::evaluate` catches the panic, discards
the writes and returns the failed read's error, or `Panicked` for any other panic. The evaluator
process keeps running.

## Source and configuration binding

Fixed standard `source_digest` is SHA-256 of the canonical XDR vector of the domain
`allowit_std_prefix`, the implementation kind, the actual module hash, the immutable SAC and the
ordered `Vec<AllowitRule>`. Each unit variant encodes as a one-symbol vector of its rule name; the
param it reads is always its canonical key. It excludes param values and full source. The module
hash fixes the operations that the code runs. The constructor and binding getter check the digest
against the actual runtime module.

Custom `source_digest` is the plain SHA-256 of the exact bytes of `crates/custom-policy/policy/policy.rs`.
`build.rs` computes `SOURCE_HASH` from the file that the contract compiles verbatim, so they
cannot drift. `AllowitCustom::OPERATIONS` lists transfer, swap and redeem; Custom runs no deposit.
The compiled policy's `operations` rule selects among them. The contract does not depend on
SDK-generated code. `scripts/check-policy-bindings.py` checks that the contract compiles and hashes
its source verbatim.

Every digest is computed from its definition, never typed in as a constant: `build.rs` hashes the
policy source at build time, the wallet hashes the prefix tuple when the owner configures it and on
every binding check, and the host reports the module hash. Tests recompute each digest from the
same definition.

The complete source has separate offline owner authorization, scoped to wallet, network, policy,
prefix and monotonic source revision. Changing only that offchain suffix needs no chain call.
Each execution separately carries `source_hash`, covered by agent/server authorization and the x402
digest. Offline updates do not replace already signed operation bytes or their recovery identity.

`deploy_policy` changes owner configuration at exactly the next `deployment_version`.
With `wasm_hash=None`, params change without code redeployment. Prefix, policy state, custody,
execution nonce and pause remain intact when only params change. The new revision rejects old
inflight packets. A changed prefix or executable requires a new owner binding.

Owner packets bind their exact meaning. Struct decoding ignores extra keys and reads absent
`Option` keys as `None`, so the constructor and `deploy_policy` require owner authorization for
the canonical re-encoding of the decoded packet. A params map decodes as sent, so an absent key is
unset. A packet with legacy, extra or absent keys fails
authorization unless the owner signed that canonical form.

`contract_version` 4 stores `params` and the free-form `policy_state` as key => `AllowitValue`
maps, and `Vec<AllowitRule>`. Version 3 stored the canonical params as a typed struct and policy
state of raw values, version 2 a typed accounting history struct, and version 1 a text-keyed params
map and symbol rules. Execution, `state()`, `policy_state()` and `set_pause` accept only the exact
canonical encoding of version 4. Owner `recover` and `invoke`
decode a typed struct of only the fields they keep, so an in-place upgrade from an earlier layout
never locks recovery. `deploy_policy` carries `policy_state` over; an earlier layout stores none or stores
other values, so `deploy_policy` rejects it with `InvalidState`. No layout migrates implicitly: recover funds from an
earlier layout and deploy a new wallet. A complete typed `deploy_policy` packet replaces params,
rules and roles, keeps policy state, nonce, pause and asset, and writes version 4. Later versions
reject even owner calls, because their kept fields may change meaning. New source hashes need new
owner bindings.

Earlier code reads State only in its own layout, so a `deploy_policy` code change from version 4
to an earlier release permanently locks custody. Each
wallet Wasm declares `allowit_custody_layout` metadata equal to `CONTRACT_VERSION`.
`contract_admin.py` refuses a code change to Wasm that declares another layout or none. Recover
funds before any change across layouts. Every later layout bump needs the same rule.

## Shared engine

`AllowitContext` carries the contract `Env`, so it is not a contract value. The shared engine
exposes each canonical rule as
`<rule>(params: Map<Symbol, AllowitValue>, state: Map<Symbol, AllowitValue>, request: AllowitRequest) -> Result<T, AllowitError>`,
where `state` is the current policy state.
Callers use its generated `AllowitEngineClient`.
It builds the context with its own `Env`, runs `allowit::<rule>(&ctx, ctx.params.get(allowit::<RULE>))`
and returns the same pass value or rule error.
It holds no custody, params or policy state. No policy wallet, release tool or server in this repository
calls it; offchain evaluation uses `allowit` directly. It remains the engine parent's administered
checker for onchain callers that cannot bundle `allowit`. Its tests match `AllowitRule` exhaustively, so a
new rule fails to compile until the engine exposes it. The `test-deny` fixture aborts every rule
with contract error `TEST_DENY` (1000), outside `allowit::AllowitError`. `engine_version` 4 marks this ABI:
its `AllowitRequest` names the general operations `transfer`, `swap`, `deposit`, `redeem` and
`custom(contract, function)`, and carries `token_in`, `amount_in`, `token_out` and `min_out`.
Release 3 named Stellar operations and lacked those facts. It replaces the shipped release 1 ABI, whose methods take `(request: EngineRequest, state:
EngineState)`. Release 2 was never released. An `upgrade_engine` from a deployed release 1 or 3
engine to release 4 breaks every onchain caller of the earlier methods, so migrate or retire those
callers first.

## Typed operations

`execute` and the intercepted door take one `AllowitExecutionRequest`. Its `operation` is an
`AllowitStellarOperation`, whose variants carry named arguments:

| Variant | Arguments | Native call |
| --- | --- | --- |
| `Transfer` | `token`, `to`, `amount` | SEP-41 `token.transfer(wallet, to, amount)` |
| `Swap` | `router`, `amount_in`, `amount_out_min`, `path`, `deadline` | `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet, deadline)` |
| `Deposit` | `vault`, `assets`, `min_shares` | SEP-56 `vault.deposit(assets, wallet, wallet, wallet)` |
| `Redeem` | `vault`, `shares`, `min_assets` | SEP-56 `vault.redeem(shares, wallet, wallet, wallet)` |

The wallet is the source, owner, receiver and operator of every native call, so no argument names
it. Soroban decodes the request as typed values: a wrong type, a missing argument or an unknown
variant fails before the wallet runs. Struct decoding ignores an extra key, so a key such as a
foreign `from` changes nothing. Agent and server sign the raw request through `require_auth` on
`execute`, and the canonical encoding of the decoded request in `__check_auth`.

`to_core()` maps each variant onto the general `AllowitOperation` that rules read: `transfer`,
`swap`, `deposit` or `redeem`. The rail-neutral policy core never sees a SEP or router name. Each
tier lists the operations it runs in `AllowitPolicy::OPERATIONS`, and `policy_binding().operations`
reports them; a request for another operation is `UnsupportedOperation`. Simple and Common run all
four; Custom runs transfer, swap and redeem.

The request also carries `module_digest`, the wallet's Wasm SHA-256, so agent and server approve
one exact executable, and `expense`, which is `Unpriced` or `Priced(AllowitExpenseBounds)`. In
Stellar CLI JSON a transfer request is:

```json
{
  "policy_instance": "0101…01", "source_hash": "0909…09", "operation_id": "0000…01",
  "nonce": 0, "deployment_version": 0, "expires_at": 1767225600, "module_digest": "<wallet Wasm SHA-256>",
  "operation": {"Transfer": {"token": "<asset SAC>", "to": "<recipient>", "amount": "100"}},
  "expense": "Unpriced", "args": {}
}
```

## Expenses and native effects

An external payment spends principal plus attributable gas. A deposit retains principal as shares.
Its conversion cost plus attributable gas counts toward spent limits. Daily total includes principal
plus separate gas; embedded conversion fees are not counted twice. Underlying units use seven
decimals. Share units retain their independent native scale.

`AllowitExecutionRequest.expense` is `Unpriced` or `Priced(AllowitExpenseBounds)`. The bounds hold
asset, decimals, gas units, conversion units, spent units, attributable fee ceiling, observation
ledger and UTC day as typed fields. The server approves exact conservative economic ceilings. The kernel checks denomination, day,
ledger, operation class, nonnegative units and the fee/gas identity. It cannot observe final
transaction gas. XLM/stroop identity conversion is intrinsic; other gas conversions need an
admitted trusted source. Onchain counters retain ceilings. The server separately settles actual
expenses and temporary loss. No automatic onchain refund authority follows from that accounting.

`execute` and the owner-enabled intercepted door require agent and server authority. The kernel
checks the operation that the tier runs, policy identity, source and module, immutable asset,
amounts, positive debit, pause, expiry, configuration version, execution nonce, single-use
operation ID and the execution params' bounds independently of business checks.
The intercepted door validates the same typed operation as `execute` and admits a transfer, swap
or redeem, each only with its exact signed tree.
State, effects and receipts commit atomically. Denials and native failures roll them back.

SEP-56 deposits name vault, assets and minimum shares; the wallet is source, operator and share
receiver.
Ordinary `recipients` controls destination vaults; no separate vault list or code-hash pin applies.
The vault must report the immutable underlying SAC. Custody authorizes one exact deeper
`transfer(wallet, vault, assets)`. Extra debits, including a second debit later refunded, lack authority.
Returned shares must match the observed balance credit and meet the minimum. Any conversion-loss
ceiling also checks `preview_redeem(actual_shares)`. Foreign reads precede final balances.
The immutable SAC balance read is last. A vault getter cannot mutate already-checked effects.

`AllowitTransferReceipt` retains the underlying leg. `deposit_receipt(operation_id)` and `sep56_deposit`
record the observed share output. Vault code can misreport ownership, valuation or redeemability.
The wrapper bounds SAC spending and interface observations; it cannot prove investment value.
Owner `invoke` can redeem shares independently, and the agent can redeem them under the policy.

## Swaps and redeems

A swap trades the asset for another token, or back, through an exact-input router such as
Soroswap. A redeem burns SEP-56 vault shares for the asset. Both have two doors, and both doors run
the same `validate_operation` and `admit`: the same invariants, rules, `post_flight` and state
writes.

- **Intercepted.** The agent sends the plain call that a simple wallet would sign, and the wallet
  intercepts it in `__check_auth`:
  `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet, deadline)` or
  `vault.redeem(shares, wallet, wallet, wallet)`. The custom-account signature is an
  `AllowitPolicyAuthorization`, as for an x402 transfer. `x402_enabled` enables this door.
- **`execute`.** The agent and server authorize `execute` with the same request. The wallet calls
  the router or vault itself, observes the effects and stores a receipt, which
  `swap_receipt(operation_id)` and `redeem_receipt(operation_id)` return with the `swap` and
  `sep56_redeem` events. Only this door can check a redeem's output.

| | Intercepted | `execute` |
| --- | --- | --- |
| Agent transaction | The plain router or vault call | `wallet.execute(request)` |
| Swap minimum output | The router enforces the signed `amount_out_min` | The router check, and the wallet checks the credit |
| Redeem minimum output | None: SEP-56 `redeem` has no argument for it, and `__check_auth` cannot call the vault | The wallet checks the credit against `min_assets` |
| Output receipt | None; the router, token and vault events | Stored receipt and event |
| Debit authority | Exactly the signed tree | One exact `transfer`, by `authorize_as_current_contract` |

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

### The intercepted authorization tree

`__check_auth` receives every node of the signed tree in host preorder and accepts only these exact
shapes, compared with the decoded request:

- Transfer: `[asset.transfer(wallet, to, amount)]`.
- Swap: `[router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet, deadline),
  path[0].transfer(wallet, pair, amount_in)]`. The pair is a contract other than the wallet and the
  router. The kernel does not recompute it: the router pays its own pair, so another pair fails the
  host's authorization matching.
- Redeem: `[vault.redeem(shares, wallet, wallet, wallet)]`.

Any other node count is `InvalidInvocation`, another call `UnsupportedOperation`, and other
arguments `InvalidInvocation`. A deposit has no intercepted form.

The host calls `__check_auth` once per authorization entry, at the first `require_auth` that matches
it: the router's `to.require_auth()` or the vault's `operator.require_auth()`. The later debit in
the same tree matches its node without another call. The intercepted door does not support a vault
that calls `require_auth` for the wallet twice in one call. With one signed entry, the second
`require_auth` finds no unmatched entry and the transaction fails. The host then tries the next
entry for the wallet, so a client can supply a second entry with the same `redeem` root and its own
signed execution (the next nonce and a new `operation_id`). `__check_auth` admits each signed entry
as a separate operation: it consumes its own nonce and the policy charges it separately, so the one
real redeem counts twice. Recording-mode simulation of such a vault returns both entries; the
server co-signs at most one wallet entry per intercepted transaction. Such a vault must use the
`execute` door, where the wallet is the vault's direct invoker and authorizes the call once.

```
agent tx: router.swap_exact_tokens_for_tokens(in, min, [asset, X], wallet, deadline)
  router: wallet.require_auth()  ->  wallet.__check_auth(payload, signature, [swap, transfer])
            validate_operation -> match_contexts -> agent and server signatures -> admit
            (binding, replay, pause, nonce, version, expiry, expense, policy, post_flight)
            store state, nonce + 1 and the replay marker
  router: amounts.last() >= min, else the whole transaction rolls back
  router: asset.transfer(wallet, pair, in)  (matches the signed sub-node)
  pair:   X.transfer(pair, wallet, out)
```

The client simulates the call in recording mode to get the wallet's entry, signs the host payload
and the request, and simulates again with the signed entry in enforcing mode. Recording mode does
not run `__check_auth`, so only the second simulation finds the wallet's own storage footprint.
Replay protection has four layers: the host authorization nonce, the strict execution nonce, the
persistent `operation_id` marker, and `expires_at` with `deployment_version`.

### Request facts and accounting

| Op | `recipient` | `amount` (asset units) | `token_in` / `amount_in` | `token_out` / `min_out` |
| --- | --- | --- | --- | --- |
| transfer | `to` | amount | asset / amount | `None` / 0 |
| deposit | vault | assets | asset / assets | vault shares / `min_shares` |
| swap, asset to X | router | `amount_in` | asset / `amount_in` | X / `amount_out_min` |
| swap, X to asset | router | `amount_out_min`, a floor | X / `amount_in` | asset / `amount_out_min` |
| redeem | vault | `min_assets`, a floor | vault shares / `shares` | asset / `min_assets` |

`recipients` allows routers and vaults; no separate list applies. `tokens` checks the asset and,
for a swap, its other endpoint. `transaction_cap` and `day_total_cap` read the gross amount, so
their limits on reverse swaps and redeems are floors. Swaps and redeems follow the deposit expense
model: `conversion_units` is the loss ceiling, and `spent_units` equals it plus `gas_units`. A
forward swap's loss cannot exceed `amount_in`. An `execute` redeem checks its loss against the
vault's `preview_redeem`. The wallet cannot price a swap's other token, so agent and server attest
a swap's `conversion_units`, and on the intercepted door also a redeem's. Custom policy can add its own params, such as a
`swap_cap`, in a `match` arm of `operations`.

### Observed effects in `execute`

An `execute` swap reads `router_pair_for(path[0], path[1])`, authorizes exactly
`path[0].transfer(wallet, pair, amount_in)`, calls the router and requires: one returned amount per
path token, the first equal to `amount_in`, the last at least `amount_out_min`; an exact debit; and
a credit equal to the last returned amount. Both endpoints are Stellar Asset Contracts, so no
untrusted code runs after the router returns.

An `execute` redeem requires the vault to report the asset before and after the call, the share
balance to fall by exactly `shares`, and the asset credit to equal the returned assets and be at
least `min_assets`. With expense bounds it reads `preview_redeem(shares)` before the call and
requires `preview - min(preview, assets) <= conversion_units`. The final read is the asset balance.

### Limits

- An intercepted redeem has no onchain output floor. The vault allowlist, the server's
  `preview_redeem` check before it signs and short expiries bound it; use `execute` when a redeem
  needs a floor.
- An intercepted redeem does not check the vault's underlying asset or the burned share amount.
- The intercepted door stores no output receipt. The server reconciles from the router `swap`,
  token `transfer` and vault `withdraw` events.
- An allowlisted router that misbehaves can lose up to `amount_in`, never more.
- Another contract can wrap the agent's entry and move the pool or vault price earlier in the same
  transaction. `amount_out_min` bounds a swap's loss; a redeem's loss has no onchain bound.
- The strict execution nonce orders every operation across both doors.
- Testnet resets change router and token addresses: update `recipients` and `tokens` with
  `deploy_policy`.

## Owner authority and public metadata

Owner pause, configuration, recovery, upgrades and exact `invoke` bypass agent/server business checks
and never call an engine. Owner authorization binds exact target, arguments and supplied subtrees.
`policy_binding()` reports the executable, the source binding and the operations that the wallet
runs. `state()` returns the custody State, and `policy_state()` the current policy
state map. Unknown stored layouts reject. Upgrades do not migrate state.

Classic G-address multisig has no contract prefix enforcement. Owner-selected signer thresholds
control native transactions. Its policy source and economic checks run offchain before signing.

## Crate boundaries

`crates/allowit` holds the shared rule core (`core.rs`) and both backends. The core with the host
backend becomes `sdk/core` in the SDK repository, for the offchain server and SDK evaluator. The
Soroban backend with the policy wallet, protocol, custom policy and engine crates becomes
`stellar/core`. Authored policy names only `allowit::`, so the split does not change policy source.
