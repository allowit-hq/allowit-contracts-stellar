<div align="center">

# Allowit contracts for Stellar

*Policy wallets that let an AI agent spend on Stellar, within limits the owner sets*

[![Validate contracts](https://img.shields.io/github/actions/workflow/status/allowit-hq/allowit-contracts-stellar/contracts.yml?style=flat-square&label=Validate%20contracts)](https://github.com/allowit-hq/allowit-contracts-stellar/actions/workflows/contracts.yml)
[![Rust 1.98.0](https://img.shields.io/badge/Rust-1.98.0-dea584?style=flat-square&logo=rust&logoColor=white)](rust-toolchain.toml)
[![Soroban SDK 28.0.0](https://img.shields.io/badge/Soroban%20SDK-28.0.0-black?style=flat-square)](Cargo.toml)
[![Stellar CLI 28.1.0](https://img.shields.io/badge/Stellar%20CLI-28.1.0-black?style=flat-square)](https://developers.stellar.org/docs/tools/cli/stellar-cli)

[Overview](#overview) • [Three wallets](#three-policy-wallets) • [Policy source](#write-a-policy) • [Roles](#who-holds-which-key) • [How an operation happens](#how-an-operation-happens) • [Quick start](#quick-start) • [Operate a wallet](#operate-a-wallet) • [Docs](#documentation)

</div>

**Go on. On your terms.** Allowit lets your AI agents spend and invest, within a policy you set. This repository holds the Soroban smart contracts that enforce that policy on Stellar: owner-controlled wallets that move funds only when the agent and an independent server both sign, and only when the owner's policy says yes.

## Overview

A policy wallet is a Soroban contract that holds one native Stellar asset. The owner decides who may ask it to pay, deposit, swap or redeem, how much, to whom and until when. Every delegated SEP-41 transfer, SEP-56 vault deposit and redeem, and router swap needs two signatures, the agent's and the server's, and passes the wallet's own checks before a single stroop moves. The owner keeps the keys to everything else: pause, reconfigure, recover funds, upgrade the code and make exact passthrough calls.

Three wallet implementations share one custody core (`crates/policy-wallet`) and one owner interface. They differ only in where the policy runs.

> [!NOTE]
> Amounts, limits and usage are tracked in the asset's native base units. Only the installed asset can be paid out. A swap may leave the wallet holding a token listed in `tokens`; only a reverse swap or an owner `invoke` moves it. The wallet refuses to pay itself and refuses to pay the asset's issuer, because an issuer payment burns tokens.

## Three policy wallets

| Wallet | Who approves an operation | Where the policy runs |
| --- | --- | --- |
| `AllowitSimplePolicyEngine` | Agent and server | Offchain. The server checks the authored policy before it signs. The contract enforces custody invariants only. |
| `AllowitCommonPolicyEngine` | Agent and server | Onchain, from the standard prefix: the leading canonical rule calls of the authored policy, which the owner approves as `rules`. |
| `AllowitCustomPolicy` | Agent and server | Onchain, compiled. The complete authored policy file compiles verbatim into its own contract, on the same custody mixins. |

Pick **Simple** when your server already runs the whole policy and you want the lightest contract. Pick **Common** when you want standard limits enforced by the ledger itself. Pick **Custom** when the policy needs logic the canonical rules do not cover.

### The canonical rules

The canonical rules live in `crates/allowit`. Each rule reads one value that the policy looks up in the owner's `params` map, and returns its passing constraint or an error. The standard contract admits only these nine keys, runs only the rules the owner lists, in that order, and skips a rule whose param is absent. An empty list means no onchain business checks, like Simple.

| Rule and param key | What it does |
| --- | --- |
| `transaction_cap` | Caps the gross amount of one operation |
| `spent_cap` | Caps cumulative irreversible expenses |
| `day_spent_cap` | Caps irreversible expenses per UTC day |
| `day_total_cap` | Caps gross amounts plus attributable gas per UTC day |
| `call_cap` | Caps the number of successful operations; zero denies all |
| `recipients` | Allows only listed destinations, including vaults and swap routers; an empty list denies all |
| `tokens` | Allows only listed token contracts: the asset and any token a swap trades against it; an empty list denies all |
| `expiry` | Denies from a Unix timestamp on, and requires each request to expire no later than it |
| `operations` | Allows only listed op names, such as `transfer`, `deposit`, `swap` or `redeem`, and returns the op name for a `match` |

Value types, the standard state keys and error mapping are in [docs/architecture.md](docs/architecture.md).

## Write a policy

Policy source is ordinary synchronous Rust against `crates/allowit`. The offchain server and `AllowitCustomPolicy` compile the same file verbatim:

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

- `execute(ctx)` takes only the context. `AllowitContext` is plain data: the backend `env`, the owner's `params`, the current policy `state` and the `request`.
- `params` and `request.args` are key => `AllowitValue` maps. The owner sets params at install and changes them by signed update. The agent supplies args per call.
- A rule takes the looked-up value, so it may read any key, such as a custom `vendor_cap`.
- Only an error that the policy returns denies. A policy may catch a rule error and continue.
- `allowit::param(ctx, key)` and `allowit::arg(ctx, key)` return the typed value of an owner param or an agent arg. They panic when the key is missing or mistyped. A panic denies the run and discards its writes.
- After approval the wallet and the server run the same `allowit::post_flight`. It updates the standard state keys and applies the policy's `allowit::set_state` writes. Simple and Common never add or change a policy key, so their post-flight denies every policy write, on the server as onchain. Policy keys left by earlier Custom code stay unchanged.

`scripts/policy_source.py` admits policy code through an allowlist, so the same file behaves the same offchain and onchain. `scripts/contract_admin.py` derives the standard `rules` from the source file. The server uses `allowit = { default-features = false, features = ["std"] }` and builds with `overflow-checks = true`. The full authoring rules are in [docs/architecture.md](docs/architecture.md).

## Who holds which key

A wallet knows three addresses, and they must all be different.

- **Owner.** Creates the wallet and signs every configuration change. The owner alone can `deploy_policy`, `set_pause`, `recover` funds and `invoke` any contract call through the wallet. None of these need the agent or the server.
- **Agent.** The AI agent, or whatever acts for you. It co-signs delegated operations, through `execute` or an intercepted authorization, and nothing else.
- **Server.** An independent signer that co-signs every delegated operation. It is a second pair of eyes, not a shared checker contract and not an administrator.

A separate **engine parent** contract can manage the code of a shared rule-checking engine. It holds no custody authority: it cannot touch a wallet's funds, configuration or signers. See [docs/engine-parent.md](docs/engine-parent.md).

> [!TIP]
> No Soroban contract yet? A classic G-address account can get Simple-style authorization with plain multisig: owner weight 3, agent and server weight 1, thresholds 2/2/3. `scripts/wallet_admin.py` prepares exactly that. Classic reserves still apply, and custom onchain policy code needs a contract wallet.

## How an operation happens

1. The agent builds an `AllowitExecutionRequest`: the wallet's policy identity and source hash, a fresh operation id, the wallet's current nonce and deployment version, an expiry, the exact SEP-41 transfer, SEP-56 deposit or redeem, or router swap arguments, optional expense bounds and its per-call `args`.
2. Agent and server both authorize `execute`.
3. The wallet checks everything before it runs the policy: the installed module, entrypoint and argument schema; canonical argument encoding; the installed asset and the wallet as source; no replay of the operation id; not paused; nonce and deployment version current; not expired; positive amount; recipient is neither the wallet nor the issuer.
4. The wallet runs its local policy (custody checks only on Simple, the standard prefix on Common, the compiled file on Custom) against the params and the current policy state.
5. The post-flight state, the next nonce and the replay marker are written, then the token transfer, vault deposit or redeem, or router swap runs. A deposit grants the vault exactly one `transfer` of the checked amount and checks the returned shares. A swap grants the router exactly one `transfer` of `amount_in` to its pair and checks both token balances. A redeem checks the burned shares and the asset credit against `min_assets`. Everything commits together and a receipt comes back. If anything fails, nothing moves.

### Intercepted transfers, swaps and redeems

The owner can enable custom-account authorization with `x402_enabled`. The agent and the server must then be G-addresses. The agent then sends the plain call that a simple wallet would sign: `asset.transfer(wallet, to, amount)` (x402), `router.swap_exact_tokens_for_tokens(amount_in, amount_out_min, path, wallet, deadline)` or `vault.redeem(shares, wallet, wallet, wallet)`. The host asks the wallet's `__check_auth` to authorize it. The wallet verifies both Ed25519 signatures over the host payload and the execution request, requires that the signed authorization tree is exactly that call, and applies the same policy, replay and usage checks as a direct `execute`. A swap's tree also holds its one `transfer` of the first path token to the router's pair. The router enforces the signed `amount_out_min`; an intercepted redeem has no onchain output floor, so use `execute` when a redeem needs one. See [docs/architecture.md](docs/architecture.md#swaps-and-redeems).

## Quick start

You need:

- [Rust](https://rustup.rs) with `rustup`. `rust-toolchain.toml` pins Rust 1.98.0 and the `wasm32v1-none` target.
- [Stellar CLI](https://developers.stellar.org/docs/tools/cli/stellar-cli) 28.1.0.
- Python 3.10 or later.
- Git.

```sh
git clone https://github.com/allowit-hq/allowit-contracts-stellar.git
cd allowit-contracts-stellar

python3 scripts/check-policy-bindings.py  # verify the custom policy argument schema binding
scripts/build-contracts.sh                # build the test fixtures and every Wasm
cargo test --workspace --locked           # authorization, custody and portability regressions
```

The build leaves these contracts in `target/wasm32v1-none/release/`, plus the `allowit_sep56_test_vault.wasm` test vault:

```
allowit_simple_policy_engine.wasm
allowit_common_policy_engine.wasm
allowit_custom_policy.wasm
allowit_wallet_engine.wasm
allowit_engine_parent.wasm
```

Write a public manifest of source hashes and artifact hashes with `python3 scripts/artifacts.py --output PATH`.

> [!TIP]
> The `AllowitCustomPolicy` sample source is `crates/custom-policy/policy/policy.rs`. Its contract compiles that file verbatim as a module, and `build.rs` binds `SOURCE_HASH` to its bytes. No SDK code generation is involved. `scripts/policy-smoke.rs` compiles the sample against the host backend with plain `rustc`. `cargo test` builds and runs it, then compares its outcomes on the shared vectors in `scripts/policy-vectors.rs` with the Soroban backend and the custom, standard and simple Wasm. `STELLAR_BIN` selects the Stellar CLI executable.

The administration tools need the pinned Python Stellar SDK. Keep it in a virtual environment:

```sh
python3 -m venv /tmp/allowit-admin
/tmp/allowit-admin/bin/pip install -r scripts/requirements-admin.txt
/tmp/allowit-admin/bin/python -m unittest discover -s scripts/tests -v
```

## Operate a wallet

The owner interface is the same on all three wallets:

```
__constructor(config)                         owner
state()                                       anyone
policy_state()                                anyone
policy_binding()                              anyone
policy_binding_for(argument_schema_digest)    anyone
deposit_receipt(operation_id)                 anyone
swap_receipt(operation_id)                    anyone
redeem_receipt(operation_id)                  anyone
execute(execution)                            agent and server
deploy_policy(deployment)                     owner, plus the new owner if it changes
set_pause(paused, deployment_version)         owner
recover(recipient, amount)                    owner
invoke(contract, function, args, auth)        owner
```

`AllowitPolicyConfig` names the `owner`, `agent`, `server`, `asset`, `policy_instance`, `source_digest`, ordered `rules`, `params` and `x402_enabled`. The asset and the policy identity are fixed for the life of the wallet. Everything else changes through `deploy_policy`, which also accepts an optional new Wasm hash. With no new Wasm hash, params change without code redeployment. Both `deploy_policy` and `set_pause` must target exactly the next `deployment_version`. Pause, policy state and the execution nonce survive every deployment.

`scripts/contract_admin.py` prepares unsigned transactions for `upload`, `deploy-parent`, `deploy-wallet` and `admin`. It simulates, assembles fees and authorization entries, and hands you XDR to review and sign with your own keys. Its `read` action runs a read-only simulation of `state`, `engine` or `policy_binding`. It never signs, submits or retries. `scripts/wallet_admin.py` prepares and verifies classic-account multisig (`inspect`, `verify-wallet`, `verify-admin`, `setup-wallet`, `shutdown-wallet`, `setup-admin`) and also never signs or submits. Both tools run from the virtual environment above. Save signed bytes before broadcast and reconcile the original transaction hash after uncertainty.

```sh
/tmp/allowit-admin/bin/python scripts/contract_admin.py read --network testnet --contract "$WALLET" --source "$OWNER" --method policy_binding
```

The step-by-step guide, including params encoding and owner handoffs, is in [docs/admin.md](docs/admin.md). Release packets for mainnet are covered in [docs/mainnet.md](docs/mainnet.md).

## Project structure

```
crates/
  allowit/                Portable policy core, canonical rules and the host and Soroban backends
  protocol/               Shared request, receipt and binding types
  policy-wallet/          Custody core, owner operations and the policy_wallet! macro
  simple-policy-engine/   AllowitSimplePolicyEngine contract
  common-policy-engine/   AllowitCommonPolicyEngine contract
  custom-policy/          AllowitCustomPolicy contract and its sample policy source
  engine/                 Standalone shared rule engine contract
  engine-parent/          Upgrade parent for the shared engine
  test-vault/             SEP-56 vault for deposit and redeem tests
scripts/                  Build, policy checks, smoke vectors, administration and release tooling
docs/                     Architecture, engine parent, administration, mainnet
```

## Part of Allowit

- [allowit.xyz](https://allowit.xyz) tells the story and holds the official narrative.
- [allowit-sdk](https://github.com/allowit-hq/allowit-sdk) is the policy language and runtime. The `crates/allowit` core with its host backend becomes its `sdk/core`, for the offchain server and SDK evaluator.
- [allowit-contracts-solana](https://github.com/allowit-hq/allowit-contracts-solana) is the Solana sibling.
- [allowit-cli](https://github.com/allowit-hq/allowit-cli) is the Go CLI for evaluating and executing actions under a policy.

## Documentation

- [Architecture and authoring](docs/architecture.md): wallets, policy source, rules, configuration, intercepted authorization, deposits, swaps, redeems and owner operations.
- [Engine parent](docs/engine-parent.md): shared engine state, calls and lifetime.
- [Setup and administration](docs/admin.md): preparing, reviewing and signing wallet transactions.
- [Mainnet preparation](docs/mainnet.md): bounded, unsigned release packets.

## Contributing

Pull requests run the portable policy checks and the chain-free policy smoke tests. The full Wasm build and `cargo test --workspace --locked` run on a schedule and on demand. Before you open a pull request:

```sh
python3 scripts/check-policy-bindings.py
cargo fmt --all --check
scripts/build-contracts.sh
cargo test --workspace --locked
```

Keep contract code, build and API documentation and release inputs here. [AGENTS.md](AGENTS.md) describes the repository scope.

## License

The source is public, but every crate declares `license = "UNLICENSED"` and the repository has no license file, so no open-source license is granted.
