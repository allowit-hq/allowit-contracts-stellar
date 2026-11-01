# Wallet administration

These tools prepare transactions. They do not fund accounts, sign, submit or retry them. Use existing funded accounts. Native preparation reads current sequence and signer state from Horizon. Contract preparation uses Stellar CLI 28.1.0 and RPC. Its `--build-only` flag returns raw, unassembled XDR. The contract tool adds five-minute time bounds, then runs `stellar tx simulate` to assemble resource fees, footprint and authorization entries. It rejects changes to transaction intent or unexpected signatures. Its output is assembled unsigned XDR. `--send=no` returns a read simulation result, not unsigned XDR.

Use Python 3.10 or later (below 4.0) and Stellar CLI 28.1.0. Install the pinned Python SDK in a local virtual environment:

```sh
python3 -m venv /tmp/allowit-admin
/tmp/allowit-admin/bin/pip install -r scripts/requirements-admin.txt
/tmp/allowit-admin/bin/python -m unittest discover -s scripts/tests -v
```

Select `--network testnet` explicitly. Mainnet preparation additionally requires `--allow-mainnet`. Public addresses and hashes belong in arguments. Never pass secret seeds. Use Stellar CLI identities backed by the OS secure store for manual signing. `STELLAR_BIN` selects the CLI executable for contract tooling. Contract subprocesses ignore inherited Stellar signing and network overrides.

## Native wallet and engine administrator

The classic CLI retains `--engine` for its service co-signer. This means the wallet `server` role, not the parent-managed shared checker address.

The native wallet owner is its account master key. Setup admits only an existing account with master weight 1, no other signers and default thresholds. It atomically adds agent/engine weight 1, changes owner weight to 3, and sets thresholds 2/2/3. Setup never silently replaces existing authority. Signer verification rejects unexpected signers, hash/preauthorized signers and threshold drift.

```sh
python scripts/wallet_admin.py setup-wallet --network testnet --account "$OWNER" --agent "$AGENT" --engine "$ENGINE" > /tmp/setup.xdr
python scripts/wallet_admin.py verify-wallet --network testnet --account "$OWNER" --agent "$AGENT" --engine "$ENGINE"
```

Verification succeeds only after the configuration transaction settles. To disable automation, use `shutdown-wallet` with the same addresses. It atomically removes agent and engine and raises all thresholds to 3. Only the owner can authorize it. Prefer `--transaction-source OTHER_OWNER_ACCOUNT` to use an independent owner-only fee/sequence account. All shutdown operations still name the wallet as their source. Sign with both wallet owner and transaction source. This prevents the agent pair from invalidating shutdown through the wallet sequence, although admission and offer checks can still race ledger changes. Verification rejects open Horizon offers. Shutdown reports offers but still prepares signer removal. Revoke signers first, then reconcile offers and allowances. Removing signers does not revoke persistent SAC allowances, liquidity positions or prior issuer changes. Horizon cannot enumerate all SAC allowances. Read and zero allowances for every known spender separately. Treat unknown prior delegations as unresolved. This native profile grants broad low/medium authority, so shutdown cannot promise complete revocation.

Prepare a separate native engine administrator with `setup-admin --account "$ADMIN" --member "$A" --member "$B" --member "$C"`. The three distinct members receive weight 1. All thresholds become 2. The account master becomes weight 0 unless it is one of those members. `verify-admin` checks that exact configuration. Keep the necessary master and member secure-store identities available before setup.

Review and sign the exact XDR manually:

```sh
stellar tx decode /tmp/setup.xdr
stellar tx sign --network testnet --sign-with-key owner-secure-identity /tmp/setup.xdr > /tmp/setup-signed.xdr
stellar tx send --network testnet /tmp/setup-signed.xdr
```

The source account signs initial setup under its existing master authority. Later admin operations need two member signatures on the same envelope. Native envelopes expire after five minutes and bind the next account sequence. Do not reuse them after other transactions consume that sequence. After an uncertain submission, check the original transaction hash and ledger state before preparing a replacement.

## Contract setup and owner administration

[Engine parent](engine-parent.md) defines parent state, executable references, version ordering and recovery.

Run `scripts/build-contracts.sh` before contract tests or deployment preparation. It checks policy
bindings, builds the test fixtures, then rebuilds the default deployable artifacts. Select the
reviewed source and placement manifest when preparing a policy executable.

Use `contract_admin.py upload --source "$OWNER" --wasm PATH` separately for the engine, parent and
policy wallet Wasm. Review, sign and submit prepared uploads manually, retaining each resulting hash.

Prepare `deploy-parent --source "$ADMIN" --owner "$ADMIN" --engine-wasm HASH --wasm
 target/wasm32v1-none/release/allowit_engine_parent.wasm --wasm-hash PARENT_HASH`, with three
`--member` values. The script verifies the native admin quorum, local Wasm and creation executable
hash. The constructor creates the shared engine. Read its address with `read --contract
PARENT_ADDRESS --source "$ADMIN" --method engine`.

A read simulation does not commit TTL updates. Submit a reviewed native CLI invocation of the
parent's `engine()` before the parent, engine reference or engine code expires. Select an explicit
fee source and `--auth-mode root`. The admin tool does not admit this maintenance invocation.
Restore archived dependencies through separate reviewed transactions.

Prepare `deploy-wallet --source "$OWNER" --config JSON --wasm PATH --wasm-hash HASH --tier TIER --policy-source FILE`.
Select `allowit_simple_policy_engine.wasm`, `allowit_common_policy_engine.wasm`, or a reviewed
`allowit_custom_policy.wasm`. Config contains exactly `owner`, `agent`, `server`, `asset`,
`policy_instance`, `source_digest`, `rules`, `params`, and `x402_enabled`.
The asset is an immutable native SAC. `policy_instance` and `source_digest` are 32-byte hex
strings, and `policy_instance` is nonzero.
`rules` contains the ordered standard prefix of canonical rule names. The tool derives it from the
authored `--policy-source` file and rejects any other list: Common binds the source's prefix,
Simple and Custom bind an empty list. `--tier custom` also requires `source_digest` to be the
SHA-256 of that file. Owner `deploy_policy` packets take the same two options for the target tier.
Every tier requires one self-contained, portable source file. The tooling rejects every
construct listed in [One portable policy source](architecture.md#one-portable-policy-source), such
as macros other than the assertion and `matches!` macros, writes to `ctx.env`, the map inside params
and args, list methods, indexing and pointer-width methods. Simple and Common store only standard
state, so the tool rejects their packets when the source calls `allowit::set_state`. It also runs the std-only
compile described there, so it needs `rustc`. For `--tier custom`, also build the
reviewed custom Wasm from the same file, which is the Soroban compile.

Params JSON is an object of key => value, at most 32 keys of 1 to 32 ASCII letters, digits or
underscores. An absent key is unset. The tool infers each value's `AllowitValue` type: an integer is
`Int`, a boolean `Bool`, a G or C address `Addr`, other text `Str` and a list `List`. A one-key
object such as `{"Str": "GA..."}` names the type explicitly. A value holds at most 64 nested values,
and a text at most 256 bytes. All params encode in at most 16 KiB, counted as the wallet counts
them: 40 bytes per key, 80 per value and each text padded to four bytes. Full allowlists fit beside
every other canonical param and 28 `operations` entries of the longest form. Simple and Common admit only the canonical keys `payment_limit`,
`lifetime_spending_limit`, `daily_spending_limit`, `daily_volume_limit` (nonnegative integers), `call_limit`, `expires_at`
(unsigned 64-bit integers), `destinations` and `tokens` (address lists), and `operations` (`"*"` or
a list of op names, such as `["transfer"]`). Custom admits its policy's
own keys, such as `vendor_cap`. A Custom policy state holds at most 39 keys, the seven standard keys
and 32 policy keys, and 16 KiB counted the same way. No call deletes a state key, and
`deploy_policy` keeps the state, so a policy write past either bound denies every operation that
makes it. The standard
preflight skips an absent selected rule; full policy code denies it. The tool accepts such a packet and prints a warning.
Legacy names such as `per_transfer`, `daily_limit` or `max_calls` reject on the standard tiers.
Negative caps reject at standard configuration. Code changes defer the new tier validation to
delegated admission.
Duplicate JSON keys reject. Fund the wallet only with its
installed asset. `recover` transfers only that asset. A forward swap can leave the wallet holding
another Stellar Asset Contract token. Common and Custom can restrict that token with `tokens`;
Simple relies on the server. Only a reverse swap or an owner `invoke` of that token's `transfer`
moves it; `recover` cannot.

`admin --family wallet --contract ADDRESS --source "$OWNER" --method METHOD --arguments JSON` admits
`deploy_policy`, `set_pause` and `recover`. Parent administration uses `--family parent`, its native
admin source and three `--member` values.

A deployment argument contains exactly `deployment_version`, `owner`, `agent`, `server`,
`source_digest`, `rules`, `params`, `x402_enabled`, and `wasm_hash`. The target version is current plus
one. Use null for unchanged code. A non-null `wasm_hash` also requires `--wasm PATH` with that hash;
the tool refuses Wasm without `allowit_custody_layout` metadata equal to 4. Code for another custody
layout cannot read the stored State, so such a change, including a rollback to an earlier release,
locks custody permanently. Recover funds before any change across layouts. Deployment preserves
pause and policy state. A changed owner must also authorize. `x402_enabled` enables custom-account authorization: the agent can then send a plain x402 `asset.transfer`, a plain `router.swap_exact_tokens_for_tokens` or a plain `vault.redeem`, and the wallet's `__check_auth` applies the policy to it. Enable it for payments only when swaps and redeems are also acceptable. On Common and Custom the `operations` and `destinations` rules can still deny them; on Simple only the server's offchain policy does. Enabled custom-account authorization requires distinct G-agent and G-server keys and both signatures.
False disables all three plain calls without changing direct two-role execution authorization. Classic signer rotation and `shutdown-wallet` do not revoke raw-key delegation. The contract wallet owner must disable `x402_enabled`, pause, or replace the agent/server address through `deploy_policy`.

Owner passthrough uses `invoke(contract, function, args, auth)`. Prepare this exact call with the
native CLI and inspect every nested authorization entry. This general owner operation is outside
the restricted admin tool's method allowlist. Only the current owner can authorize it.

`set_pause` takes `paused` and the next `deployment_version`. `recover` takes `recipient` and positive
native `amount`, with no configuration version or usage update. Parent methods use their separate current `version`. `set_admin` takes the candidate `owner`. Argument fields must match the chosen method. The tool admits native owner
accounts with only their active master signer and satisfiable thresholds. Parent `set_admin` checks
its candidate's exact 2-of-3 membership. Other owner authorization schemes require their own adapter.

Owner/admin handoffs require both authorities on the same intent. Envelope signing alone does not
fill independent Soroban authorization entries. Collect and check them before submission. Preparation
does not establish candidate acceptance. Review the exact invocation roots, allowed constructor
children, resource fee and footprint. `--max-fee` bounds total/resource fees in stroops. Prepared
envelopes expire after five minutes. Save signed bytes before broadcast and reconcile the original
hash after an uncertain response. The tool never signs, submits, restores or retries automatically.

Use `read --contract POLICY_WALLET_ADDRESS --source "$OWNER" --method policy_binding` to inspect the contract
release, policy instance, module/source digests and the operations that the wallet runs. `state` returns the custody
State, including `params` and `policy_state`; `policy_state` returns the current policy state map
alone. Archived data requires native restoration and is never reinitialized.
The SDK rejects unavailable or ambiguous state observations before new signing. Owner pause,
deployment and recovery do not depend on shared engine availability.

Wallets with layout `contract_version` 1 (text-keyed params map), 2 (accounting history struct) or
3 (typed canonical params and raw state values) cannot execute under layout 4, and their accounting
does not migrate. Owner `recover` and `invoke` still work after an in-place upgrade, because they
read only the fields they keep; `deploy_policy` rejects an earlier layout with `InvalidState`. Drain
such a wallet with `recover` and deploy a new one. `contract_admin.py` builds `deploy_policy`
packets only for layout 4; read an earlier state with that release's tooling. `recover` does not read `state()`, so the tool also drains an upgraded wallet.

Normal operations do not migrate state. An incompatible change uses this explicit maintenance
sequence: pause, deploy and run a migration contract, deploy the new contract using the migrated
state, then unpause. Compatible code updates retain the installed format, policy state and replay records.

The parent stores `owner`, `version` and `engine`. Wallet deployment and contract release versions remain separate.
Older parent state uses different field names. Migrate that state explicitly before installing this parent executable on an existing address.
