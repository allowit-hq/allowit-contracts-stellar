# Wallet administration

These tools prepare transactions. They do not fund accounts, sign, submit or retry them. Use existing funded accounts. Native preparation reads current sequence and signer state from Horizon. Contract preparation uses Stellar CLI 28.1.0 and RPC. Its `--build-only` flag returns raw, unassembled XDR. The contract tool adds five-minute time bounds, then runs `stellar tx simulate` to assemble resource fees, footprint and authorization entries. It rejects changes to transaction intent or unexpected signatures. Its output is assembled unsigned XDR. `--send=no` returns a read simulation result, not unsigned XDR.

One Rust binary, `allowit-stellar-admin`, does this work. Build it from `crates/allowit-stellar` and use Stellar CLI 28.1.0 for the contract actions:

```sh
cargo build --locked --release --manifest-path crates/allowit-stellar/Cargo.toml --bin allowit-stellar-admin
ADMIN_BIN=crates/allowit-stellar/target/release/allowit-stellar-admin
cargo test --locked --manifest-path crates/allowit-stellar/Cargo.toml --bin allowit-stellar-admin
```

The native actions are `inspect`, `verify-admin`, `setup-admin` and the per-agent wallet actions `verify-agent-wallet`, `fund-agent-wallet`, `pause-agent-wallet`, `resume-agent-wallet`, `withdraw-agent-wallet` and `close-agent-wallet`. `verify-wallet`, `setup-wallet` and `shutdown-wallet` are legacy: see [Legacy owner-account profile](#legacy-owner-account-profile). The contract actions are `upload`, `deploy-parent`, `deploy-wallet`, `read` and `admin`. A preparing action prints unsigned base64 XDR on standard output. A refusal prints one line on standard error and exits with status 1; a usage error exits with status 2. An address error never repeats its input. `--help` prints the usage. Run the binary from this checkout: the owner-packet compile reads the locked Core sources through `cargo metadata`.

The release scripts `scripts/testnet_release.py` and `scripts/mainnet_release.py` use the Python modules `scripts/contract_admin.py` and `scripts/wallet_admin.py` for the same checks. Those modules have no command line. The binary's tests reproduce recorded outputs of both modules (`crates/allowit-stellar/tests/fixtures/native_admin_vectors.json` and `contract_admin_vectors.json`), so the two implementations agree.

Select `--network testnet` explicitly. Mainnet preparation additionally requires `--allow-mainnet`. Public addresses and hashes belong in arguments. Never pass secret seeds. Use Stellar CLI identities backed by the OS secure store for manual signing. `STELLAR_BIN` selects the CLI executable for contract tooling. Contract subprocesses ignore inherited Stellar signing and network overrides.

## Native wallet and engine administrator

The classic CLI retains `--engine` for its service co-signer. This means the wallet `server` role, not the parent-managed shared checker address.

### One wallet account per agent

A Native wallet is its own classic account. Each agent gets one. The owner's account is never the wallet.

| Signer | Weight | Authority |
| --- | --- | --- |
| Owner | 3 | Everything, alone: payments, signer changes, the account merge |
| Agent | 1 | Payments, only together with the server |
| Server | 1 | Payments, only together with the agent |
| The account's own key | 0 | None after setup |

The thresholds are 2 (low), 2 (medium) and 3 (high). Agent and server together reach 2. Neither reaches it alone, and together they stay below 3, so they cannot change signers or merge the account. The server co-signs a payment only after its policy check.

**Setup** is one transaction from the owner's account, in `allowit_stellar::owner`. The owner's account pays the fee and the starting balance. The operations create the account, add the owner, the agent and the server as signers, set the thresholds and set the weight of the account's own key to 0. All of it applies atomically. Two signatures are needed: the owner's, and one signature of the new account's own key, because the new account is the source of its own signer operations. A wallet for an issued asset also adds its trustline in the same transaction.

The new account's key is derived, so nothing extra is stored. The owner signs a fixed message that names the network, the agent and a wallet index, through the same message signing as the owner sign-in (SEP-53). The key seed is `SHA-256("allowit-stellar-native-wallet-seed-v1" || signature)`. Ed25519 signatures are deterministic, so the same owner key derives the same account again from the same three values. A signer that signs the same message in two ways still yields a usable one-time key; the setup result then reports `derivation.method` `one-time`, and the address cannot be computed again. After setup the key has weight 0 and carries no authority.

The starting balance holds the reserve of the account: two base reserves and one for each signer, 2.5 XLM, and 0.5 XLM more for a trustline. That reserve stays locked in the account until the owner closes it. Without a named amount the setup sends the reserve and 0.5 XLM for the network fees of the wallet's own payments.

Setup never replaces existing authority. A wallet account that already exists is admitted only with the exact roles. Any other signer, a hash, pre-authorized or signed-payload signer, a threshold other than 2/2/3 or a weight on the account's own key is refused, and nothing is signed. A setup transaction cannot apply twice: the account already exists, and the owner's sequence moved.

**Owner actions** each need one owner signature. The owner's account is the transaction source and pays the fee, so the agent and the server cannot interfere through the wallet's sequence.

```sh
"$ADMIN_BIN" verify-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE"
"$ADMIN_BIN" fund-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE" --amount 100000000 > /tmp/fund.xdr
"$ADMIN_BIN" pause-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE" > /tmp/pause.xdr
"$ADMIN_BIN" resume-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE" > /tmp/resume.xdr
"$ADMIN_BIN" withdraw-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE" --amount 50000000 > /tmp/withdraw.xdr
"$ADMIN_BIN" close-agent-wallet --network testnet --account "$WALLET" --owner "$OWNER" --agent "$AGENT" --engine "$ENGINE" > /tmp/close.xdr
```

- `fund` sends XLM from the owner's account to the wallet.
- `pause` removes the agent signer. The server alone is below the payment threshold, so no payment settles. `resume` restores the agent signer.
- `withdraw` sends funds from the wallet to the owner, or to `--recipient`.
- `close` removes every signer and merges the account into the owner's account. The balance and the reserve return to the owner. The network checks every signature before the first operation, so the owner's signature also authorizes the merge after its own signer is removed.

Amounts are in stroops. The binary prepares these actions for a wallet that holds XLM. The server prepares the same actions for an installed wallet through its owner routes; for a wallet with an issued asset, `close` first returns that asset and removes its trustline.

Verification reads the account's signers, weights and thresholds. The server reads them before every co-signature and refuses a wallet whose signers or thresholds differ from its registered roles.

### Legacy owner-account profile

Earlier releases turned the owner's own account into the wallet: the account key had weight 3, and agent and server were added with weight 1 under thresholds 2/2/3. Agent and server together could then spend the owner's whole account, and one owner account served one agent. No server registers that profile any more.

`setup-wallet`, `verify-wallet` and `shutdown-wallet` still prepare and verify it, so an owner can verify and shut down such an account. The release scripts do not use them. `shutdown-wallet` atomically removes agent and engine and raises all thresholds to 3. Only the owner can authorize it. Prefer `--transaction-source OTHER_OWNER_ACCOUNT` to use an independent owner-only fee/sequence account. Verification rejects open Horizon offers. Shutdown reports offers but still prepares signer removal. Removing signers does not revoke persistent SAC allowances, liquidity positions or prior issuer changes.

Prepare a separate native engine administrator with `setup-admin --account "$ADMIN" --member "$A" --member "$B" --member "$C"`. The three distinct members receive weight 1. All thresholds are set to 2. The account master gets weight 0 unless it is one of those members. `verify-admin` checks that exact configuration. Keep the necessary master and member secure-store identities available before setup.

Review and sign the exact XDR manually:

```sh
stellar tx decode /tmp/setup.xdr
stellar tx sign --network testnet --sign-with-key owner-secure-identity /tmp/setup.xdr > /tmp/setup-signed.xdr
stellar tx send --network testnet /tmp/setup-signed.xdr
```

The administrator account signs its initial setup under its existing master authority. Later admin operations need two member signatures on the same envelope. Native envelopes expire after five minutes and bind the next account sequence. Do not reuse them after other transactions consume that sequence. After an uncertain submission, check the original transaction hash and ledger state before preparing a replacement.

## Contract setup and owner administration

[Engine parent](engine-parent.md) defines parent state, executable references, version ordering and recovery.

Run `scripts/build-contracts.sh` before contract tests or deployment preparation. It checks policy
bindings, builds the test fixtures, then rebuilds the default deployable artifacts. Select the
reviewed source and placement manifest when preparing a policy executable.

Use `allowit-stellar-admin upload --source "$OWNER" --wasm PATH` separately for the engine, parent and
policy wallet Wasm. Review, sign and submit prepared uploads manually, retaining each resulting hash.

Prepare `deploy-parent --source "$ADMIN" --owner "$ADMIN" --engine-wasm HASH --wasm
 target/wasm32v1-none/release/allowit_engine_parent.wasm --wasm-hash PARENT_HASH`, with three
`--member` values. The tool verifies the native admin quorum, local Wasm and creation executable
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
and args, list methods, indexing other than `ctx.params[key]` and pointer-width methods. Simple and Common store only standard
state, so the tool rejects their packets when the source calls `allowit::set_state`. It also runs the std-only
compile described there, so it needs `rustc`. For `--tier custom`, also build the
reviewed custom Wasm from the same file, which is the Soroban compile:

```sh
scripts/build-custom-policy.sh POLICY.rs OUT_DIR
```

The script builds the committed tree with `POLICY.rs` as `contracts/allowit-custom-policy/policy/policy.rs`
and leaves the checkout unchanged. It prints one JSON line with `source_digest` (the SHA-256 of
`POLICY.rs`, the wallet `source_digest`), `wasm_hash` (the SHA-256 of the Wasm, the `--wasm-hash`)
and the `wasm` path. The same revision, source, Rust toolchain and Stellar CLI give the same Wasm.

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
own keys, such as `vendor_limit`. A Custom policy state holds at most 39 keys, the seven standard keys
and 32 policy keys, and 16 KiB counted the same way. No call deletes a state key, and
`deploy_policy` keeps the state, so a policy write past either bound denies every operation that
makes it. The standard
preflight skips an absent selected rule; full policy code stops with `MissingParam` when it reads it. The tool accepts such a packet and prints a warning.
Legacy names such as `per_transfer`, `daily_limit` or `max_calls` reject on the standard tiers.
Negative limits reject at standard configuration. Code changes defer the new tier validation to
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
such a wallet with `recover` and deploy a new one. The tool builds `deploy_policy`
packets only for layout 4; read an earlier state with that release's tooling. `recover` does not read `state()`, so the tool also drains an upgraded wallet.

Normal operations do not migrate state. An incompatible change uses this explicit maintenance
sequence: pause, deploy and run a migration contract, deploy the new contract using the migrated
state, then unpause. Compatible code updates retain the installed format, policy state and replay records.

The parent stores `owner`, `version` and `engine`. Wallet deployment and contract release versions remain separate.
Older parent state uses different field names. Migrate that state explicitly before installing this parent executable on an existing address.
