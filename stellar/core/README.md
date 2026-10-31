# Stellar rail core

*Prepare, authorize and settle a policy-bound Stellar transfer, with the agent and the service each holding their own key.*

`allowit-stellar-wallet` is the Stellar rail core. It turns a canonical execution request into an exact Stellar transaction, routes it through the custody the owner chose (a classic G-address account or a policy wallet contract), collects the two required authorizations, and keeps the signed bytes so an uncertain broadcast can be recovered instead of repeated. The custody contracts themselves live in the [`crates/`](../../crates) folder of this repository; the engine of the [Allowit SDK](https://github.com/allowit-hq/allowit-sdk) composes this crate on the agent's behalf.

Run its checks with:

```sh
cargo fmt --manifest-path stellar/core/Cargo.toml --check
cargo test --locked --manifest-path stellar/core/Cargo.toml
cargo clippy --locked --manifest-path stellar/core/Cargo.toml --all-targets -- -D warnings
```

The rest of this page is the reference for how the crate behaves.

## Request profile and custody

This crate maps the canonical `ExecutionRequest` to one admitted native operation: a `stellar::sep41_transfer` SEP-41 transfer, or a `stellar::sep56_deposit` SEP-56 deposit into a vault for a policy wallet. Each operation has its own argument schema (`TRANSFER_SCHEMA`, `DEPOSIT_SCHEMA`). Native classic custody checks the current account weights and applicable transaction and payment thresholds. The 3/1/1 weights and 2/2/3 thresholds are deployment templates, not admission requirements. Classic custody admits only a transfer.

Policy wallet custody calls the layout 4 `execute` entrypoint (`CONTRACT_VERSION` 4). The execute request carries the exact native arguments, the installed executable and schema, `source_hash`, the server-attested `expense` (`AllowitExpenseBounds`, gas in the wallet asset) and the agent's bounded `args` (`Map<Symbol, AllowitValue>`). `ExecutionTerms` holds `args` and `expense`; agent and server sign them with the request.

## Policy tiers and source

`config.tier` selects `simple`, `common` or `custom`. `config.language` is `portable` for every policy wallet. `config.rules` holds the ordered canonical rules: the standard prefix for Common, none otherwise. `config.params` holds the owner params at installation: the canonical keys in `PARAM_KEYS` plus Custom keys. `config.sourceDigest` is the standard prefix digest for Simple and Common, and the SHA-256 of the source for Custom. `config.server` is the independent G-address service signer.

`policy::source_shape` is the Rust port of the `scripts/policy_source.py` gate: one self-contained file, `allowit` as the only path root, the macro, attribute and identifier allowlists, and one `pub fn execute(ctx: &AllowitContext) -> allowit::Result`. It returns the standard prefix, whether the source is canonical-only and whether it writes state. `policy::params_from_json` matches `scripts/contract_admin.py` `params`, and `policy::policy_rules` matches its `policy_rules`. `tests/policy_vectors.rs` replays vectors that `scripts/policy-core-vectors.py` records from the Python tools. The std-only host compile stays in the server build gate.

`policy::evaluate` runs a policy on the host as the wallet does. A Common wallet runs its standard prefix first. A canonical-only source, or any source with a compiled evaluator, then runs in full. Otherwise the result is `Evaluation::Prefix`: only the onchain part ran. The legacy `allowit::v1` compiler verifies only legacy-language classic installs.

## Owner setup

`admin::PolicyConfig::for_policy` builds the `AllowitPolicyConfig` constructor packet of a validated installation, and `constructor_args` emits it. `admin::Deployer` prepares unsigned setup transactions through Stellar RPC simulation:

- `upload_wasm` prepares `UploadContractWasm` of wallet code that declares custody layout 4 (`check_wallet_code`).
- `create_wallet` prepares `CreateContractV2` with the constructor packet. The owner is the transaction source and must be owner-only. `wallet_address` derives the wallet address from the owner and salt.

`admin::validate_auth` admits only the exact authorization scope of the host function. `admin::check_assembled` applies the `contract_admin.py` `prepare_xdr` intent checks to an assembled transaction: an unsigned v1 transaction from the source with one host function, where simulation added only authorization, resources and their fee within the ceiling. `admin::sign_owner_transaction` signs an unsigned prepared transaction as its G-account source. `rpc::send_and_poll` submits signed bytes and polls the original hash; `TRY_AGAIN_LATER` resends the same bytes, and an unknown result names the hash for a later lookup.

## Service and agent authorization

For a policy wallet, call `rpc::prepare`, then the service authorization, then `rpc::simulate` again. Initial simulation records authorization on a copy of the intent without auth entries, because Stellar RPC rejects recording mode when entries are present, and checks the recorded scope against the intent's entries. The second simulation enforces the signed service authorization and computes the final resource needs, including the service entry's nonce key. Only then deliver the prepared packet for agent revalidation and signing. Agent and service authority are both required. Direct execution requires an existing Stellar server account whose configured key meets its current medium threshold. Preparation reads that account and checks its quorum; enforce-mode simulation checks actual native authorization. The service authorization changes the transaction hash; the agent signs the final transaction. The service entry's nonce derives from the network, the policy wallet address, the operation nonce, the deployment version and the service key. Soroban tracks authorization nonces per signer, so one service key can serve several policy wallets.

The service evaluates the installed policy on the host before it signs. A Custom wallet runs its whole policy onchain, so native preflight completes it; use `authorize_server(prepared, seed, now, None)`. A Simple or Common wallet runs at most its standard prefix onchain. If its source is not canonical-only, use `authorize_server_with(prepared, seed, now, evaluator)` with the evaluator that the server build gate compiled from `config.policy_source`; a prefix-only evaluation is refused. Layout 4 keeps standard accounting onchain, so `authorize_server` rejects service accounting.

`rpc::revalidate_prepared` revalidates an existing unsigned packet through a trusted RPC without changing its transaction or hash. Fresh resource requirements must fit the existing resources, and quorum is checked on the unchanged original transaction, so an exact-hash preauthorization of the source stays valid.

`rpc::operation_receipt` reads the settled receipts of an operation from the wallet's persistent storage. A transfer has a `TransferReceipt`. A deposit also has a `DepositReceipt` with the settled share credit; its transfer receipt is the underlying debit to the vault.

Use `rpc::trusted_state_for_discovery` for public network, account and policy wallet binding discovery without requiring a formerly configured customer signer. Its `DiscoveredState` reports both live authority and whether a policy wallet is paused. Discovery does not authorize an operation. `rpc::trusted_state` checks the presented customer key against current authority. Classic custody accounting must come from the durable policy coordinator; a policy wallet reads its standard accounting from the wallet.

The current policy wallet agent account can have multiple signers. The customer signing key is `config.agent`; the policy wallet transaction source and fee payer are the current agent account in `state.source.address`. Additional Ed25519, hash, preauthorized and signed-payload keys do not lock out a sufficient current customer quorum.

Classic authorization verifies both customer and server role proofs. `SignedOperation.role_signatures` keeps both proofs, and `validate_signed` and the first `rpc::submit` broadcast require them, even when the customer weight alone meets the account thresholds. A retained record without role proofs stays valid for status and recovery only. Exact quorum checks include matching transaction preauthorizations; policy wallet checks use the final hash after resource simulation. The transaction envelope contains only the signatures needed by current chain thresholds, including any matching preauthorization, so unused signatures cannot invalidate it. High-threshold administration and owner weights are reported from live state rather than imposed by this transfer profile.

`prepare`, `sign` and `authorize` bind the exact request and signatures. Native transactions bind their operation ID in the hash memo. Soroban transactions use no memo and bind the same identity inside the signed `execute` arguments.

New native bounds start at zero and end at the exact approved expiry. Retained native bounds may start at their original creation time. Validation preserves those signed bytes for status and refuses new authorization.

Policy wallet preparation needs resource simulation before signing. Native configuration permits at most 1,000,000 stroops (0.1 XLM) in fees. The policy wallet ceiling is 10,000,000 stroops (1 XLM), because each wallet operation pays rent for a persistent replay entry at the network's longest lifetime. The exact request must cover the installed fee bound. Simulated resource fees plus inclusion fee must fit that bound. Preparation never increases it.

`validate_retained_prepared` and `validate_retained_signed` verify the original transport, effects, hashes and signatures without compiling policy source. Use them only for read-only history and original-hash recovery. Native transaction signatures do not prove the accompanying policy source metadata. Before calling these helpers, compare that metadata with the original owner-approved binding in the durable record or client token. New preparation, signing and first broadcast still require current policy admission and fresh transaction bounds.

`rpc::submit` retains signed bytes before broadcast. `recover` queries the original transaction hash. A later `submit` of the same operation queries that hash first; while the transaction is not on the ledger and the signed operation is still valid, it resends the same bytes, for example after `TRY_AGAIN_LATER`. The same sequence number and hash mean the network includes them at most once. An uncertain broadcast never authorizes a replacement payment or releases its reservation. Terminal settlement remains distinct from external delivery.

The signing seed stays with its actor. Wallet configuration contains public installation data. Historical signed packets remain read-only and cannot start new preparation. `rpc::checker_version` requires an explicit shared checker contract address; the service signer is never used as a checker address. Client-held signing material must remain private and is not part of public wallet configuration. Production promotion is a separate operation.

`x402::SigningRequest` describes one exact SAC transfer authorization. Its `WalletState` includes verified custody, tier, pause and owner-enabled x402 state; mismatched or disabled state rejects before digest construction. `signing_digest` derives the contract's domain-separated digest from the network, full authorization tree and native execution request. External agent and server signers review that request and sign the digest independently. `assemble` verifies both signatures and emits the exact `PolicyAuthorization`; it rejects missing, swapped or transplanted signatures. These encoding helpers do not approve a policy or accept payer-supplied state as trusted. Each actor must use current trusted binding and state. The server signs the digest only after `x402::verify_server(request, now, evaluator)` accepts it: it runs `verify_operation` on the exact request and terms and applies the same rule as the service authorization, so a Simple or Common source that is not canonical-only needs its compiled evaluator. The facilitator simulates the final transaction in enforce mode.

The owner must enable x402. Its raw Ed25519 keys need no funded G-accounts. Native account signer or threshold changes do not revoke those raw keys; rotate the wallet's configured keys or disable x402 through an owner-authorized deployment. Direct execution continues to use native account authorization.

`admin::OwnerAdmin` prepares unsigned owner transactions for `deploy_policy` (the next version with new params, rules or owner keys and the installed code), `deploy_code` (the same with uploaded layout 4 code installed atomically), `set_pause`, `recover` and `recover_to`. `PolicyDeployment::for_source` binds a source and params to the installed tier, as `contract_admin.py` does for an owner packet. Each call checks only what the contract entrypoint reads: `recover` reads the kept fields of any readable layout (1 to 4), so a wallet with a broken binding stays recoverable; `set_pause` and `deploy_code` also need the exact layout 4 state; `deploy_policy` also needs the installed executable and policy binding. Preparation simulates each call in recording mode without auth entries, checks that the recorded entries name exactly the required owners (the current owner, plus the new owner for an owner handoff), and puts those entries in the unsigned transaction for the owners to sign.

An owner handoff returns the new owner in `pending_authorizers`. Its transaction cannot be submitted yet, and its hash is provisional. The new owner signs its recorded entry with a `signature_expiration_ledger` after the latest ledger. `OwnerAdmin::complete_owner_handoff` checks that entry and its signature, simulates again in enforce mode for the final fee and resources, and returns the final transaction and hash. The current owner signs only that transaction.

`recover` moves the full balance observed at preparation. An agent payment that settles first makes it fail with `InsufficientFunds`. Pause automation with `set_pause` before a recovery.
