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

This crate maps the canonical `ExecutionRequest` to the admitted `stellar::sep41_transfer` profile. Native classic custody checks the current account weights and applicable transaction and payment thresholds. The 3/1/1 weights and 2/2/3 thresholds are deployment templates, not admission requirements. Policy wallet custody calls the selected implementation’s public `execute` entrypoint with exact native arguments, installed executable, schema and source identity.

`config.policy_engine` selects SimplePolicyEngine, CommonPolicyEngine or CustomPolicy. `config.server` is the independent G-address service signer. `admin::PolicyConfig::for_policy` binds the selected implementation to complete source, exact Common selectors and owner configuration. `constructor_args` emits the single `PolicyConfig` constructor packet. Custom source is emitted by `stellar-native POLICY.rs`; fixed Simple/Common artifacts use configuration instead of source-specific code. Discovery verifies the installed executable, source digest, engine kind, asset and complete selector list.

The source profile admits local asset, recipient and monetary guards, boolean control flow and explicit rejection. Unsupported or external-evidence expressions fail admission. USDC helper constants retain their six-decimal meaning and lower to seven-decimal SAC comparisons. Native request amounts and counters remain exact base units. Raw source integer amount fields are rejected because their unit projection is ambiguous. XLM supports admitted asset and recipient guards; USDC financial helpers cannot be used for XLM.

For a policy wallet, call `rpc::prepare`, then `authorize_server(prepared, seed, now, accounting)`, then `rpc::simulate` again. Initial simulation records authorization on a copy of the intent without auth entries, because Stellar RPC rejects recording mode when entries are present, and checks the recorded scope against the intent's entries. The second simulation enforces the signed service authorization and computes the final resource needs, including the service entry's nonce key. Only then deliver the prepared packet for agent revalidation and signing. Agent and service authority are both required. Direct execution requires an existing Stellar server account whose configured key meets its current medium threshold. Preparation reads that account and checks its quorum; enforce-mode simulation checks actual native authorization. The service authorization changes the transaction hash; the agent signs the final transaction. The service entry's nonce derives from the network, the policy wallet address, the operation nonce, the deployment version and the service key. Soroban tracks authorization nonces per signer, so one service key can serve several policy wallets.

Simple requires authoritative durable `NativeAccounting` at service authorization. The SDK evaluates the exact scalar source and request using those counters and checks nonce/version against live custody. A successful Simple simulation alone is not business-policy approval. Common and Custom require native policy preflight and reject service accounting overrides. Keep service accounting under a stable wallet/network/policy identity across owner configuration, code and source changes. Do not reset it from Grant or current balance. Preserve outstanding reservations and uncertain submissions; charge each verified receipt once.

Use `rpc::trusted_state_for_discovery` for public network, account and policy wallet binding discovery without requiring a formerly configured customer signer. Its `DiscoveredState` reports both live authority and whether a policy wallet is paused. Discovery does not authorize an operation. `rpc::trusted_state` checks the presented customer key against current authority. Native accounting must come from the durable policy coordinator.

The current policy wallet agent account can have multiple signers. The customer signing key is `config.agent`; the policy wallet transaction source and fee payer are the current agent account in `state.source.address`. Additional Ed25519, hash, preauthorized and signed-payload keys do not lock out a sufficient current customer quorum.

Classic authorization verifies both customer and server role proofs. Exact quorum checks include matching transaction preauthorizations; policy wallet checks use the final hash after resource simulation. The transaction envelope contains only the signatures needed by current chain thresholds, including any matching preauthorization, so unused signatures cannot invalidate it. High-threshold administration and owner weights are reported from live state rather than imposed by this transfer profile.

`prepare`, `sign` and `authorize` bind the exact request and signatures. Native transactions bind their operation ID in the hash memo. Soroban transactions use no memo and bind the same identity inside the signed `execute` arguments.

New native bounds start at zero and end at the exact approved expiry. Retained native bounds may start at their original creation time. Validation preserves those signed bytes for status and refuses new authorization.

Policy wallet preparation needs resource simulation before signing. Native configuration permits at most 1,000,000 stroops (0.1 XLM) in fees. The policy wallet ceiling is 2,000,000 stroops (0.2 XLM). The exact request must cover the installed fee bound. Simulated resource fees plus inclusion fee must fit that bound. Preparation never increases it.

`validate_retained_prepared` and `validate_retained_signed` verify the original transport, effects, hashes and signatures without compiling policy source. Use them only for read-only history and original-hash recovery. Native transaction signatures do not prove the accompanying policy source metadata. Before calling these helpers, compare that metadata with the original owner-approved binding in the durable record or client token. New preparation, signing and first broadcast still require current policy admission and fresh transaction bounds.

`rpc::submit` retains signed bytes before broadcast. `recover` queries the original transaction hash. A later `submit` of the same operation queries that hash first; while the transaction is not on the ledger and the signed operation is still valid, it resends the same bytes, for example after `TRY_AGAIN_LATER`. The same sequence number and hash mean the network includes them at most once. An uncertain broadcast never authorizes a replacement payment or releases its reservation. Terminal settlement remains distinct from external delivery.

The signing seed stays with its actor. Wallet configuration contains public installation data. Historical signed packets remain read-only and cannot start new preparation. `rpc::checker_version` requires an explicit shared checker contract address; the service signer is never used as a checker address. Client-held signing material must remain private and is not part of public wallet configuration. Production promotion is a separate operation.

`x402::SigningRequest` describes one exact SAC transfer authorization. Its `WalletState` includes verified custody, engine kind, pause and owner-enabled x402 state; mismatched or disabled state rejects before digest construction. `signing_digest` derives the contract's domain-separated digest from the network, full authorization tree and native execution request. External agent and server signers review that request and sign the digest independently. `assemble` verifies both signatures and emits the exact `PolicyAuthorization`; it rejects missing, swapped or transplanted signatures. These encoding helpers do not approve a policy or accept payer-supplied state as trusted. Each actor must use current trusted binding and state; the service applies the same Simple accounting or Common/Custom native-preflight requirement before signing. The facilitator simulates the final transaction in enforce mode.

The owner must enable x402. Its raw Ed25519 keys need no funded G-accounts. Native account signer or threshold changes do not revoke those raw keys; rotate the wallet's configured keys or disable x402 through an owner-authorized deployment. Direct execution continues to use native account authorization.

`admin::OwnerAdmin` prepares unsigned owner transactions for `deploy_policy`, `set_pause` and `recover`. It simulates each one in recording mode without auth entries, checks that the recorded entries name exactly the required owners (the current owner, plus the new owner for an owner handoff through `deploy_policy`), and puts those entries in the unsigned transaction for the owners to sign.

An owner handoff returns the new owner in `pending_authorizers`. Its transaction cannot be submitted yet, and its hash is provisional. The new owner signs its recorded entry with a `signature_expiration_ledger` after the latest ledger. `OwnerAdmin::complete_owner_handoff` checks that entry and its signature, simulates again in enforce mode for the final fee and resources, and returns the final transaction and hash. The current owner signs only that transaction.

`recover` moves the full balance observed at preparation. An agent payment that settles first makes it fail with `InsufficientFunds`. Pause automation with `set_pause` before a recovery.
