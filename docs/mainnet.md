# Mainnet contract preparation

`mainnet_release.py` prepares bounded, unsigned Stellar release packets. It never signs or broadcasts. Keep plans, authorization requests and packets in a private directory. Do not place keys or seeds in them. Python and CLI versions follow [administration](admin.md).

The tool pins one reviewed contract source revision, every build input and the exact engine, parent and `AllowitCommonPolicyEngine` Wasm hashes. The previous pins (`b5a5d4b13e9162dc9034df85442ea2251f65a845`) store custody layout 1, so the tool rejects every plan until a reviewed release of layout 4 is pinned. The smoke wallet selects the `destinations`, `payment_limit`, `daily_volume_limit`, `lifetime_spending_limit`, `call_limit` and `expires_at` prefix, with the same-named canonical params. The wallet `source_digest` is the standard prefix digest derived from the wallet artifact hash. Executions carry the SHA-256 of the literal six-call source in the tool as `source_hash`; the tool computes it at startup. Each execution signs conservative XLM expense ceilings: the full execute fee cap is gas, and spent units are payment plus gas. The separate parent manages a shared checker; it has no custody authority over this wallet.

## Plan and accounts

Build the pinned contracts with `scripts/build-contracts.sh`. Write the manifest with `python scripts/artifacts.py --output /PRIVATE/manifest.json`. A later tooling revision is admitted only when every contract build input still matches the pinned source. Copy [the plan template](../scripts/mainnet-plan.example.json), replace its placeholders and select a future `expires_at` param. Artifact paths can be absolute or relative to the plan.

Use separate owner, agent, server and recipient accounts. Owner, agent and server each require only their native master key. The parent administrator requires three distinct weight-one Ed25519 members and thresholds 2/2/2. The server co-signer is separate from the parent-managed checker. The tool checks these authority profiles and does not change them.

Fund the accounts independently. Keep each source above its classic reserve and assigned stage fee caps. The owner also needs the funding principal. Check liabilities and pending transactions separately; preflight does not calculate spendable balances. The example caps total 50 XLM. Initial wallet funding is capped at 0.002 XLM and the single smoke payment at 0.001 XLM. These are ceilings, not fee quotations.

```sh
python scripts/mainnet_release.py check --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/check.json
python scripts/mainnet_release.py preflight --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/preflight.json
```

`check` is offline and reports the unique packet directory. `preflight` reads public network and account state. Every CLI request uses the selected RPC endpoint and network passphrase.

## Prepare and reconcile

Obtain approval before exporting private Wasm or transaction arguments to a public RPC. Use `--allow-payload-export` only after that approval. It permits preparation, not signing or payment.

Stages are `upload-engine`, `upload-parent`, `upload-wallet`, `deploy-parent`, `deploy-wallet`, `fund`, and `execute`. Each requires successful settlement of previous original packets. The parent constructor creates its checker. The Common wallet constructor receives the owner, agent, server, immutable XLM asset, source identity, selected rules and params. The `deploy-wallet` stage binds that packet to the Common tier and the release's smoke policy source, as `contract_admin.py --tier common --policy-source` does, so it needs `rustc`. It disables x402 for this direct-transfer smoke plan.

```sh
python scripts/mainnet_release.py prepare --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --stage upload-engine --output /PRIVATE/packets-PLAN_DIGEST/upload-engine.json
python scripts/mainnet_release.py settle --plan /PRIVATE/plan.json --allow-mainnet --prepared /PRIVATE/packets-PLAN_DIGEST/upload-engine.json --output /PRIVATE/upload-engine-status.json
```

Between preparation and settlement checks, review the exact unsigned packet with an independent secure wallet. Archive signed bytes before an operator broadcasts them. These tools provide no broadcast operation. For funding and execution, provide `--parent` and `--wallet` from their original settled deployment packets.

Each stage has one immutable packet path. Do not overwrite a packet or prepare a replacement under the same plan. Preserve expired, failed and uncertain packets, reconcile them, and obtain a separately reviewed plan before replacement. Copied plans and other signing tools are outside this local cap.

## Two-party execution authorization

Execution requires the agent's transaction signature and separate native server authorization. It uses two preparation steps:

```sh
python scripts/mainnet_release.py prepare --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --stage execute --parent C_PARENT --wallet C_WALLET --operation-id HEX --output /PRIVATE/packets-PLAN_DIGEST/execute-auth.json
python scripts/mainnet_release.py complete-execute --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --prepared /PRIVATE/packets-PLAN_DIGEST/execute-auth.json --server-auth /PRIVATE/signed-server-auth.xdr --output /PRIVATE/packets-PLAN_DIGEST/execute.json
```

The first packet is not ready for transaction signing. An independent server signer must review and sign its exact `server_authorization_xdr` using the plan's network passphrase. Return the complete signed Soroban authorization entry, without changing its invocation, nonce or ledger expiry. The tool never requests a server key.

Completion verifies the server signature, current signer profiles, original transaction, wallet state, exact principal and authorization window. It then runs an enforce-mode simulation with the signed server entry. Only resource data and a bounded fee can change. The result still has no transaction-envelope signatures. The agent can review and sign that final packet through its secure wallet. Do not sign the earlier authorization request as a transaction.

## Simulations and settlement

After funding, use `simulate-e2e` with the parent, wallet and a nonzero operation ID. It checks a positive receipt, forbidden recipient, excessive amount, stale deployment version and expiry. After execution, a fresh operation ID plus `--replay-id ORIGINAL_HEX` checks replay rejection. These record-mode simulations do not establish actual signatures or settlement; completion separately enforces the server signature.

`settle` queries the original transaction hash. Missing or uncertain results stay unresolved. Success requires the exact receipt and a charged fee within the original bid and stage cap. Funding checks the wallet's exact balance increase. Execution checks wallet and recipient balances plus the standard policy state keys `calls` and `spent` (payment plus gas ceiling). Concurrent owner activity can prevent exact comparison and requires reconciliation. Use a new status-output filename for each observation.

Read simulations do not renew TTL. Follow [administration](admin.md) for submitted lifetime maintenance and restoration. Network deployment and live settlement require separate operator authorization.
