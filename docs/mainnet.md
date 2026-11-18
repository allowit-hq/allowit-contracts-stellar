# Mainnet contract preparation

`mainnet_release.py` prepares bounded, unsigned Stellar release packets. It never signs or broadcasts. Keep plans, authorization requests and packets in a private directory. Do not place keys or seeds in them. Python and CLI versions follow [administration](admin.md).

The tool pins one reviewed contract source revision, every build input and the exact engine, parent and `AllowitCommonPolicyEngine` Wasm hashes. Until a reviewed release of custody layout 5 is pinned, the tool rejects every plan. The smoke wallet selects the `destinations`, `payment_limit`, `daily_volume_limit`, `lifetime_spending_limit`, `call_limit` and `expires_at` prefix, with the same-named canonical params. The wallet stores the SHA-256 of the literal six-call source in the tool as its `source_hash`, and the plan's `gas_cap_stroops` as its gas cap. The separate parent manages a shared checker; it has no custody authority over this wallet.

## Plan and accounts

Build the pinned contracts with `scripts/build-contracts.sh`. Write the manifest with `python scripts/artifacts.py --output /PRIVATE/manifest.json`. A later tooling revision is admitted only when every contract build input still matches the pinned source. Copy [the plan template](../scripts/mainnet-plan.example.json), replace its placeholders and select a future `expires_at` param. Artifact paths can be absolute or relative to the plan.

Use separate owner, admin, agent, server and recipient keys. The owner requires only its native master key. The agent and the server are Ed25519 keys that need no account. The parent administrator requires three distinct weight-one Ed25519 members and thresholds 2/2/2. The server co-signer is separate from the parent-managed checker. The tool checks these authority profiles and does not change them.

Fund the accounts independently. Keep each source above its classic reserve and assigned stage fee caps. The owner also needs the funding principal. Check liabilities and pending transactions separately; preflight does not calculate spendable balances. The example fee caps total 49 XLM. Initial wallet funding is at most 0.002 XLM. These are ceilings, not fee quotations.

```sh
python scripts/mainnet_release.py check --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/check.json
python scripts/mainnet_release.py preflight --plan /PRIVATE/plan.json --allow-mainnet --output /PRIVATE/preflight.json
```

`check` is offline and reports the unique packet directory. `preflight` reads public network and account state. Every CLI request uses the selected RPC endpoint and network passphrase.

## Prepare and reconcile

Obtain approval before exporting private Wasm or transaction arguments to a public RPC. Use `--allow-payload-export` only after that approval. It permits preparation, not signing or payment.

Stages are `upload-engine`, `upload-parent`, `upload-wallet`, `deploy-parent`, `deploy-wallet` and `fund`. Each requires successful settlement of previous original packets. The parent constructor creates its checker. The Common wallet constructor receives the owner, the agent's and the server's keys, the immutable XLM asset, the source hash, the gas cap, the selected rules and params. The `deploy-wallet` stage binds that packet to the Common tier and the release's smoke policy source, as `contract_admin.py --tier common --policy-source` does, so it needs `rustc`.

```sh
python scripts/mainnet_release.py prepare --plan /PRIVATE/plan.json --allow-mainnet --allow-payload-export --stage upload-engine --output /PRIVATE/packets-PLAN_DIGEST/upload-engine.json
python scripts/mainnet_release.py settle --plan /PRIVATE/plan.json --allow-mainnet --prepared /PRIVATE/packets-PLAN_DIGEST/upload-engine.json --output /PRIVATE/upload-engine-status.json
```

Between preparation and settlement checks, review the exact unsigned packet with an independent secure wallet. Archive signed bytes before an operator broadcasts them. These tools provide no broadcast operation. For funding, provide `--wallet` from its original settled deployment packet.

Each stage has one immutable packet path. Do not overwrite a packet or prepare a replacement under the same plan. Preserve expired, failed and uncertain packets, reconcile them, and obtain a separately reviewed plan before replacement. Copied plans and other signing tools are outside this local control.

## Smoke payment

An agent payment needs the agent's and the server's signatures of the wallet's own authorization
and the server's sending account as the transaction source. Run the smoke payment through the
Allowit CLI and server with the plan's agent and server keys, after funding. This tool prepares no
agent payment.

## Settlement

`settle` queries the original transaction hash. Missing or uncertain results stay unresolved. Success requires a charged fee within the original bid and stage fee cap. Funding checks the wallet's exact balance increase. Concurrent owner activity can prevent exact comparison and requires reconciliation. Use a new status-output filename for each observation.

Read simulations do not renew TTL. Follow [administration](admin.md) for submitted lifetime maintenance and restoration. Network deployment and live settlement require separate operator authorization.
