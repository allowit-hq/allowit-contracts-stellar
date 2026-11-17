# Stellar browser adapter

`@allowit/stellar` supplies native profiles, asset derivation, wallet signing, owner handoffs, receipt validation and explorer links. Consumers supply their authenticated REST transport. The adapter does not own application sessions or presentation layout.

## Rail plugin

`@allowit/stellar/plugin` is the Stellar plugin for the AllowIt SDK registry. Only the SDK registration imports it. Hosts reach it through `<allowit-rail kind network>` and the registry functions, never by name. The default export has the rail `id`, its CAIP-2 `networks`, `validateAddress`, `explorerUrl`, `assets`, the test declaration and the element tags. `define()` registers the elements once; importing the module touches no DOM.

| kind | element | `data` | events |
|---|---|---|---|
| `address` | `allowit-stellar-address` | `{network, address, label?}` | none |
| `explorer-link` | `allowit-stellar-explorer-link` | `{network, kind, id, text?}` | none |
| `amount` | `allowit-stellar-amount` | `{network, asset, units}` | none |
| `wallet-sign-in` | `allowit-stellar-wallet-sign-in` | `{network, message}` | `allowit-signed-in {address, signature}`, `allowit-error` |
| `owner-sign` | `allowit-stellar-owner-sign` | `{network, step, summary, owner?, expected?}` | `allowit-signed {signedPayload, hash}`, `allowit-cancel`, `allowit-error` |
| `build-attest` | `allowit-stellar-build-attest` | `{network, message, summary?}` | `allowit-signed {signature, codeHash}`, `allowit-cancel`, `allowit-error` |
| `owner-answer` | `allowit-stellar-owner-answer` | `{network, owner, message}` | `allowit-signed {signature, answer, snapshot}`, `allowit-cancel`, `allowit-error` |
| `receipt` | `allowit-stellar-receipt` | `{network, receipt}` | none |
| `binding-review` | `allowit-stellar-binding-review` | `{network, installation}` | `allowit-verified {ok, detail}` |

`owner-sign` signs only a transaction whose hash equals the reviewed `step.hash`, and only before `step.expiresAt`. With `expected`, it also runs the owner verifier Wasm on the step. `wallet-sign-in` signs only a CAIP-122 message whose first line names the current site and whose second line is the wallet account. `build-attest` signs only a custom build attestation message of the element's network whose `owner` is the wallet account; `signature` is the SEP-53 message signature as lowercase hexadecimal. `owner-answer` signs only an owner review answer message of the element's network, with the account `owner`, and shows the fields of that message: the decision question with its score, or the lookup that failed; `signature` is the SEP-53 message signature as base64. The wallet API loads on the first signing click.

The plugin also supplies `walletKinds(network)`, `walletKind(document)`, `nativeAsset(network)` and
`assetDisplay(network, asset)`. `walletKind` reads the route and tier of a policy, draft, profile or installation and
returns `native`, `simple`, `standard` or `custom`; the tier `common` is the `standard` kind.
`review` holds the Review and sign link: `fragment`, `parseLink`, `agentPrompt` and `paramLines`.
`parseLink` returns the proposal, which has exactly eight keys, the work prompt, and the values that the chat
collected beside the proposal: `agent`, `amount` and `walletKind`. Each is null when the link does not carry it.
`walletKind` is a kind id; the host checks it against `walletKinds(network)` before it offers that kind.
`ownerWorkflow.installAndFund` installs and funds the reviewed wallet. One workflow runs per journal key.
It settles a saved signed step first. A confirmation or `owner_transaction_settled` completes it once Horizon holds
that successful transaction; every Horizon read ends after 15 s. On `owner_transaction_expired`
Horizon decides: a transaction that applied completes the step, proof that it never applied archives its signed
bytes and lets the owner sign a new step, and an unreadable chain keeps the step. `owner_transaction_failed` archives the step when Horizon holds that failed transaction. `owner_transaction_pending`
and `network_unavailable` keep the step for a retry (`OwnerFlowError.retry`). A saved step and the funded marker name
the policy, agent key and amount; a resume with other inputs is refused.

A new policy wallet has a fee account: the account that sends the agent's operations and pays their network fees.
The server refuses a creation without one with `fee_account_required`. `installAndFund` then makes the account's
setup key at random in memory (`newFeeAccountKey`), names the account to the server as `setup.feeAccount`, and adds
the key's one signature to the owner-signed `create_fee_account` step before the bytes enter the journal. The owner
signs no message for it. The key is used once and dropped; nothing stores, derives or recovers it, because the
creation sets its weight to 0 and makes the owner a signer that reaches every threshold alone. The journal keeps the
address of an account whose creation was signed under `<key>:fee-account` until the wallet is installed, so a reload
names the same account. When the service prepares the creation of a saved account again, Horizon decides: an account
that the ledger holds stays and the step is refused as stale (`OwnerFlowError.retry`), an unreadable ledger keeps
the account too, and only an account that the ledger does not hold is replaced. Its signed creation never applied,
so nothing holds funds: the workflow makes a new key and names its account. A journal without a saved
address names no account, so a deployment that another browser or an earlier release took past its fee account and
not to its wallet continues here with a new account. The earlier account stays under the owner's key alone: the
owner closes it, and Horizon lists it under `accounts?signer=<owner>`. The workflow adopts no existing account,
because neither the journal nor the ledger says which one no wallet uses. The element shows
what a `create_fee_account` step funds: the account and the XLM that it starts with.

With `expected.feeAccount` the owner verifier admits the `create_fee_account` step of exactly that account for the
selected agent and server, and reconstructs the creation and each update with the fee account as the agent address.

`ownerWorkflow.feeAccount({network, document})` reads the fee account that an installation, profile or policy names
from Horizon: `{address, exists, balance, spendable, low, text, refill}`. `low` is true below two operations at the
wallet's fee ceiling. It is null for a document without a fee account. `ownerWorkflow.refillFees` builds one payment
of XLM from the owner's account to the fee account, has the host's `sign` sign it as the step `refill_fees` and sends
the signed bytes to Horizon itself. With `journal` and `key` the signed payment is saved before it is sent. A result
that is unknown rejects with `RefillPendingError` and keeps it; the next call settles it first. It is done when Horizon
holds it as successful, it is sent again while its own time bound lasts, and a new payment is signed only when Horizon
holds it as failed or has read past its time bound while the owner's sequence is still below the payment's sequence.

`ownerWorkflow.updateParams` changes installed params on an active wallet with one owner signature. The host passes
each changed param with its complete typed value, such as `{daily_spending_limit: {Int: '50000000'}}`, and one journal
key per change. The service checks the values and prepares the `update_params` step: one call that writes the next
configuration revision of the wallet and keeps its recorded usage and request nonce. The workflow settles a saved
signed step first, as `installAndFund` does, and never prepares or signs a confirmed change again under its key.
A refusal keeps the typed code of the service in `OwnerFlowError.code`: `param_invalid`, `param_out_of_range`,
`update_unavailable` or `revision_changed`.
The `owner-sign` element checks an `update_params` step of a Standard wallet against `data.expected` like an install
step: the selection holds the complete new params and `update: {deploymentVersion, x402Enabled}`. The verifier
reconstructs the exact policy packet, so a step with another value, revision, wallet or code is not signed.

## Build and test

The package exports JavaScript modules and TypeScript declarations. StrKey decoding, asset contract IDs and network passphrases come from `@stellar/stellar-sdk`. `test:browser` reads the Common Wasm that `scripts/build-contracts.sh` builds. Run these commands from `npm/stellar/`:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build:browser
pnpm run test:browser
pnpm --config.ignore-scripts=true pack --dry-run --json
pnpm --config.ignore-scripts=true pack
```

The build regenerates `dist/` from `src/`. Keep the distribution with its source so consumers can install the package with lifecycle scripts disabled. pnpm installs the package from a release tag with a path selector: `github:allowit-hq/allowit-contracts-stellar#vX.Y.Z&path:/npm/stellar`. Signing retains original signed bytes before broadcast, and recovery observes the original transaction.

`customerKeyFromEntropy` encodes caller-supplied entropy. The caller generates entropy and retains the secret. `stellarSignInChallengeTimes` binds the native message and returns its dates. `connectStellarWallet` requires the caller's timestamp-admission capability. The capability must return `true` for admitted dates. HTTP-session freshness rules remain with the consumer.

`deployAdkOwnerDraft` deploys and funds a reviewed ADK agent draft on Stellar Testnet. It creates no fee account, so it refuses a wallet that needs one and names `installAndFund` and the CLI. The consumer supplies its REST transport, owner confirmation of the installation and portable build admission. A Resume settles the saved step before it signs another one. When the server rejects a sent step with the `OWNER_TRANSACTION_EXPIRED` code and Horizon excludes the transaction, the journal drops the step and keeps its signed bytes under `adkOwnerArchiveKey`. `adkParamLines` labels draft params with the Core registry and shows amounts in XLM.

Portable bundle encoders require a consumer admission callback. The consumer checks authoring metadata and unresolved inputs. The adapter checks native wire types, selected policy identity, hashes and signatures. A missing callback rejects the export.
