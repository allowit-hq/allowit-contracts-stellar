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
| `owner-answer` | `allowit-stellar-owner-answer` | `{network, owner, message}` | `allowit-signed {signature, answer, snapshot}`, `allowit-cancel`, `allowit-error` |
| `receipt` | `allowit-stellar-receipt` | `{network, receipt}` | none |
| `binding-review` | `allowit-stellar-binding-review` | `{network, installation}` | `allowit-verified {ok, detail}` |

`owner-sign` signs only a transaction whose hash equals the reviewed `step.hash`, and only before `step.expiresAt`. With `expected`, it also runs the owner verifier Wasm on the step. `wallet-sign-in` signs only a CAIP-122 message whose first line names the current site and whose second line is the wallet account. `owner-answer` signs only an owner review answer message of the element's network, with the account `owner`, and shows the fields of that message: the decision question with its score, or the lookup that failed; `signature` is the SEP-53 message signature as base64. The API of the Varial wallet extension (formerly Freighter; its package is still `@stellar/freighter-api`) loads on the first signing click.

The plugin also supplies `walletKinds(network)`, `walletKind(document)`, `nativeAsset(network)` and
`assetDisplay(network, asset)`. `walletKind` reads the route and tier of a policy, draft, profile or installation and
returns `native`, `simple`, `standard` or `custom`; the tier `common` is the `standard` kind.
`review` holds the Review and sign link: `fragment`, `parseLink`, `agentPrompt` and `paramLines`.
`parseLink` returns the proposal, which has exactly eight keys, the work prompt, and the values that the chat
collected beside the proposal: `agent`, `amount` and `walletKind`. Each is null when the link does not carry it.
`walletKind` is a kind id; the host checks it against `walletKinds(network)` before it offers that kind.
The owner workflows, `installAndFund` and `updateParams`, are the SDK's: it holds their journal, their recovery of a
signed step whose result is unknown and their typed errors. `ownerChain` supplies what only Stellar can answer:

- `transaction(network, hash)`: the Horizon record of a transaction, `'missing'`, or null when Horizon gives no clear
  answer. Every Horizon read ends after 15 s.
- `expiredRecord(network, hash, signedPayload)`: for a signed step past its time bound, its ledger when it applied, or
  null when it can never apply. The signed bytes decide the time bound. The step never applied only when Horizon has
  read past that bound and holds the failed transaction, or holds none while the source sequence is still below the
  transaction's. Anything else rejects, and the SDK keeps the step.
- `keypairSetup`: `prepare` builds a Native wallet account's setup (below) and returns its step with `complete`, which
  checks the owner's signed bytes and adds the new account's own signature; `read` reads the hash, roles and time bound
  of signed setup bytes; `send` sends them to Horizon; `configuration` is the installation document of the account.
- `approval`: `read` reads the exact approval message of a network, `holds` checks it against the reviewed policy and
  the wallet's own configuration, `step` makes the `approve_policy` step, `walletOwner` reads the account's one signer
  of the owner's weight, and `signedBy` checks an Ed25519 signature over the step's digest.

The `owner-sign` element checks an `update_params` step of a Standard wallet against `data.expected` like an install
step: the selection holds the complete new params and `update: {deploymentVersion, x402Enabled}`. The verifier
reconstructs the exact policy packet, so a step with another value, revision, wallet or code is not signed.

### Native wallet

A Native policy needs the wallet account of its agent: a new classic account, one for each agent. The SDK's
`installAndFund` deploys it without a server step. The service answers the deployment of such a draft with
`wallet_setup_required` and the roles `{owner, agent, server}`. The workflow then, with these hooks:

1. Builds the setup from the owner's own sequence (`prepareNativeSetup` in `native-wallet.ts`): one transaction that creates the account with
   its starting balance, adds the owner signer (weight 3), the agent signer (1) and the server signer (1), sets the
   thresholds 2, 2 and 3 and gives the account's own key weight 0. The starting balance is the reserve of the account
   (2.5 XLM), 0.5 XLM for the fees of the owner's own steps and the owner's funding amount.
2. Has the host's `sign` sign it as the step `set_up_wallet`. The account's own key is random, lives in `complete` only
   and signs the creation once beside the owner. The `owner-sign` element reads the step from its bytes: it shows the
   wallet account, the agent and the funding, and it refuses any transaction that is not exactly this setup.
3. Saves the signed bytes in the host's journal under `<key>:wallet-setup` and sends them with `send`. They stay saved
   until the service has registered the wallet, so a run that stops in between names the same account again and signs
   no second setup. A result that is unknown is settled first: done when Horizon holds it as successful, sent again
   while its time bound lasts, and replaced only when Horizon holds it as failed or has read past its time bound
   without it.
4. Registers the account for the policy (`native/register` with the installation document and the `policyId`).
5. Asks for the owner's approval of the policy (`native/approval`) and has `sign` sign it as the step `approve_policy`:
   a message, never a transaction. The payload is the base64 UTF-8 text of the message, and the hash its SEP-53 digest.
   The element signs only the exact approval message of its network, shows the wallet account and the hashes of the
   source and the values, and compares them with `data.expected` when the host passes `{policyId, wallet, sourceHash,
   paramsHash}`. The host passes `reviewed: {source, params}`, and `rules` and `tier` when it shows them: the policy that the owner reviewed. The
   workflow signs only an approval that states exactly that policy and the wallet account's own configuration (its
   network, route, asset and fee ceiling). The server's digests `irHash` and `moduleDigest` and the name of its
   installation, `policyInstance`, are left to the server; a Native wallet enforces none of them. It keeps the signature only when the owner's account
   made it, and confirms the approval with `micro/allocation/confirm`.

So a Native deployment takes two owner signatures: the setup, which also funds the wallet, and the approval. No
funding step follows. The SDK's `updateParams` on a Native wallet is one `approve_policy` signature and no transaction: the
account holds no values, so the service answers the change with the approval message of the new values. The host
passes `installed: {wallet, source, rules, params, tier}`, the policy that the owner reviewed. The workflow signs
only an approval of that policy with the changed params replaced, checked as for the deployment's approval; any
other field or value is refused before a signature.

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

`deployAdkOwnerDraft` deploys and funds a reviewed ADK agent draft on Stellar Testnet. The consumer supplies its REST transport, owner confirmation of the installation and portable build admission. A Resume settles the saved step before it signs another one. When the server rejects a sent step with the `OWNER_TRANSACTION_EXPIRED` code and Horizon excludes the transaction, the journal drops the step and keeps its signed bytes under `adkOwnerArchiveKey`. `adkParamLines` labels draft params with the Core registry and shows amounts in XLM.

Portable bundle encoders require a consumer admission callback. The consumer checks authoring metadata and unresolved inputs. The adapter checks native wire types, selected policy identity, hashes and signatures. A missing callback rejects the export.
