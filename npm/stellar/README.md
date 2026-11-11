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
| `receipt` | `allowit-stellar-receipt` | `{network, receipt}` | none |
| `binding-review` | `allowit-stellar-binding-review` | `{network, installation}` | `allowit-verified {ok, detail}` |

`owner-sign` signs only a transaction whose hash equals the reviewed `step.hash`, and only before `step.expiresAt`. With `expected`, it also runs the owner verifier Wasm on the step. `wallet-sign-in` signs only a CAIP-122 message whose first line names the current site and whose second line is the wallet account. The wallet API loads on the first signing click.

The plugin also supplies `walletKinds(network)`, `walletKind(document)`, `nativeAsset(network)` and
`assetDisplay(network, asset)`. `walletKind` reads the route and tier of a policy, draft, profile or installation and
returns `native`, `simple`, `standard` or `custom`; the tier `common` is the `standard` kind.
`review` holds the Review and sign link: `fragment`, `parseLink`, `agentPrompt` and `paramLines`.
`ownerWorkflow.installAndFund` installs and funds the reviewed wallet. One workflow runs per journal key.
It settles a saved signed step first. A confirmation or `owner_transaction_settled` completes it once Horizon holds
that successful transaction; every Horizon read ends after 15 s. On `owner_transaction_expired`
Horizon decides: a transaction that applied completes the step, proof that it never applied archives its signed
bytes and lets the owner sign a new step, and an unreadable chain keeps the step. `owner_transaction_failed` archives the step when Horizon holds that failed transaction. `owner_transaction_pending`
and `network_unavailable` keep the step for a retry (`OwnerFlowError.retry`). A saved step and the funded marker name
the policy, agent key and amount; a resume with other inputs is refused.

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
