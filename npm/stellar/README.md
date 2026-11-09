# Stellar browser adapter

`@allowit/stellar` supplies native profiles, asset derivation, wallet signing, owner handoffs, receipt validation and explorer links. Consumers supply their authenticated REST transport. The adapter does not own application sessions or presentation layout.

The package exports JavaScript modules and TypeScript declarations. `test:browser` reads the Common Wasm that `scripts/build-contracts.sh` builds. Run these commands from `npm/stellar/`:

```sh
pnpm install --frozen-lockfile --ignore-scripts
pnpm run build:browser
pnpm run test:browser
pnpm --config.ignore-scripts=true pack --dry-run --json
pnpm --config.ignore-scripts=true pack
```

The build regenerates `dist/` from `src/`. Keep the distribution with its source so consumers can install the package with lifecycle scripts disabled. pnpm installs the package from a release tag with a path selector: `github:allowit-hq/allowit-contracts-stellar#vX.Y.Z&path:/npm/stellar`. Signing retains original signed bytes before broadcast, and recovery observes the original transaction.

`customerKeyFromEntropy` encodes caller-supplied entropy. The caller generates entropy and retains the secret. `stellarSignInChallengeTimes` binds the native message and returns its dates. `connectStellarWallet` requires the caller's timestamp-admission capability. The capability must return `true` for admitted dates. HTTP-session freshness rules remain with the consumer.

`deployAdkOwnerDraft` deploys and funds a reviewed ADK agent draft on Stellar Testnet. The consumer supplies its REST transport, owner confirmation of the installation and portable build admission. When the server reports a sent step as expired, the journal drops the step and keeps its signed bytes under `adkOwnerArchiveKey`. `adkParamLines` labels draft params with the Core registry and shows amounts in XLM.

Portable bundle encoders require a consumer admission callback. The consumer checks authoring metadata and unresolved inputs. The adapter checks native wire types, selected policy identity, hashes and signatures. A missing callback rejects the export.
