# Stellar browser adapter

`@allowit/stellar-browser` supplies native profiles, asset derivation, wallet signing, owner handoffs, receipt validation and explorer links. Consumers supply their authenticated REST transport. The adapter does not own application sessions or presentation layout.

The package exports JavaScript modules and TypeScript declarations. Run `npm install --ignore-scripts` and `npm run build:browser` to regenerate `browser/dist` from `browser/src`. Keep the distribution with its source so Git consumers work when install scripts are disabled. Pin the repository to an immutable commit when consuming it before a registry release. Signing retains original signed bytes before broadcast, and recovery observes the original transaction.

`customerKeyFromEntropy` encodes caller-supplied entropy. The caller generates entropy and retains the secret. `stellarSignInChallengeTimes` binds the native message and returns its dates. `connectStellarWallet` requires the caller's timestamp-admission capability. The capability must return `true` for admitted dates. HTTP-session freshness rules remain with the consumer.

Portable bundle encoders require a consumer admission callback. The consumer checks authoring metadata and unresolved inputs. The adapter checks native wire types, selected policy identity, hashes and signatures. A missing callback rejects the export.
