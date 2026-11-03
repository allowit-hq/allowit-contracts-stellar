# Stellar browser adapter

`@allowit/stellar-browser` supplies native profiles, asset derivation, wallet signing, owner handoffs, receipt validation and explorer links. Consumers supply their authenticated REST transport. The adapter does not own application sessions or presentation layout.

The package exports JavaScript modules and TypeScript declarations. Run `npm install --ignore-scripts` and `npm run build:browser` to regenerate `browser/dist` from `browser/src`. Keep the distribution with its source so Git consumers work when install scripts are disabled. Pin the repository to an immutable commit when consuming it before a registry release. Signing retains original signed bytes before broadcast, and recovery observes the original transaction.
