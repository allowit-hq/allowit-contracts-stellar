# Stellar browser adapter

`@allowit/stellar-browser` supplies native profiles, asset derivation, wallet signing, owner handoffs, receipt validation and explorer links. Consumers supply their authenticated REST transport. The adapter does not own application sessions or presentation layout.

The package exports TypeScript source. Pin the repository to an immutable commit when consuming it before a registry release. Signing retains original signed bytes before broadcast, and recovery observes the original transaction.
