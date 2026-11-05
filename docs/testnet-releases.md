# Testnet releases

An approved annotated `vX.Y.Z` tag starts **Build Stellar release**.
The build verifies canonical source, runs the contract checks and records exact Wasm and sample-policy hashes.
**Deploy and publish Stellar release** runs from default `main` after that build succeeds.
It verifies the triggering run and attempt, tag object, source ancestry and artifact bytes.
It repeats these checks after environment approval, before signing or mutation, and before publication.
Release tags must remain protected and immutable.
The pipeline does not create or move tags.

## Resources and authority

The controller uploads five content-addressed Wasms: Simple, Common, Custom, wallet engine and engine parent.
It creates one initialized Simple, Common and Custom smoke wallet for the configured Testnet operator.
It uploads engine and parent code without creating their instances.
The Common wallet uses the sample policy's source-derived rules.
The Custom wallet uses the sample source compiled in that exact release.

The smoke wallets use native Testnet XLM and explicit test parameters.
The controller neither funds these wallets nor executes transfers, payments or owner administration.
It permits the approved constructor's intrinsic lifetime effects within the transaction fee cap.
It refuses standalone lifetime extension and explicit or automatic archive restoration.
User wallet creation, funding, approval and activation remain owner-authorized SDK and app actions.

Configure the GitHub environment `stellar-testnet` with deployment access for `main` only.
Preserve required reviewers and existing deployment protections.
Tag build jobs do not receive this environment's secret.

| Setting | Value |
| --- | --- |
| Secret `STELLAR_TESTNET_OWNER_SECRET` | Dedicated Testnet operator key, with no user or production authority |
| Variable `STELLAR_TESTNET_OWNER` | Independently configured public G address for that key |
| Variable `STELLAR_TESTNET_AGENT` | Distinct public G address for the smoke agent |
| Variable `STELLAR_TESTNET_SERVER` | Distinct public G address for the smoke server |

The operator must have only its master signer and default master weight and thresholds.
Only this controller may use that key.
Friendbot may create the configured absent operator account after fixed-network verification.
The controller checks the resulting account before preparing any envelope.
There is no bootstrap-run variable or historical checkpoint authority.

## Reconciliation and signing

The controller fixes the Testnet passphrase, RPC and Horizon URLs.
Both services must agree on a recent native ledger header.
Its close time must be within 120 seconds of current UTC, with at most 30 seconds of future skew.
The endpoint tips may differ by at most 12 ledgers.
Ledger 128 supplies the fixed generation anchor. It is not genesis.
An unavailable anchor or disagreement prevents mutation.
A changed generation during a run requires a fresh run and signer barrier.

Every target derives from the immutable tag, wallet kind and operator identity.
Mutable agent and server configuration does not change the target.
A configuration change therefore fails at the existing target instead of selecting a replacement wallet.
Before mutation, the controller inspects all currently live code, wallets and configuration in one bounded native ledger-entry batch.
It checks exact executable bytes, native value variants, roles, parameters, lifetimes and pristine wallet state.
Pristine state includes the expected custody version, deployment version, nonce, pause flag, policy state and native token label.

A wholly read-only run can finish without a signing delay.
A run that needs mutation waits after acquisition of the workflow's global exclusive signer slot.
Matching native ledger time must exceed that entry UTC time by 450 seconds.
Queue and environment-wait time do not count.
This barrier covers earlier envelopes whose maximum validity is bounded by 300 seconds from their verified native header.
It assumes exclusive controller use of the dedicated key and trustworthy runner UTC.
External or unbounded signed packets require separate operator reconciliation.

Targets remain fixed during the barrier. Initially live resources must remain valid.
Earlier bounded packets may settle before the barrier completes.
The controller then freezes current CREATE or REUSE decisions and the expected operator sequence.
A disappeared REUSE never becomes CREATE.
Missing persistent data alone does not prove absence.
A conditional target requires successful exact native simulation without restoration metadata before signing.
A constructor simulation also requires exact Wasm and operator-account readback first.
Archived data, a restore preamble or unknown resource extensions prevent creation.
This includes automatic restoration described by [CAP-0066](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0066.md).

Each envelope contains one exact upload or constructor operation at the current sequence plus one.
It expires within 300 seconds of the verified native header and uses only source-account authorization.
The maximum transaction fee is 125 Testnet XLM, including constructor storage rent.
Before signing and sending, the controller rechecks every REUSE, every completed CREATE, the pending target, operator authority, source and network.
It retains exact signed bytes privately and records their public hash, sequence and expiry before transmission.
A timeout, duplicate submission or missing receipt never authorizes a replacement.
The current run polls only the original hash and stops on failure or uncertainty.
A failed transaction can consume its sequence and fees.

Final success requires one fresh coherent readback of all desired resources and exact wallet state.
`RESOURCE_STATE_VERIFIED` describes that recorded observation.
It does not claim historical receipt completeness, a prior reset, user acceptance or settlement of unrelated packets.
A later run reconciles current desired state independently.
A resource without this run's receipt is `observed-existing`.

## Outputs and reruns

`source-manifest.json` records the exact tag, source, toolchain, published Core source, sample policy and Wasm hashes.
The build artifact also carries `release-build.json`, bound to its exact GitHub run and attempt.
Artifact names include the producing run and attempt to prevent cross-attempt ambiguity.
The publisher preserves existing source assets and appends an immutable deployment snapshot:

```text
testnet-deployment-vX.Y.Z-GENERATION_HASH-RUN_ID-ATTEMPT.json
```

Each snapshot contains current native state and this run's original transaction outcomes.
Public progress snapshots also remain in the run's Actions artifact, including after failure.
A filename collision with different bytes fails. No publication uses `--clobber`.
A publication failure does not change resource state or establish historical receipts.
Earlier release assets and Actions history never authorize mutations.
Private signed packets never enter public artifacts or release assets.

To request another build of an existing approved tag from `main`:

```sh
gh workflow run release.yml --repo allowit-hq/allowit-contracts-stellar --ref main -f tag=v0.3.0
```

One global queued workflow uses the signer at a time, without cancelling a running signer.
GitHub queues at most 100 pending runs in this group and cancels additional runs.
A canceled or skipped deployment run does not establish release completion.
Inspect these entries and request another build of the existing tag when necessary.
The signing job has read-only GitHub permissions. A separate publisher alone has release write access.
Public child processes receive an explicit environment without signing or provider credentials.
Only GitHub read/write commands receive their job's scoped GitHub token.
The controller has no Mainnet, package-registry or user-key path.
