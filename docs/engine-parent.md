# Engine parent

The engine parent owns one shared engine's executable reference. Its owner can replace the engine
code, transfer parent administration, and upgrade the parent. This authority controls shared checks.
It does not control wallet custody code, wallet owner operations, params, policy state, or server signing keys.

## State and creation

`AllowitParentState` contains three native fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `owner` | `Address` | Current parent administrator. Native account or contract authorization applies. |
| `version` | `u64` | Administration sequence. Creation uses zero. Each successful administration call adds one. |
| `engine` | `Address` | Managed engine address. Code upgrades preserve this address and its instance data. |

`STATE_KEY` names the native `u32` key `0` in instance storage. The constant removes an unexplained
literal without changing the stored key. This slot is local to the parent. Another contract's key
`0` refers to that other contract's storage.

`__constructor(owner, engine_wasm)` requires the owner's authorization. `engine_wasm` is the exact
32-byte hash of uploaded Wasm. The parent creates the executable reference named `engine`, then
deploys an engine with no constructor arguments. Deployment uses the parent's address and an
all-zero 32-byte salt. The engine executable is `ExternalRef { owner: parent_address, tag: "engine" }`.
The host resolves that reference to the selected Wasm. Failure rolls back creation and state writes.

The parent stores no signing key, token balance accounting or wallet policy. Simple, Common and
Custom wallets run their checks locally and have no shared-engine address field. The parent manages
the separate shared-checker interface. Changing the parent owner does not change a wallet owner.

## Calls and authorization

Soroban supplies `env`. Callers do not serialize it. Hash arguments are 32 bytes. Administration
`version` arguments must equal the current stored value, not the next value. They are distinct from
wallet `deployment_version`, custody `contract_version`, and engine `engine_version` release metadata.

| Call | Authorization and behavior |
| --- | --- |
| `state()` | No authorization. Return state and renew the parent instance and code lifetime. Do not load the engine. |
| `engine()` | No authorization. Return the engine address and renew parent, engine instance, referenced code and reference lifetimes. |
| `upgrade_engine(new_hash, version)` | Current owner authorizes the exact invocation. Replace the `engine` executable reference with uploaded Wasm and add one to the version. |
| `set_admin(owner, version)` | Current owner and candidate owner authorize the exact invocation. Reject the parent or managed engine as candidate. Store the accepted owner and add one to the version. |
| `upgrade_parent(new_hash, version)` | Current owner authorizes the exact invocation. Select uploaded parent Wasm and add one to the version. Retain parent address and instance state. |

Administration calls increment the sequence even if they select the same hash or current owner.
`StaleVersion` is error `1`, `Overflow` is error `2`, and `InvalidAdmin` is error `3`. Invalid native
authorization, missing uploaded Wasm, and host deployment failures can also reject a call. Failed
calls roll back the state, version and executable changes together.

The reference update changes the code used by subsequent engine calls. It does not replace the
engine address or authorize wallet spending. An engine release that changes the interface or state
interpretation breaks the callers that rely on the old one. Engine release 4 takes the
`AllowitContext` fields `params`, `state` and `request` and returns each rule's pass value. Its
`AllowitRequest` carries the swap and redeem facts `token_in`, `amount_in`, `token_out` and
`min_out`; release 3 took the same arguments with a request without them, so a release 3 caller
fails against release 4. Both replace the shipped release 1 interface, whose methods take
`(request: EngineRequest, state: EngineState)`. Release 2 was never released. `upgrade_engine` from
a deployed release 1 or 3 engine to release 4 therefore breaks every onchain caller of that release.
Wallets in this repository do not call the engine; migrate or retire other callers before that
upgrade. A code hash identifies the exact executable. The parent administration version does not
identify its release semantics.

## Lifetime and recovery

Lifetime changes occur only in `load()` helpers. Parent loading renews its own instance and code to
the network maximum when their remaining lifetime falls below half that maximum. Engine loading
uses the same thresholds. The host renews an ExternalRef engine's reference and code together.

`state()` and administration paths do not load the engine. This preserves parent administration
when an engine dependency is unavailable. `engine()` can fail if its dependencies need restoration.
Restore archived entries through reviewed native transactions. Simulation alone does not commit
lifetime updates. Submit an authorized maintenance transaction when renewal becomes necessary.

Parent upgrades must read the retained state layout. The earlier map used `upgrade_authority` and
`revision`. It cannot be decoded as the current `owner` and `version` map. A named constant does not
migrate those fields. Run an explicit migration before installing incompatible parent code on an
existing address. Normal calls do not perform speculative migration or interpret missing state as
new ownership. See [administration](admin.md) for unsigned transaction preparation and authorization.
