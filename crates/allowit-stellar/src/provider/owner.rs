//! Native owner workflows use caller-owned custody, Core HTTP sessions and SDK-opened stores.
use super::runtime::{
    Runtime,
    owner::SetupRequest,
    owner_client::{
        GeneratedPolicy, OwnerClient,
        workflow::{self, Outcome, OwnerCapabilities, OwnerPolicy},
    },
};
use crate::host::{
    error::{Error, Result},
    owner::{self, Context},
    vendors::OwnerProvider,
};
use allowit_core::client::store::Store;
pub struct Owner;
pub static OWNER: Owner = Owner;
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > 1_048_576 {
        return Err(Error::usage("Public owner document exceeds its limit"));
    }
    crate::host::typed_request::validate_json(bytes, 1_048_576)?;
    serde_json::from_slice(bytes).map_err(|_| Error::usage("Invalid public owner document"))
}
fn selected(bytes: &[u8]) -> Result<OwnerPolicy> {
    let out: Outcome = decode(bytes)?;
    out.selection.validate()?;
    Ok(out.selection)
}
fn check(cx: &Context<'_>, p: &OwnerPolicy) -> Result<()> {
    if crate::host::routing::normalize(&p.config.network)?
        != crate::host::routing::normalize(cx.network)?
        || p.config.owner != cx.signer.address()
        || p.config.server != cx.authority.public_key()
    {
        return Err(Error::config(
            "Policy differs from the selected owner or rail",
        ));
    }
    p.validate()
}
fn fee(text: &str) -> Result<u32> {
    if text.is_empty()
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|v| v.is_ascii_digit())
    {
        return Err(Error::usage("Fee must use canonical positive base units"));
    }
    text.parse::<u32>()
        .ok()
        .filter(|v| u64::from(*v) >= super::server_owner::fee_bounds().minimum)
        .ok_or_else(|| Error::usage("Fee exceeds the selected rail's supported bounds"))
}
fn runtime(url: &str) -> Result<Runtime> {
    Runtime::new(url).map_err(|_| Error::config("Invalid owner RPC endpoint"))
}
fn client(cx: &Context<'_>) -> Result<OwnerClient> {
    let mut c = OwnerClient::with_authority(cx.authority, cx.origin, cx.signer.address())?;
    c.authenticate(&super::OwnerSignerRef(cx.signer), (cx.clock)()?)?;
    Ok(c)
}
/// The network of a Native wallet setup, by its canonical id, whichever alias the caller
/// selected: the request, the retained record and the registration document name it, so the
/// server's templates and the identity of a resumed request name the same network. The owner's
/// key and the server's key are those of this network. A key store or a server authority of
/// another network of the rail holds a valid account of this one too, so the ids are compared:
/// no setup installs the server key of one network in a wallet of another.
fn setup_network(cx: &Context<'_>) -> Result<&'static str> {
    let network = crate::host::routing::normalize(cx.network)?;
    for (role, other) in [
        ("owner key", cx.signer.network()),
        ("server authority", cx.authority.network()),
    ] {
        if crate::host::routing::normalize(other).ok() != Some(network) {
            return Err(Error::config(format!(
                "The {role} belongs to another network than the wallet setup"
            )));
        }
    }
    Ok(network)
}
fn emit(value: impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| Error::config("Cannot encode owner result"))
}
/// The amount of a setup in the base units of the wallet's asset. XLM and every issued Stellar
/// asset have seven decimals.
fn setup_funding(amount: &str) -> Result<i64> {
    i64::try_from(workflow::amount_units(amount)?)
        .ok()
        .filter(|units| *units > 0)
        .ok_or_else(|| Error::usage("The setup funding amount is out of range"))
}
/// The fee per operation of the setup that a Native deployment signs: the most that `limit`
/// allows for the whole setup transaction of `operations`, within the setup's own bounds. The
/// network charges its current fee, at most this bid.
fn native_setup_fee(limit: u32, operations: u32) -> Result<u32> {
    let minimum = u32::try_from(super::server_owner::fee_bounds().minimum)
        .map_err(|_| Error::config("Invalid rail fee bounds"))?;
    let per_operation = (limit / operations).min(100_000);
    if per_operation < minimum {
        return Err(Error::usage(format!(
            "The fee limit is below the setup fee of {} stroops",
            u64::from(minimum) * u64::from(operations)
        )));
    }
    Ok(per_operation)
}
/// A Native draft for a new wallet account deploys as the app deploys it: one owner transaction
/// creates the agent's wallet account and funds it with `amount`, and the server's registration
/// of the account binds the draft to it. The account runs no wallet code, so the deployment
/// takes no executable. The outcome selects the bound draft for activation.
fn deploy_native(
    cx: &Context<'_>,
    policy: GeneratedPolicy,
    r: &owner::Deploy<'_>,
) -> Result<serde_json::Value> {
    if !r.executable.is_empty() {
        return Err(Error::usage(
            "A Native wallet is an account and runs no wallet code: deploy it without an executable",
        ));
    }
    if r.fee_asset_amount.is_some() {
        return Err(Error::usage(
            "A Native wallet pays its fees in XLM from its own account: deploy it without a fee asset amount",
        ));
    }
    if r.server != cx.authority.public_key() {
        return Err(Error::usage(
            "Deployment server differs from independently configured authority",
        ));
    }
    // The account holds the draft's asset, which the server drafted from its template of the
    // network: the setup adds the trustline of an issued asset, and funds the account in it.
    let b = &policy.runtime.instance_binding;
    let asset = b
        .asset_issuer
        .as_ref()
        .map(|issuer| crate::owner::Trustline {
            code: b.asset_symbol.clone(),
            issuer: issuer.clone(),
        });
    let funding = r.amount.map(setup_funding).transpose()?;
    let operations = crate::owner::SETUP_OPERATIONS
        + u32::from(asset.is_some())
        + u32::from(asset.is_some() && funding.is_some());
    let request = SetupRequest {
        network: setup_network(cx)?.into(),
        owner: cx.signer.address().into(),
        agent: r.agent.into(),
        server: r.server.into(),
        request_id: r.request_id.into(),
        fee_per_operation: native_setup_fee(fee(r.fee_limit)?, operations)?,
        asset,
        funding,
    };
    request.validate()?;
    let runtime = runtime(cx.rpc_url)?;
    let store = (cx.store)()?;
    emit(client(cx)?.deploy_native(
        &runtime,
        OwnerCapabilities {
            store: &store,
            rpc: runtime.rpc(),
            signer: &super::OwnerSignerRef(cx.signer),
            clock: cx.clock,
        },
        &policy,
        &request,
    )?)
}
impl OwnerProvider for Owner {
    fn deploy(&self, cx: &Context<'_>, r: owner::Deploy<'_>) -> Result<serde_json::Value> {
        let policy: GeneratedPolicy = decode(r.draft)?;
        if policy.runtime.wallet.kind == "owner-wallet" {
            return deploy_native(cx, policy, &r);
        }
        if r.executable.len() > 131_072 {
            return Err(Error::usage(
                "Selected wallet executable exceeds its native limit",
            ));
        }
        let p = workflow::deployment_policy(
            policy,
            cx.signer.address(),
            r.agent,
            r.server,
            r.executable,
        )?;
        check(cx, &p)?;
        let runtime = runtime(cx.rpc_url)?;
        let store = (cx.store)()?;
        emit(client(cx)?.deploy(
            OwnerCapabilities {
                store: &store,
                rpc: runtime.rpc(),
                signer: &super::OwnerSignerRef(cx.signer),
                clock: cx.clock,
            },
            &p,
            r.request_id,
            r.amount,
            r.fee_asset_amount,
            fee(r.fee_limit)?,
        )?)
    }
    fn fund(
        &self,
        cx: &Context<'_>,
        document: &[u8],
        id: &str,
        amount: &str,
        limit: &str,
    ) -> Result<serde_json::Value> {
        let p = selected(document)?;
        check(cx, &p)?;
        workflow::amount_units(amount)?;
        let runtime = runtime(cx.rpc_url)?;
        let store = (cx.store)()?;
        emit(client(cx)?.fund(
            OwnerCapabilities {
                store: &store,
                rpc: runtime.rpc(),
                signer: &super::OwnerSignerRef(cx.signer),
                clock: cx.clock,
            },
            &p,
            id,
            amount,
            fee(limit)?,
        )?)
    }
    fn activate(&self, cx: &Context<'_>, r: owner::Activate<'_>) -> Result<serde_json::Value> {
        // Both alternatives decode directly from the original bytes. Duplicate fields cannot disappear into Value.
        let p = match decode::<Outcome>(r.document) {
            Ok(out) => out.selection,
            Err(_) => workflow::native_policy(
                decode(r.document)?,
                cx.signer.address(),
                r.agent.ok_or_else(|| {
                    Error::usage("This draft requires an explicit agent and server")
                })?,
                r.server.ok_or_else(|| {
                    Error::usage("This draft requires an explicit agent and server")
                })?,
            )?,
        };
        check(cx, &p)?;
        let runtime = runtime(cx.rpc_url)?;
        let store = (cx.store)()?;
        emit(client(cx)?.activate(
            OwnerCapabilities {
                store: &store,
                rpc: runtime.rpc(),
                signer: &super::OwnerSignerRef(cx.signer),
                clock: cx.clock,
            },
            &p,
            r.request_id,
        )?)
    }
    fn export(
        &self,
        cx: &Context<'_>,
        document: &[u8],
        id: &str,
    ) -> Result<Box<serde_json::value::RawValue>> {
        let p = selected(document)?;
        check(cx, &p)?;
        let runtime = runtime(cx.rpc_url)?;
        let store = (cx.store)()?;
        let raw = client(cx)?.export_raw(&store, &p, runtime.rpc(), id, (cx.clock)()?)?;
        Ok(raw)
    }
    /// The asset of a new Native wallet as [`Self::setup`] reads and checks it: the same network
    /// and key checks, the setup's role check of the owner and the server, the server's template
    /// through the same reader, and the same asset check, so a host shows what the setup would
    /// fund and the lookup refuses what the setup refuses. The owner signs in to read it and
    /// signs nothing else; the lookup asks the RPC nothing.
    fn native_wallet_asset(&self, cx: &Context<'_>) -> Result<owner::NativeWalletAsset> {
        let network = setup_network(cx)?;
        super::runtime::owner::check_roles(&[cx.signer.address(), cx.authority.public_key()])?;
        let asset = client(cx)?.native_wallet_asset(network, (cx.clock)()?)?;
        super::runtime::owner::check_wallet_asset(asset.as_ref())?;
        Ok(match asset {
            Some(asset) => owner::NativeWalletAsset {
                symbol: asset.code,
                issuer: Some(asset.issuer),
            },
            None => owner::NativeWalletAsset {
                symbol: "XLM".into(),
                issuer: None,
            },
        })
    }
    fn setup(&self, cx: &Context<'_>, r: owner::Setup<'_>) -> Result<serde_json::Value> {
        if r.server != cx.authority.public_key() {
            return Err(Error::usage(
                "Setup server differs from independently configured authority",
            ));
        }
        let funding = r.amount.map(setup_funding).transpose()?;
        let fee_per_operation = fee(r.fee_per_operation)?;
        let network = setup_network(cx)?;
        // The caller's own values are checked first, the RPC endpoint and the network that it
        // serves among them: a setup that must fail asks the owner for no sign-in, opens no
        // journal and asks the server nothing. The wallet asset is checked after the server's
        // template names it.
        let request = |asset| SetupRequest {
            network: network.into(),
            owner: cx.signer.address().into(),
            agent: r.agent.into(),
            server: r.server.into(),
            request_id: r.request_id.into(),
            fee_per_operation,
            asset,
            funding,
        };
        request(None).validate_caller_values()?;
        let runtime = runtime(cx.rpc_url)?;
        workflow::network(runtime.rpc(), network)?;
        // The server's template of the network names the asset that the wallet holds. It is
        // read before anything is signed for the ledger, so a server that offers no wallet on
        // this network stops the setup before an account exists. A request that the store
        // retains keeps its own asset: its resume does not depend on the template of today.
        // Such a resume asks the server nothing before its retained bytes are settled on the
        // ledger, as before: the owner's session starts at the registration.
        // The journal is open for the read of the retained request only: the sign-in and the
        // template request hold no lock, so a slow server holds up no payment and no recovery
        // of the same journal. The workflow opens the journal again and checks the request
        // identity, the asset included, against whatever the journal retains by then.
        let retained = workflow::retained_setup_asset(&(cx.store)()?, r.request_id)?;
        let (asset, session) = match retained {
            Some(asset) => (asset, None),
            None => {
                let client = client(cx)?;
                let asset = client.native_wallet_asset(network, (cx.clock)()?)?;
                (asset, Some(client))
            }
        };
        let request = request(asset);
        request.validate()?;
        let store = (cx.store)()?;
        let mut configured = workflow::configure_native(
            &runtime,
            &store,
            &request,
            &super::OwnerSignerRef(cx.signer),
            cx.clock,
        )?;
        // The registration reads and writes no journal, so the journal's lock is released
        // before the server is asked: a slow registration holds up no payment and no recovery
        // of the same journal.
        drop(store);
        // The ledger now holds the wallet. The server registers it from the ledger, so no
        // server configuration names it. A refusal leaves the wallet set up: the same request
        // ID asks again and signs nothing.
        let registration = session
            .map_or_else(|| client(cx), Ok)
            .and_then(|client| {
                client.register_native(&configured["configuration"], None, (cx.clock)()?)
            })
            .map_err(|error| {
                let mut refused = Error::api(
                    error.status.unwrap_or(409),
                    format!(
                        "The wallet account {} is set up on the ledger, but the server did not register it: {}. Run the same setup again.",
                        configured["wallet"].as_str().unwrap_or_default(),
                        error.message
                    ),
                );
                refused.api_code = error.api_code;
                refused
            })?;
        configured["registered"] = registration["registered"].clone();
        configured["walletKind"] = serde_json::json!("native");
        Ok(configured)
    }
    fn status(
        &self,
        store: &Store,
        network: &str,
        url: &str,
        id: &str,
    ) -> Result<serde_json::Value> {
        workflow::status(store, &runtime(url)?, id, network)
    }
    fn edit_params(&self, cx: &Context<'_>, r: owner::EditParams<'_>) -> Result<serde_json::Value> {
        let draft: GeneratedPolicy = decode(r.draft)?;
        emit(client(cx)?.edit_params(&draft, r.changes, (cx.clock)()?)?)
    }
    fn revise(&self, cx: &Context<'_>, r: owner::Revise<'_>) -> Result<serde_json::Value> {
        let draft: GeneratedPolicy = decode(r.draft)?;
        emit(client(cx)?.revise(&draft, r.instruction, (cx.clock)()?)?)
    }
    fn update_params(
        &self,
        cx: &Context<'_>,
        r: owner::UpdateParams<'_>,
    ) -> Result<serde_json::Value> {
        let p = selected(r.document)?;
        check(cx, &p)?;
        let update = crate::host::runtime::ParamsUpdate {
            policy_id: p.policy.id.clone(),
            expected_revision: r.expected_revision,
            changes: r.changes.clone(),
        };
        // An invalid update fails before the journal opens or the server is asked. A keypair
        // wallet holds no params: its workflow checks the update against the portable binding.
        if p.config.route != crate::WalletRoute::Native {
            super::params_update::next_params(&p.config, &update)?;
        }
        let limit = fee(r.fee_limit)?;
        let runtime = runtime(cx.rpc_url)?;
        let store = (cx.store)()?;
        emit(client(cx)?.update_params(
            OwnerCapabilities {
                store: &store,
                rpc: runtime.rpc(),
                signer: &super::OwnerSignerRef(cx.signer),
                clock: cx.clock,
            },
            &p,
            r.request_id,
            &update,
            limit,
        )?)
    }
    /// Read the wallet through the owner's RPC and compare it with the owner's document. No
    /// server call and no signature: the result does not depend on the backend.
    fn verify(&self, cx: &Context<'_>, document: &[u8]) -> Result<owner::Verification> {
        let p = selected(document)?;
        check(cx, &p)?;
        let runtime = runtime(cx.rpc_url)?;
        super::params_update::verify(runtime.rpc(), &p.policy.id, &p.config)
    }
    fn paired_export(&self, network: &str, document: &[u8]) -> Result<owner::PairedExport> {
        // A deployment, funding or update outcome selects its policy; a draft is the policy.
        let policy: GeneratedPolicy = match decode::<Outcome>(document) {
            Ok(outcome) => outcome.selection.policy,
            Err(_) => decode(document)?,
        };
        if crate::host::routing::normalize(&policy.network)?
            != crate::host::routing::normalize(network)?
        {
            return Err(Error::config("The policy belongs to another network"));
        }
        let binding = &policy.runtime.instance_binding;
        let shape = crate::provider::source_shape(
            binding.route == "native",
            binding.tier == Some(crate::PolicyTier::Custom),
            &policy.code,
        )?;
        let kind = policy
            .wallet_kind
            .or(match (binding.route.as_str(), binding.tier) {
                ("native", _) => Some(allowit_core::vendor::kinds::WalletKind::Native),
                (_, Some(crate::PolicyTier::Simple)) => {
                    Some(allowit_core::vendor::kinds::WalletKind::Simple)
                }
                (_, Some(crate::PolicyTier::Common)) => {
                    Some(allowit_core::vendor::kinds::WalletKind::Standard)
                }
                (_, Some(crate::PolicyTier::Custom)) => {
                    Some(allowit_core::vendor::kinds::WalletKind::Custom)
                }
                _ => None,
            })
            .ok_or_else(|| Error::config("The policy names no wallet kind"))?;
        // Core reads the calls of the source, as the derivation does.
        let calls = allowit_core::policy_source::source_calls(&policy.code)
            .map_err(crate::provider::failure)?;
        let mut export = owner::PairedExport::of(
            policy.id.clone(),
            policy.network.clone(),
            kind,
            policy.code.clone(),
            policy.source_hash.clone(),
            calls.rules,
            shape.prefix,
            calls.host_calls,
            binding
                .portable
                .params
                .0
                .iter()
                .map(|(key, value)| {
                    value
                        .to_core()
                        .map(|value| (key.clone(), value))
                        .map_err(crate::provider::failure)
                })
                .collect::<Result<_>>()?,
        );
        on_chain_placement(&mut export, &policy.code)?;
        Ok(export)
    }
}
/// The native placement of a Custom wallet whose source has a server part: the contract compiles
/// the on-chain part that Core derives, so the placement holds that part and the rules that Core
/// reads in it. The host placement keeps the whole source and every rule that it calls.
fn on_chain_placement(export: &mut owner::PairedExport, source: &str) -> Result<()> {
    if export.native.wallet_kind != allowit_core::vendor::kinds::WalletKind::Custom {
        return Ok(());
    }
    let parts = crate::policy::custom_parts(source).map_err(crate::provider::failure)?;
    if parts.server_part {
        export.native.rules = allowit_core::policy_source::source_calls(&parts.onchain)
            .map_err(crate::provider::failure)?
            .rules;
        export.native.source = Some(parts.onchain);
    }
    Ok(())
}
#[cfg(test)]
mod paired_export_tests {
    use super::*;
    /// The placements of a split Custom source come from Core: the host placement holds the
    /// whole source and every rule that it calls, a raw identifier included, in source order; the
    /// native placement holds the on-chain part and the rules that stay in it. A call limit in a
    /// branch of a server decision runs only on the server.
    #[test]
    fn a_split_custom_export_takes_both_placements_from_core() {
        const TWICE: &str = "use allowit::prelude::*;\nuse allowit::AllowitDecision;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    let score = allowit::decision(ctx, &AllowitDecision { id: \"research\", query: \"Is this research?\", deny_below: 3000, allow_above: 8000 })?;\n    if score < 9000 {\n        allowit::call_limit(ctx, &ctx.params[allowit::CALL_LIMIT])?;\n    }\n    allowit::r#payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n";
        let calls = allowit_core::policy_source::source_calls(TWICE).unwrap();
        let export = |kind| {
            let mut export = owner::PairedExport::of(
                "p".into(),
                "stellar:testnet".into(),
                kind,
                TWICE.into(),
                "h".into(),
                calls.rules.clone(),
                vec![],
                calls.host_calls.clone(),
                Default::default(),
            );
            on_chain_placement(&mut export, TWICE).unwrap();
            export
        };
        let custom = export(allowit_core::vendor::kinds::WalletKind::Custom);
        let onchain = crate::policy::custom_parts(TWICE).unwrap().onchain;
        assert!(!onchain.contains("call_limit"));
        assert_eq!(custom.host.source, TWICE);
        assert_eq!(custom.host.rules, ["call_limit", "payment_limit"]);
        assert_eq!(custom.native.source.as_deref(), Some(onchain.as_str()));
        assert_eq!(custom.native.rules, ["payment_limit"]);
        // Another kind keeps Core's placement as it is.
        let simple = export(allowit_core::vendor::kinds::WalletKind::Simple);
        assert!(simple.native.source.is_none() && simple.native.rules.is_empty());
    }
}

#[cfg(test)]
mod storage_boundary_tests {
    use super::*;
    struct Signer;
    impl crate::host::Signer for Signer {
        fn network(&self) -> &str {
            "stellar:testnet"
        }
        fn address(&self) -> &str {
            "unused-before-validation"
        }
        fn sign_hash(&self, _: &[u8]) -> Result<Vec<u8>> {
            panic!("invalid draft requested a signature")
        }
    }
    #[test]
    fn invalid_owner_input_fails_before_requesting_a_caller_store() {
        let authority = crate::host::config::ServerAuthority::validated(
            "stellar:testnet",
            "http://localhost:3000",
            &crate::account_for_seed(&[13; 32]),
        )
        .unwrap();
        let context = Context {
            network: "stellar:testnet",
            backend: authority.origin(),
            authority: &authority,
            origin: "http://localhost:5173",
            rpc_url: "invalid",
            store: &|| panic!("invalid draft requested a journal"),
            signer: &Signer,
            clock: &|| Ok(1),
        };
        let error = OWNER
            .deploy(
                &context,
                owner::Deploy {
                    draft: b"invalid",
                    agent: "unused",
                    server: "unused",
                    executable: &[],
                    request_id: "invalid-001",
                    fee_limit: "100",
                    amount: None,
                    fee_asset_amount: None,
                },
            )
            .unwrap_err();
        assert_eq!(
            error.message,
            "The request file must contain a JSON object."
        );
    }
    /// A setup with an invalid value of the caller fails before the journal opens, before the
    /// owner signs a sign-in and before the server is asked: the store and the signer of this
    /// test panic when they are used, and the server origin answers nothing. So does a setup
    /// whose owner key or server authority belongs to another network of the rail.
    #[test]
    fn an_invalid_setup_fails_before_the_journal_the_sign_in_and_the_server() {
        struct Owner(&'static str, String);
        impl crate::host::Signer for Owner {
            fn network(&self) -> &str {
                self.0
            }
            fn address(&self) -> &str {
                &self.1
            }
            fn sign_hash(&self, _: &[u8]) -> Result<Vec<u8>> {
                panic!("an invalid setup requested a signature")
            }
        }
        let owner = crate::account_for_seed(&[11; 32]);
        let agent = crate::account_for_seed(&[12; 32]);
        let server = crate::account_for_seed(&[13; 32]);
        // `selected` is the network of the call, `keys` the network of the owner's key store
        // and `service` the network of the configured server authority.
        let setup = |[selected, keys, service]: [&'static str; 3],
                     agent: &str,
                     request_id: &str,
                     amount: Option<&str>| {
            let authority = crate::host::config::ServerAuthority::validated(
                service,
                "http://localhost:3000",
                &server,
            )
            .unwrap();
            let signer = Owner(keys, owner.clone());
            let context = Context {
                network: selected,
                backend: authority.origin(),
                authority: &authority,
                origin: "http://localhost:5173",
                rpc_url: "invalid",
                store: &|| panic!("an invalid setup requested a journal"),
                signer: &signer,
                clock: &|| Ok(1),
            };
            OWNER
                .setup(
                    &context,
                    owner::Setup {
                        agent,
                        server: &server,
                        request_id,
                        fee_per_operation: "100",
                        amount,
                    },
                )
                .unwrap_err()
                .message
        };
        let id = "setup-invalid-001";
        for (selected, canonical) in [
            ("stellar:testnet", "stellar:testnet"),
            ("stellar:pubnet", "stellar:pubnet"),
            ("stellar:mainnet", "stellar:pubnet"),
        ] {
            let same = [selected, selected, canonical];
            for (agent, request_id, amount, message) in [
                ("GAGENT", id, None, "Expected canonical Stellar G account"),
                (
                    agent.as_str(),
                    "bad id",
                    None,
                    "Invalid Stellar setup request ID",
                ),
                (
                    agent.as_str(),
                    id,
                    Some("0"),
                    "Asset amount exceeds the supported positive range",
                ),
                (
                    owner.as_str(),
                    id,
                    None,
                    "Owner, agent and server must be distinct G accounts",
                ),
                // The most that a wallet of an issued asset takes passes the early check, which
                // does not know the asset yet: the next check, of the RPC endpoint, stops it.
                (
                    agent.as_str(),
                    id,
                    Some("100000000"),
                    "Invalid owner RPC endpoint",
                ),
                (
                    agent.as_str(),
                    id,
                    Some("100000000.0000001"),
                    "The setup funding amount is out of range",
                ),
            ] {
                assert_eq!(
                    setup(same, agent, request_id, amount),
                    message,
                    "{selected}"
                );
            }
            // A valid request of this network with a key store or a server authority of the
            // other network of the rail: the account of each key is valid on both.
            let other = if canonical == "stellar:testnet" {
                "stellar:pubnet"
            } else {
                "stellar:testnet"
            };
            assert_eq!(
                setup([selected, other, canonical], &agent, id, None),
                "The owner key belongs to another network than the wallet setup",
                "{selected}"
            );
            assert_eq!(
                setup([selected, selected, other], &agent, id, None),
                "The server authority belongs to another network than the wallet setup",
                "{selected}"
            );
            // A valid request whose RPC endpoint is no URL.
            assert_eq!(
                setup(same, &agent, id, None),
                "Invalid owner RPC endpoint",
                "{selected}"
            );
        }
    }
    /// A setup whose RPC endpoint serves another network than the setup fails before the
    /// journal opens and before the owner signs a sign-in. The loopback endpoint answers one
    /// `getNetwork` with the Testnet passphrase, for a setup on pubnet.
    #[test]
    #[cfg_attr(not(feature = "e2e"), ignore = "end-to-end: run with --features e2e")]
    fn a_setup_with_an_rpc_of_another_network_fails_before_the_journal_and_the_sign_in() {
        use std::io::{Read, Write};
        struct Owner(String);
        impl crate::host::Signer for Owner {
            fn network(&self) -> &str {
                "stellar:pubnet"
            }
            fn address(&self) -> &str {
                &self.0
            }
            fn sign_hash(&self, _: &[u8]) -> Result<Vec<u8>> {
                panic!("a setup on another network requested a signature")
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let rpc = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let header = String::from_utf8(request).unwrap().to_ascii_lowercase();
            let length: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map(|value| value.trim().parse().unwrap())
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let call: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(call["method"], "getNetwork");
            let reply = serde_json::json!({"jsonrpc":"2.0","id":call["id"],
                "result":{"passphrase":crate::passphrase("stellar:testnet").unwrap()}})
            .to_string();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
        });
        let server = crate::account_for_seed(&[13; 32]);
        let authority = crate::host::config::ServerAuthority::validated(
            "stellar:pubnet",
            "http://localhost:3000",
            &server,
        )
        .unwrap();
        let signer = Owner(crate::account_for_seed(&[11; 32]));
        let context = Context {
            network: "stellar:pubnet",
            backend: authority.origin(),
            authority: &authority,
            origin: "http://localhost:5173",
            rpc_url: &url,
            store: &|| panic!("a setup on another network requested a journal"),
            signer: &signer,
            clock: &|| Ok(1),
        };
        let error = OWNER
            .setup(
                &context,
                owner::Setup {
                    agent: &crate::account_for_seed(&[12; 32]),
                    server: &server,
                    request_id: "setup-network-001",
                    fee_per_operation: "100",
                    amount: None,
                },
            )
            .unwrap_err();
        rpc.join().unwrap();
        assert_eq!(
            error.message,
            "Owner RPC network differs from the selected policy"
        );
    }
    /// A Native draft deploys without wallet code and pays its fees in XLM. Each refusal comes
    /// before the journal, the network or a signature.
    #[test]
    fn a_native_deployment_is_refused_before_the_journal_when_its_inputs_do_not_fit() {
        let authority = crate::host::config::ServerAuthority::validated(
            "stellar:testnet",
            "http://localhost:3000",
            &crate::account_for_seed(&[13; 32]),
        )
        .unwrap();
        let context = Context {
            network: "stellar:testnet",
            backend: authority.origin(),
            authority: &authority,
            origin: "http://localhost:5173",
            rpc_url: "invalid",
            store: &|| panic!("a refused deployment opened the journal"),
            signer: &Signer,
            clock: &|| Ok(1),
        };
        let mut policy = crate::test_support::owner_generation_fixture()["policy"].clone();
        crate::test_support::server::native_new_wallet(&mut policy);
        let draft = serde_json::to_vec(&policy).unwrap();
        let agent = crate::account_for_seed(&[12; 32]);
        let server = crate::account_for_seed(&[13; 32]);
        let deploy = |executable: &[u8], server: &str, fee_limit: &str, fee_asset: Option<&str>| {
            OWNER
                .deploy(
                    &context,
                    owner::Deploy {
                        draft: &draft,
                        agent: &agent,
                        server,
                        executable,
                        request_id: "deploy-native-001",
                        fee_limit,
                        amount: Some("20"),
                        fee_asset_amount: fee_asset,
                    },
                )
                .unwrap_err()
                .message
        };
        assert_eq!(
            deploy(b"\0asm", &server, "2000000000", None),
            "A Native wallet is an account and runs no wallet code: deploy it without an executable"
        );
        assert_eq!(
            deploy(&[], &server, "2000000000", Some("1")),
            "A Native wallet pays its fees in XLM from its own account: deploy it without a fee asset amount"
        );
        assert_eq!(
            deploy(&[], &agent, "2000000000", None),
            "Deployment server differs from independently configured authority"
        );
        assert_eq!(
            deploy(&[], &server, "399", None),
            "The fee limit is below the setup fee of 400 stroops"
        );
        // The setup's own checks come next, also before the journal: this signer names no
        // account.
        assert_eq!(
            deploy(&[], &server, "2000000000", None),
            "Expected canonical Stellar G account"
        );
    }
    #[test]
    fn the_native_setup_bids_what_the_fee_limit_allows_within_its_bounds() {
        let operations = crate::owner::SETUP_OPERATIONS;
        assert_eq!(native_setup_fee(400, operations).unwrap(), 100);
        assert_eq!(native_setup_fee(1_000, operations).unwrap(), 250);
        assert_eq!(
            native_setup_fee(2_000_000_000, operations).unwrap(),
            100_000
        );
        assert!(native_setup_fee(399, operations).is_err());
        // A trustline and the funding of an issued asset add two operations to the bid.
        assert_eq!(native_setup_fee(1_200, operations + 2).unwrap(), 200);
        assert_eq!(
            native_setup_fee(599, operations + 2).unwrap_err().message,
            "The fee limit is below the setup fee of 600 stroops"
        );
    }
}
