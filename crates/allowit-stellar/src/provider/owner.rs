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
fn emit(value: impl serde::Serialize) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|_| Error::config("Cannot encode owner result"))
}
impl OwnerProvider for Owner {
    fn deploy(&self, cx: &Context<'_>, r: owner::Deploy<'_>) -> Result<serde_json::Value> {
        let policy: GeneratedPolicy = decode(r.draft)?;
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
    fn setup(&self, cx: &Context<'_>, r: owner::Setup<'_>) -> Result<serde_json::Value> {
        /// The amount of a setup in the base units of the wallet's asset. XLM and every issued
        /// Stellar asset have seven decimals.
        fn setup_funding(amount: &str) -> Result<i64> {
            i64::try_from(workflow::amount_units(amount)?)
                .ok()
                .filter(|units| *units > 0)
                .ok_or_else(|| Error::usage("The setup funding amount is out of range"))
        }
        if r.server != cx.authority.public_key() {
            return Err(Error::usage(
                "Setup server differs from independently configured authority",
            ));
        }
        let funding = r.amount.map(setup_funding).transpose()?;
        let fee_per_operation = fee(r.fee_per_operation)?;
        // The server's template of the network names the asset that the wallet holds. It is
        // read before anything is signed for the ledger, so a server that offers no wallet on
        // this network stops the setup before an account exists. A request that the store
        // retains keeps its own asset: its resume does not depend on the template of today.
        let client = client(cx)?;
        let store = (cx.store)()?;
        let asset = match workflow::retained_setup_asset(&store, r.request_id)? {
            Some(asset) => asset,
            None => client.native_wallet_asset(cx.network, (cx.clock)()?)?,
        };
        let request = SetupRequest {
            network: cx.network.into(),
            owner: cx.signer.address().into(),
            agent: r.agent.into(),
            server: r.server.into(),
            request_id: r.request_id.into(),
            fee_per_operation,
            asset,
            funding,
        };
        request.validate()?;
        let mut configured = workflow::configure_native(
            &runtime(cx.rpc_url)?,
            &store,
            &request,
            &super::OwnerSignerRef(cx.signer),
            cx.clock,
        )?;
        // The ledger now holds the wallet. The server registers it from the ledger, so no
        // server configuration names it. A refusal leaves the wallet set up: the same request
        // ID asks again and signs nothing.
        let registration = (cx.clock)()
            .and_then(|now| client.register_native(&configured["configuration"], now))
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
}
