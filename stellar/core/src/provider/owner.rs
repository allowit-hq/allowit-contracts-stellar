//! Selected native owner binding. Custody, HTTP sessions and journals stay in the SDK engine.
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
use allowit_policy_sdk::client::store::Store;
use std::path::Path;
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
fn store(root: &Path) -> Result<Store> {
    Store::open(&root.join("stellar-owner-workflows"))
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
        let store = store(cx.root)?;
        emit(client(cx)?.deploy(
            OwnerCapabilities {
                store: &store,
                rpc: runtime.rpc(),
                signer: &super::OwnerSignerRef(cx.signer),
                clock: cx.clock,
            },
            &p,
            r.request_id,
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
        let store = store(cx.root)?;
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
        let store = store(cx.root)?;
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
        let store = store(cx.root)?;
        let raw = client(cx)?.export_raw(&store, &p, runtime.rpc(), id, (cx.clock)()?)?;
        Ok(raw)
    }
    fn setup(&self, cx: &Context<'_>, r: owner::Setup<'_>) -> Result<serde_json::Value> {
        if r.server != cx.authority.public_key() {
            return Err(Error::usage(
                "Setup server differs from independently configured authority",
            ));
        }
        if !crate::host::routing::info(cx.network)?.testnet {
            return Err(Error::unsupported(
                "Native setup is available on the selected test network only",
            ));
        }
        let request = SetupRequest {
            network: cx.network.into(),
            owner: cx.signer.address().into(),
            agent: r.agent.into(),
            server: r.server.into(),
            request_id: r.request_id.into(),
            fee_per_operation: fee(r.fee_per_operation)?,
        };
        request.validate()?;
        workflow::configure_native(
            &runtime(cx.rpc_url)?,
            &store(cx.root)?,
            &request,
            &super::OwnerSignerRef(cx.signer),
            cx.clock,
        )
    }
    fn status(&self, root: &Path, network: &str, url: &str, id: &str) -> Result<serde_json::Value> {
        workflow::status(&store(root)?, &runtime(url)?, id, network)
    }
}
