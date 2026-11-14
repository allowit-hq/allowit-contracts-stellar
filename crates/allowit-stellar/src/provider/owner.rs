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
        let mut configured = workflow::configure_native(
            &runtime(cx.rpc_url)?,
            &(cx.store)()?,
            &request,
            &super::OwnerSignerRef(cx.signer),
            cx.clock,
        )?;
        // The ledger now holds the wallet. The server registers it from the ledger, so no
        // server configuration names it. A refusal leaves the wallet set up: the same request
        // ID asks again and signs nothing.
        let registration = client(cx)
            .and_then(|client| {
                client.register_native(&configured["configuration"], (cx.clock)()?)
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
        // An invalid update fails before the journal opens or the server is asked.
        super::params_update::next_params(&p.config, &update)?;
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
        let shape = crate::host::authoring::check(&policy.code)?;
        let binding = &policy.runtime.instance_binding;
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
        let (rules, evidence_functions) = source_calls(&policy.code);
        Ok(owner::PairedExport::of(
            policy.id.clone(),
            policy.network.clone(),
            kind,
            policy.code.clone(),
            policy.source_hash.clone(),
            rules,
            shape.prefix,
            evidence_functions,
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
        ))
    }
}
/// One token of policy source that a call can consist of.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    /// `::`
    Path,
    /// `(`
    Open,
    Other,
}
/// The tokens of Rust source without comments and without the contents of string, byte-string
/// and character literals. Whitespace separates tokens and is not a token.
fn tokens(source: &str) -> Vec<Token> {
    let c: Vec<char> = source.chars().collect();
    let ident = |ch: char| ch.is_alphanumeric() || ch == '_';
    let (mut out, mut i) = (Vec::new(), 0);
    // A raw string: `r`, hashes and a quote. Returns the number of hashes.
    let raw_start = |i: usize| -> Option<usize> {
        let mut at = i + usize::from(c.get(i) == Some(&'b'));
        if c.get(at) != Some(&'r') {
            return None;
        }
        at += 1;
        let hashes = c[at..].iter().take_while(|ch| **ch == '#').count();
        (c.get(at + hashes) == Some(&'"')).then_some(hashes)
    };
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch == '/' && c.get(i + 1) == Some(&'/') {
            while i < c.len() && c[i] != '\n' {
                i += 1;
            }
        } else if ch == '/' && c.get(i + 1) == Some(&'*') {
            // Block comments nest.
            let mut depth = 1;
            i += 2;
            while i < c.len() && depth > 0 {
                if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
        } else if let Some(hashes) = raw_start(i) {
            i += usize::from(c[i] == 'b') + 1 + hashes + 1;
            while i < c.len()
                && !(c[i] == '"'
                    && c[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|h| **h == '#')
                        .count()
                        == hashes)
            {
                i += 1;
            }
            i += 1 + hashes;
            out.push(Token::Other);
        } else if ch == '"' || (ch == 'b' && c.get(i + 1) == Some(&'"')) {
            i += 1 + usize::from(ch == 'b');
            while i < c.len() && c[i] != '"' {
                i += 1 + usize::from(c[i] == '\\');
            }
            i += 1;
            out.push(Token::Other);
        } else if ch == '\'' {
            // A character literal closes within a few characters; a lifetime does not close.
            let close = if c.get(i + 1) == Some(&'\\') {
                c[i + 2..]
                    .iter()
                    .take(12)
                    .position(|x| *x == '\'')
                    .map(|n| i + 2 + n)
            } else {
                (c.get(i + 2) == Some(&'\'')).then_some(i + 2)
            };
            i = close.map_or(i + 1, |close| close + 1);
            out.push(Token::Other);
        } else if ident(ch) {
            let start = i;
            while i < c.len() && ident(c[i]) {
                i += 1;
            }
            out.push(Token::Ident(c[start..i].iter().collect()));
        } else if ch == ':' && c.get(i + 1) == Some(&':') {
            i += 2;
            out.push(Token::Path);
        } else {
            i += 1;
            out.push(if ch == '(' { Token::Open } else { Token::Other });
        }
    }
    out
}
/// The calls of checked source, in source order and without repeats: the canonical rules
/// (`allowit::<rule>`) and the host evidence functions (`<namespace>::<function>` of another
/// lowercase namespace). The source gate admits no other lowercase path call. Comments and
/// literals hold no call, and a path may have whitespace around `::`.
fn source_calls(source: &str) -> (Vec<String>, Vec<String>) {
    let tokens = tokens(source);
    let (mut rules, mut evidence) = (Vec::<String>::new(), Vec::<String>::new());
    for (at, window) in tokens.windows(4).enumerate() {
        let [
            Token::Ident(namespace),
            Token::Path,
            Token::Ident(function),
            Token::Open,
        ] = window
        else {
            continue;
        };
        // A longer path, such as `a::b::c(`, is not a direct call of `b::c`.
        if at > 0 && tokens[at - 1] == Token::Path {
            continue;
        }
        if namespace == "allowit" {
            if allowit_core::vendor::kinds::STANDARD_PARAMS.contains(&function.as_str())
                && !rules.contains(function)
            {
                rules.push(function.clone());
            }
        } else if namespace.starts_with(|c: char| c.is_ascii_lowercase()) {
            let name = format!("{namespace}::{function}");
            if !evidence.contains(&name) {
                evidence.push(name);
            }
        }
    }
    (rules, evidence)
}
#[cfg(test)]
mod paired_export_tests {
    use super::*;
    #[test]
    fn source_calls_lists_rules_and_evidence_functions_in_source_order() {
        let source = "use allowit::prelude::*;\n// allowit::call_limit(ctx) in a comment\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    let operation = allowit::operations(ctx, &ctx.params[allowit::OPERATIONS].ok())?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS].ok())?;\n    let report = catalog::report (ctx, 1)?;\n    allowit::tokens(ctx, &ctx.params[allowit::TOKENS].ok())?;\n    let output: Address = ctx.params[SWAP_TOKEN].ok();\n    let x = Some(output);\n    allowit::payment_limit(ctx, &ctx.params[REPORT_LIMIT].ok())?;\n    Ok(())\n}\n";
        let (rules, evidence) = source_calls(source);
        assert_eq!(rules, ["operations", "tokens", "payment_limit"]);
        assert_eq!(evidence, ["catalog::report"]);
    }
    #[test]
    fn source_calls_ignores_comments_and_literals_and_reads_spaced_paths() {
        // A call inside a block comment, a nested block comment, a string, a raw string or a
        // character literal is no call.
        let quiet = "pub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    /* allowit::call_limit(ctx) /* allowit::tokens(ctx) */ catalog::report(ctx) */\n    let a = \"allowit::destinations(ctx) \\\" catalog::quote(ctx)\";\n    let b = r#\"allowit::payment_limit(ctx) \" still\"#;\n    let c = '(';\n    let d: &'static str = \"\";\n    Ok(())\n}\n";
        assert_eq!(source_calls(quiet), (vec![], vec![]));
        // Whitespace and line breaks around `::` and before `(` are part of the same call. A
        // longer path is not a call of its tail, and a path that is not called is no call.
        let spaced = "pub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit :: call_limit (ctx, &ctx.params[allowit::CALL_LIMIT])?;\n    catalog\n        ::report(ctx)?;\n    outer::catalog::quote(ctx)?;\n    let f = allowit::tokens;\n    Ok(())\n}\n";
        assert_eq!(
            source_calls(spaced),
            (
                vec!["call_limit".to_owned()],
                vec!["catalog::report".to_owned()]
            )
        );
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
                },
            )
            .unwrap_err();
        assert_eq!(
            error.message,
            "The request file must contain a JSON object."
        );
    }
}
