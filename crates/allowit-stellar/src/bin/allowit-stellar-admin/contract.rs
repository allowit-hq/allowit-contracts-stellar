//! Contract setup and administration: explicit unsigned XDR for Wasm upload, parent and wallet
//! deployment and the owner and parent methods of the allowlist. Stellar CLI 28.1.0 builds and
//! simulates; this tool checks that simulation added only resources, fees and the expected
//! authorization entries. It never signs and never submits.
use super::{Get, Result, admin, fetch, owner_only, public};
use allowit_stellar::policy::{self, PolicyTier};
use allowit_stellar::{CONTRACT_VERSION, admin as checks, hash, hex};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use stellar_strkey::Contract;
use stellar_xdr::{
    ContractExecutable, HostFunction, OperationBody, Preconditions, PreconditionsV2, TimeBounds,
    TimePoint, TransactionEnvelope,
};

pub const ACTIONS: [&str; 5] = ["upload", "deploy-parent", "deploy-wallet", "read", "admin"];
const TIERS: [&str; 3] = ["simple", "common", "custom"];
// No transfers, token approvals, general calls or arbitrary method dispatch.
const WALLET: [(&str, &[&str]); 3] = [
    ("deploy_policy", &["deployment"]),
    ("set_pause", &["paused", "deployment_version"]),
    ("recover", &["recipient", "amount"]),
];
const PARENT: [(&str, &[&str]); 3] = [
    ("upgrade_engine", &["new_hash", "version"]),
    ("upgrade_parent", &["new_hash", "version"]),
    ("set_admin", &["owner", "version"]),
];
const DEPLOYMENT: [&str; 9] = [
    "deployment_version",
    "owner",
    "agent",
    "server",
    "source_digest",
    "rules",
    "params",
    "x402_enabled",
    "wasm_hash",
];
const CONFIG: [&str; 9] = [
    "owner",
    "agent",
    "server",
    "asset",
    "policy_instance",
    "source_digest",
    "rules",
    "params",
    "x402_enabled",
];
const CORE: &str = "https://github.com/allowit-hq/allowit-core.git";
const PORTABLE: &str = "crates/allowit-core/src/portable/";

/// The Stellar CLI: arguments and optional standard input to trimmed standard output.
pub type Cli<'a> = &'a dyn Fn(&[String], Option<&str>) -> Result<String>;

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// Public JSON. A duplicate key could show a reviewer one value and the contract another.
pub fn public_json(text: &str) -> Result<Value> {
    struct Unique;
    impl<'de> serde::Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("JSON")
                }
                fn visit_bool<E>(self, _: bool) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_i64<E>(self, _: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_u64<E>(self, _: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_f64<E>(self, _: f64) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_str<E>(self, _: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_unit<E>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique)
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> std::result::Result<Unique, A::Error> {
                    while seq.next_element::<Unique>()?.is_some() {}
                    Ok(Unique)
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut seen = BTreeSet::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if !seen.insert(key) {
                            return Err(serde::de::Error::custom("Duplicate public JSON key"));
                        }
                        map.next_value::<Unique>()?;
                    }
                    Ok(Unique)
                }
            }
            d.deserialize_any(Visitor)
        }
    }
    let invalid = |error: serde_json::Error| {
        if error.to_string().contains("Duplicate public JSON key") {
            "Duplicate public JSON key".to_string()
        } else {
            "Expected public JSON".to_string()
        }
    };
    serde_json::from_str::<Unique>(text).map_err(invalid)?;
    serde_json::from_str(text).map_err(invalid)
}

/// A JSON integer: no fraction, no exponent, no boolean and no text.
fn integer(value: &Value) -> Option<i128> {
    let Value::Number(number) = value else {
        return None;
    };
    let text = number.to_string();
    if text.contains(['.', 'e', 'E']) {
        return None;
    }
    text.parse().ok()
}
fn is_contract(value: &str) -> bool {
    Contract::from_string(value).is_ok_and(|c| c.to_string() == value)
}
/// A public G or C address.
fn address(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|text| public(text).is_ok() || is_contract(text))
        .ok_or_else(|| "Expected a public Stellar G or C address".to_string())
}
fn account(value: &Value) -> Result<&str> {
    let text = value.as_str().ok_or(super::BAD_ADDRESS)?;
    public(text)?;
    Ok(text)
}
fn contract(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|text| is_contract(text))
        .ok_or_else(|| "Expected a contract C address".to_string())
}
fn code_hash(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(|| "Expected 32-byte hexadecimal Wasm hash".to_string())
}
fn deployment_version(value: &Value) -> Result<u64> {
    integer(value)
        .and_then(|v| u64::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| "Invalid deployment version".to_string())
}
fn exact_keys<'a>(value: &'a Value, expected: &[&str]) -> Option<&'a Map<String, Value>> {
    let map = value.as_object()?;
    (map.len() == expected.len() && expected.iter().all(|key| map.contains_key(*key)))
        .then_some(map)
}
/// Owner params in the pinned CLI spec JSON, a key => `AllowitValue` object.
fn params(value: &Value, tier: Option<PolicyTier>) -> Result<Value> {
    serde_json::to_value(policy::params_from_json(value, tier)?).map_err(|e| e.to_string())
}

/// The local Wasm is the file that the pinned hash names.
fn pinned_wasm(path: Option<&str>, expected: &Value) -> Result<String> {
    let expected = code_hash(expected)?.to_lowercase();
    let path = path.ok_or("Code deployment requires --wasm and its pinned --wasm-hash")?;
    let wasm = std::fs::read(path).map_err(|_| "Cannot read the local Wasm")?;
    if hex(&hash(&wasm)) != expected {
        return Err("Local Wasm does not match the pinned deployment hash".into());
    }
    Ok(expected)
}
/// Refuse a wallet code change to Wasm with another custody layout. That code, including a
/// rollback to the version 1 release, cannot read the stored State and locks custody for good.
fn wallet_code(wasm_hash: &Value, path: Option<&str>) -> Result<()> {
    if wasm_hash.is_null() {
        return Ok(());
    }
    pinned_wasm(path, wasm_hash)?;
    let wasm = std::fs::read(path.unwrap_or_default()).map_err(|_| "Cannot read the local Wasm")?;
    if checks::custody_layout(&wasm)? != Some(CONTRACT_VERSION) {
        return Err(format!(
            "New wallet code must declare custody layout {CONTRACT_VERSION}; recover funds before any layout change"
        ));
    }
    Ok(())
}
/// Refuse an owner packet for another stored layout. Recovery does not depend on the layout.
fn wallet_layout(state: &Value) -> Result<()> {
    if integer(&state["contract_version"]) != Some(i128::from(CONTRACT_VERSION)) {
        return Err(format!(
            "Wallet state is not layout version {CONTRACT_VERSION}; recover its funds or redeploy it"
        ));
    }
    Ok(())
}

fn run_checked(command: &mut Command, failure: &str) -> Result<Vec<u8>> {
    let output = command.output().map_err(|_| failure.to_string())?;
    if !output.status.success() {
        return Err(failure.into());
    }
    Ok(output.stdout)
}
/// The portable `allowit` library of the locked Core dependency: a canonical release tag or an
/// exact revision whose checkout holds exactly the committed files.
fn core_portable() -> Result<PathBuf> {
    let failure = "Cannot resolve the locked Core tooling";
    let metadata = run_checked(
        Command::new("cargo")
            .args(["metadata", "--locked", "--format-version", "1"])
            .current_dir(env!("CARGO_MANIFEST_DIR")),
        failure,
    )?;
    let metadata: Value = serde_json::from_slice(&metadata).map_err(|_| failure)?;
    let packages: Vec<&Value> = metadata["packages"]
        .as_array()
        .map(|packages| {
            packages
                .iter()
                .filter(|package| package["name"] == "allowit-core")
                .collect()
        })
        .unwrap_or_default();
    let [package] = packages.as_slice() else {
        return Err("The build must resolve exactly one Core package".into());
    };
    let identity = "Core must resolve to a canonical Core release tag or exact revision";
    let is_revision = |text: &str| {
        text.len() == 40
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let source = package["source"].as_str().unwrap_or_default();
    let (reference, revision) = source
        .strip_prefix(&format!("git+{CORE}?"))
        .and_then(|rest| rest.split_once('#'))
        .ok_or(identity)?;
    let release_tag = reference.strip_prefix("tag=v").is_some_and(|version| {
        let parts: Vec<&str> = version.split('.').collect();
        parts.len() == 3
            && parts
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    });
    if !is_revision(revision) || !(release_tag || reference.strip_prefix("rev=") == Some(revision))
    {
        return Err(identity.into());
    }
    let manifest = package["manifest_path"].as_str().ok_or(failure)?;
    let root = Path::new(manifest)
        .canonicalize()
        .ok()
        .and_then(|path| path.ancestors().nth(3).map(Path::to_path_buf))
        .ok_or(failure)?;
    let git =
        |args: &[&str]| run_checked(Command::new("git").arg("-C").arg(&root).args(args), failure);
    if String::from_utf8_lossy(&git(&["rev-parse", "HEAD"])?).trim() != revision {
        return Err("Core checkout does not match its locked release".into());
    }
    for name in ["lib.rs", "core.rs"] {
        let relative = format!("{PORTABLE}{name}");
        let path = root.join(&relative).canonicalize().map_err(|_| failure)?;
        if !path.starts_with(&root) {
            return Err("Core tooling must remain inside its released source root".into());
        }
        if std::fs::read(&path).map_err(|_| failure)?
            != git(&["show", &format!("{revision}:{relative}")])?
        {
            return Err(format!(
                "Core tooling differs from its locked release: {relative}"
            ));
        }
    }
    Ok(root.join(PORTABLE))
}
/// A private directory that is removed on drop.
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path =
            std::env::temp_dir().join(format!("allowit-policy-{}-{nanos}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&path)
            .map_err(|_| "Cannot create a private build directory")?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn rustc(args: &[&std::ffi::OsStr], what: &str) -> Result<()> {
    let rustc = std::env::var_os("RUSTC")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "rustc".into());
    // Function pointer comparisons depend on code layout and optimization. Forbid, so that no
    // source `#[allow]`, `#[expect]` or `#[warn]` can lower the level.
    let output = Command::new(rustc)
        .args(["--edition=2024", "-C", "overflow-checks=on", "-F"])
        .arg("unpredictable_function_pointer_comparisons")
        .args(args)
        .output()
        .map_err(|_| "The std-only policy compile requires rustc (set RUSTC or PATH)")?;
    if !output.status.success() {
        return Err(format!(
            "Policy source fails the std-only compile of the {what}:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}
/// Compile authored policy source as the offchain server does: as a module of a `no_std` crate
/// whose only dependency is `allowit` with only the `std` feature, with overflow checks on. It
/// fails when the source imports another crate, calls a rail SDK method, orders addresses or
/// uses a host-only `std` prelude item.
pub fn host_compile(path: &str) -> Result<()> {
    let portable = core_portable()?;
    let source = Path::new(path)
        .canonicalize()
        .map_err(|_| "Cannot read the policy source")?;
    let source = source.to_str().ok_or("Policy source path is not UTF-8")?;
    if source.contains("\"#") || source.contains('\n') {
        return Err("Policy source path cannot be named in a Rust raw string".into());
    }
    let out = Scratch::new()?;
    let lib = out.0.join("liballowit.rlib");
    let os = std::ffi::OsStr::new;
    rustc(
        &[
            os("--crate-type=rlib"),
            os("--crate-name=allowit"),
            os("--cfg"),
            os("feature=\"std\""),
            portable.join("lib.rs").as_os_str(),
            os("-o"),
            lib.as_os_str(),
        ],
        "allowit std backend",
    )?;
    let host = out.0.join("policy_host.rs");
    std::fs::write(
        &host,
        format!(
            "#![no_std]\n#[path = r#\"{source}\"#]\nmod policy;\npub const EXECUTE: fn(&allowit::AllowitContext) -> allowit::Result = policy::execute;\n"
        ),
    )
    .map_err(|_| "Cannot write the policy host crate")?;
    let mut external = std::ffi::OsString::from("allowit=");
    external.push(&lib);
    rustc(
        &[
            os("--crate-type=rlib"),
            os("--crate-name=policy_host"),
            os("--extern"),
            &external,
            host.as_os_str(),
            os("-o"),
            out.0.join("libpolicy_host.rlib").as_os_str(),
        ],
        "policy",
    )
}

/// Bind an owner packet to its authored source. Every tier requires one self-contained file that
/// binds `allowit` only to the canonical crate and passes `compile`, the std-only compile of the
/// offchain server. Common binds the source's standard prefix; Simple and Custom bind none.
/// Custom also binds the source bytes. Returns the warning for prefix rules without a param.
pub fn policy_rules(
    value: &Value,
    tier: Option<&str>,
    source_path: Option<&str>,
    compile: &dyn Fn(&str) -> Result<()>,
) -> Result<Option<String>> {
    let required = "Owner packets require --tier (simple, common, custom) and --policy-source";
    let (tier, path) = match (tier, source_path) {
        (Some("simple"), Some(path)) => (PolicyTier::Simple, path),
        (Some("common"), Some(path)) => (PolicyTier::Common, path),
        (Some("custom"), Some(path)) => (PolicyTier::Custom, path),
        _ => return Err(required.into()),
    };
    let bytes = std::fs::read(path).map_err(|_| "Cannot read the policy source")?;
    let source = std::str::from_utf8(&bytes).map_err(|_| "Policy source is not UTF-8")?;
    let shape = policy::source_shape(source)?;
    compile(path)?;
    let expected = if tier == PolicyTier::Common {
        shape.prefix
    } else {
        vec![]
    };
    if value["rules"] != json!(expected) {
        let names: Vec<String> = expected.iter().map(|rule| format!("\"{rule}\"")).collect();
        return Err(format!(
            "Rules must be the standard prefix derived from the policy source: [{}]",
            names.join(", ")
        ));
    }
    if tier == PolicyTier::Custom && value["source_digest"] != hex(&hash(&bytes)) {
        return Err("Custom source_digest must be the SHA-256 of the policy source".into());
    }
    // Simple and Common store only standard state, so their server denies every policy write.
    if tier != PolicyTier::Custom && shape.writes_state {
        return Err(
            "Simple and Common cannot store allowit::set_state writes; use the custom tier".into(),
        );
    }
    let empty = json!({});
    let values = value.get("params").unwrap_or(&empty);
    params(values, Some(tier))?;
    // Valid configuration: the owner can set the param later without code redeployment.
    let unset: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|rule| values.get(rule).is_none())
        .collect();
    Ok((!unset.is_empty()).then(|| {
        format!(
            "Warning: the standard preflight skips prefix rules whose param is absent: {}. The full policy denies them with MissingParam.",
            unset.join(", ")
        )
    }))
}

/// Field checks of one `AllowitPolicyDeployment`.
fn deployment(value: &Value) -> Result<()> {
    let map = exact_keys(value, &DEPLOYMENT)
        .ok_or("Deployment fields must exactly match the policy wallet ABI")?;
    deployment_version(&map["deployment_version"])?;
    for role in ["owner", "agent", "server"] {
        address(&map[role])?;
    }
    params(&map["params"], None)?;
    code_hash(&map["source_digest"])?;
    let keys = policy::param_keys();
    let canonical = map["rules"].as_array().is_some_and(|rules| {
        rules
            .iter()
            .all(|rule| rule.as_str().is_some_and(|name| keys.contains(&name)))
    });
    if !canonical {
        return Err(format!(
            "Rules must name canonical rules: {}",
            keys.join(", ")
        ));
    }
    let x402 = map["x402_enabled"]
        .as_bool()
        .ok_or("x402_enabled must be boolean")?;
    if x402
        && ["agent", "server"]
            .iter()
            .any(|role| account(&map[*role]).is_err())
    {
        return Err(
            "x402_enabled (custom-account authorization) requires native G-agent and G-server signers"
                .into(),
        );
    }
    if !map["wasm_hash"].is_null() {
        code_hash(&map["wasm_hash"])?;
    }
    Ok(())
}

fn methods(family: &str) -> &'static [(&'static str, &'static [&'static str])] {
    if family == "wallet" { &WALLET } else { &PARENT }
}
/// The exact argument names and types of one allowlisted method.
pub fn checked_args(method: &str, values: &Value, family: &str) -> Result<()> {
    let expected = methods(family)
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, keys)| *keys)
        .ok_or("Method is outside the admin allowlist")?;
    let map = exact_keys(values, expected).ok_or_else(|| {
        let mut sorted = expected.to_vec();
        sorted.sort_unstable();
        format!("Arguments must exactly match {}", sorted.join(", "))
    })?;
    for (key, value) in map {
        match key.as_str() {
            "deployment" => deployment(value)?,
            "deployment_version" => {
                deployment_version(value)?;
            }
            "version" => {
                integer(value)
                    .and_then(|v| u64::try_from(v).ok())
                    .ok_or("Invalid integer version")?;
            }
            "amount" => {
                integer(value)
                    .filter(|v| *v > 0)
                    .ok_or("Invalid integer amount")?;
            }
            "new_hash" => {
                code_hash(value)?;
            }
            "paused" => {
                value.as_bool().ok_or("paused must be boolean")?;
            }
            "owner" => {
                account(value)?;
            }
            _ => {
                address(value)?;
            }
        }
    }
    Ok(())
}

/// Stellar CLI arguments of the named values. A text value passes unchanged; any other value is
/// compact JSON, with the params of a deployment or config in the pinned CLI spec form.
pub fn serialize(values: &Map<String, Value>) -> Result<Vec<String>> {
    let mut args = vec![];
    for (key, value) in values {
        let mut value = value.clone();
        if key == "deployment" || key == "config" {
            value["params"] = params(&value["params"], None)?;
        }
        args.push(format!("--{}", key.replace('_', "-")));
        args.push(match &value {
            Value::String(text) => text.clone(),
            other => serde_json::to_string(other).map_err(|e| e.to_string())?,
        });
    }
    Ok(args)
}

#[derive(Debug, Default)]
pub struct Arguments {
    pub action: String,
    pub network: String,
    pub allow_mainnet: bool,
    pub source: String,
    pub wasm: Option<String>,
    pub wasm_hash: Option<String>,
    pub engine_wasm: Option<String>,
    pub owner: Option<String>,
    pub config: Option<String>,
    pub contract: Option<String>,
    pub method: Option<String>,
    pub family: String,
    pub tier: Option<String>,
    pub policy_source: Option<String>,
    pub members: Vec<String>,
    pub candidate_members: Vec<String>,
    pub max_fee: u32,
    pub arguments: String,
}

pub fn parse(args: &[String]) -> Result<Arguments> {
    let mut out = Arguments {
        network: "testnet".into(),
        family: "wallet".into(),
        max_fee: 10_000_000,
        arguments: "{}".into(),
        ..Arguments::default()
    };
    let mut source = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = || -> Result<String> {
            inline
                .clone()
                .or_else(|| rest.next().cloned())
                .ok_or_else(|| format!("{flag} expects one argument"))
        };
        let g = |value: String| public(&value).map(|_| value);
        match flag {
            "--allow-mainnet" if inline.is_none() => out.allow_mainnet = true,
            "--network" => out.network = value()?,
            "--source" => source = Some(g(value()?)?),
            "--wasm" => out.wasm = Some(value()?),
            "--wasm-hash" => out.wasm_hash = Some(value()?),
            "--engine-wasm" => out.engine_wasm = Some(value()?),
            "--owner" => out.owner = Some(value()?),
            "--config" => out.config = Some(value()?),
            "--contract" => out.contract = Some(value()?),
            "--method" => out.method = Some(value()?),
            "--family" => out.family = value()?,
            "--tier" => out.tier = Some(value()?),
            "--policy-source" => out.policy_source = Some(value()?),
            "--member" => out.members.push(g(value()?)?),
            "--candidate-member" => out.candidate_members.push(g(value()?)?),
            "--max-fee" => {
                out.max_fee = value()?
                    .parse()
                    .map_err(|_| "--max-fee expects an integer")?
            }
            "--arguments" => out.arguments = value()?,
            _ if !flag.starts_with('-') && out.action.is_empty() => out.action = flag.into(),
            _ => return Err("Unrecognized arguments".into()),
        }
    }
    if !ACTIONS.contains(&out.action.as_str()) {
        return Err("Unknown action".into());
    }
    if !["testnet", "mainnet"].contains(&out.network.as_str()) {
        return Err("--network is testnet or mainnet".into());
    }
    if !["wallet", "parent"].contains(&out.family.as_str()) {
        return Err("--family is wallet or parent".into());
    }
    if out
        .tier
        .as_deref()
        .is_some_and(|tier| !TIERS.contains(&tier))
    {
        return Err("--tier is simple, common or custom".into());
    }
    out.source = source.ok_or("--source is required")?;
    Ok(out)
}

fn text(value: &Option<String>) -> Value {
    value.as_ref().map_or(Value::Null, |text| json!(text))
}

/// The Stellar CLI command of one action and its warning. Every preparing command carries
/// `--build-only`; a read carries `--send=no`. No command can sign or submit.
pub fn command(
    args: &Arguments,
    compile: &dyn Fn(&str) -> Result<()>,
) -> Result<(Vec<String>, Option<String>)> {
    if args.network == "mainnet" && !args.allow_mainnet && args.action != "read" {
        return Err("Mainnet preparation requires --allow-mainnet".into());
    }
    public(&args.source)?;
    let base = strings(&["--network", &args.network, "--source-account", &args.source]);
    let (tier, policy_source) = (args.tier.as_deref(), args.policy_source.as_deref());
    if args.action == "upload" {
        let wasm = args.wasm.as_deref().ok_or("--wasm is required")?;
        let mut command = strings(&["contract", "upload", "--wasm", wasm, "--build-only"]);
        command.extend(base);
        return Ok((command, None));
    }
    if args.action.starts_with("deploy-") {
        pinned_wasm(args.wasm.as_deref(), &text(&args.wasm_hash))?;
        let mut values = Map::new();
        let mut warning = None;
        if args.action == "deploy-parent" {
            let owner = text(&args.owner);
            values.insert("owner".into(), json!(address(&owner)?));
            let engine = text(&args.engine_wasm);
            values.insert("engine_wasm".into(), json!(code_hash(&engine)?));
            if owner != args.source.as_str() {
                return Err("Parent deployment source must be its native admin account".into());
            }
        } else {
            let config = public_json(args.config.as_deref().ok_or("--config is required")?)?;
            let map = exact_keys(&config, &CONFIG)
                .ok_or("Config fields must exactly match the policy wallet ABI")?;
            let mut packet = map.clone();
            packet.remove("asset");
            packet.remove("policy_instance");
            packet.insert("deployment_version".into(), json!(1));
            packet.insert("wasm_hash".into(), Value::Null);
            deployment(&Value::Object(packet))?;
            warning = policy_rules(&config, tier, policy_source, compile)?;
            contract(&map["asset"])?;
            let instance = code_hash(&map["policy_instance"])?;
            if instance.bytes().all(|b| b == b'0') {
                return Err("Policy identity must be nonzero".into());
            }
            if map["owner"] != args.source.as_str() {
                return Err("Policy wallet deployment source must be its owner".into());
            }
            let roles: BTreeSet<&str> = ["owner", "agent", "server"]
                .iter()
                .filter_map(|role| map[*role].as_str())
                .collect();
            if roles.len() != 3 {
                return Err("Owner, agent and server must differ".into());
            }
            values.insert("config".into(), config);
        }
        let wasm = args.wasm.as_deref().unwrap_or_default();
        let mut command = strings(&["contract", "deploy", "--wasm", wasm, "--build-only"]);
        command.extend(base);
        command.push("--".into());
        command.extend(serialize(&values)?);
        return Ok((command, warning));
    }
    let target = text(&args.contract);
    let target = contract(&target).map_err(|_| "Target must be a contract C address")?;
    let method = args.method.as_deref().unwrap_or_default();
    if args.action == "read" {
        if !["state", "engine", "policy_binding"].contains(&method) {
            return Err("Only state, engine and policy_binding reads are supported".into());
        }
        let mut command = strings(&["contract", "invoke", "--id", target, "--send=no"]);
        command.extend(base);
        command.extend(strings(&["--", method]));
        return Ok((command, None));
    }
    let values = public_json(&args.arguments)?;
    checked_args(method, &values, &args.family)?;
    let mut warning = None;
    if method == "deploy_policy" {
        warning = policy_rules(&values["deployment"], tier, policy_source, compile)?;
        wallet_code(&values["deployment"]["wasm_hash"], args.wasm.as_deref())?;
    }
    let mut command = strings(&["contract", "invoke", "--id", target, "--build-only"]);
    command.extend(base);
    command.extend(strings(&["--", method]));
    command.extend(serialize(
        values.as_object().ok_or("Expected public JSON")?,
    )?);
    Ok((command, warning))
}

/// Run the pinned Stellar CLI. Inherited Stellar signing, source and network overrides are
/// ignored, and no input is a secret.
pub fn stellar_cli(args: &[String], input: Option<&str>) -> Result<String> {
    let cli = std::env::var_os("STELLAR_BIN").unwrap_or_else(|| "stellar".into());
    run_cli(&cli, args, input)
}
pub fn run_cli(cli: &std::ffi::OsStr, args: &[String], input: Option<&str>) -> Result<String> {
    use std::io::Write;
    let clean = |command: &mut Command| {
        let inherited: Vec<_> = std::env::vars_os()
            .map(|(key, _)| key)
            .filter(|key| key.to_string_lossy().starts_with("STELLAR_"))
            .collect();
        for key in inherited {
            command.env_remove(key);
        }
    };
    let mut version = Command::new(cli);
    clean(version.arg("--version"));
    let version = run_checked(&mut version, "Stellar CLI 28.1.0 is required")?;
    if !version.starts_with(b"stellar 28.1.0 ") {
        return Err("Stellar CLI 28.1.0 is required".into());
    }
    let mut command = Command::new(cli);
    clean(command.args(args));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|_| "Cannot run the Stellar CLI")?;
    if let Some(mut stdin) = child.stdin.take() {
        // A command that reads no input may exit first; its status decides the result.
        let _ = stdin.write_all(input.unwrap_or_default().as_bytes());
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "Cannot run the Stellar CLI")?;
    if !output.status.success() {
        return Err(format!(
            "Stellar CLI failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Options of one assembly. `now` is the current Unix time.
pub struct Assembly<'a> {
    pub source: &'a str,
    pub network: &'a str,
    pub now: u64,
    pub max_fee: u32,
    pub candidate: Option<&'a str>,
    pub expected_wasm: Option<&'a str>,
}

/// Assemble RPC resources without permitting transaction-intent changes. The raw transaction is
/// unsigned v1 from the selected source with one host function. It gets five-minute time
/// bounds, then simulation may add only authorization, resources and their fee.
pub fn prepare_xdr(cli: Cli, raw_xdr: &str, a: &Assembly) -> Result<String> {
    let unsigned = "Expected unsigned v1 transaction with the selected native source";
    let TransactionEnvelope::Tx(mut raw) = allowit_stellar::read(raw_xdr.trim())? else {
        return Err(unsigned.into());
    };
    let source = stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256(public(a.source)?));
    if !raw.signatures.is_empty() || raw.tx.source_account != source {
        return Err(unsigned.into());
    }
    let one = "Expected exactly one Soroban host-function operation";
    let [operation] = raw.tx.operations.as_slice() else {
        return Err(one.into());
    };
    let OperationBody::InvokeHostFunction(invoke) = &operation.body else {
        return Err(one.into());
    };
    let expected_wasm = match a.expected_wasm {
        Some(text) => Some(allowit_stellar::unhex::<32>(code_hash(&json!(text))?)?),
        None => None,
    };
    if let Some(wasm) = expected_wasm
        && !matches!(&invoke.host_function, HostFunction::CreateContractV2(create)
            if create.executable == ContractExecutable::Wasm(stellar_xdr::Hash(wasm)))
    {
        return Err("Deployment transaction does not use the pinned Wasm executable".into());
    }
    if operation
        .source_account
        .as_ref()
        .is_some_and(|account| *account != raw.tx.source_account)
    {
        return Err("Operation source differs from selected transaction source".into());
    }
    let bounds = TimeBounds {
        min_time: TimePoint(0),
        max_time: TimePoint(a.now + 300),
    };
    raw.tx.cond = match raw.tx.cond {
        Preconditions::V2(v2) => Preconditions::V2(PreconditionsV2 {
            time_bounds: Some(bounds),
            ..v2
        }),
        _ => Preconditions::Time(bounds),
    };
    let bounded = allowit_stellar::xdr(&TransactionEnvelope::Tx(raw))?;
    let simulate = strings(&[
        "tx",
        "simulate",
        "--network",
        a.network,
        "--source-account",
        a.source,
        "--auth-mode",
        "root",
    ]);
    let assembled = cli(&simulate, Some(&bounded))?;
    let assembled: TransactionEnvelope = allowit_stellar::read(assembled.trim())
        .map_err(|_| "Simulation must return unsigned assembled Soroban XDR")?;
    let assembled = allowit_stellar::xdr(&assembled)?;
    if a.max_fee == 0 {
        return Err("Simulated fee exceeds the explicitly selected ceiling".into());
    }
    checks::check_assembled(
        &format!("stellar:{}", a.network),
        &bounded,
        &assembled,
        a.source,
        a.max_fee,
        a.candidate,
        expected_wasm,
    )?;
    Ok(assembled)
}

/// Run one action: check the live accounts and contract state, build with the CLI and assemble.
/// Returns standard output and an optional warning for standard error.
pub fn run(
    args: &Arguments,
    get: Get,
    cli: Cli,
    compile: &dyn Fn(&str) -> Result<()>,
    now: u64,
) -> Result<(String, Option<String>)> {
    let (prepared, warning) = command(args, compile)?;
    let (action, family) = (args.action.as_str(), args.family.as_str());
    let method = args.method.as_deref().unwrap_or_default();
    let values = public_json(&args.arguments)?;
    if action == "deploy-parent" || action == "admin" && family == "parent" {
        admin(&fetch(get, &args.network, &args.source)?, &args.members)?;
        if action == "admin" && method == "set_admin" {
            let candidate = account(&values["owner"])?;
            admin(
                &fetch(get, &args.network, candidate)?,
                &args.candidate_members,
            )?;
        }
    }
    if action == "deploy-wallet" || action == "admin" && family == "wallet" {
        owner_only(&fetch(get, &args.network, &args.source)?)?;
    }
    let mut candidate = None;
    // Recover needs no state(): the contract checks its kept owner, under any layout it can read.
    if action == "admin" && !(family == "wallet" && method == "recover") {
        let target = args.contract.as_deref().unwrap_or_default();
        let read = strings(&[
            "contract",
            "invoke",
            "--id",
            target,
            "--network",
            &args.network,
            "--source-account",
            &args.source,
            "--send=no",
            "--",
            "state",
        ]);
        let state: Value =
            serde_json::from_str(&cli(&read, None)?).map_err(|_| "Contract state is not JSON")?;
        let authority = state["owner"]
            .as_str()
            .ok_or("Contract state has no owner")?;
        if family == "wallet" && method == "deploy_policy" {
            wallet_layout(&state)?;
            let policy = &values["deployment"];
            let roles: BTreeSet<&str> = ["owner", "agent", "server"]
                .iter()
                .filter_map(|role| policy[*role].as_str())
                .collect();
            if roles.len() != 3 || roles.contains(target) {
                return Err("Owner, agent, server and policy wallet must be distinct".into());
            }
            if policy["owner"] != authority {
                let next = account(&policy["owner"])?;
                owner_only(&fetch(get, &args.network, next)?)?;
                candidate = Some(next.to_string());
            }
        }
        if args.source != authority {
            return Err("Source is not the contract's current owner/admin".into());
        }
        if family == "parent" {
            if integer(&values["version"]).is_none()
                || integer(&values["version"]) != integer(&state["version"])
            {
                return Err("Expected version does not match current state".into());
            }
            if method == "set_admin" {
                candidate = Some(account(&values["owner"])?.to_string());
            }
        } else {
            let target_version = if method == "deploy_policy" {
                &values["deployment"]["deployment_version"]
            } else {
                &values["deployment_version"]
            };
            let next = integer(&state["deployment_version"]).and_then(|v| v.checked_add(1));
            if next.is_none() || integer(target_version) != next {
                return Err("Policy deployment must use the next version".into());
            }
        }
    }
    let output = cli(&prepared, None)?;
    if action == "read" {
        return Ok((output, warning));
    }
    let assembled = prepare_xdr(
        cli,
        &output,
        &Assembly {
            source: &args.source,
            network: &args.network,
            now,
            max_fee: args.max_fee,
            candidate: candidate.as_deref(),
            expected_wasm: args
                .wasm_hash
                .as_deref()
                .filter(|_| action.starts_with("deploy-")),
        },
    )?;
    Ok((assembled, warning))
}
