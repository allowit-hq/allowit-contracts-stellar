//! Stellar administration in one binary. The native account actions prepare unsigned
//! transactions and verify account profiles from Horizon state. The contract actions (`contract`
//! module) prepare unsigned Soroban transactions with the pinned Stellar CLI. No action signs or
//! submits, and every input is public.
#![cfg(not(target_arch = "wasm32"))]
use allowit_core::transport::{
    http::{HttpClient, Method, Request},
    rpc::Options,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use stellar_strkey::ed25519::PublicKey as AccountKey;
use stellar_xdr::{
    Limits, Memo, MuxedAccount, Operation, OperationBody, Preconditions, SequenceNumber,
    SetOptionsOp, Signer, SignerKey, TimeBounds, TimePoint, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};

type Result<T> = std::result::Result<T, String>;

const ACTIONS: [&str; 6] = [
    "inspect",
    "verify-wallet",
    "verify-admin",
    "setup-wallet",
    "shutdown-wallet",
    "setup-admin",
];
const USAGE: &str = "usage: allowit-stellar-admin {inspect,verify-wallet,verify-admin,setup-wallet,shutdown-wallet,setup-admin} \
[--network {testnet,mainnet}] [--allow-mainnet] --account ACCOUNT [--agent AGENT] [--engine ENGINE] \
[--member MEMBER] [--transaction-source ACCOUNT] [--fee FEE]
       allowit-stellar-admin {upload,deploy-parent,deploy-wallet,read,admin} \
[--network {testnet,mainnet}] [--allow-mainnet] --source ACCOUNT [--wasm PATH] [--wasm-hash HEX] \
[--engine-wasm HEX] [--owner ACCOUNT] [--config JSON] [--contract CONTRACT] [--method METHOD] \
[--family {wallet,parent}] [--tier {simple,common,custom}] [--policy-source PATH] [--member MEMBER] \
[--candidate-member MEMBER] [--max-fee STROOPS] [--arguments JSON]";
const HELP: &str = "Every action reads public state or prints unsigned XDR. No action signs or submits. \
Pass only public addresses and hashes, never a secret seed. See docs/admin.md.";
const BAD_ADDRESS: &str = "Expected a public Stellar G address";
const MAX_RESPONSE_BYTES: usize = 1 << 20;

fn horizon(network: &str) -> Result<&'static str> {
    match network {
        "testnet" => Ok("https://horizon-testnet.stellar.org"),
        "mainnet" => Ok("https://horizon.stellar.org"),
        _ => Err("Unsupported network".into()),
    }
}

/// A public G address. The error never echoes the input, which could be a pasted secret.
fn public(value: &str) -> Result<[u8; 32]> {
    AccountKey::from_string(value)
        .map(|key| key.0)
        .map_err(|_| BAD_ADDRESS.to_string())
}
fn text<'a>(state: &'a Value, key: &str) -> Result<&'a str> {
    state[key]
        .as_str()
        .ok_or_else(|| format!("Account state has no {key}"))
}
fn entries(state: &Value) -> Result<&Vec<Value>> {
    state["signers"]
        .as_array()
        .ok_or_else(|| "Account state has no signers".to_string())
}
/// A signer weight or threshold: a JSON integer from 0 to 255.
fn byte(value: &Value) -> Option<u8> {
    value.as_u64().and_then(|v| u8::try_from(v).ok())
}

/// Every signer by key. Only unique Ed25519 signers are admitted.
fn signers(state: &Value) -> Result<BTreeMap<String, u8>> {
    let mut result = BTreeMap::new();
    for entry in entries(state)? {
        let key = entry["key"].as_str().unwrap_or_default();
        if entry["type"] != "ed25519_public_key" || result.contains_key(key) {
            return Err("Only unique Ed25519 signers are admitted".into());
        }
        public(key)?;
        let weight = byte(&entry["weight"]).ok_or("Invalid signer weight")?;
        result.insert(key.to_string(), weight);
    }
    Ok(result)
}
fn thresholds(state: &Value) -> Result<[u8; 3]> {
    let mut out = [0; 3];
    for (slot, key) in out
        .iter_mut()
        .zip(["low_threshold", "med_threshold", "high_threshold"])
    {
        *slot = byte(&state["thresholds"][key]).ok_or("Invalid account thresholds")?;
    }
    Ok(out)
}

/// Admit a native master-key owner, never an agent/evaluator quorum.
fn owner_only(state: &Value) -> Result<String> {
    let account = text(state, "account_id")?;
    public(account)?;
    let mut active = vec![];
    for signer in entries(state)? {
        if byte(&signer["weight"]).ok_or("Invalid signer weight")? > 0 {
            active.push(signer);
        }
    }
    let [master] = active.as_slice() else {
        return Err(OWNER_ONLY.into());
    };
    if master["type"] != "ed25519_public_key" || master["key"] != account {
        return Err(OWNER_ONLY.into());
    }
    let weight = byte(&master["weight"]).ok_or("Invalid signer weight")?;
    let satisfiable = ["low_threshold", "med_threshold", "high_threshold"]
        .iter()
        .all(|key| byte(&state["thresholds"][*key]).is_some_and(|t| t <= weight));
    if !satisfiable {
        return Err("Owner thresholds must remain satisfiable by its master key".into());
    }
    Ok(account.to_string())
}
const OWNER_ONLY: &str =
    "Policy wallet owner must have only its master key active; delegated native quorums are unsafe";

/// An existing account that no setup has touched: master weight 1 and default thresholds.
fn fresh(state: &Value) -> Result<()> {
    let account = text(state, "account_id")?;
    public(account)?;
    if signers(state)? != BTreeMap::from([(account.to_string(), 1)])
        || thresholds(state)? != [0, 0, 0]
    {
        return Err(
            "Setup requires an existing fresh account with only master weight 1 and default thresholds"
                .into(),
        );
    }
    Ok(())
}
fn distinct_roles(account: &str, agent: &str, engine: &str) -> Result<()> {
    public(agent)?;
    public(engine)?;
    if BTreeSet::from([account, agent, engine]).len() != 3 {
        return Err("Owner, agent and engine must differ".into());
    }
    Ok(())
}
/// The exact native wallet profile: owner 3, agent 1, engine 1 and thresholds 2/2/3.
fn wallet(state: &Value, agent: &str, engine: &str) -> Result<()> {
    let account = text(state, "account_id")?;
    public(account)?;
    distinct_roles(account, agent, engine)?;
    let expected = BTreeMap::from([
        (account.to_string(), 3),
        (agent.to_string(), 1),
        (engine.to_string(), 1),
    ]);
    if signers(state)? != expected || thresholds(state)? != [2, 2, 3] {
        return Err("Account is not the exact owner/agent/engine 3/1/1 profile".into());
    }
    Ok(())
}
/// The exact engine administrator profile: three members of weight 1, thresholds 2/2/2 and a
/// master key of weight 0 unless it is a member.
fn admin(state: &Value, members: &[String]) -> Result<()> {
    for key in members {
        public(key)?;
    }
    if members.iter().collect::<BTreeSet<_>>().len() != 3 {
        return Err("Three distinct admin members are required".into());
    }
    let mut expected: BTreeMap<String, u8> = members.iter().map(|key| (key.clone(), 1)).collect();
    expected
        .entry(text(state, "account_id")?.to_string())
        .or_insert(0);
    if signers(state)? != expected || thresholds(state)? != [2, 2, 2] {
        return Err("Account is not the exact three-member 2-of-3 profile".into());
    }
    Ok(())
}

/// Inputs of one preparation. `now` is the current Unix time; the transaction lapses 300
/// seconds later.
struct Preparation<'a> {
    action: &'a str,
    network: &'a str,
    agent: Option<&'a str>,
    engine: Option<&'a str>,
    members: &'a [String],
    fee: u32,
    now: u64,
    source_state: Option<&'a Value>,
}

fn set_options(body: SetOptionsOp) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::SetOptions(body),
    }
}
fn blank() -> SetOptionsOp {
    SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: None,
        low_threshold: None,
        med_threshold: None,
        high_threshold: None,
        home_domain: None,
        signer: None,
    }
}
fn signer(key: &str, weight: u32) -> Result<Operation> {
    Ok(set_options(SetOptionsOp {
        signer: Some(Signer {
            key: SignerKey::Ed25519(Uint256(public(key)?)),
            weight,
        }),
        ..blank()
    }))
}
fn weights(master: u32, low: u32, med: u32, high: u32) -> Operation {
    set_options(SetOptionsOp {
        master_weight: Some(master),
        low_threshold: Some(low),
        med_threshold: Some(med),
        high_threshold: Some(high),
        ..blank()
    })
}

/// The unsigned transaction of one setup or shutdown, as base64 XDR. Every operation of one
/// action is in one transaction, so the profile changes atomically.
fn prepare(state: &Value, p: &Preparation) -> Result<String> {
    horizon(p.network)?;
    if !(100..=100_000).contains(&p.fee) {
        return Err("Fee must be 100..100000 stroops per operation".into());
    }
    let account = text(state, "account_id")?;
    public(account)?;
    if let Some(source) = p.source_state {
        let id = text(source, "account_id")?;
        if p.action != "shutdown-wallet" || [Some(account), p.agent, p.engine].contains(&Some(id)) {
            return Err("A separate transaction source is supported only for shutdown".into());
        }
        owner_only(source)?;
    }
    let payer = p.source_state.unwrap_or(state);
    let sequence: i64 = text(payer, "sequence")?
        .parse()
        .map_err(|_| "Invalid account sequence")?;
    if sequence < 0 {
        return Err("Negative sequence".into());
    }
    let roles = || -> Result<(&str, &str)> {
        Ok((p.agent.ok_or(BAD_ADDRESS)?, p.engine.ok_or(BAD_ADDRESS)?))
    };
    let mut operations = match p.action {
        "setup-wallet" => {
            fresh(state)?;
            let (agent, engine) = roles()?;
            distinct_roles(account, agent, engine)?;
            vec![signer(agent, 1)?, signer(engine, 1)?, weights(3, 2, 2, 3)]
        }
        "shutdown-wallet" => {
            let (agent, engine) = roles()?;
            wallet(state, agent, engine)?;
            vec![signer(agent, 0)?, signer(engine, 0)?, weights(3, 3, 3, 3)]
        }
        "setup-admin" => {
            fresh(state)?;
            for key in p.members {
                public(key)?;
            }
            if p.members.len() != 3 || p.members.iter().collect::<BTreeSet<_>>().len() != 3 {
                return Err("Three distinct admin members are required".into());
            }
            let mut operations = vec![];
            for key in p.members.iter().filter(|key| *key != account) {
                operations.push(signer(key, 1)?);
            }
            let master = u32::from(p.members.iter().any(|key| key == account));
            operations.push(weights(master, 2, 2, 2));
            operations
        }
        _ => return Err("Unsupported preparation action".into()),
    };
    if p.source_state.is_some() {
        for operation in &mut operations {
            operation.source_account = Some(MuxedAccount::Ed25519(Uint256(public(account)?)));
        }
    }
    let count = u32::try_from(operations.len()).map_err(|e| e.to_string())?;
    let transaction = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(public(text(payer, "account_id")?)?)),
        fee: p.fee * count,
        seq_num: SequenceNumber(sequence.checked_add(1).ok_or("Invalid account sequence")?),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(p.now + 300),
        }),
        memo: Memo::None,
        operations: operations.try_into().map_err(|_| "Too many operations")?,
        ext: TransactionExt::V0,
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: transaction,
        signatures: VecM::default(),
    })
    .to_xdr_base64(Limits::none())
    .map_err(|e| e.to_string())
}

/// One public Horizon read. `get` returns the JSON body of a URL.
type Get<'a> = &'a dyn Fn(&str) -> Result<Value>;

fn fetch(get: Get, network: &str, account: &str) -> Result<Value> {
    public(account)?;
    let state = get(&format!("{}/accounts/{account}", horizon(network)?))?;
    if state["account_id"] != account {
        return Err("Account response mismatch".into());
    }
    Ok(state)
}
/// Refuse an account with open offers, or only warn when `reject` is false.
fn no_offers(get: Get, network: &str, account: &str, reject: bool) -> Result<Option<&'static str>> {
    public(account)?;
    let offers = get(&format!(
        "{}/accounts/{account}/offers?limit=1",
        horizon(network)?
    ))?;
    let records = offers["_embedded"]["records"]
        .as_array()
        .ok_or("Invalid Horizon offers response")?;
    if records.is_empty() {
        return Ok(None);
    }
    if reject {
        return Err("Open offers prevent native-wallet verification".into());
    }
    Ok(Some(
        "Warning: open offers remain. Revoke signers first, then reconcile offers and allowances.",
    ))
}

#[derive(Debug, Default)]
struct Arguments {
    action: String,
    network: String,
    allow_mainnet: bool,
    account: String,
    agent: Option<String>,
    engine: Option<String>,
    members: Vec<String>,
    transaction_source: Option<String>,
    fee: u32,
}

fn parse(args: &[String]) -> Result<Arguments> {
    let mut out = Arguments {
        network: "testnet".into(),
        fee: 100,
        ..Arguments::default()
    };
    let mut account = None;
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
        let address = |value: String| public(&value).map(|_| value);
        match flag {
            "--allow-mainnet" if inline.is_none() => out.allow_mainnet = true,
            "--network" => out.network = value()?,
            "--account" => account = Some(address(value()?)?),
            "--agent" => out.agent = Some(address(value()?)?),
            "--engine" => out.engine = Some(address(value()?)?),
            "--member" => out.members.push(address(value()?)?),
            "--transaction-source" => out.transaction_source = Some(address(value()?)?),
            "--fee" => out.fee = value()?.parse().map_err(|_| "--fee expects an integer")?,
            _ if !flag.starts_with('-') && out.action.is_empty() => out.action = flag.into(),
            _ => return Err("Unrecognized arguments".into()),
        }
    }
    if !ACTIONS.contains(&out.action.as_str()) {
        return Err(format!(
            "The action is one of {}, {}",
            ACTIONS.join(", "),
            contract::ACTIONS.join(", ")
        ));
    }
    horizon(&out.network).map_err(|_| "--network is testnet or mainnet")?;
    out.account = account.ok_or("--account is required")?;
    let prepares = out.action.starts_with("setup") || out.action.starts_with("shutdown");
    if out.network == "mainnet" && prepares && !out.allow_mainnet {
        return Err("Mainnet preparation requires --allow-mainnet".into());
    }
    if ["setup-wallet", "shutdown-wallet", "verify-wallet"].contains(&out.action.as_str())
        && (out.agent.is_none() || out.engine.is_none())
    {
        return Err("--agent and --engine are required".into());
    }
    if out.transaction_source.is_some() && out.action != "shutdown-wallet" {
        return Err("--transaction-source is supported only for shutdown".into());
    }
    Ok(out)
}

/// Run one action and return its standard output and an optional warning for standard error.
fn run(args: &Arguments, get: Get, now: u64) -> Result<(String, Option<&'static str>)> {
    let state = fetch(get, &args.network, &args.account)?;
    let mut warning = None;
    if ["verify-wallet", "shutdown-wallet"].contains(&args.action.as_str()) {
        let reject = args.action == "verify-wallet";
        warning = no_offers(get, &args.network, &args.account, reject)?;
    }
    let (agent, engine) = (args.agent.as_deref(), args.engine.as_deref());
    let output = match args.action.as_str() {
        "inspect" => {
            let mut public_state = serde_json::Map::new();
            for key in ["account_id", "sequence", "signers", "thresholds"] {
                let value = state
                    .get(key)
                    .ok_or(format!("Account state has no {key}"))?;
                public_state.insert(key.into(), value.clone());
            }
            serde_json::to_string_pretty(&json!(public_state)).map_err(|e| e.to_string())?
        }
        "verify-wallet" => {
            wallet(
                &state,
                agent.ok_or(BAD_ADDRESS)?,
                engine.ok_or(BAD_ADDRESS)?,
            )?;
            "Exact native wallet profile verified".into()
        }
        "verify-admin" => {
            admin(&state, &args.members)?;
            "Exact engine administrator profile verified".into()
        }
        _ => {
            let source_state = match &args.transaction_source {
                Some(source) => Some(fetch(get, &args.network, source)?),
                None => None,
            };
            prepare(
                &state,
                &Preparation {
                    action: &args.action,
                    network: &args.network,
                    agent,
                    engine,
                    members: &args.members,
                    fee: args.fee,
                    now,
                    source_state: source_state.as_ref(),
                },
            )?
        }
    };
    Ok((output, warning))
}

fn horizon_get(url: &str) -> Result<Value> {
    let client = HttpClient::new(Options {
        timeout: Duration::from_secs(20),
        max_response_bytes: MAX_RESPONSE_BYTES,
        no_proxy: false,
        connect_timeout: None,
    })
    .map_err(|e| e.to_string())?;
    let request = Request {
        method: Method::Get,
        url,
        headers: &[("accept".to_string(), "application/json".to_string())],
        body: None,
    };
    let response = client.send(request, None).map_err(|e| e.to_string())?;
    if response.status != 200 {
        return Err(format!("Horizon returned HTTP {}", response.status));
    }
    serde_json::from_slice(&response.body).map_err(|_| "Invalid Horizon response".to_string())
}

/// The action: the first argument that is neither a flag nor the value of a flag.
fn action_of(args: &[String]) -> Option<&str> {
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if !arg.starts_with('-') {
            return Some(arg);
        }
        if arg != "--allow-mainnet" && !arg.contains('=') {
            rest.next();
        }
    }
    None
}

/// True when `-h` or `--help` stands where a flag can stand, not where a flag's value does.
fn help_requested(args: &[String]) -> bool {
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "-h" || arg == "--help" {
            return true;
        }
        if arg.starts_with('-') && arg != "--allow-mainnet" && !arg.contains('=') {
            rest.next();
        }
    }
    false
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if help_requested(&args) {
        println!("{USAGE}\n\n{HELP}");
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let usage = |error: String| -> ! {
        eprintln!("{USAGE}\nallowit-stellar-admin: error: {error}");
        std::process::exit(2)
    };
    let result = if action_of(&args).is_some_and(|action| contract::ACTIONS.contains(&action)) {
        let parsed = contract::parse(&args).unwrap_or_else(|error| usage(error));
        contract::run(
            &parsed,
            &horizon_get,
            &contract::stellar_cli,
            &contract::host_compile,
            now,
        )
    } else {
        let parsed = parse(&args).unwrap_or_else(|error| usage(error));
        run(&parsed, &horizon_get, now).map(|(output, warning)| (output, warning.map(String::from)))
    };
    match result {
        Ok((output, warning)) => {
            if let Some(warning) = warning {
                eprintln!("{warning}");
            }
            println!("{output}");
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

mod contract;
#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod tests;
