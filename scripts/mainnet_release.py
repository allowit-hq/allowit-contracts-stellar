#!/usr/bin/env python3
"""Prepare bounded Stellar release transactions and simulate policy wallet E2E checks. Never sign or submit."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
from types import SimpleNamespace
from urllib.request import Request, urlopen

from stellar_sdk import Account, Address, Asset, Network, TransactionBuilder, TransactionEnvelope, Keypair, scval, xdr
import contract_admin as ca
import wallet_admin as wa

ROOT = Path(__file__).resolve().parents[1]
RPC = {"mainnet": "https://mainnet.sorobanrpc.com", "testnet": "https://soroban-testnet.stellar.org"}
STAGES = ("upload-engine", "upload-parent", "upload-wallet", "deploy-parent", "deploy-wallet", "fund", "execute")
NAMES = {"engine": "allowit_wallet_engine.wasm", "parent": "allowit_engine_parent.wasm", "wallet": "allowit_common_policy_engine.wasm"}
READ_METHODS = {"getNetwork", "getLatestLedger", "getLedgerEntries", "simulateTransaction", "getTransaction"}
# Earlier reviewed releases store other custody layouts. Re-pin a reviewed release of layout 4.
DEFAULT_REVISION = None
DEFAULT_HASHES = {}
WALLET_KIND = "common_policy_engine"
POLICY_DENIED = 18
BUILD_SCRIPTS = ("build-contracts.sh", "check-policy-bindings.py", "policy_source.py", "core_sources.py")

# The smoke policy is entirely one standard prefix of canonical calls. Its rules derive from the source.
SMOKE_SOURCE = b"""use allowit::prelude::*;
/// Smoke-test my mainnet wallet. Pay only the pinned recipient, cap each payment, cap the daily
/// volume, cap total spending, allow only a few payments and stop when the params expire.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Pay only the pinned recipient"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    // "cap each payment"
    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;
    // "cap the daily volume"
    allowit::daily_volume_limit(ctx, &ctx.params[allowit::DAILY_VOLUME_LIMIT])?;
    // "cap total spending"
    allowit::lifetime_spending_limit(ctx, &ctx.params[allowit::LIFETIME_SPENDING_LIMIT])?;
    // "allow only a few payments"
    allowit::call_limit(ctx, &ctx.params[allowit::CALL_LIMIT])?;
    // "stop when the params expire"
    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;
    Ok(())
}
"""
RULES = ca.standard_prefix(SMOKE_SOURCE.decode())
# Executions carry this as `source_hash`: the SHA-256 of the literal source above.
SMOKE_SOURCE_HASH = hashlib.sha256(SMOKE_SOURCE).digest()


# Bind every delegated CLI operation to the same endpoint and passphrase as direct RPC reads.
_ORIGINAL_CLI_RUN = ca.cli_run

def network_cli(args, input_data=None):
    args = list(args)
    if "--network" not in args:
        raise ValueError("CLI operations require an explicit network")
    index = args.index("--network")
    network = args[index + 1]
    args[index:index + 2] = ["--rpc-url", RPC[network], "--network-passphrase", wa.PASSPHRASE[network]]
    return _ORIGINAL_CLI_RUN(args, input_data=input_data)

ca.cli_run = network_cli


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def integer(value, minimum=1, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Expected a bounded integer")
    return value


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def rpc(network, method, params=None):
    if method not in READ_METHODS:
        raise ValueError("Only read and simulation RPC methods are admitted")
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
    request = Request(RPC[network], data=body, headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=40) as response:
        result = json.load(response)
    if "error" in result:
        raise ValueError("RPC request failed: " + json.dumps(result["error"]))
    return result["result"]


def check_network(network):
    actual = rpc(network, "getNetwork")
    if actual["passphrase"] != wa.PASSPHRASE[network]:
        raise ValueError("RPC network passphrase does not match the plan")
    return actual


def gas(plan):
    """Attributable XLM gas ceiling of one smoke execution: its full fee cap in stroops."""
    return plan["fee_caps_stroops"]["execute"]


def smoke_params(plan):
    """Return the smoke params: exactly the selected rules' canonical keys, checked as Common does."""
    params = plan["params"]
    if not isinstance(params, dict) or set(params) != set(RULES) or params["destinations"] != [plan["recipient"]]:
        raise ValueError("Smoke params require exactly the selected canonical rule keys and pinned recipient")
    for name in set(RULES) - {"destinations"}:
        integer(params[name])
    if params["daily_volume_limit"] < plan["payment_stroops"] + gas(plan):
        raise ValueError("Smoke payment and gas exceed daily capacity")
    ca.params(params, "common")
    return params


def plain_params(native):
    """The plain JSON params of a decoded state map: each AllowitValue as its inner value."""
    def plain(value):
        kind, inner = value
        return [plain(item) for item in inner] if kind == "List" else inner
    return {key: plain(value) for key, value in native.items()}


def prefix_digest(kind, module, asset, rules):
    """The contract's standard_prefix_digest: SHA-256 of canonical XDR of its binding tuple
    (domain, kind, module hash, asset, rules).

    The ordered rules are a Vec<AllowitRule>; each unit enum variant encodes as a one-symbol vector."""
    checks = scval.to_vec([scval.to_vec([scval.to_symbol(rule)]) for rule in rules])
    value = scval.to_vec([scval.to_symbol("allowit_std_prefix"), scval.to_symbol(kind), scval.to_bytes(bytes.fromhex(module)), scval.to_address(asset),
                          checks])
    return digest(value.to_xdr_bytes())


def wallet_config(plan):
    source = prefix_digest(WALLET_KIND, plan["artifacts"]["wallet"]["sha256"], plan["asset"], RULES)
    return {"owner":plan["owner"],"agent":plan["agent"],"server":plan["server"],"asset":plan["asset"],"policy_instance":plan["policy_instance"],"source_digest":source,"rules":RULES,"params":smoke_params(plan),"x402_enabled":False}


def usage(plan, wallet):
    """Standard policy state: successful calls and lifetime irreversible expenses. Absent keys are zero."""
    state = plain_params(read_contract(plan, wallet, "state")["policy_state"])
    return int(state.get("calls", 0)), int(state.get("spent", 0))


def server_entry(envelope, plan, signed):
    tx = envelope.transaction
    if not tx.v1 or envelope.signatures or tx.source.account_id != plan["agent"] or len(tx.operations) != 1:
        raise ValueError("Execution must be an unsigned single-operation agent envelope")
    operation = tx.operations[0]
    if not isinstance(operation,ca.InvokeHostFunction): raise ValueError("Expected a Soroban execution operation")
    if operation.source is not None and operation.source.to_xdr_object() != tx.source.to_xdr_object():
        raise ValueError("Execution operation source differs from the agent")
    unsigned = copy.deepcopy(operation)
    entries = [entry for entry in operation.auth if entry.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS]
    sources = [entry for entry in operation.auth if entry.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT]
    if len(entries) != 1 or len(sources) != 1 or len(operation.auth) != 2:
        raise ValueError("Execution requires exactly agent-source and server authorization")
    entry = entries[0]
    if entry.credentials.address.address != Address(plan["server"]).to_xdr_sc_address():
        raise ValueError("Unexpected server authorization address")
    if (entry.credentials.address.signature.type != xdr.SCValType.SCV_VOID) != signed:
        raise ValueError("Unexpected server signature state")
    for candidate in unsigned.auth:
        if candidate.credentials.type == xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS:
            candidate.credentials.address.signature = scval.to_void()
    ca.validate_auth(unsigned,plan["server"],plan["network"])
    return entry


def complete_execute(plan, prepared, signed_xdr):
    if prepared.get("stage") != "execute" or prepared.get("signing_ready") is not False or prepared.get("plan_digest") != digest(canonical(plan)):
        raise ValueError("Use the original execute authorization request for this plan")
    if len(signed_xdr) > 8192:
        raise ValueError("Server authorization exceeds the bounded packet size")
    network = plan["network"]
    envelope = TransactionEnvelope.from_xdr(prepared["unsigned_xdr"],wa.PASSPHRASE[network])
    if envelope.hash_hex() != prepared["transaction_hash"]:
        raise ValueError("Original execution bytes differ from their retained hash")
    original = server_entry(envelope,plan,signed=False)
    if original.to_xdr() != prepared["server_authorization_xdr"]:
        raise ValueError("Server request differs from the retained transaction")
    signed = xdr.SorobanAuthorizationEntry.from_xdr(signed_xdr)
    if signed.to_xdr()!=signed_xdr: raise ValueError("Server authorization must use canonical XDR")
    stripped = copy.deepcopy(signed)
    if stripped.credentials.type != xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS:
        raise ValueError("Server must supply address authorization")
    stripped.credentials.address.signature = scval.to_void()
    if stripped != original:
        raise ValueError("Server changed the exact authorization scope, nonce or expiry")
    now = int(time.time())
    tx = envelope.transaction
    bounds = tx.preconditions.time_bounds if tx.preconditions else None
    if not bounds or bounds.min_time != 0 or not now < bounds.max_time <= now + 300:
        raise ValueError("Original execution time bounds are expired or unbounded")
    state,binding = wallet_state(plan,prepared["wallet"],prepared["parent"])
    host = tx.operations[0].host_function
    invocation = host.invoke_contract
    if host.type != xdr.HostFunctionType.HOST_FUNCTION_TYPE_INVOKE_CONTRACT or invocation is None or len(invocation.args) != 1:
        raise ValueError("Expected the exact wallet execution invocation")
    original_request = scval.from_struct(invocation.args[0])
    expiry = scval.to_native(original_request["expires_at"])
    if expiry > bounds.max_time:
        raise ValueError("Execution expiry exceeds the original transaction bounds")
    priced, bounds = scval.from_enum(original_request["expense"])
    if priced != "Priced":
        raise ValueError("Execution must carry expense bounds")
    cost = scval.from_struct(bounds)
    observed, day = scval.to_native(cost["observed_ledger"]), scval.to_native(cost["day"])
    expected = execution(plan,state,binding,prepared["operation_id"],observed,expires_at=expiry,day=day)
    if invocation.contract_address != Address(prepared["wallet"]).to_xdr_sc_address() or invocation.function_name.sc_symbol != b"execute" or invocation.args != [expected]:
        raise ValueError("Execution differs from the plan's exact transfer")
    if prepared["expected_receipt"] != expected_receipt(plan,prepared["wallet"],state,prepared["operation_id"]):
        raise ValueError("Execution state changed after preparation")
    calls, spent = usage(plan,prepared["wallet"])
    effects = {"wallet":prepared["wallet"],"wallet_balance":balance(plan,prepared["wallet"]),"recipient_balance":balance(plan,plan["recipient"]),"calls":calls,"spent_total":spent}
    if prepared["expected_effects"] != effects:
        raise ValueError("Wallet balances or usage changed after original preparation")
    for role in ("agent","server"):
        account = wa.fetch(network,plan[role]);wa.owner_only(account)
        if role == "agent" and tx.sequence != int(account["sequence"]) + 1:
            raise ValueError("Agent sequence changed after original preparation")
    ledger = integer(int(rpc(network,"getLatestLedger")["sequence"]),1,2**32-1)
    credential = signed.credentials.address
    if not ledger < credential.signature_expiration_ledger.uint32 <= ledger+50:
        raise ValueError("Server authorization ledger window is expired or too broad")
    signatures = scval.to_native(credential.signature)
    if not isinstance(signatures,list) or len(signatures)!=1 or set(signatures[0])!={"public_key","signature"}:
        raise ValueError("Require one native Ed25519 server signature")
    public = Keypair.from_public_key(plan["server"])
    signature = signatures[0]
    if signature["public_key"] != public.raw_public_key() or not isinstance(signature["signature"],bytes) or len(signature["signature"])!=64:
        raise ValueError("Server signature key differs from the plan")
    payload=xdr.HashIDPreimage(xdr.EnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION,soroban_authorization=xdr.HashIDPreimageSorobanAuthorization(xdr.Hash(Network(wa.PASSPHRASE[network]).network_id()),credential.nonce,credential.signature_expiration_ledger,signed.root_invocation))
    try:
        public.verify(hashlib.sha256(payload.to_xdr_bytes()).digest(),signature["signature"])
    except Exception as error:
        raise ValueError("Invalid server authorization signature") from error
    tx.operations[0].auth=[signed if e.credentials.type==xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS else e for e in tx.operations[0].auth]
    raw=envelope.to_xdr()
    assembled=ca.cli_run(["tx","simulate","--network",network,"--source-account",plan["agent"],"--auth-mode","enforce"],input_data=raw)
    final=TransactionEnvelope.from_xdr(assembled,wa.PASSPHRASE[network])
    server_entry(final,plan,signed=True)
    normalized=copy.deepcopy(final.transaction);normalized.fee=tx.fee;normalized.soroban_data=tx.soroban_data
    if normalized.to_xdr_object()!=tx.to_xdr_object() or final.transaction.soroban_data is None or final.transaction.fee < tx.fee or final.transaction.fee>plan["fee_caps_stroops"]["execute"] or final.transaction.soroban_data.resource_fee.int64<0 or final.transaction.soroban_data.resource_fee.int64>plan["fee_caps_stroops"]["execute"]:
        raise ValueError("Enforce simulation changed the original intent or exceeded its fee cap")
    result=copy.deepcopy(prepared)
    result.update(signing_ready=True,unsigned_xdr=assembled,transaction_hash=final.hash_hex(),fee_bid_stroops=final.transaction.fee,authorization_request_hash=prepared["transaction_hash"])
    return result


def load_plan(path):
    path = Path(path).resolve()
    plan = json.loads(path.read_text())
    fields = {"schema", "network", "network_passphrase", "source_revision", "artifact_manifest", "artifacts", "owner", "admin", "admin_members", "agent", "server", "asset", "recipient", "forbidden_recipient", "policy_instance", "params", "fund_stroops", "payment_stroops", "fee_caps_stroops", "total_fee_cap_stroops"}
    if set(plan) != fields or plan["schema"] != 1:
        raise ValueError("Plan fields must match schema 1 exactly")
    network = plan["network"]
    if network not in RPC or plan["network_passphrase"] != wa.PASSPHRASE[network]:
        raise ValueError("Select the exact Stellar network and passphrase")
    if not re.fullmatch(r"[0-9a-f]{40}", plan["source_revision"]):
        raise ValueError("Pin the complete contract source revision")
    if DEFAULT_REVISION is None or plan["source_revision"] != DEFAULT_REVISION:
        raise ValueError("This smoke tool admits only the reviewed default contract revision; re-pin one of custody layout 4")
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != plan["source_revision"]:
        # Tooling commits may follow the contract revision, but every build source must match it.
        subprocess.run(["git", "merge-base", "--is-ancestor", plan["source_revision"], "HEAD"], cwd=ROOT, check=True)
    manifest_path = Path(plan["artifact_manifest"])
    if not manifest_path.is_absolute():
        manifest_path = path.parent / manifest_path
    manifest = json.loads(manifest_path.read_text())
    manifest_revision = manifest["git_revision"]
    if not re.fullmatch(r"[0-9a-f]{40}", manifest_revision):
        raise ValueError("Manifest must pin a complete source revision")
    subprocess.run(["git", "merge-base", "--is-ancestor", plan["source_revision"], manifest_revision], cwd=ROOT, check=True, capture_output=True)
    subprocess.run(["git", "merge-base", "--is-ancestor", manifest_revision, "HEAD"], cwd=ROOT, check=True, capture_output=True)
    for entry in manifest["sources"]:
        relative = entry["path"]
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise ValueError("Manifest source path escapes the repository")
        committed = subprocess.check_output(["git", "show", plan["source_revision"] + ":" + relative], cwd=ROOT)
        if digest(committed) != entry["sha256"] or digest((ROOT / relative).read_bytes()) != entry["sha256"]:
            raise ValueError("Build source differs from the pinned revision: " + relative)
    for name in ("owner", "admin", "agent", "server", "recipient", "forbidden_recipient"):
        ca.account(plan[name])
    if len({plan[k] for k in ("owner", "admin", "agent", "server", "recipient", "forbidden_recipient")}) != 6:
        raise ValueError("Use separate owner, admin, agent, server and recipient accounts")
    members = plan["admin_members"]
    if not isinstance(members, list) or len(members) != 3 or len(set(members)) != 3:
        raise ValueError("Pin exactly three distinct admin members")
    for member in members:
        ca.account(member)
    if set(members) & {plan["owner"], plan["agent"], plan["server"]}:
        raise ValueError("Admin members must differ from custody owner and agent")
    ca.code_hash(plan["policy_instance"])
    if int(plan["policy_instance"], 16) == 0:
        raise ValueError("Policy identity must be nonzero")
    params = smoke_params(plan)
    native = Asset.native().contract_id(wa.PASSPHRASE[network])
    if plan["asset"] != native or params["destinations"] != [plan["recipient"]]:
        raise ValueError("Release smoke tests require native XLM and one pinned recipient")
    integer(plan["payment_stroops"])
    integer(plan["fund_stroops"])
    if not plan["payment_stroops"] <= plan["fund_stroops"] <= params["lifetime_spending_limit"] or plan["payment_stroops"] + gas(plan) > params["lifetime_spending_limit"]:
        raise ValueError("Payment, gas, funding and lifetime spending limit params are inconsistent")
    if plan["payment_stroops"] > params["payment_limit"]:
        raise ValueError("Smoke payment exceeds the payment limit")
    caps = plan["fee_caps_stroops"]
    if set(caps) != set(STAGES):
        raise ValueError("Set one fee cap for every release stage")
    for value in caps.values():
        integer(value, 100, 2**32 - 1)
    if sum(caps.values()) > integer(plan["total_fee_cap_stroops"]):
        raise ValueError("Stage fee caps exceed the aggregate release fee cap")
    if set(plan["artifacts"]) != set(NAMES):
        raise ValueError("Pin engine, parent and policy wallet artifacts")
    for name, artifact in plan["artifacts"].items():
        if set(artifact) != {"path", "sha256"}:
            raise ValueError("Artifact fields must be path and sha256")
        artifact_path = Path(artifact["path"])
        if not artifact_path.is_absolute():
            artifact_path = path.parent / artifact_path
        ca.code_hash(artifact["sha256"])
        if artifact["sha256"] != DEFAULT_HASHES[name]:
            raise ValueError("This smoke tool rejects custom and test-feature artifacts")
        entries = {entry["name"]: entry for entry in manifest["artifacts"]}
        if entries[NAMES[name]]["sha256"] != artifact["sha256"]:
            raise ValueError("Artifact differs from the reviewed build manifest")
        fixtures = (ROOT / "target/test-fixtures").glob("*.wasm")
        if any(digest(f.read_bytes()) == artifact["sha256"] for f in fixtures):
            raise ValueError("Test-feature artifacts cannot be deployed")
        if digest(artifact_path.read_bytes()) != artifact["sha256"].lower():
            raise ValueError("Artifact hash differs from plan: " + name)
    if set(entry["path"] for entry in manifest["sources"]) != set(str(f.relative_to(ROOT)) for f in [ROOT / n for n in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")] + list((ROOT / "crates").rglob("*.rs")) + list((ROOT / "crates").rglob("Cargo.toml")) + [ROOT / "scripts" / n for n in BUILD_SCRIPTS]):
        raise ValueError("Manifest must include every contract build source")
    return plan, digest(canonical(plan)), path.parent


def artifact_path(plan, base, name):
    value = Path(plan["artifacts"][name]["path"])
    return str(value if value.is_absolute() else base / value)


def read_contract(plan, contract, method):
    if method not in ("state","policy_binding","engine"):
        raise ValueError("Only public wallet and parent state reads are admitted")
    raw=raw_invoke(plan,plan["owner"],ca.contract(contract),method,[])
    result=rpc(plan["network"],"simulateTransaction",{"transaction":raw})
    if "error" in result: raise ValueError("Contract state simulation failed")
    value=scval.to_native(xdr.SCVal.from_xdr(result["results"][0]["xdr"]))
    def plain(value):
        if isinstance(value,Address): return value.address
        if isinstance(value,bytes): return value.hex()
        if isinstance(value,list): return [plain(v) for v in value]
        if isinstance(value,dict): return {plain(k):plain(v) for k,v in value.items()}
        return value
    return plain(value)


def rule_names(rules):
    """Decoded Vec<AllowitRule>. Each unit enum variant decodes as a one-symbol list."""
    if not isinstance(rules, list) or any(not isinstance(rule, list) or len(rule) != 1 or not isinstance(rule[0], str) for rule in rules):
        raise ValueError("Wallet rules are not a Vec<AllowitRule>")
    return [rule[0] for rule in rules]


def wallet_state(plan, wallet, parent):
    ca.contract(wallet)
    ca.contract(parent)
    for address, name in ((wallet, "wallet"), (parent, "parent")):
        actual = ca.cli_run(["contract", "info", "hash", "--network", plan["network"], "--id", address]).strip()
        if actual != plan["artifacts"][name]["sha256"]:
            raise ValueError("Deployed executable differs from the plan: " + name)
    state = read_contract(plan, wallet, "state")
    binding = read_contract(plan, wallet, "policy_binding")
    engine = read_contract(plan, parent, "engine")
    actual = ca.cli_run(["contract", "info", "hash", "--network", plan["network"], "--id", ca.contract(engine)]).strip()
    if actual != plan["artifacts"]["engine"]["sha256"]:
        raise ValueError("Resolved shared-engine executable differs from the plan")
    parent_state = read_contract(plan, parent, "state")
    if parent_state["owner"] != plan["admin"]:
        raise ValueError("Parent authority differs from the plan")
    expected = wallet_config(plan)
    if state["owner"] != plan["owner"] or state["agent"] != plan["agent"] or state["server"] != plan["server"] or state["asset"] != plan["asset"] or rule_names(state["rules"]) != RULES or state["x402_enabled"] or plain_params(state["params"]) != expected["params"]:
        raise ValueError("Wallet authority or params differ from the plan")
    if state["paused"]:
        raise ValueError("Wallet is paused")
    if binding["policy_instance"] != plan["policy_instance"] or binding["module_digest"] != plan["artifacts"]["wallet"]["sha256"]:
        raise ValueError("Wallet policy identity or executable differs from the plan")
    if binding["source_digest"] != expected["source_digest"] or binding["engine_kind"] != WALLET_KIND or int(binding["contract_version"]) != ca.WALLET_CONTRACT_VERSION:
        raise ValueError("Installed compiled policy differs from the plan")
    if ["transfer"] not in binding["operations"]:
        raise ValueError("Wallet does not run transfers")
    return state, binding


def raw_invoke(plan, source, contract, method, arguments):
    account = wa.fetch(plan["network"], source)
    return TransactionBuilder(Account(source, int(account["sequence"])), wa.PASSPHRASE[plan["network"]], base_fee=100).add_time_bounds(0, int(time.time()) + 300).append_invoke_contract_function_op(contract, method, arguments).build().to_xdr()


def execution(plan, state, binding, operation_id, observed_ledger, case="positive", expires_at=None, day=None):
    ca.code_hash(operation_id)
    if int(operation_id, 16) == 0:
        raise ValueError("Operation identity must be nonzero")
    recipient = plan["forbidden_recipient"] if case == "denied-recipient" else plan["recipient"]
    amount = plan["params"]["payment_limit"] + 1 if case == "over-limit" else plan["payment_stroops"]
    now = int(time.time())
    expires = expires_at if expires_at is not None else now - 1 if case == "expired" else min(now + 240, plan["params"]["expires_at"])
    if expires > plan["params"]["expires_at"]: raise ValueError("Execution expires after the expires_at param")
    if case != "expired" and expires <= now + 30:
        raise ValueError("The params must remain valid for at least 30 seconds")
    # The typed AllowitStellarOperation::Transfer with its named arguments; the wallet is the source.
    transfer = scval.to_struct({"amount": scval.to_int128(amount), "to": scval.to_address(recipient), "token": scval.to_address(plan["asset"])})
    # Conservative XLM ceilings: the full execute fee cap is attributable gas; a payment spends principal plus gas.
    expense = scval.to_struct({"gas_units": scval.to_int128(gas(plan)),
        "conversion_units": scval.to_int128(0), "spent_units": scval.to_int128(amount + gas(plan)), "max_fee_stroops": scval.to_uint32(gas(plan)),
        "observed_ledger": scval.to_uint32(integer(observed_ledger, 1, 2**32 - 1)), "day": scval.to_uint64(now // 86_400 if day is None else day)})
    request = scval.to_struct({
        "args": scval.to_map({}),
        "policy_instance": scval.to_bytes(bytes.fromhex(plan["policy_instance"])),
        "source_hash": scval.to_bytes(SMOKE_SOURCE_HASH),
        "expense": scval.to_enum("Priced", expense),
        "operation_id": scval.to_bytes(bytes.fromhex(operation_id)),
        "nonce": scval.to_uint64(int(state["nonce"])),
        "deployment_version": scval.to_uint64(int(state["deployment_version"]) + (1 if case == "stale-version" else 0)),
        "expires_at": scval.to_uint64(expires),
        "module_digest": scval.to_bytes(bytes.fromhex(binding["module_digest"])),
        "operation": scval.to_enum("Transfer", transfer)})
    return request


def expected_receipt(plan, wallet, state, operation_id):
    return {"operation_id": operation_id, "token": plan["asset"], "from": wallet, "to": plan["recipient"], "amount": plan["payment_stroops"], "nonce": int(state["nonce"]), "deployment_version": int(state["deployment_version"])}


def decode_receipt(value):
    value = scval.from_struct(value)
    return {key: scval.to_native(item) for key, item in value.items()}


def receipt_json(value):
    return {key: item.hex() if isinstance(item, bytes) else item.address if isinstance(item, Address) else item for key, item in value.items()}


def packet_path(plan, base, stage):
    return base / ("packets-" + digest(canonical(plan))) / (stage + ".json")


def require_settled(plan, base, stage, address=None):
    packet = json.loads(packet_path(plan, base, stage).read_text())
    if packet["stage"] != stage or (address and packet.get("created_contract") != address):
        raise ValueError("Deployment address differs from its original prepared packet")
    if settle(plan, packet)["status"] != "success":
        raise ValueError("Reconcile the original " + stage + " packet before the next stage")


def balance(plan, address):
    return int(json.loads(ca.cli_run(["contract", "invoke", "--network", plan["network"], "--source-account", plan["owner"], "--id", plan["asset"], "--send=no", "--", "balance", "--id", address])))


def prepare(plan, base, stage, parent=None, wallet=None, operation_id=None):
    network = plan["network"]
    wa.owner_only(wa.fetch(network, plan["owner"]))
    wa.owner_only(wa.fetch(network, plan["agent"]))
    wa.owner_only(wa.fetch(network, plan["server"]))
    wa.admin(wa.fetch(network, plan["admin"]), plan["admin_members"])
    cap = plan["fee_caps_stroops"][stage]
    source = plan["admin"] if stage == "deploy-parent" else plan["agent"] if stage == "execute" else plan["owner"]
    expected = None
    effects = None
    index = STAGES.index(stage)
    for dependency in STAGES[:index]:
        require_settled(plan, base, dependency, parent if dependency == "deploy-parent" else wallet if dependency == "deploy-wallet" else None)
    if stage.startswith("upload-") or stage in ("deploy-parent", "deploy-wallet"):
        name = stage.removeprefix("upload-").removeprefix("deploy-")
        # The wallet packet binds the Common tier and the smoke policy source it was derived from.
        with tempfile.TemporaryDirectory(prefix="allowit-release-") as tmp:
            policy = Path(tmp) / "policy.rs"
            policy.write_bytes(SMOKE_SOURCE)
            options = SimpleNamespace(action="upload" if stage.startswith("upload-") else stage, network=network, allow_mainnet=True, source=source, wasm=artifact_path(plan, base, name), wasm_hash=plan["artifacts"][name]["sha256"], owner=plan["admin"] if stage=="deploy-parent" else plan["owner"], engine_wasm=plan["artifacts"]["engine"]["sha256"], config=json.dumps(wallet_config(plan)), tier="common", policy_source=str(policy))
            raw = ca.cli_run(ca.command(options))
        assembled = ca.prepare_xdr(raw, source, network, max_fee=cap, expected_wasm=options.wasm_hash if stage.startswith("deploy-") else None)
    else:
        if not wallet or not parent:
            raise ValueError("Funding and execution require --wallet and --parent")
        state, binding = wallet_state(plan, wallet, parent)
        if stage == "fund":
            wa.owner_only(wa.fetch(network, source))
            if usage(plan, wallet) != (0, 0):
                raise ValueError("Initial funding requires an unused release wallet")
            initial_balance = balance(plan, wallet)
            if initial_balance != 0:
                raise ValueError("Initial funding requires a zero native-XLM policy wallet balance")
            effects = {"fund_wallet": wallet, "wallet_balance": initial_balance, "amount": plan["fund_stroops"]}
            raw = raw_invoke(plan, source, plan["asset"], "transfer", [scval.to_address(source), scval.to_address(wallet), scval.to_int128(plan["fund_stroops"])])
        else:
            if not operation_id:
                raise ValueError("Execution requires --operation-id")
            ledger = integer(int(rpc(network, "getLatestLedger")["sequence"]), 1, 2**32 - 1)
            raw = raw_invoke(plan, source, wallet, "execute", [execution(plan, state, binding, operation_id, ledger)])
            expected = expected_receipt(plan, wallet, state, operation_id)
            calls, spent = usage(plan, wallet)
            effects = {"wallet": wallet, "wallet_balance": balance(plan, wallet), "recipient_balance": balance(plan, plan["recipient"]), "calls": calls, "spent_total": spent}
        assembled = ca.prepare_xdr(raw, source, network, max_fee=cap, candidate=plan["server"] if stage == "execute" else None)
    envelope = TransactionEnvelope.from_xdr(assembled, wa.PASSPHRASE[network])
    if stage == "execute":
        entry = server_entry(envelope, plan, signed=False)
        entry.credentials.address.signature_expiration_ledger = xdr.Uint32(integer(int(rpc(network,"getLatestLedger")["sequence"]),1,2**32-51)+50)
        assembled = envelope.to_xdr()
    result = {"signing_ready": stage != "execute", "wallet": wallet, "parent": parent, "operation_id": operation_id, "stage": stage, "network": network, "source": source, "transaction_hash": envelope.hash_hex(), "unsigned_xdr": assembled, "fee_bid_stroops": envelope.transaction.fee, "expires_at": envelope.transaction.preconditions.time_bounds.max_time, "expected_receipt": expected, "expected_effects": effects}
    if stage == "execute":
        result["server_authorization_xdr"] = entry.to_xdr()
    host = envelope.transaction.operations[0].host_function
    if stage.startswith("deploy-"):
        result["created_contract"] = Address.from_xdr_sc_address(ca.deployment_address(host.create_contract_v2, network)).address
    return result


def simulate_cases(plan, parent, wallet, operation_id, replay_id=None):
    state, binding = wallet_state(plan, wallet, parent)
    cases = {"positive": None, "denied-recipient": POLICY_DENIED, "over-limit": POLICY_DENIED, "stale-version": 5, "expired": 7}
    ledger = integer(int(rpc(plan["network"], "getLatestLedger")["sequence"]), 1, 2**32 - 1)
    if replay_id:
        ca.code_hash(replay_id)
        cases["replay"] = 19
    results = {}
    for case, code in cases.items():
        selected_id = replay_id if case == "replay" else operation_id
        raw = raw_invoke(plan, plan["agent"], wallet, "execute", [execution(plan, state, binding, selected_id, ledger, case)])
        response = rpc(plan["network"], "simulateTransaction", {"transaction": raw, "authMode": "record"})
        if code is None:
            if "error" in response:
                raise ValueError("Positive E2E simulation failed: " + str(response["error"]))
            receipt = receipt_json(decode_receipt(xdr.SCVal.from_xdr(response["results"][0]["xdr"])))
            if receipt != expected_receipt(plan, wallet, state, selected_id):
                raise ValueError("Positive simulation returned a different receipt")
            if int(response["minResourceFee"]) + 100 > plan["fee_caps_stroops"]["execute"]:
                raise ValueError("Positive simulation exceeds the execution fee cap")
        else:
            error = response.get("error", "")
            if not re.search(r"Error\(Contract, #" + str(code) + r"\)", error):
                raise ValueError("Expected contract error " + str(code) + " for " + case + ": " + error)
        results[case] = response
    return {"wallet": wallet, "state": state, "policy_binding": binding, "cases": results, "scope": "Unsigned RPC simulations only; no effects settled"}


def settle(plan, prepared):
    if prepared["network"] != plan["network"] or prepared["plan_digest"] != digest(canonical(plan)):
        raise ValueError("Prepared transaction belongs to another plan")
    if prepared.get("signing_ready") is False:
        raise ValueError("Complete the exact server authorization before settlement checks")
    envelope = TransactionEnvelope.from_xdr(prepared["unsigned_xdr"], wa.PASSPHRASE[plan["network"]])
    if envelope.hash_hex() != prepared["transaction_hash"]:
        raise ValueError("Prepared transaction hash differs from its bytes")
    result = rpc(plan["network"], "getTransaction", {"hash": envelope.hash_hex()})
    if result["status"] not in ("SUCCESS", "FAILED"):
        return {"status": "unresolved", "transaction_hash": envelope.hash_hex(), "action": "Keep the original packet. Do not sign a replacement or release reservations.", "rpc": result}
    if result["status"] != "SUCCESS":
        return {"status": "failed", "transaction_hash": envelope.hash_hex(), "rpc": result}
    settled = TransactionEnvelope.from_xdr(result["envelopeXdr"], wa.PASSPHRASE[plan["network"]])
    if settled.hash_hex() != envelope.hash_hex():
        raise ValueError("Settled transaction differs from the prepared packet")
    if prepared.get("expected_receipt"):
        meta = xdr.TransactionMeta.from_xdr(result["resultMetaXdr"])
        soroban = meta.v4.soroban_meta if meta.v == 4 else meta.v3.soroban_meta if meta.v == 3 else None
        if soroban is None:
            raise ValueError("Successful execution lacks Soroban return metadata")
        actual = receipt_json(decode_receipt(soroban.return_value))
        if actual != prepared["expected_receipt"]:
            raise ValueError("Settled receipt differs from the approved transfer")
    charged = xdr.TransactionResult.from_xdr(result["resultXdr"]).fee_charged.int64
    if charged < 0 or charged > envelope.transaction.fee or charged > plan["fee_caps_stroops"][prepared["stage"]]:
        raise ValueError("Charged fee exceeds the reviewed stage packet")
    if (prepared.get("expected_effects") or {}).get("fund_wallet"):
        before = prepared["expected_effects"]
        if balance(plan, before["fund_wallet"]) != before["wallet_balance"] + before["amount"]:
            raise ValueError("Settled funding balance differs from the exact approved principal")
    elif prepared.get("expected_effects"):
        before = prepared["expected_effects"]
        amount = plan["payment_stroops"]
        calls, spent = usage(plan, before["wallet"])
        if (balance(plan, before["wallet"]) != before["wallet_balance"] - amount or balance(plan, plan["recipient"]) != before["recipient_balance"] + amount or calls != before["calls"] + 1 or spent != before["spent_total"] + amount + gas(plan)):
            raise ValueError("Current balances or counters differ from the exact smoke payment. Reconcile concurrent activity")
    return {"status": "success", "transaction_hash": envelope.hash_hex(), "fee_charged_stroops": charged, "rpc": result}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("check", "preflight", "prepare", "complete-execute", "simulate-e2e", "settle"))
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--allow-mainnet", action="store_true", help="Permit mainnet reads and unsigned preparation only")
    p.add_argument("--allow-payload-export", action="store_true", help="Explicitly permit private Wasm and transaction payload export to the selected network RPC")
    p.add_argument("--stage", choices=STAGES)
    p.add_argument("--parent")
    p.add_argument("--wallet")
    p.add_argument("--operation-id")
    p.add_argument("--replay-id", help="Previously settled operation identity for replay simulation")
    p.add_argument("--prepared", type=Path)
    p.add_argument("--server-auth", type=Path, help="Externally signed Soroban server authorization XDR")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Output already exists. Preserve the original packet and reconcile it first.")
    plan, plan_hash, base = load_plan(args.plan)
    if plan["network"] == "mainnet" and not args.allow_mainnet:
        p.error("Mainnet access requires --allow-mainnet")
    if args.action in ("prepare", "complete-execute", "simulate-e2e") and not args.allow_payload_export:
        p.error("This action exports private payloads. Obtain export approval, then use --allow-payload-export")
    if args.action in ("prepare", "complete-execute"):
        stage = "execute" if args.action == "complete-execute" else "execute-auth" if args.stage == "execute" else str(args.stage)
        required_path = packet_path(plan, base, stage)
        if args.output.resolve() != required_path.resolve():
            p.error("Use the unique stage packet path: " + str(required_path))
    network = None if args.action == "check" else check_network(plan["network"])
    if args.action == "check":
        result = {"scope": "Offline plan, artifact and source checks only", "packet_directory": str(base / ("packets-" + plan_hash))}
    elif args.action == "preflight":
        owner = wa.fetch(plan["network"], plan["owner"])
        wa.owner_only(owner)
        wa.owner_only(wa.fetch(plan["network"], plan["agent"]))
        wa.owner_only(wa.fetch(plan["network"], plan["server"]))
        wa.admin(wa.fetch(plan["network"], plan["admin"]), plan["admin_members"])
        result = {"network": network, "owner_sequence": owner["sequence"], "funding_cap_stroops": plan["fund_stroops"], "aggregate_fee_cap_stroops": plan["total_fee_cap_stroops"], "scope": "Public inputs and exact current signer profiles checked; no deployment acceptance"}
    elif args.action == "prepare":
        if not args.stage:
            p.error("Preparation requires --stage")
        result = prepare(plan, base, args.stage, args.parent, args.wallet, args.operation_id)
    elif args.action == "complete-execute":
        if not args.prepared or not args.server_auth or args.prepared.resolve() != packet_path(plan,base,"execute-auth").resolve():
            p.error("Use the original execute-auth packet and an externally signed --server-auth entry")
        result = complete_execute(plan,json.loads(args.prepared.read_text()),args.server_auth.read_text().strip())
    elif args.action == "simulate-e2e":
        if not args.parent or not args.wallet or not args.operation_id:
            p.error("E2E simulation requires --parent, --wallet and --operation-id")
        require_settled(plan, base, "deploy-parent", args.parent)
        require_settled(plan, base, "deploy-wallet", args.wallet)
        result = simulate_cases(plan, args.parent, args.wallet, args.operation_id, args.replay_id)
    else:
        if not args.prepared:
            p.error("Settlement checks require --prepared")
        result = settle(plan, json.loads(args.prepared.read_text()))
    result["plan_digest"] = plan_hash
    write_new(args.output, result)
    print(json.dumps({"output": str(args.output), "plan_digest": plan_hash, "status": result.get("status", "prepared" if args.action == "prepare" else "checked")}))
    if args.action == "settle" and result["status"] != "success":
        raise SystemExit(2)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, argparse.ArgumentTypeError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
