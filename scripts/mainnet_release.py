#!/usr/bin/env python3
"""Prepare bounded Stellar release transactions of the contracts and a smoke policy wallet. Never sign or submit."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import tomllib
from types import SimpleNamespace
from urllib.request import Request, urlopen

from stellar_sdk import Account, Address, Asset, Network, TransactionBuilder, TransactionEnvelope, Keypair, scval, xdr
import contract_admin as ca
from contract_admin import plain_params, rule_names
import wallet_admin as wa

ROOT = Path(__file__).resolve().parents[1]
RPC = {"mainnet": "https://mainnet.sorobanrpc.com", "testnet": "https://soroban-testnet.stellar.org"}
STAGES = ("upload-engine", "upload-parent", "upload-wallet", "deploy-parent", "deploy-wallet", "fund")
NAMES = {"engine": "allowit_wallet_engine.wasm", "parent": "allowit_engine_parent.wasm", "wallet": "allowit_common_policy_engine.wasm"}
READ_METHODS = {"getNetwork", "getLatestLedger", "getLedgerEntries", "simulateTransaction", "getTransaction"}
# Earlier reviewed releases store other custody layouts. Re-pin a reviewed release of layout 5.
DEFAULT_REVISION = None
DEFAULT_HASHES = {}
WALLET_KIND = "common_policy_engine"
BUILD_SCRIPTS = ("build-contracts.sh", "check-policy-bindings.py", "policy_source.py", "core_sources.py")

# The smoke policy is entirely one standard prefix of canonical calls. Its rules derive from the source.
SMOKE_SOURCE = b"""use allowit::prelude::*;
/// Smoke-test my mainnet wallet. Pay only the pinned recipient, limit each payment, limit the daily
/// volume, limit total spending, allow only a few payments and stop when the params expire.
pub fn execute(ctx: &AllowitContext) -> allowit::Result {
    // "Pay only the pinned recipient"
    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;
    // "limit each payment"
    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;
    // "limit the daily volume"
    allowit::daily_volume_limit(ctx, &ctx.params[allowit::DAILY_VOLUME_LIMIT])?;
    // "limit total spending"
    allowit::lifetime_spending_limit(ctx, &ctx.params[allowit::LIFETIME_SPENDING_LIMIT])?;
    // "allow only a few payments"
    allowit::call_limit(ctx, &ctx.params[allowit::CALL_LIMIT])?;
    // "stop when the params expire"
    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;
    Ok(())
}
"""
RULES = ca.standard_prefix(SMOKE_SOURCE.decode())
# The wallet stores the SHA-256 of the owner's whole source: the literal source above.
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


def smoke_params(plan):
    """Return the smoke params: exactly the selected rules' canonical keys, checked as Common does."""
    params = plan["params"]
    if not isinstance(params, dict) or set(params) != set(RULES) or params["destinations"] != [plan["recipient"]]:
        raise ValueError("Smoke params require exactly the selected canonical rule keys and pinned recipient")
    for name in set(RULES) - {"destinations"}:
        integer(params[name])
    ca.params(params, "common")
    return params


def wallet_config(plan):
    """The owner-signed configuration of the smoke wallet: the agent and server keys, the SHA-256
    of the smoke source, the gas cap and the standard prefix with its params."""
    return {"owner": plan["owner"], "agent": plan["agent"], "server": plan["server"], "asset": plan["asset"],
        "source_hash": SMOKE_SOURCE_HASH.hex(), "gas_cap": plan["gas_cap_stroops"], "rules": RULES, "params": smoke_params(plan)}


def usage(state):
    """The wallet's total figures: calls and spent, zero when its checks keep none."""
    figures = state["figures"]
    return int(figures["calls"]), int(figures["spent"])


def contract_build_sources(root):
    """List contract workspace inputs; the separate off-chain SDK is not a contract input."""
    files = [root / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml")]
    members = tomllib.loads((root / "Cargo.toml").read_text())["workspace"]["members"]
    for member in members:
        files += sorted((root / member).rglob("*.rs"))
        files += sorted((root / member).rglob("Cargo.toml"))
    return files + [root / "scripts" / name for name in BUILD_SCRIPTS]


def load_plan(path):
    path = Path(path).resolve()
    plan = json.loads(path.read_text())
    fields = {"schema", "network", "network_passphrase", "source_revision", "artifact_manifest", "artifacts", "owner", "admin", "admin_members", "agent", "server", "asset", "recipient", "params", "fund_stroops", "gas_cap_stroops", "fee_caps_stroops", "total_fee_cap_stroops"}
    if set(plan) != fields or plan["schema"] != 2:
        raise ValueError("Plan fields must match schema 2 exactly")
    network = plan["network"]
    if network not in RPC or plan["network_passphrase"] != wa.PASSPHRASE[network]:
        raise ValueError("Select the exact Stellar network and passphrase")
    if not re.fullmatch(r"[0-9a-f]{40}", plan["source_revision"]):
        raise ValueError("Pin the complete contract source revision")
    if DEFAULT_REVISION is None or plan["source_revision"] != DEFAULT_REVISION:
        raise ValueError("This smoke tool admits only the reviewed default contract revision; re-pin one of custody layout 5")
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
    for name in ("owner", "admin", "agent", "server", "recipient"):
        ca.account(plan[name])
    if len({plan[k] for k in ("owner", "admin", "agent", "server", "recipient")}) != 5:
        raise ValueError("Use separate owner, admin, agent, server and recipient accounts")
    members = plan["admin_members"]
    if not isinstance(members, list) or len(members) != 3 or len(set(members)) != 3:
        raise ValueError("Pin exactly three distinct admin members")
    for member in members:
        ca.account(member)
    if set(members) & {plan["owner"], plan["agent"], plan["server"]}:
        raise ValueError("Admin members must differ from custody owner and agent")
    params = smoke_params(plan)
    native = Asset.native().contract_id(wa.PASSPHRASE[network])
    if plan["asset"] != native or params["destinations"] != [plan["recipient"]]:
        raise ValueError("Release smoke tests require native XLM and one pinned recipient")
    integer(plan["fund_stroops"])
    integer(plan["gas_cap_stroops"], 0)
    if plan["fund_stroops"] > params["lifetime_spending_limit"]:
        raise ValueError("Funding and the lifetime spending limit param are inconsistent")
    fee_caps = plan["fee_caps_stroops"]
    if set(fee_caps) != set(STAGES):
        raise ValueError("Set one fee cap for every release stage")
    for value in fee_caps.values():
        integer(value, 100, 2**32 - 1)
    if sum(fee_caps.values()) > integer(plan["total_fee_cap_stroops"]):
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
    if set(entry["path"] for entry in manifest["sources"]) != set(str(f.relative_to(ROOT)) for f in contract_build_sources(ROOT)):
        raise ValueError("Manifest must include every contract build source")
    return plan, digest(canonical(plan)), path.parent


def artifact_path(plan, base, name):
    value = Path(plan["artifacts"][name]["path"])
    return str(value if value.is_absolute() else base / value)


def read_contract(plan, contract, method):
    if method not in ("state","engine"):
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


def wallet_state(plan, wallet):
    """The smoke wallet's `state` view, checked against the plan: its code, roles, asset, source
    hash, gas cap, rules and params, and that it is not paused."""
    ca.contract(wallet)
    actual = ca.cli_run(["contract", "info", "hash", "--network", plan["network"], "--id", wallet]).strip()
    if actual != plan["artifacts"]["wallet"]["sha256"]:
        raise ValueError("Deployed executable differs from the plan: wallet")
    state = read_contract(plan, wallet, "state")
    expected = wallet_config(plan)
    raw = lambda role: ca.StrKey.decode_ed25519_public_key(plan[role]).hex()
    if state["owner"] != plan["owner"] or state["agent"] != raw("agent") or state["server"] != raw("server") or state["asset"] != plan["asset"] or rule_names(state["rules"]) != RULES or plain_params(state["params"]) != expected["params"]:
        raise ValueError("Wallet authority or params differ from the plan")
    if state["source_hash"] != expected["source_hash"] or int(state["gas_cap"]) != expected["gas_cap"] or int(state["contract_version"]) != ca.WALLET_CONTRACT_VERSION:
        raise ValueError("Installed policy differs from the plan")
    if state["paused"]:
        raise ValueError("Wallet is paused")
    return state


def raw_invoke(plan, source, contract, method, arguments):
    account = wa.fetch(plan["network"], source)
    return TransactionBuilder(Account(source, int(account["sequence"])), wa.PASSPHRASE[plan["network"]], base_fee=100).add_time_bounds(0, int(time.time()) + 300).append_invoke_contract_function_op(contract, method, arguments).build().to_xdr()


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


def prepare(plan, base, stage, wallet=None):
    network = plan["network"]
    # The agent and the server hold keys and need no account.
    wa.owner_only(wa.fetch(network, plan["owner"]))
    wa.admin(wa.fetch(network, plan["admin"]), plan["admin_members"])
    fee_cap = plan["fee_caps_stroops"][stage]
    source = plan["admin"] if stage == "deploy-parent" else plan["owner"]
    effects = None
    index = STAGES.index(stage)
    for dependency in STAGES[:index]:
        require_settled(plan, base, dependency, wallet if dependency == "deploy-wallet" else None)
    if stage.startswith("upload-") or stage in ("deploy-parent", "deploy-wallet"):
        name = stage.removeprefix("upload-").removeprefix("deploy-")
        # The wallet packet binds the Common tier and the smoke policy source it was derived from.
        with tempfile.TemporaryDirectory(prefix="allowit-release-") as tmp:
            policy = Path(tmp) / "policy.rs"
            policy.write_bytes(SMOKE_SOURCE)
            options = SimpleNamespace(action="upload" if stage.startswith("upload-") else stage, network=network, allow_mainnet=True, source=source, wasm=artifact_path(plan, base, name), wasm_hash=plan["artifacts"][name]["sha256"], owner=plan["admin"] if stage=="deploy-parent" else plan["owner"], engine_wasm=plan["artifacts"]["engine"]["sha256"], config=json.dumps(wallet_config(plan)), tier="common", policy_source=str(policy))
            raw = ca.cli_run(ca.command(options))
        assembled = ca.prepare_xdr(raw, source, network, max_fee=fee_cap, expected_wasm=options.wasm_hash if stage.startswith("deploy-") else None)
    else:
        if not wallet:
            raise ValueError("Funding requires --wallet")
        state = wallet_state(plan, wallet)
        if usage(state) != (0, 0):
            raise ValueError("Initial funding requires an unused release wallet")
        initial_balance = balance(plan, wallet)
        if initial_balance != 0:
            raise ValueError("Initial funding requires a zero native-XLM policy wallet balance")
        effects = {"fund_wallet": wallet, "wallet_balance": initial_balance, "amount": plan["fund_stroops"]}
        raw = raw_invoke(plan, source, plan["asset"], "transfer", [scval.to_address(source), scval.to_address(wallet), scval.to_int128(plan["fund_stroops"])])
        assembled = ca.prepare_xdr(raw, source, network, max_fee=fee_cap)
    envelope = TransactionEnvelope.from_xdr(assembled, wa.PASSPHRASE[network])
    result = {"wallet": wallet, "stage": stage, "network": network, "source": source, "transaction_hash": envelope.hash_hex(), "unsigned_xdr": assembled, "fee_bid_stroops": envelope.transaction.fee, "expires_at": envelope.transaction.preconditions.time_bounds.max_time, "expected_effects": effects}
    host = envelope.transaction.operations[0].host_function
    if stage.startswith("deploy-"):
        result["created_contract"] = Address.from_xdr_sc_address(ca.deployment_address(host.create_contract_v2, network)).address
    return result


def settle(plan, prepared):
    if prepared["network"] != plan["network"] or prepared["plan_digest"] != digest(canonical(plan)):
        raise ValueError("Prepared transaction belongs to another plan")
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
    charged = xdr.TransactionResult.from_xdr(result["resultXdr"]).fee_charged.int64
    if charged < 0 or charged > envelope.transaction.fee or charged > plan["fee_caps_stroops"][prepared["stage"]]:
        raise ValueError("Charged fee exceeds the reviewed stage packet")
    if (prepared.get("expected_effects") or {}).get("fund_wallet"):
        before = prepared["expected_effects"]
        if balance(plan, before["fund_wallet"]) != before["wallet_balance"] + before["amount"]:
            raise ValueError("Settled funding balance differs from the exact approved principal")
    return {"status": "success", "transaction_hash": envelope.hash_hex(), "fee_charged_stroops": charged, "rpc": result}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("check", "preflight", "prepare", "settle"))
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--allow-mainnet", action="store_true", help="Permit mainnet reads and unsigned preparation only")
    p.add_argument("--allow-payload-export", action="store_true", help="Explicitly permit private Wasm and transaction payload export to the selected network RPC")
    p.add_argument("--stage", choices=STAGES)
    p.add_argument("--wallet")
    p.add_argument("--prepared", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.exists():
        p.error("Output already exists. Preserve the original packet and reconcile it first.")
    plan, plan_hash, base = load_plan(args.plan)
    if plan["network"] == "mainnet" and not args.allow_mainnet:
        p.error("Mainnet access requires --allow-mainnet")
    if args.action == "prepare" and not args.allow_payload_export:
        p.error("This action exports private payloads. Obtain export approval, then use --allow-payload-export")
    if args.action == "prepare":
        required_path = packet_path(plan, base, str(args.stage))
        if args.output.resolve() != required_path.resolve():
            p.error("Use the unique stage packet path: " + str(required_path))
    network = None if args.action == "check" else check_network(plan["network"])
    if args.action == "check":
        result = {"scope": "Offline plan, artifact and source checks only", "packet_directory": str(base / ("packets-" + plan_hash))}
    elif args.action == "preflight":
        owner = wa.fetch(plan["network"], plan["owner"])
        wa.owner_only(owner)
        wa.admin(wa.fetch(plan["network"], plan["admin"]), plan["admin_members"])
        result = {"network": network, "owner_sequence": owner["sequence"], "fund_stroops": plan["fund_stroops"], "aggregate_fee_cap_stroops": plan["total_fee_cap_stroops"], "scope": "Public inputs and exact current signer profiles checked; no deployment acceptance"}
    elif args.action == "prepare":
        if not args.stage:
            p.error("Preparation requires --stage")
        result = prepare(plan, base, args.stage, args.wallet)
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
