#!/usr/bin/env python3
"""Build public release inputs and deploy their exact contracts to Stellar Testnet."""
import argparse
import copy
from datetime import datetime, timezone
from dataclasses import dataclass
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import time
import tempfile
from urllib.error import HTTPError
from urllib.request import urlopen

from stellar_sdk import Account, Address, Asset, Keypair, Network, StrKey, TransactionBuilder, TransactionEnvelope, scval, xdr
from stellar_sdk import SorobanServer
from stellar_sdk.soroban_rpc import GetTransactionStatus

import contract_admin as ca

REPOSITORY = "https://github.com/allowit-hq/allowit-contracts-stellar.git"
RPC = "https://soroban-testnet.stellar.org"
HORIZON = "https://horizon-testnet.stellar.org"
PASSPHRASE = "Test SDF Network ; September 2015"
CONTRACTS = {
    "simple": "allowit_simple_policy_engine.wasm",
    "common": "allowit_common_policy_engine.wasm",
    "custom": "allowit_custom_policy.wasm",
    "engine": "allowit_wallet_engine.wasm",
    "parent": "allowit_engine_parent.wasm",
}
KINDS = {"simple": "simple_policy_engine", "common": "common_policy_engine", "custom": "custom_policy"}
MAX_FEE = 1_250_000_000  # First constructor can renew shared code; Testnet only, 125 XLM.
HEX = re.compile(r"[0-9a-f]{64}")
SHA = re.compile(r"[0-9a-f]{40}")
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
CORE_SOURCE = "git+https://github.com/allowit-hq/allowit-core.git?tag=v0.3.2#c6c9f382761a0c5b88afc5524be7220c5c56c244"
IDENTITY_KEYS = {"tag", "revision", "tag_object", "workflow_revision"}
MAX_LEDGER_AGE = 120  # Seconds, measured from the native header close time.
MAX_FUTURE_SKEW = 30
MAX_ENDPOINT_LAG = 12  # Ledgers between the two fixed public services.


def public_env(github=False):
    """Public tools receive only explicit tool paths and, for gh, its scoped token."""
    names = {"PATH", "HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "LANG", "LC_ALL"}
    if github:
        names.add("GH_TOKEN")
    return {key: value for key, value in os.environ.items() if key in names}


def public_run(args, **kwargs):
    return subprocess.run(args, env=public_env(args[0] == "gh"), **kwargs)


def public_output(args, **kwargs):
    return subprocess.check_output(args, env=public_env(args[0] == "gh"), **kwargs)


def utc_seconds():
    return time.time()


def workflow_attempt():
    values = [os.environ.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in values):
        raise ValueError("An exact GitHub workflow run and attempt are required")
    return ":".join(values)


@dataclass(frozen=True)
class Action:
    resource: str
    kind: str
    key: str
    create: bool


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def public_json_url(path):
    """Read bounded public data only from the fixed HTTPS Testnet Horizon service."""
    url = HORIZON + path
    with urlopen(url, timeout=30) as response:
        if response.geturl() != url:
            raise ValueError("Testnet identity endpoint redirected")
        data = response.read(256 * 1024 + 1)
    if len(data) > 256 * 1024:
        raise ValueError("Testnet identity response exceeds limit")
    return ca.public_json(data.decode())


def check_ledger_age(close_time):
    age = utc_seconds() - close_time
    if not -MAX_FUTURE_SKEW <= age <= MAX_LEDGER_AGE:
        raise ValueError("Public Testnet ledger header is stale or in the future")


def network_identity(rpc, recorded=None):
    """Bind the fixed RPC to public Testnet history and its earliest retained generation anchor."""
    if rpc.get_network().passphrase != PASSPHRASE:
        raise ValueError("RPC is not Stellar Testnet")
    root = public_json_url("/")
    first, latest = 128, root.get("history_latest_ledger")
    if root.get("network_passphrase") != PASSPHRASE or type(first) is not int or type(latest) is not int or not 1 <= first <= latest:
        raise ValueError("Public history is not a valid Testnet generation")
    if recorded is not None:
        first = recorded.get("ledger")
        if first != 128 or recorded.get("source") != HORIZON + "/ledgers/128" or not HEX.fullmatch(recorded.get("hash", "")):
            raise ValueError("Invalid recorded Testnet generation anchor")
    try:
        anchor = public_json_url("/ledgers/" + str(first))
    except HTTPError as error:
        error.close()
        raise ValueError("Recorded Testnet generation anchor is unavailable; stop before mutation") from error
    rpc_latest = rpc.get_latest_ledger().sequence
    if type(rpc_latest) is not int or abs(latest - rpc_latest) > MAX_ENDPOINT_LAG:
        raise ValueError("Public Testnet endpoints exceed the ledger lag limit")
    recent_sequence = min(latest, rpc_latest)
    recent = public_json_url("/ledgers/" + str(recent_sequence))
    for sequence, item in ((first, anchor), (recent_sequence, recent)):
        header = xdr.LedgerHeader.from_xdr(item["header_xdr"])
        if item.get("sequence") != sequence or header.ledger_seq.uint32 != sequence or digest(header.to_xdr_bytes()) != item.get("hash"):
            raise ValueError("Public Testnet ledger header differs from its identity")
        closed = datetime.fromtimestamp(header.scp_value.close_time.time_point.uint64, timezone.utc)
        if datetime.fromisoformat(item["closed_at"].replace("Z", "+00:00")) != closed:
            raise ValueError("Public Testnet ledger close time differs from its native header")
    close_time = xdr.LedgerHeader.from_xdr(recent["header_xdr"]).scp_value.close_time.time_point.uint64
    matches = rpc.get_ledgers(start_ledger=recent_sequence, limit=1).ledgers
    if len(matches) != 1 or matches[0].sequence != recent_sequence or matches[0].hash != recent["hash"]:
        raise ValueError("Public Testnet RPC and history disagree")
    rpc_header = xdr.LedgerHeaderHistoryEntry.from_xdr(matches[0].header_xdr)
    if rpc_header.hash.hash.hex() != recent["hash"] or rpc_header.header.to_xdr() != recent["header_xdr"]:
        raise ValueError("Public Testnet RPC and history ledger headers disagree")
    check_ledger_age(close_time)
    now = datetime.now(timezone.utc).isoformat()
    generation = {"ledger": first, "hash": anchor["hash"], "closed_at": anchor["closed_at"],
        "source": HORIZON + "/ledgers/" + str(first), "observed_at": now}
    if recorded is not None and recorded["hash"] == generation["hash"]:
        if recorded.get("closed_at") != generation["closed_at"]:
            raise ValueError("Recorded Testnet anchor metadata differs from its native header")
        generation = recorded
    return {"network": "stellar:testnet", "network_id": Network(PASSPHRASE).network_id().hex(),
        "rpc": RPC, "horizon": HORIZON, "passphrase": PASSPHRASE,
        "generation": generation,
        "genesis_available": False,
        "observed": {"ledger": recent_sequence, "hash": recent["hash"], "observed_at": now,
            "close_time": close_time,
            "horizon_header_xdr": recent["header_xdr"], "rpc_header_xdr": matches[0].header_xdr}}


def check_network_metadata(identity):
    expected = {"network": "stellar:testnet", "network_id": Network(PASSPHRASE).network_id().hex(),
        "rpc": RPC, "horizon": HORIZON, "passphrase": PASSPHRASE}
    generation = identity.get("generation", {})
    if any(identity.get(key) != value for key, value in expected.items()) or identity.get("genesis_available") is not False or generation.get("ledger") != 128 or generation.get("source") != HORIZON + "/ledgers/128" or not HEX.fullmatch(generation.get("hash", "")):
        raise ValueError("Recorded Testnet network metadata is inconsistent")


def same_generation(left, right):
    return all(left.get(key) == right.get(key) for key in
        ("network", "network_id", "rpc", "horizon", "passphrase", "genesis_available")) and all(
            left.get("generation", {}).get(key) == right.get("generation", {}).get(key)
            for key in ("ledger", "hash", "source", "closed_at"))


def deployment_filename(manifest, identity, attempt):
    return "testnet-deployment-" + manifest["tag"] + "-" + identity["generation"]["hash"] + "-" + attempt.replace(":", "-") + ".json"


def source_equal(left, right):
    return {k: v for k, v in left.items() if k != "workflow_revision"} == {
        k: v for k, v in right.items() if k != "workflow_revision"}


def read_public(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Expected a bounded regular public checkpoint")
    return ca.public_json(path.read_text())


def gh_json(path, missing=False):
    result = public_run(["gh", "api", path], capture_output=True, text=True, timeout=30)
    data = ca.public_json(result.stdout)
    if result.returncode:
        if missing and data.get("status") == "404":
            return None
        raise ValueError("Cannot read canonical GitHub release state")
    return data


def current_authority(manifest):
    """Check this build and controller attempt, never lifetime Actions history."""
    check_canonical_tag(manifest)
    root = Path(__file__).resolve().parents[1]
    automation = git(root, "rev-parse", "HEAD")
    if automation != os.environ.get("GITHUB_WORKFLOW_SHA"):
        raise ValueError("Controller source differs from the executing workflow")
    if version("stellar-sdk") != "16.1.0" or public_run(["git", "-C", str(root), "diff", "--quiet", "HEAD", "--", "scripts",
        ".github/workflows/testnet-release.yml"], capture_output=True).returncode:
        raise ValueError("Controller files or native SDK differ from the approved source")
    for commit in (automation, manifest["revision"], manifest["workflow_revision"]):
        if public_run(["git", "-C", str(root), "merge-base", "--is-ancestor", commit, "refs/release/main"], capture_output=True).returncode:
            raise ValueError("Release inputs must belong to canonical main")
    attempt = workflow_attempt()
    current = gh_json("repos/allowit-hq/allowit-contracts-stellar/actions/runs/" + attempt.split(":")[0] + "/attempts/" + attempt.split(":")[1])
    if (current.get("path") != ".github/workflows/testnet-release.yml" or current.get("event") != "workflow_run"
        or current.get("head_repository", {}).get("full_name") != "allowit-hq/allowit-contracts-stellar"
        or current.get("head_branch") != "main" or current.get("head_sha") != automation
        or current.get("run_attempt") != int(attempt.split(":")[1])):
        raise ValueError("Current controller attempt is not canonical main")
    run_id, run_attempt = (os.environ.get(name, "") for name in ("RELEASE_BUILD_RUN_ID", "RELEASE_BUILD_RUN_ATTEMPT"))
    if any(not re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run_id, run_attempt)):
        raise ValueError("An exact successful build attempt is required")
    event = read_public(Path(os.environ["GITHUB_EVENT_PATH"]))
    trigger = event.get("workflow_run", {})
    if trigger.get("id") != int(run_id) or trigger.get("run_attempt") != int(run_attempt):
        raise ValueError("Selected build attempt differs from the current workflow trigger")
    built = gh_json("repos/allowit-hq/allowit-contracts-stellar/actions/runs/" + run_id + "/attempts/" + run_attempt)
    if (built.get("path") != ".github/workflows/release.yml" or built.get("event") not in ("push", "workflow_dispatch")
        or built.get("head_repository", {}).get("full_name") != "allowit-hq/allowit-contracts-stellar"
        or built.get("head_sha") != manifest["workflow_revision"]
        or (built.get("event") == "push" and (built.get("head_branch") != manifest["tag"] or built.get("head_sha") != manifest["revision"]))
        or (built.get("event") == "workflow_dispatch" and built.get("head_branch") != "main")
        or built.get("conclusion") != "success"
        or built.get("run_attempt") != int(run_attempt)):
        raise ValueError("Release bundle has no matching successful canonical build")
    return {"automation": automation, "controller_attempt": attempt, "build_run": run_id + ":" + run_attempt}


def build_record(manifest, attempt):
    return {"schema": 1, "repository": REPOSITORY, "build_attempt": attempt,
        **{key: manifest[key] for key in IDENTITY_KEYS}}


def current_bundle(directory):
    manifest = check_bundle(directory)
    authority = current_authority(manifest)
    if read_public(directory / "release-build.json") != build_record(manifest, authority["build_run"]):
        raise ValueError("Downloaded artifact belongs to another build attempt")
    return manifest, authority


def write(path, value, private=False):
    """Atomic replace and fsync; private transaction packets never enter the public bundle."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    temporary = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(canonical(value) + b"\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def git(root, *args):
    return public_output(["git", "-C", str(root), *args], text=True).strip()


def release_identity(root, tag, workflow_sha):
    if not TAG.fullmatch(tag) or not SHA.fullmatch(workflow_sha):
        raise ValueError("Expected a vX.Y.Z tag and exact workflow commit")
    reference = "refs/tags/" + tag
    if git(root, "cat-file", "-t", reference) != "tag":
        raise ValueError("Release tags must be annotated")
    revision = git(root, "rev-parse", reference + "^{commit}")
    tag_object = git(root, "rev-parse", reference)
    main = git(root, "rev-parse", "refs/release/main")
    for commit in (revision, workflow_sha):
        if public_run(["git", "-C", str(root), "merge-base", "--is-ancestor", commit, main], capture_output=True).returncode:
            raise ValueError("Release and workflow commits must belong to canonical main")
    remote = git(root, "ls-remote", REPOSITORY, reference, reference + "^{}")
    expected = {reference: tag_object, reference + "^{}": revision}
    if {line.split()[1]: line.split()[0] for line in remote.splitlines()} != expected:
        raise ValueError("Canonical release tag changed or is unavailable")
    return {"tag": tag, "revision": revision, "tag_object": tag_object, "workflow_revision": workflow_sha}


def check_canonical_tag(manifest):
    """Recheck the remote tag after protected-environment approval and before mutation."""
    reference = "refs/tags/" + manifest["tag"]
    remote = public_output(["git", "ls-remote", REPOSITORY, reference, reference + "^{}"], text=True, timeout=30)
    if {line.split()[1]: line.split()[0] for line in remote.splitlines()} != {reference: manifest["tag_object"], reference + "^{}": manifest["revision"]}:
        raise ValueError("Canonical release tag changed or is unavailable")


def bundle(source, identity, output):
    if set(identity) != IDENTITY_KEYS:
        raise ValueError("Unexpected release identity fields")
    if git(source, "rev-parse", "HEAD") != identity["revision"] or git(source, "status", "--porcelain"):
        raise ValueError("Build source must be the clean exact release revision")
    version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"]["version"]
    if "v" + version != identity["tag"]:
        raise ValueError("Tag and workspace version differ")
    if tomllib.loads((source / "stellar/core/Cargo.toml").read_text())["package"]["version"] != version:
        raise ValueError("Native host and workspace release versions differ")
    for relative in ("Cargo.lock", "stellar/core/Cargo.lock"):
        packages = tomllib.loads((source / relative).read_text())["package"]
        identities = {item["source"] for item in packages if "allowit-core" in item.get("source", "")}
        if identities != {CORE_SOURCE}:
            raise ValueError("Release must use the single published Core v0.3.2 source")
    sample = source / "crates/custom-policy/policy/policy.rs"
    # Resolve this with the release's own checked policy gate, before the signing job.
    helper = "import sys;sys.path.insert(0,sys.argv[1]);from policy_source import standard_prefix;import json;print(json.dumps(standard_prefix(open(sys.argv[2]).read())))"
    rules = json.loads(public_output([sys.executable, "-c", helper, str(source / "scripts"), str(sample)], text=True))
    output.mkdir(parents=True, exist_ok=True)
    result = {"schema": 1, "repository": REPOSITORY, **identity, "core_source": CORE_SOURCE,
        "toolchain": {"rust": "1.98.0", "stellar": "28.1.0"}, "artifacts": {}}
    target = Path(json.loads(public_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=source, text=True))["target_directory"])
    for kind, filename in CONTRACTS.items():
        data = (target / "wasm32v1-none/release" / filename).read_bytes()
        if not 8 < len(data) <= 2 * 1024 * 1024 or data[:8] != b"\0asm\x01\0\0\0":
            raise ValueError("Expected a bounded contract Wasm")
        if kind in KINDS and ca.custody_layout(data) != ca.WALLET_CONTRACT_VERSION:
            raise ValueError("Unsupported wallet custody layout")
        (output / filename).write_bytes(data)
        result["artifacts"][kind] = {"file": filename, "sha256": digest(data), "bytes": len(data)}
    data = sample.read_bytes()
    (output / "sample-policy.rs").write_bytes(data)
    result["sample_policy"] = {"file": "sample-policy.rs", "sha256": digest(data), "rules": rules}
    write(output / "source-manifest.json", result)
    write(output / "release-build.json", build_record(result, workflow_attempt()))
    return result


def check_bundle(directory):
    path = directory / "source-manifest.json"
    if path.is_symlink() or path.stat().st_size > 128 * 1024:
        raise ValueError("Expected a bounded regular release manifest")
    manifest = ca.public_json(path.read_text())
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or manifest.get("repository") != REPOSITORY or not TAG.fullmatch(manifest.get("tag", "")):
        raise ValueError("Invalid release manifest identity")
    if not SHA.fullmatch(manifest.get("revision", "")) or not SHA.fullmatch(manifest.get("workflow_revision", "")) or not SHA.fullmatch(manifest.get("tag_object", "")):
        raise ValueError("Invalid release revisions")
    if manifest.get("core_source") != CORE_SOURCE:
        raise ValueError("Release Core source differs from the approved published version")
    if set(manifest.get("artifacts", {})) != set(CONTRACTS) or manifest.get("toolchain") != {"rust": "1.98.0", "stellar": "28.1.0"}:
        raise ValueError("Unexpected release artifacts or toolchain")
    for kind, filename in CONTRACTS.items():
        item = manifest["artifacts"][kind]
        path = directory / filename
        if item.get("file") != filename or path.is_symlink() or not path.is_file() or not 8 < path.stat().st_size <= 2 * 1024 * 1024:
            raise ValueError("Unexpected release artifact path")
        data = path.read_bytes()
        if not 8 < len(data) <= 2 * 1024 * 1024 or item.get("bytes") != len(data) or item.get("sha256") != digest(data) or data[:8] != b"\0asm\x01\0\0\0":
            raise ValueError("Release artifact differs from its manifest")
        if kind in KINDS and ca.custody_layout(data) != ca.WALLET_CONTRACT_VERSION:
            raise ValueError("Unsupported wallet custody layout")
    sample = manifest["sample_policy"]
    rules = sample.get("rules")
    if sample.get("file") != "sample-policy.rs" or (directory / "sample-policy.rs").is_symlink() or (directory / "sample-policy.rs").stat().st_size > 64 * 1024 or digest((directory / "sample-policy.rs").read_bytes()) != sample.get("sha256"):
        raise ValueError("Compiled sample policy identity differs")
    if not isinstance(rules, list) or not rules or len(rules) != len(set(rules)) or any(rule not in ca.PARAM_KEYS for rule in rules):
        raise ValueError("Invalid standard policy prefix")
    return manifest


def contract_id(owner, salt):
    preimage = xdr.ContractIDPreimage(xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
        from_address=xdr.ContractIDPreimageFromAddress(Address(owner).to_xdr_sc_address(), xdr.Uint256(salt)))
    value = xdr.HashIDPreimage(xdr.EnvelopeType.ENVELOPE_TYPE_CONTRACT_ID,
        contract_id=xdr.HashIDPreimageContractID(xdr.Hash(Network(PASSPHRASE).network_id()), preimage))
    return StrKey.encode_contract(hashlib.sha256(value.to_xdr_bytes()).digest())


def config_for(manifest, kind, owner, agent, server):
    module = manifest["artifacts"][kind]["sha256"]
    asset = Asset.native().contract_id(PASSPHRASE)
    rules = manifest["sample_policy"]["rules"] if kind == "common" else []
    params = {"payment_limit": 10_000_000, "lifetime_spending_limit": 50_000_000,
        "daily_spending_limit": 50_000_000, "daily_volume_limit": 50_000_000,
        "call_limit": 10, "destinations": [agent], "tokens": [asset],
        "expires_at": 4_102_444_800, "operations": ["transfer"]}
    source = manifest["sample_policy"]["sha256"] if kind == "custom" else ca.prefix_digest(KINDS[kind], module, asset, rules)
    instance = digest(canonical(["allowit_testnet_release_v1", manifest["tag"], kind, owner]))
    return {"owner": owner, "agent": agent, "server": server, "asset": asset,
        "policy_instance": instance, "source_digest": source, "rules": rules, "params": params, "x402_enabled": False}


def check_constructor(create, config, module, salt):
    """Compare the CLI builder against independent caller-owned native constructor intent."""
    if create is None or create.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM or create.executable.wasm_hash.hash.hex() != module or len(create.constructor_args) != 1:
        raise ValueError("Constructor does not use the exact release executable/configuration")
    preimage = create.contract_id_preimage
    if preimage.type != xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS or preimage.from_address.address != Address(config["owner"]).to_xdr_sc_address() or preimage.from_address.salt.uint256 != salt:
        raise ValueError("Constructor owner or deterministic salt differs")
    if create.constructor_args[0].to_xdr_bytes() != config_scval(config).to_xdr_bytes():
        raise ValueError("Constructor native XDR differs from the release intent")


def config_scval(config):
    """Encode the intended variants independently of native simulation."""
    params = {}
    for name, value in config["params"].items():
        if name in ("destinations", "tokens", "operations"):
            tag, encode = ("Str", scval.to_string) if name == "operations" else ("Addr", scval.to_address)
            params[name] = scval.to_enum("List", scval.to_vec([scval.to_enum(tag, encode(item)) for item in value]))
        else:
            params[name] = scval.to_enum("Int", scval.to_int128(value))
    fields = {key: scval.to_address(config[key]) for key in ("owner", "agent", "server", "asset")}
    fields.update(policy_instance=scval.to_bytes(bytes.fromhex(config["policy_instance"])),
        source_digest=scval.to_bytes(bytes.fromhex(config["source_digest"])),
        rules=scval.to_vec([scval.to_enum(rule, None) for rule in config["rules"]]),
        params=scval.to_struct(params), x402_enabled=scval.to_bool(config["x402_enabled"]))
    return scval.to_struct(fields)


def code_key(value):
    return xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_CODE,
        contract_code=xdr.LedgerKeyContractCode(xdr.Hash(bytes.fromhex(value))))


def instance_key(wallet):
    return xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA, contract_data=xdr.LedgerKeyContractData(
        Address(wallet).to_xdr_sc_address(), xdr.SCVal(xdr.SCValType.SCV_LEDGER_KEY_CONTRACT_INSTANCE),
        xdr.ContractDataDurability.PERSISTENT))


def wallet_intent(manifest, kind, owner, agent, server):
    config = config_for(manifest, kind, owner, agent, server)
    salt = bytes.fromhex(digest(canonical(["allowit_testnet_release_salt_v1", manifest["tag"], kind, owner])))
    return config, salt, contract_id(owner, salt)


def native_header(rpc, sequence):
    items = rpc.get_ledgers(start_ledger=sequence, limit=1).ledgers
    if len(items) != 1 or items[0].sequence != sequence:
        raise ValueError("Native snapshot header is unavailable")
    item = items[0]
    native = xdr.LedgerHeaderHistoryEntry.from_xdr(item.header_xdr)
    header = native.header
    if header.ledger_seq.uint32 != sequence or native.hash.hash.hex() != item.hash or digest(header.to_xdr_bytes()) != item.hash:
        raise ValueError("Native snapshot header differs from its identity")
    check_ledger_age(header.scp_value.close_time.time_point.uint64)
    return {"ledger": sequence, "hash": item.hash, "header_xdr": item.header_xdr}


def nonrestoring(simulation):
    if simulation.error or simulation.restore_preamble is not None or not simulation.transaction_data:
        raise ValueError("Simulation did not prove an eligible non-restoring action")
    data = xdr.SorobanTransactionData.from_xdr(simulation.transaction_data)
    if data.ext.v not in (0, 1) or (data.ext.v == 1 and (
        data.ext.resource_ext is None or data.ext.resource_ext.archived_soroban_entries)):
        raise ValueError("Archived or unknown Soroban resources prohibit creation")
    return data


class Deployment:
    def __init__(self, directory, output, private, key, agent, server):
        self.directory, self.output, self.private, self.key = directory, output, private, key
        self.manifest, self.authority = current_bundle(directory)
        for address in (key.public_key, agent, server):
            ca.account(address)
        if len({key.public_key, agent, server}) != 3:
            raise ValueError("Release owner, agent and server must differ")
        self.agent, self.server = agent, server
        self.rpc = SorobanServer(RPC)
        # This starts after the workflow's global signer slot and environment admission.
        self.slot_entered = utc_seconds()
        self.identity = network_identity(self.rpc)
        self.intents = {kind: wallet_intent(self.manifest, kind, key.public_key, agent, server) for kind in KINDS}
        self.account_key = xdr.LedgerKey(xdr.LedgerEntryType.ACCOUNT,
            account=xdr.LedgerKeyAccount(key.xdr_account_id()))
        self.asset_key = instance_key(Asset.native().contract_id(PASSPHRASE))
        self.keys = [self.account_key, self.asset_key]
        self.keys += [code_key(value) for value in dict.fromkeys(item["sha256"] for item in self.manifest["artifacts"].values())]
        self.keys += [instance_key(intent[2]) for intent in self.intents.values()]
        self.completed = set()
        self.expected_sequence = None
        self.snapshot_number = 0
        self.public = {"schema": 1, "network": "stellar:testnet", "rpc": RPC, "source": self.manifest,
            "owner": key.public_key, "agent": agent, "server": server,
            "deployment_automation_revision": self.authority["automation"], "workflow_attempt": workflow_attempt(),
            "build_attempt": self.authority["build_run"], "network_identity": self.identity,
            "signer_slot_entered_at": self.slot_entered,
            "code": {}, "wallets": {}, "transactions": [], "status": "IN_PROGRESS",
            "scope": "Current initialized release smoke resources, not historical receipt completeness or owner acceptance. No wallet funding or payment execution."}
        private.mkdir(parents=True, exist_ok=True, mode=0o700)
        if private.is_symlink() or private.stat().st_mode & 0o077 or private.resolve().is_relative_to(directory.resolve()):
            raise ValueError("Use a separate private transaction directory with mode0700")
        if output.exists() or any(private.iterdir()):
            raise ValueError("Use fresh run paths and preserve earlier packets")

    def save(self):
        write(self.output, self.public)
        self.snapshot_number += 1
        snapshot = self.output.with_name(self.output.stem + "-snapshot-" + str(self.snapshot_number).zfill(3) + ".json")
        immutable(snapshot, canonical(self.public) + b"\n")

    def current(self):
        if current_bundle(self.directory) != (self.manifest, self.authority):
            raise ValueError("Current release source or automation changed")
        observed = network_identity(self.rpc, self.identity["generation"])
        if not same_generation(observed, self.identity):
            raise ValueError("Testnet generation changed; a fresh run and barrier are required")
        self.identity = observed
        self.public["network_identity"] = observed

    def snapshot(self):
        response = self.rpc.get_ledger_entries(self.keys)
        if type(response.latest_ledger) is not int or response.latest_ledger < self.identity["observed"]["ledger"]:
            raise ValueError("Resource snapshot precedes the verified native header")
        evidence = native_header(self.rpc, response.latest_ledger)
        requested = {key.to_xdr() for key in self.keys}
        entries = {}
        for item in response.entries:
            if item.key not in requested or item.key in entries:
                raise ValueError("Resource snapshot has an unexpected or duplicate key")
            entries[item.key] = (item, xdr.LedgerEntryData.from_xdr(item.xdr))
        return response.latest_ledger, entries, evidence

    def account_state(self, snapshot):
        found = snapshot[1].get(self.account_key.to_xdr())
        if found is None:
            return None
        data = found[1]
        account = data.account
        if data.type != xdr.LedgerEntryType.ACCOUNT or account.account_id != self.key.xdr_account_id() or account.signers or account.thresholds.thresholds != b"\x01\x00\x00\x00":
            raise ValueError("Use the configured dedicated master-only Testnet account")
        return account.seq_num.sequence_number.int64

    def resource(self, action, snapshot):
        found = snapshot[1].get((code_key(action.key) if action.resource == "code" else instance_key(action.key)).to_xdr())
        if found is None:
            return None  # Ambiguous until exact native simulation proves eligible absence.
        item, data = found
        if type(item.live_until_ledger_seq) is not int or item.live_until_ledger_seq <= snapshot[0]:
            raise ValueError("Release resource is expired or its lifetime is unknown")
        if action.resource == "code":
            if data.type != xdr.LedgerEntryType.CONTRACT_CODE or data.contract_code.hash.hash.hex() != action.key or digest(data.contract_code.code) != action.key:
                raise ValueError("Native code readback differs from the release")
            return {"sha256": action.key, "bytes": len(data.contract_code.code), "ledger": snapshot[0], "live_until_ledger": item.live_until_ledger_seq}
        if data.type != xdr.LedgerEntryType.CONTRACT_DATA or data.contract_data.contract != Address(action.key).to_xdr_sc_address() or data.contract_data.key != instance_key(action.key).contract_data.key or data.contract_data.durability != xdr.ContractDataDurability.PERSISTENT or data.contract_data.val.type != xdr.SCValType.SCV_CONTRACT_INSTANCE:
            raise ValueError("Wallet is not the exact persistent contract instance")
        instance = data.contract_data.val.instance
        module = self.manifest["artifacts"][action.kind]["sha256"]
        if instance.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM or instance.executable.wasm_hash.hash.hex() != module:
            raise ValueError("Existing deterministic wallet uses different code")
        storage = instance.storage.sc_map if instance.storage is not None else []
        if len(storage) != 1 or storage[0].key.to_xdr_bytes() != scval.to_uint32(0).to_xdr_bytes():
            raise ValueError("Wallet instance has an unknown storage layout")
        config = self.intents[action.kind][0]
        fields = scval.from_struct(config_scval(config))
        fields.update(policy_state=scval.to_map({}), contract_version=scval.to_uint32(ca.WALLET_CONTRACT_VERSION),
            token=scval.to_string("XLM"), deployment_version=scval.to_uint64(0), nonce=scval.to_uint64(0), paused=scval.to_bool(False))
        if storage[0].val.to_xdr_bytes() != scval.to_struct(fields).to_xdr_bytes():
            raise ValueError("Wallet native configuration or pristine state differs")
        return {"contract": action.key, "wasm_sha256": module, "ledger": snapshot[0], "live_until_ledger": item.live_until_ledger_seq,
            "config": config, "state": {**config, "params": ca.params(config["params"], action.kind), "policy_state": {},
                "contract_version": ca.WALLET_CONTRACT_VERSION, "token": "XLM", "deployment_version": 0, "nonce": 0, "paused": False},
            "state_xdr": storage[0].val.to_xdr(), "funding": "No release funds are transferred to smoke wallets."}

    def asset_present(self, snapshot):
        found = snapshot[1].get(self.asset_key.to_xdr())
        if found is None or found[1].type != xdr.LedgerEntryType.CONTRACT_DATA:
            raise ValueError("The required native asset contract is absent")
        item, data = found
        if data.contract_data.contract != self.asset_key.contract_data.contract or data.contract_data.key != self.asset_key.contract_data.key or data.contract_data.durability != xdr.ContractDataDurability.PERSISTENT or data.contract_data.val.type != xdr.SCValType.SCV_CONTRACT_INSTANCE or data.contract_data.val.instance.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_STELLAR_ASSET:
            raise ValueError("The required asset is not the exact native SAC")
        if type(item.live_until_ledger_seq) is not int or item.live_until_ledger_seq <= snapshot[0]:
            raise ValueError("Native asset lifetime is unavailable")

    def preflight(self):
        self.current()
        snapshot = self.snapshot()
        self.asset_present(snapshot)
        account = self.account_state(snapshot)
        plan = [Action("account", "owner", self.key.public_key, account is None)]
        for kind, item in self.manifest["artifacts"].items():
            if not any(a.key == item["sha256"] for a in plan):
                action = Action("code", kind, item["sha256"], False)
                plan.append(Action("code", kind, action.key, self.resource(action, snapshot) is None))
        for kind, intent in self.intents.items():
            action = Action("wallet", kind, intent[2], False)
            plan.append(Action("wallet", kind, action.key, self.resource(action, snapshot) is None))
        self.expected_sequence = account
        self.public["plan"] = [{"resource": a.resource, "kind": a.kind, "key": a.key, "mode": "CONDITIONAL" if a.create else "REUSE"} for a in plan]
        return tuple(plan)

    def guard(self, plan, pending=None):
        self.current()
        snapshot = self.snapshot()
        self.asset_present(snapshot)
        if self.account_state(snapshot) != self.expected_sequence:
            raise ValueError("Dedicated operator sequence or presence changed")
        for action in plan[1:]:
            observed = self.resource(action, snapshot)
            if not action.create or action in self.completed:
                if observed is None:
                    raise ValueError("A frozen or completed resource disappeared")
            elif observed is not None:
                raise ValueError("A conditional target appeared after preflight")
        if pending is not None and (pending not in plan or not pending.create or pending in self.completed):
            raise ValueError("Action is not an eligible frozen target")
        return snapshot

    def quiesce(self, plan):
        started = time.monotonic()
        while True:
            self.current()
            snapshot = self.snapshot()
            self.asset_present(snapshot)
            self.account_state(snapshot)
            # Prior bounded envelopes may settle while this new controller waits.
            # Targets stay fixed. Every resource that was live must remain valid.
            for action in plan[1:]:
                observed = self.resource(action, snapshot)
                if not action.create and observed is None:
                    raise ValueError("A reused resource disappeared during the signer barrier")
            if self.identity["observed"]["close_time"] > self.slot_entered + 450:
                self.public["quiescence"] = {"slot_entered_at": self.slot_entered, "barrier_close_time": self.identity["observed"]["close_time"], "barrier_ledger": self.identity["observed"]["ledger"]}
                return self.preflight()
            if time.monotonic() - started > 900:
                raise ValueError("Observed native ledger time did not cross the signer barrier")
            time.sleep(5)

    def ensure_account(self, plan):
        if plan[0].create:
            self.guard(plan, plan[0])
            # Fixed endpoint and configured public address. The secret never enters Friendbot.
            from urllib.parse import urlencode
            url = "https://friendbot.stellar.org?" + urlencode({"addr": self.key.public_key})
            self.public["operator"] = {"account": self.key.public_key, "friendbot_requested": True,
                "observation": "request-unresolved"}
            self.save()
            with urlopen(url, timeout=30) as response:
                if response.geturl() != url or len(response.read(256 * 1024 + 1)) > 256 * 1024:
                    raise ValueError("Unexpected Friendbot response")
            self.current()
            snapshot = self.snapshot()
            self.expected_sequence = self.account_state(snapshot)
            if self.expected_sequence is None:
                raise ValueError("Dedicated Testnet operator creation is unconfirmed")
            self.public["operator"].update(observation="observed-present", sequence=self.expected_sequence, ledger=snapshot[0])
            self.save()
            self.completed.add(plan[0])
        self.guard(plan)

    def prepare(self, action, plan):
        self.guard(plan, action)
        close = self.identity["observed"]["close_time"]
        builder = TransactionBuilder(Account(self.key.public_key, self.expected_sequence), PASSPHRASE, base_fee=100).add_time_bounds(0, close + 300)
        if action.resource == "code":
            data = (self.directory / self.manifest["artifacts"][action.kind]["file"]).read_bytes()
            if digest(data) != action.key:
                raise ValueError("Upload bytes differ from the exact release")
            raw = builder.append_upload_contract_wasm_op(data).build()
        else:
            config, salt, wallet = self.intents[action.kind]
            if wallet != action.key:
                raise ValueError("Frozen wallet target changed")
            raw = builder.append_create_contract_op(self.manifest["artifacts"][action.kind]["sha256"], self.key.public_key,
                constructor_args=[config_scval(config)], salt=salt).build()
            check_constructor(raw.transaction.operations[0].host_function.create_contract_v2, config,
                self.manifest["artifacts"][action.kind]["sha256"], salt)
        simulation = self.rpc.simulate_transaction(raw, use_upgraded_auth=False)
        if simulation.latest_ledger < self.identity["observed"]["ledger"]:
            raise ValueError("Native simulation is older than the verified network observation")
        nonrestoring(simulation)
        prepared = self.rpc.prepare_transaction(raw, simulation)
        tx = prepared.transaction
        if prepared.signatures or not tx.v1 or len(tx.operations) != 1 or tx.soroban_data is None:
            raise ValueError("Simulation changed the native transaction shape")
        nonrestoring(simulation)
        ext = tx.soroban_data.ext
        if ext.v not in (0, 1) or (ext.v == 1 and (ext.resource_ext is None or ext.resource_ext.archived_soroban_entries)):
            raise ValueError("Assembled transaction requests archive restoration")
        if tx.fee > MAX_FEE or tx.soroban_data.resource_fee.int64 < 0 or tx.soroban_data.resource_fee.int64 > MAX_FEE:
            raise ValueError("Native simulation exceeds the release fee cap")
        ca.validate_auth(tx.operations[0], network="testnet")
        normalized = copy.deepcopy(tx)
        normalized.fee = raw.transaction.fee
        normalized.soroban_data = raw.transaction.soroban_data
        normalized.operations[0].auth = raw.transaction.operations[0].auth
        if normalized.to_xdr_object().to_xdr_bytes() != raw.transaction.to_xdr_object().to_xdr_bytes() or tx.fee < raw.transaction.fee:
            raise ValueError("Simulation changed exact release intent")
        target = code_key(action.key) if action.resource == "code" else instance_key(action.key)
        if target not in tx.soroban_data.resources.footprint.read_write:
            raise ValueError("Simulation did not classify the exact creation target")
        return prepared

    def submit(self, action, plan):
        prepared = self.prepare(action, plan)
        self.guard(plan, action)
        if prepared.transaction.sequence != self.expected_sequence + 1 or prepared.transaction.preconditions.time_bounds.max_time > self.identity["observed"]["close_time"] + 300 or prepared.transaction.preconditions.time_bounds.max_time <= self.identity["observed"]["close_time"]:
            raise ValueError("Prepared sequence or native validity changed")
        prepared.sign(self.key)
        signed, tx_hash = prepared.to_xdr(), prepared.hash_hex()
        stage = ("upload-" if action.resource == "code" else "deploy-") + action.kind
        immutable(self.private / (stage + ".json"), canonical({"signed_xdr": signed, "hash": tx_hash}) + b"\n", private=True)
        record = {"stage": stage, "transaction_hash": tx_hash, "sequence": prepared.transaction.sequence,
            "expires_at": prepared.transaction.preconditions.time_bounds.max_time, "fee_cap_stroops": prepared.transaction.fee, "status": "prepared"}
        self.public["transactions"].append(record)
        self.save()
        self.guard(plan, action)
        record["status"] = "unknown"
        self.save()
        try:
            sent = self.rpc.send_transaction(signed)
            if sent.hash != tx_hash:
                raise ValueError("Broadcast returned another transaction identity")
            for _ in range(30):
                receipt = self.rpc.get_transaction(tx_hash)
                if receipt.status in (GetTransactionStatus.SUCCESS, GetTransactionStatus.FAILED):
                    if receipt.transaction_hash != tx_hash or receipt.envelope_xdr != signed or not receipt.ledger or not receipt.result_xdr:
                        raise ValueError("Native receipt differs from the exact original packet")
                    result = xdr.TransactionResult.from_xdr(receipt.result_xdr)
                    if (receipt.status == GetTransactionStatus.SUCCESS) != (result.result.code == xdr.TransactionResultCode.txSUCCESS):
                        raise ValueError("Native receipt result and status disagree")
                    self.current()
                    if not 0 < receipt.ledger <= self.rpc.get_latest_ledger().sequence:
                        raise ValueError("Receipt ledger is not in current native history")
                    header = native_header(self.rpc, receipt.ledger)
                    record.update(status=receipt.status.value, ledger=receipt.ledger, result_xdr=receipt.result_xdr, ledger_header=header)
                    self.save()
                    if receipt.status != GetTransactionStatus.SUCCESS:
                        raise ValueError("Original release transaction failed; inspect its recorded sequence")
                    break
                time.sleep(2)
            else:
                raise ValueError("Original transaction has no confirmed receipt")
        except Exception:
            self.save()
            raise ValueError("Submission is unresolved or failed; preserve original hash " + tx_hash) from None
        self.current()
        snapshot = self.snapshot()
        if self.account_state(snapshot) != prepared.transaction.sequence or self.resource(action, snapshot) is None:
            raise ValueError("Successful transaction has no exact account/resource readback")
        self.expected_sequence = prepared.transaction.sequence
        self.completed.add(action)
        self.guard(plan)

    def final_readback(self, plan):
        snapshot = self.guard(plan)
        self.public["code"], self.public["wallets"] = {}, {}
        for action in plan[1:]:
            observed = self.resource(action, snapshot)
            if observed is None:
                raise ValueError("Final coherent readback is missing a desired resource")
            observed["observation"] = "created-this-run" if action in self.completed else "observed-existing"
            if action.resource == "code":
                for kind, item in self.manifest["artifacts"].items():
                    if item["sha256"] == action.key:
                        self.public["code"][kind] = observed
            else:
                self.public["wallets"][action.kind] = observed
        self.public["operator"] = {"account": self.key.public_key, "sequence": self.account_state(snapshot),
            "ledger": snapshot[0], "observation": "observed-present",
            "friendbot_requested": self.public.get("operator", {}).get("friendbot_requested", False)}
        self.public["resource_observation"] = snapshot[2]
        self.current()
        self.public["status"] = "RESOURCE_STATE_VERIFIED"
        self.public["verified_at"] = datetime.now(timezone.utc).isoformat()
        self.save()
        return self.public

    def run(self):
        plan = self.preflight()
        self.save()
        if any(action.create for action in plan):
            plan = self.quiesce(plan)
            self.guard(plan)
            self.ensure_account(plan)
            for action in plan[1:]:
                if action.create:
                    self.submit(action, plan)
        return self.final_readback(plan)


def immutable(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if private else 0o755)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != data:
            raise ValueError("An immutable run snapshot already has different bytes") from None
        return
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def publish(directory):
    manifest, authority = current_bundle(directory)
    files = list(directory.glob("testnet-deployment-v*.json"))
    if len(files) != 1:
        raise ValueError("Expected one immutable per-run deployment snapshot")
    deployment = read_public(files[0])
    if deployment.get("status") != "RESOURCE_STATE_VERIFIED" or deployment.get("source") != manifest or deployment.get("workflow_attempt") != workflow_attempt() or deployment.get("build_attempt") != authority["build_run"] or deployment.get("deployment_automation_revision") != authority["automation"]:
        raise ValueError("Snapshot does not verify current desired release state")
    if files[0].name != deployment_filename(manifest, deployment["network_identity"], workflow_attempt()):
        raise ValueError("Snapshot name differs from its exact run/generation")
    check_network_metadata(deployment["network_identity"])
    existing = gh_json("repos/allowit-hq/allowit-contracts-stellar/releases/tags/" + manifest["tag"], missing=True)
    assets = [directory / name for name in CONTRACTS.values()] + [directory / "sample-policy.rs", directory / "source-manifest.json", files[0]]
    if existing is None:
        notes = directory.parent / "release-notes.md"
        notes.write_text("Current release code and initialized smoke-wallet state were verified on Stellar Testnet.\n"
            "The snapshot records this run's original transaction outcomes. Receipt-less reuse is observed-existing.\n")
        current_bundle(directory)
        public_run(["gh", "release", "create", manifest["tag"], "--repo", "allowit-hq/allowit-contracts-stellar", "--verify-tag", "--title", manifest["tag"], "--notes-file", str(notes), *map(str, assets)], check=True, capture_output=True)
        return
    names = {item["name"] for item in existing.get("assets", [])}
    with tempfile.TemporaryDirectory() as temporary:
        for path in assets:
            if path.name in names:
                public_run(["gh", "release", "download", manifest["tag"], "--repo", "allowit-hq/allowit-contracts-stellar", "--pattern", path.name, "--dir", temporary], check=True, capture_output=True)
                old = Path(temporary) / path.name
                same = source_equal(read_public(old), manifest) if path.name == "source-manifest.json" else old.read_bytes() == path.read_bytes()
                if not same:
                    raise ValueError("Immutable published release asset differs")
            else:
                current_bundle(directory)
                public_run(["gh", "release", "upload", manifest["tag"], str(path), "--repo", "allowit-hq/allowit-contracts-stellar"], check=True, capture_output=True)


def main():
    # Remove the private owner secret before public validation or any child process.
    secret = os.environ.pop("STELLAR_TESTNET_OWNER_SECRET", "")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    metadata = commands.add_parser("metadata")
    metadata.add_argument("--repository", type=Path, required=True)
    metadata.add_argument("--tag", required=True)
    metadata.add_argument("--workflow-sha", required=True)
    metadata.add_argument("--output", type=Path, required=True)
    build = commands.add_parser("bundle")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--identity", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    publication = commands.add_parser("publish")
    publication.add_argument("--bundle", type=Path, required=True)
    deploy = commands.add_parser("deploy")
    for name in ("bundle", "identity", "output", "private"):
        deploy.add_argument("--" + name, type=Path, required=True)
    for role in ("owner", "agent", "server"):
        deploy.add_argument("--" + role, required=True)
    args = parser.parse_args()
    if args.action != "deploy":
        secret = ""
    if args.action == "metadata":
        result = release_identity(args.repository, args.tag, args.workflow_sha)
        write(args.output, result)
        for key, value in result.items():
            print(key + "=" + value)
    elif args.action == "bundle":
        bundle(args.source, read_public(args.identity), args.output)
    elif args.action == "publish":
        publish(args.bundle)
    else:
        manifest, _ = current_bundle(args.bundle)
        identity = read_public(args.identity)
        if set(identity) != IDENTITY_KEYS or any(manifest[key] != value for key, value in identity.items()):
            raise ValueError("Deployment bundle is not the verified release")
        current_authority(manifest)
        try:
            key = Keypair.from_secret(secret)
        except Exception:
            raise ValueError("A dedicated Testnet operator secret is required") from None
        finally:
            secret = ""
        if key.public_key != ca.account(args.owner):
            raise ValueError("Secret differs from the independently configured operator")
        result = Deployment(args.bundle, args.output, args.private, key, args.agent, args.server).run()
        immutable(args.output.parent / deployment_filename(manifest, result["network_identity"], workflow_attempt()), canonical(result) + b"\n")
        print("Current release resource state verified on Stellar Testnet.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Release stopped. Inspect the immutable public checkpoints; preserve original signed packets.", file=sys.stderr)
        sys.exit(1)
