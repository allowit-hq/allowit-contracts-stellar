#!/usr/bin/env python3
"""Build public release inputs and deploy their exact contracts to Stellar Testnet."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.error import HTTPError
from urllib.request import urlopen

from stellar_sdk import Address, Asset, Keypair, Network, StrKey, TransactionEnvelope, scval, xdr
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
CORE_SOURCE = "git+https://github.com/allowit-hq/allowit-core.git?tag=v0.3.1#96b558633d4e01a077d3fd1e75d2b9fe927f2036"
IDENTITY_KEYS = {"tag", "revision", "tag_object", "workflow_revision"}


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


def network_identity(rpc, recorded=None):
    """Bind the fixed RPC to public Testnet history and its earliest retained generation anchor."""
    if rpc.get_network().passphrase != PASSPHRASE:
        raise ValueError("RPC is not Stellar Testnet")
    root = public_json_url("/")
    first, latest = root.get("history_elder_ledger"), root.get("history_latest_ledger")
    if root.get("network_passphrase") != PASSPHRASE or type(first) is not int or type(latest) is not int or not 1 <= first <= latest:
        raise ValueError("Public history is not a valid Testnet generation")
    if recorded is not None:
        first = recorded.get("ledger")
        if type(first) is not int or first < 1 or recorded.get("source") != HORIZON + "/ledgers/" + str(first) or not HEX.fullmatch(recorded.get("hash", "")):
            raise ValueError("Invalid recorded Testnet generation anchor")
    try:
        anchor = public_json_url("/ledgers/" + str(first))
    except HTTPError as error:
        raise ValueError("Recorded Testnet generation anchor is unavailable; stop before mutation") from error
    recent_sequence = min(latest, rpc.get_latest_ledger().sequence)
    recent = public_json_url("/ledgers/" + str(recent_sequence))
    for sequence, item in ((first, anchor), (recent_sequence, recent)):
        header = xdr.LedgerHeader.from_xdr(item["header_xdr"])
        if item.get("sequence") != sequence or header.ledger_seq.uint32 != sequence or digest(header.to_xdr_bytes()) != item.get("hash"):
            raise ValueError("Public Testnet ledger header differs from its identity")
    matches = rpc.get_ledgers(start_ledger=recent_sequence, limit=1).ledgers
    if len(matches) != 1 or matches[0].sequence != recent_sequence or matches[0].hash != recent["hash"]:
        raise ValueError("Public Testnet RPC and history disagree")
    rpc_header = xdr.LedgerHeaderHistoryEntry.from_xdr(matches[0].header_xdr)
    if rpc_header.hash.hash.hex() != recent["hash"] or rpc_header.header.to_xdr() != recent["header_xdr"]:
        raise ValueError("Public Testnet RPC and history ledger headers disagree")
    now = datetime.now(timezone.utc).isoformat()
    generation = {"ledger": first, "hash": anchor["hash"], "closed_at": anchor["closed_at"],
        "source": HORIZON + "/ledgers/" + str(first), "observed_at": now}
    if recorded is not None and recorded["hash"] == generation["hash"]:
        generation = recorded
    return {"network": "stellar:testnet", "network_id": Network(PASSPHRASE).network_id().hex(),
        "rpc": RPC, "horizon": HORIZON, "passphrase": PASSPHRASE,
        "generation": generation,
        "genesis_available": first == 1,
        "observed": {"ledger": recent_sequence, "hash": recent["hash"], "observed_at": now,
            "horizon_header_xdr": recent["header_xdr"], "rpc_header_xdr": matches[0].header_xdr}}


def same_generation(left, right):
    return all(left.get(key) == right.get(key) for key in
        ("network", "network_id", "rpc", "horizon", "passphrase", "genesis_available")) and all(
            left.get("generation", {}).get(key) == right.get("generation", {}).get(key)
            for key in ("ledger", "hash", "source", "closed_at"))


def deployment_filename(manifest, identity):
    return "testnet-deployment-" + manifest["tag"] + "-" + identity["generation"]["hash"] + ".json"


def source_equal(left, right):
    return {k: v for k, v in left.items() if k != "workflow_revision"} == {
        k: v for k, v in right.items() if k != "workflow_revision"}


def read_public(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Expected a bounded regular public checkpoint")
    return ca.public_json(path.read_text())


def gh_json(path, missing=False):
    result = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    data = ca.public_json(result.stdout)
    if result.returncode:
        if missing and data.get("status") == "404":
            return None
        raise ValueError("Cannot read canonical GitHub release state")
    return data


def fetch_previous(manifest, output):
    """Read published identities and prior public checkpoints before exposing deployment secrets."""
    output.mkdir(parents=True, exist_ok=False)
    release = gh_json("repos/allowit-hq/allowit-contracts-stellar/releases/tags/" + manifest["tag"], missing=True)
    if release is not None:
        published = output / "published"
        published.mkdir()
        subprocess.run(["gh", "release", "download", manifest["tag"], "--repo", "allowit-hq/allowit-contracts-stellar",
            "--pattern", "source-manifest.json", "--pattern", "testnet-deployment-" + manifest["tag"] + "-*.json", "--dir", str(published)], check=True, capture_output=True)
        if not source_equal(read_public(published / "source-manifest.json"), manifest):
            raise ValueError("Published release artifacts differ")
        if not list(published.glob("testnet-deployment-*.json")):
            raise ValueError("Published release has no versioned deployment identity")
    prefix = "stellar-testnet-checkpoint-" + manifest["tag"] + "-"
    for page in range(1, 11):
        records = gh_json("repos/allowit-hq/allowit-contracts-stellar/actions/artifacts?per_page=100&page=" + str(page))["artifacts"]
        for item in records:
            if not item["name"].startswith(prefix):
                continue
            run = gh_json("repos/allowit-hq/allowit-contracts-stellar/actions/runs/" + str(item["workflow_run"]["id"]))
            if run.get("path") != ".github/workflows/testnet-release.yml" or run.get("event") != "workflow_run" or run.get("head_repository", {}).get("full_name") != "allowit-hq/allowit-contracts-stellar":
                raise ValueError("Prior checkpoint belongs to another workflow")
            head = item["workflow_run"]["head_sha"]
            if not SHA.fullmatch(head) or subprocess.run(["git", "merge-base", "--is-ancestor", head, "refs/release/main"], capture_output=True).returncode:
                raise ValueError("Prior deployment checkpoint is not from canonical main")
            if item["expired"]:
                raise ValueError("Prior deployment checkpoint expired; operator reconciliation is required")
            target = output / ("run-" + str(item["id"]))
            subprocess.run(["gh", "run", "download", str(item["workflow_run"]["id"]), "--repo", "allowit-hq/allowit-contracts-stellar",
                "--name", item["name"], "--dir", str(target)], check=True, capture_output=True)
        if len(records) < 100:
            return
    raise ValueError("Deployment checkpoint discovery exceeds limit; stop before mutation")


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
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


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
        if subprocess.run(["git", "-C", str(root), "merge-base", "--is-ancestor", commit, main], capture_output=True).returncode:
            raise ValueError("Release and workflow commits must belong to canonical main")
    remote = git(root, "ls-remote", REPOSITORY, reference, reference + "^{}")
    expected = {reference: tag_object, reference + "^{}": revision}
    if {line.split()[1]: line.split()[0] for line in remote.splitlines()} != expected:
        raise ValueError("Canonical release tag changed or is unavailable")
    return {"tag": tag, "revision": revision, "tag_object": tag_object, "workflow_revision": workflow_sha}


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
            raise ValueError("Release must use the single published Core v0.3.1 source")
    sample = source / "crates/custom-policy/policy/policy.rs"
    # Resolve this with the release's own checked policy gate, before the signing job.
    helper = "import sys;sys.path.insert(0,sys.argv[1]);from policy_source import standard_prefix;import json;print(json.dumps(standard_prefix(open(sys.argv[2]).read())))"
    rules = json.loads(subprocess.check_output([sys.executable, "-c", helper, str(source / "scripts"), str(sample)], text=True))
    output.mkdir(parents=True, exist_ok=True)
    result = {"schema": 1, "repository": REPOSITORY, **identity, "core_source": CORE_SOURCE,
        "toolchain": {"rust": "1.98.0", "stellar": "28.1.0"}, "artifacts": {}}
    target = Path(json.loads(subprocess.check_output(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=source, text=True))["target_directory"])
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
    instance = digest(canonical(["allowit_testnet_release_v1", manifest["revision"], kind, module, owner, agent, server]))
    return {"owner": owner, "agent": agent, "server": server, "asset": asset,
        "policy_instance": instance, "source_digest": source, "rules": rules, "params": params, "x402_enabled": False}


def check_constructor(create, config, module, salt):
    """Compare the CLI builder against independent caller-owned native constructor intent."""
    if create is None or create.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM or create.executable.wasm_hash.hash.hex() != module or len(create.constructor_args) != 1:
        raise ValueError("Constructor does not use the exact release executable/configuration")
    preimage = create.contract_id_preimage
    if preimage.type != xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS or preimage.from_address.address != Address(config["owner"]).to_xdr_sc_address() or preimage.from_address.salt.uint256 != salt:
        raise ValueError("Constructor owner or deterministic salt differs")
    def plain(value):
        if isinstance(value, Address):
            return value.address
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, list):
            return [plain(item) for item in value]
        if isinstance(value, dict):
            return {key: plain(item) for key, item in value.items()}
        return value
    decoded = plain(scval.to_native(create.constructor_args[0]))
    if not isinstance(decoded, dict) or set(decoded) != set(config):
        raise ValueError("Constructor fields differ from the release intent")
    decoded["params"] = ca.plain_params(decoded["params"])
    decoded["rules"] = ca.rule_names(decoded["rules"])
    if decoded != config:
        raise ValueError("Constructor values differ from the release intent")


class Deployment:
    def __init__(self, directory, output, private, key, agent, server, previous=None):
        self.directory, self.output, self.private, self.key = directory, output, private, key
        self.manifest = check_bundle(directory)
        for address in (key.public_key, agent, server):
            ca.account(address)
        if len({key.public_key, agent, server}) != 3:
            raise ValueError("Release owner, agent and server must differ")
        self.agent, self.server = agent, server
        self.previous = []
        if previous is not None:
            for path in sorted(previous.rglob("*.json")):
                if path.name == "source-manifest.json":
                    continue
                data = read_public(path)
                if not source_equal(data.get("source", {}), self.manifest) or any(data.get(k) != v for k, v in
                    (("owner", key.public_key), ("agent", agent), ("server", server), ("network", "stellar:testnet"))):
                    raise ValueError("Prior deployment source, roles or network differ; stop before mutation")
                for kind, item in data.get("wallets", {}).items():
                    if kind not in KINDS or item.get("config") != config_for(self.manifest, kind, key.public_key, agent, server):
                        raise ValueError("Prior wallet configuration differs; stop before mutation")
                self.previous.append(data)
        recorded = self.previous[-1]["network_identity"]["generation"] if self.previous else None
        self.rpc = SorobanServer(RPC)
        identity = network_identity(self.rpc, recorded)
        self.public = {"schema": 1, "network": "stellar:testnet", "rpc": RPC,
            "source": self.manifest, "owner": key.public_key, "agent": agent, "server": server,
            "deployment_automation_revision": git(Path(__file__).resolve().parents[1], "rev-parse", "HEAD"),
            "code": {}, "wallets": {}, "transactions": [],
            "network_identity": identity, "status": "IN_PROGRESS",
            "scope": "Release-controlled initialized smoke wallets; no user wallet, user funds, or Mainnet deployment. Shared engine/parent code is uploaded only."}
        private.mkdir(parents=True, exist_ok=True, mode=0o700)
        if private.is_symlink() or private.stat().st_mode & 0o077:
            raise ValueError("Private transaction directory must have mode0700")
        if private.resolve().is_relative_to(directory.resolve()) or output.exists() or any(private.glob("*.json")):
            raise ValueError("Use separate fresh private and public checkpoint paths; preserve earlier packets")

    def save(self):
        write(self.output, self.public)

    def reconcile_previous(self):
        """Resolve original hashes before any rerun can fund, sign or submit another transaction."""
        now = int(datetime.now(timezone.utc).timestamp())
        for checkpoint in self.previous:
            if not same_generation(checkpoint["network_identity"], self.public["network_identity"]):
                continue  # The recorded anchor was read and its different hash proved a reset.
            if checkpoint.get("status") == "VERIFIED":
                continue
            for record in checkpoint.get("transactions", []):
                tx_hash, expires = record.get("transaction_hash"), record.get("expires_at")
                if not HEX.fullmatch(tx_hash or "") or type(expires) is not int or expires <= 0:
                    raise ValueError("Prior transaction identity is incomplete; operator reconciliation is required")
                receipt = self.rpc.get_transaction(tx_hash)
                if receipt.status == GetTransactionStatus.SUCCESS:
                    envelope = TransactionEnvelope.from_xdr(receipt.envelope_xdr, PASSPHRASE)
                    if envelope.hash_hex() != tx_hash or envelope.transaction.source.account_id != self.key.public_key or not receipt.ledger:
                        raise ValueError("Prior transaction receipt differs from the original identity")
                elif receipt.status != GetTransactionStatus.FAILED and now <= expires:
                    raise ValueError("Prior submission remains uncertain; preserve its original hash " + tx_hash)

    def ensure_account(self):
        key = xdr.LedgerKey(xdr.LedgerEntryType.ACCOUNT, account=xdr.LedgerKeyAccount(self.key.xdr_account_id()))
        found = self.entry(key)
        if found is None:
            ca.cli_run(["--config-dir", str(self.private / "cli"), "keys", "add", "release-owner", "--public-key", self.key.public_key])
            self.cli(["keys", "fund", "release-owner"])
            found = self.entry(key)
        if found is None:
            raise ValueError("Testnet release account is not funded")
        account = found[2].account
        if account is None or account.account_id != self.key.xdr_account_id() or account.signers or account.thresholds.thresholds != b"\x01\x00\x00\x00":
            raise ValueError("Use a dedicated master-key-only Testnet release account")

    def entry(self, key):
        response = self.rpc.get_ledger_entries([key])
        if len(response.entries) > 1:
            raise ValueError("RPC returned duplicate ledger entries")
        if not response.entries:
            return None
        item = response.entries[0]
        if item.key != key.to_xdr():
            raise ValueError("RPC returned another ledger key")
        return response, item, xdr.LedgerEntryData.from_xdr(item.xdr)

    def code(self, value):
        key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_CODE, contract_code=xdr.LedgerKeyContractCode(xdr.Hash(bytes.fromhex(value))))
        found = self.entry(key)
        if found is None:
            return None
        response, item, data = found
        if data.type != xdr.LedgerEntryType.CONTRACT_CODE or data.contract_code.hash.hash.hex() != value or digest(data.contract_code.code) != value:
            raise ValueError("Onchain code differs from the release")
        if type(item.live_until_ledger_seq) is not int or item.live_until_ledger_seq <= response.latest_ledger:
            raise ValueError("Release code is expired or its lifetime is unavailable")
        return {"sha256": value, "bytes": len(data.contract_code.code), "ledger": response.latest_ledger,
            "live_until_ledger": item.live_until_ledger_seq}

    def instance(self, wallet, expected):
        key = xdr.LedgerKey(xdr.LedgerEntryType.CONTRACT_DATA,
            contract_data=xdr.LedgerKeyContractData(Address(wallet).to_xdr_sc_address(), scval.to_ledger_key_contract_instance(), xdr.ContractDataDurability.PERSISTENT))
        found = self.entry(key)
        if found is None:
            return None
        response, item, data = found
        if data.type != xdr.LedgerEntryType.CONTRACT_DATA or data.contract_data.val.type != xdr.SCValType.SCV_CONTRACT_INSTANCE:
            raise ValueError("Wallet readback is not a native contract instance")
        instance = data.contract_data.val.instance
        if instance.executable.type != xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM or instance.executable.wasm_hash.hash.hex() != expected:
            raise ValueError("Existing deterministic wallet uses different code")
        if type(item.live_until_ledger_seq) is not int or item.live_until_ledger_seq <= response.latest_ledger:
            raise ValueError("Release wallet is expired or its lifetime is unavailable")
        return {"contract": wallet, "wasm_sha256": expected, "ledger": response.latest_ledger,
            "live_until_ledger": item.live_until_ledger_seq}

    def cli(self, args, packet=None):
        args = list(args)
        at = args.index("--") if "--" in args else len(args)
        args[at:at] = ["--rpc-url", RPC, "--network-passphrase", PASSPHRASE]
        return ca.cli_run(["--config-dir", str(self.private / "cli"), *args], input_data=packet)

    def submit(self, stage, raw, candidate=None, expected_wasm=None):
        # The native preparation helper permits simulation to add only auth/resources/fees.
        original = ca.cli_run
        def configured(args, input_data=None):
            args = list(args)
            if "--network" in args:
                at = args.index("--network")
                args[at:at + 2] = ["--rpc-url", RPC, "--network-passphrase", PASSPHRASE]
            return original(["--config-dir", str(self.private / "cli"), *args], input_data=input_data)
        ca.cli_run = configured
        try:
            unsigned = ca.prepare_xdr(raw, self.key.public_key, "testnet", max_fee=MAX_FEE,
                candidate=candidate, expected_wasm=expected_wasm)
        finally:
            ca.cli_run = original
        envelope = TransactionEnvelope.from_xdr(unsigned, PASSPHRASE)
        envelope.sign(self.key)
        signed = envelope.to_xdr()
        tx_hash = envelope.hash_hex()
        # Retain exact signed bytes privately before any transmission; never publish them.
        write(self.private / (stage + ".json"), {"unsigned_xdr": unsigned, "signed_xdr": signed, "hash": tx_hash}, private=True)
        record = {"stage": stage, "transaction_hash": tx_hash, "status": "prepared",
            "fee_cap_stroops": envelope.transaction.fee,
            "expires_at": envelope.transaction.preconditions.time_bounds.max_time}
        self.public["transactions"].append(record)
        self.save()
        try:
            self.cli(["tx", "send"], signed)
        except subprocess.CalledProcessError:
            # CLI owns submission/polling. Never generate a replacement transaction here.
            record["status"] = "unknown"
            self.save()
            raise ValueError("Submission uncertain; inspect retained transaction " + tx_hash) from None
        receipt = self.rpc.get_transaction(tx_hash)
        if receipt.status != GetTransactionStatus.SUCCESS or receipt.envelope_xdr != signed or not receipt.ledger:
            raise ValueError("Transaction lacks an exact successful Testnet receipt")
        record.update(status="SUCCESS", ledger=receipt.ledger)
        self.save()

    def read_state(self, wallet):
        raw = self.cli(["contract", "invoke", "--id", wallet, "--source-account", self.key.public_key, "--send=no", "--", "state"])
        return json.loads(raw)

    def run(self):
        self.reconcile_previous()
        self.save()
        self.ensure_account()
        for kind, descriptor in self.manifest["artifacts"].items():
            expected = descriptor["sha256"]
            if self.code(expected) is None:
                raw = self.cli(["contract", "upload", "--wasm", str(self.directory / descriptor["file"]),
                    "--optimize=false", "--source-account", self.key.public_key, "--build-only"])
                envelope = TransactionEnvelope.from_xdr(raw, PASSPHRASE)
                host = envelope.transaction.operations[0].host_function
                if host.type != xdr.HostFunctionType.HOST_FUNCTION_TYPE_UPLOAD_CONTRACT_WASM or digest(host.wasm) != expected:
                    raise ValueError("Upload bytes differ from the release artifact")
                self.submit("upload-" + kind, raw)
            observed = self.code(expected)
            if observed is None or observed["bytes"] != descriptor["bytes"]:
                raise ValueError("Code upload has no exact onchain readback")
            self.public["code"][kind] = observed
            self.save()
        for kind in KINDS:
            config = config_for(self.manifest, kind, self.key.public_key, self.agent, self.server)
            salt = bytes.fromhex(digest(canonical(["allowit_testnet_release_salt_v1", self.manifest["tag"], config])))
            wallet = contract_id(self.key.public_key, salt)
            expected = self.manifest["artifacts"][kind]["sha256"]
            if self.instance(wallet, expected) is None:
                args = ["contract", "deploy", "--wasm", str(self.directory / CONTRACTS[kind]), "--optimize=false",
                    "--salt", salt.hex(), "--source-account", self.key.public_key, "--build-only", "--", *ca.serialize({"config": config})]
                # Network flags precede the constructor's '--' separator.
                at = args.index("--")
                args[at:at] = ["--rpc-url", RPC, "--network-passphrase", PASSPHRASE]
                raw = ca.cli_run(["--config-dir", str(self.private / "cli"), *args])
                create = TransactionEnvelope.from_xdr(raw, PASSPHRASE).transaction.operations[0].host_function.create_contract_v2
                check_constructor(create, config, expected, salt)
                if create is None or Address.from_xdr_sc_address(ca.deployment_address(create, "testnet")).address != wallet:
                    raise ValueError("Native constructor target differs from the release")
                self.submit("deploy-" + kind, raw, expected_wasm=expected)
            observed = self.instance(wallet, expected)
            state = self.read_state(wallet)
            for field in ("owner", "agent", "server", "asset", "policy_instance", "source_digest", "rules", "x402_enabled"):
                if state.get(field) != config[field]:
                    raise ValueError("Wallet state differs from release configuration: " + field)
            if state.get("params") != ca.params(config["params"], kind) or state.get("contract_version") != ca.WALLET_CONTRACT_VERSION:
                raise ValueError("Wallet parameters or custody layout differ")
            if observed is None:
                raise ValueError("Wallet has no onchain readback")
            self.public["wallets"][kind] = {**observed, "config": config, "state": state,
                "funding": "No release funds are transferred to smoke wallets."}
            self.save()
        final_identity = network_identity(self.rpc, self.public["network_identity"]["generation"])
        if not same_generation(final_identity, self.public["network_identity"]):
            raise ValueError("Testnet generation changed during deployment")
        self.public["network_identity"] = final_identity
        self.public["status"] = "VERIFIED"
        self.public["verified_at"] = datetime.now(timezone.utc).isoformat()
        self.save()
        return self.public


def publish(directory, previous):
    manifest = check_bundle(directory)
    files = list(directory.glob("testnet-deployment-*.json"))
    if len(files) != 1:
        raise ValueError("Expected one versioned public deployment manifest")
    deployment = read_public(files[0])
    if deployment.get("status") != "VERIFIED" or not source_equal(deployment.get("source", {}), manifest):
        raise ValueError("Deployment is not the verified release")
    if files[0].name != deployment_filename(manifest, deployment["network_identity"]):
        raise ValueError("Deployment manifest filename differs from its generation")
    reference = "refs/tags/" + manifest["tag"]
    remote = subprocess.check_output(["git", "ls-remote", REPOSITORY, reference, reference + "^{}"], text=True)
    if {line.split()[1]: line.split()[0] for line in remote.splitlines()} != {reference: manifest["tag_object"], reference + "^{}": manifest["revision"]}:
        raise ValueError("Canonical release tag changed")
    published = previous / "published"
    if published.exists():
        if not source_equal(read_public(published / "source-manifest.json"), manifest):
            raise ValueError("Published release artifacts differ")
        existing = published / files[0].name
        if existing.exists():
            old = read_public(existing)
            if not same_generation(old["network_identity"], deployment["network_identity"]) or any(old.get(k) != deployment.get(k) for k in ("owner", "agent", "server")) or any(
                any(old["wallets"][kind][k] != deployment["wallets"][kind][k] for k in ("contract", "wasm_sha256", "config")) for kind in KINDS):
                raise ValueError("Published deployment identity differs")
            return  # Preserve the first immutable manifest and all release assets.
        subprocess.run(["gh", "release", "upload", manifest["tag"], str(files[0]), "--repo", "allowit-hq/allowit-contracts-stellar"], check=True, capture_output=True)
    else:
        notes = directory.parent / "release-notes.md"
        notes.write_text("Exact release artifacts and dedicated operator smoke wallets are verified on Stellar Testnet.\n\n"
            "These wallets do not establish the human owner's app acceptance.\n\nSee source-manifest.json and " + files[0].name + " for code, configuration, generation and receipts.\n")
        assets = [directory / filename for filename in CONTRACTS.values()] + [directory / "sample-policy.rs", directory / "source-manifest.json", files[0]]
        subprocess.run(["gh", "release", "create", manifest["tag"], "--repo", "allowit-hq/allowit-contracts-stellar", "--verify-tag", "--title", manifest["tag"],
            "--notes-file", str(notes), *map(str, assets)], check=True, capture_output=True)


def main():
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
    previous = commands.add_parser("previous")
    previous.add_argument("--bundle", type=Path, required=True)
    previous.add_argument("--output", type=Path, required=True)
    publication = commands.add_parser("publish")
    publication.add_argument("--bundle", type=Path, required=True)
    publication.add_argument("--previous", type=Path, required=True)
    deploy = commands.add_parser("deploy")
    deploy.add_argument("--bundle", type=Path, required=True)
    deploy.add_argument("--identity", type=Path, required=True)
    deploy.add_argument("--output", type=Path, required=True)
    deploy.add_argument("--private", type=Path, required=True)
    deploy.add_argument("--owner", required=True)
    deploy.add_argument("--agent", required=True)
    deploy.add_argument("--server", required=True)
    deploy.add_argument("--previous", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "metadata":
        result = release_identity(args.repository, args.tag, args.workflow_sha)
        write(args.output, result)
        for key, value in result.items():
            print(key + "=" + value)
    elif args.action == "bundle":
        bundle(args.source, json.loads(args.identity.read_text()), args.output)
    elif args.action == "previous":
        fetch_previous(check_bundle(args.bundle), args.output)
    elif args.action == "publish":
        publish(args.bundle, args.previous)
    else:
        manifest = check_bundle(args.bundle)
        identity = json.loads(args.identity.read_text())
        if any(manifest.get(key) != value for key, value in identity.items()):
            raise ValueError("Deployment bundle is not the verified release")
        secret = os.environ.pop("STELLAR_TESTNET_OWNER_SECRET", "")
        try:
            key = Keypair.from_secret(secret)
        except Exception:
            raise ValueError("A dedicated Testnet release owner secret is required") from None
        if key.public_key != ca.account(args.owner):
            raise ValueError("Release secret does not match its configured public owner")
        result = Deployment(args.bundle, args.output, args.private, key, args.agent, args.server, args.previous).run()
        write(args.output.parent / deployment_filename(manifest, result["network_identity"]), result)
        print("Verified release contracts on Stellar Testnet.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        # Do not print native CLI packet output or secret parse diagnostics.
        message = str(error) if isinstance(error, ValueError) else "Release command failed; inspect the public checkpoint."
        print(message, file=sys.stderr)
        sys.exit(1)
