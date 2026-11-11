import copy
import argparse
from io import StringIO
import json
import hashlib
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wallet_admin as wa
import contract_admin as ca
from stellar_sdk import Keypair, TransactionEnvelope, Account, TransactionBuilder, Address, StrKey, xdr

KEYS = [Keypair.from_raw_ed25519_seed(bytes([n]) * 32).public_key for n in range(1, 6)]
ROOT = Path(__file__).resolve().parents[2]
HEAD = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n"


def source(body, head=HEAD):
    return head + body + "    Ok(())\n}\n"


def CALL(rule):
    """One canonical prefix statement: the rule on its own canonical param key."""
    return "    allowit::{0}(ctx, &ctx.params[allowit::{1}])?;\n".format(rule, rule.upper())


def leb128(value):
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def meta_wasm(*entries):
    """Minimal Wasm module with one `contractmetav0` section of XDR ScMetaEntry V0 entries."""
    meta = b""
    for key, value in entries:
        meta += bytes(4)
        for field in (key, value):
            meta += len(field).to_bytes(4, "big") + field + bytes(-len(field) % 4)
    name = b"contractmetav0"
    body = leb128(len(name)) + name + meta
    return b"\0asm\x01\0\0\0" + b"\0" + leb128(len(body)) + body


def state():
    return {"account_id": KEYS[0], "sequence": "42", "signers": [
        {"key": KEYS[0], "weight": 1, "type": "ed25519_public_key"}],
        "thresholds": {"low_threshold": 0, "med_threshold": 0, "high_threshold": 0}}


class NativeAdmin(unittest.TestCase):
    def test_native_param_keys_match_portable_policy(self):
        from policy_source import PARAM_KEYS
        self.assertEqual(tuple(ca.PARAM_KEYS), tuple(PARAM_KEYS))

    def test_owner_only_admission(self):
        wa.owner_only(state())
        value = state()
        value["signers"][0]["weight"] = 3
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        wa.owner_only(value)
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.owner_only(value)
        for change in ("zero", "drift", "hash"):
            value = state()
            if change == "zero":
                value["signers"][0]["weight"] = 0
            elif change == "drift":
                value["thresholds"]["high_threshold"] = 2
            else:
                value["signers"].append({"key": "hash", "weight": 1, "type": "sha256_hash"})
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                wa.owner_only(value)

    def test_admin_candidate_exact_admission(self):
        value = state()
        with self.assertRaises(ValueError):
            wa.admin(value, KEYS[1:4])
        value["signers"][0]["weight"] = 0
        value["signers"] += [{"key": key, "weight": 1, "type": "ed25519_public_key"} for key in KEYS[1:4]]
        value["thresholds"] = dict.fromkeys(("low_threshold", "med_threshold", "high_threshold"), 2)
        wa.admin(value, KEYS[1:4])
        value["signers"][1]["weight"] = 2
        with self.assertRaises(ValueError):
            wa.admin(value, KEYS[1:4])


class ContractAdmin(unittest.TestCase):
    def test_exact_allowlist_and_types(self):
        self.assertEqual(ca.checked_args("set_pause", {"paused": True, "deployment_version": 3}, "wallet")["paused"], True)
        for value in ({"paused": "false", "deployment_version": 3}, {"paused": True, "deployment_version": True}, {"paused": True, "deployment_version": 3, "target": KEYS[1]}):
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                ca.checked_args("set_pause", value, "wallet")
        self.assertNotIn("transfer", ca.WALLET)
        self.assertNotIn("approve", ca.WALLET)
        self.assertNotIn("set_params", ca.PARENT)
        # Parent arguments are the owner and the version; old names and out-of-range versions reject.
        values = {"owner": KEYS[1], "version": 0}
        self.assertEqual(ca.checked_args("set_admin", values, "parent"), values)
        for old in ({"new_admin": KEYS[1], "expected_revision": 0},
                    {"owner": KEYS[1], "version": -1},
                    {"owner": KEYS[1], "version": 2**64}):
            with self.assertRaises(ValueError):
                ca.checked_args("set_admin", old, "parent")

    def test_params_encode_typed_values_and_standard_tiers_admit_only_canonical_keys(self):
        values = {"lifetime_spending_limit": 2**127 - 1, "call_limit": 0, "destinations": [KEYS[1]], "tokens": []}
        self.assertEqual(ca.params(values, "common"), {"lifetime_spending_limit": {"Int": str(2**127 - 1)}, "call_limit": {"Int": "0"},
                                                       "destinations": {"List": [{"Addr": KEYS[1]}]}, "tokens": {"List": []}})
        self.assertEqual(ca.params({}, "simple"), {})
        tagged = json.loads(ca.serialize({"deployment": {"params": values}})[1])["params"]
        self.assertEqual(tagged["lifetime_spending_limit"], {"Int": str(2**127 - 1)})
        self.assertNotIn("expires_at", tagged)
        # Custom params: inferred or explicitly typed values within the contract's bounds.
        custom = {"vendor_limit": -5, "note": "pay invoices", "vendor": KEYS[2], "as_text": {"Str": KEYS[2]}, "urgent": True,
                  "pairs": [[1, KEYS[1]]]}
        self.assertEqual(ca.params(custom, "custom"), {"vendor_limit": {"Int": "-5"}, "note": {"Str": "pay invoices"},
                                                        "vendor": {"Addr": KEYS[2]}, "as_text": {"Str": KEYS[2]},
                                                        "urgent": {"Bool": True}, "pairs": {"List": [{"List": [{"Int": "1"}, {"Addr": KEYS[1]}]}]}})
        for invalid in ({"vendor_limit": 1}, {"lifetime_spending_limit": -1}, {"lifetime_spending_limit": 2**127},
                        {"call_limit": 2**64}, {"expires_at": True}, {"payment_limit": "1"}, {"destinations": KEYS[1]},
                        {"tokens": ["not-an-address"]}, {"destinations": [[KEYS[1]]]}):
            with self.subTest(params=invalid), self.assertRaises(ValueError):
                ca.params(invalid, "common")
        # `operations` is "*" or a list of op names, which may be empty.
        pool = "custom:" + StrKey.encode_contract(bytes([3]) * 32)
        for valid in ("*", [], ["transfer", "swap", "deposit", "redeem", "custom", "custom.swap", pool + ".claim"]):
            with self.subTest(operations=valid):
                ca.params({"operations": valid}, "common")
        self.assertEqual(ca.params({"operations": ["deposit"]}, "simple"), {"operations": {"List": [{"Str": "deposit"}]}})
        for invalid in ("transfer", ["*"], ["pay"], ["Transfer"], [1], [KEYS[1]], 0, ["custom."], ["custom.a-b"],
                        [pool], [pool + "." + "f" * 33], ["custom:" + KEYS[1] + ".swap"]):
            with self.subTest(operations=invalid), self.assertRaisesRegex(ValueError, "operations"):
                ca.params({"operations": invalid}, "common")
        for invalid in ({"bad key": 1}, {"k" * 33: 1}, {1: 1}, {"x": 1.5}, {"x": None}, {"x": {"Int": "1"}},
                        {"x": {"Map": 1}}, {"x": "y" * 257}, {"x": list(range(65))}, {"x": [list(range(64))]},
                        {"x": 2**127}, {"k" + str(i): i for i in range(33)}):
            with self.subTest(params=invalid), self.assertRaises((ValueError, TypeError)):
                ca.params(invalid, "custom")
        # Params encode in at most 16 KiB, counted as the wallet counts them: 40 bytes per key, 80
        # per value and each text padded to four bytes. 40 + 80 + 48 * 336 + 40 + 80 + 16 is 16 KiB.
        texts = ["x" * 256] * 48
        self.assertIn("b", ca.params({"a": texts, "b": "x" * 16}, "custom"))
        with self.assertRaisesRegex(ValueError, "16384 bytes"):
            ca.params({"a": texts, "b": "x" * 17}, "custom")
        # The largest standard params fit.
        full = {key: 0 for key in ca.PARAM_KEYS} | {"destinations": [KEYS[1]] * 64, "tokens": [KEYS[2]] * 64,
                                                    "operations": ["custom:C" + "A" * 55 + "." + "f" * 32] * 28}
        self.assertEqual(len(ca.params(full, "common")), 9)
        with self.assertRaisesRegex(ValueError, "16384 bytes"):
            ca.params(dict(full, operations=full["operations"] * 2), "common")
        # The count error names the limit of the tier.
        for tier, limit in (("common", 9), ("simple", 9), ("custom", 32)):
            with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "at most {} keys".format(limit)):
                ca.params({"k" + str(i): i for i in range(limit + 1)}, tier)
        deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                      "rules": ["lifetime_spending_limit", "destinations"], "params": values, "x402_enabled": False, "wasm_hash": None}
        ca.deployment(deployment)
        with self.assertRaises(ValueError):
            ca.deployment(dict(deployment, rules=["daily_limit"]))
        with self.assertRaises(ValueError):
            ca.public_json('{"custom":1,"custom":2}')

    def test_assembly_preserves_intent_and_adds_resources(self):
        raw = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"], base_fee=100).append_upload_contract_wasm_op(b"test-wasm").set_timeout(0).build()
        calls = []
        def simulate(arguments, input_data=None):
            calls.append(arguments)
            result = TransactionEnvelope.from_xdr(input_data, wa.PASSPHRASE["testnet"])
            self.assertEqual(result.signatures, [])
            self.assertEqual(result.transaction.preconditions.time_bounds.min_time, 0)
            self.assertEqual(result.transaction.preconditions.time_bounds.max_time, 1300)
            result.transaction.fee += 123
            result.transaction.soroban_data = xdr.SorobanTransactionData(
                xdr.SorobanTransactionDataExt(0),
                xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(100), xdr.Uint32(0), xdr.Uint32(0)),
                xdr.Int64(123))
            return result.to_xdr()
        with patch.object(ca, "cli_run", side_effect=simulate):
            output = ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000)
        assembled = TransactionEnvelope.from_xdr(output, wa.PASSPHRASE["testnet"])
        self.assertEqual(assembled.signatures, [])
        self.assertIsNotNone(assembled.transaction.soroban_data)
        self.assertEqual(assembled.transaction.source.account_id, KEYS[0])
        self.assertEqual(assembled.transaction.sequence, 43)
        self.assertEqual(assembled.transaction.operations[0].host_function, raw.transaction.operations[0].host_function)
        self.assertEqual(calls, [["tx", "simulate", "--network", "testnet", "--source-account", KEYS[0], "--auth-mode", "root"]])
        for mutation in ("sequence", "bounds", "host", "unsigned_resources", "fee"):
            def altered(arguments, input_data=None):
                result = TransactionEnvelope.from_xdr(simulate(arguments, input_data), wa.PASSPHRASE["testnet"])
                if mutation == "sequence":
                    result.transaction.sequence += 1
                elif mutation == "bounds":
                    result.transaction.preconditions.time_bounds.max_time += 1
                elif mutation == "host":
                    other = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_upload_contract_wasm_op(b"other-wasm").set_timeout(0).build()
                    result.transaction.operations[0].host_function = other.transaction.operations[0].host_function
                elif mutation == "fee":
                    result.transaction.fee = 10_000_001
                else:
                    result.transaction.soroban_data = None
                return result.to_xdr()
            with patch.object(ca, "cli_run", side_effect=altered):
                with self.assertRaises(ValueError):
                    ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000)
        with self.assertRaises(ValueError):
            ca.prepare_xdr(raw.to_xdr(), KEYS[1], "testnet", now=1000)

    def test_deployment_constructor_authorization(self):
        create = xdr.CreateContractArgsV2(
            xdr.ContractIDPreimage(xdr.ContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS,
                from_address=xdr.ContractIDPreimageFromAddress(Address(KEYS[0]).to_xdr_sc_address(), xdr.Uint256(bytes([5]) * 32))),
            xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(bytes([6]) * 32)),
            [Address(KEYS[0]).to_xdr_sc_val(), xdr.SCVal(xdr.SCValType.SCV_U64, u64=xdr.Uint64(7))])
        host = xdr.HostFunction(xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2, create_contract_v2=create)
        child = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
            xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN,
            contract_fn=xdr.InvokeContractArgs(ca.deployment_address(create, "testnet"), xdr.SCSymbol(b"__constructor"), create.constructor_args)), [])
        root = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(
            xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CREATE_CONTRACT_V2_HOST_FN,
            create_contract_v2_host_fn=create), [child])
        entry = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT), root)
        operation = ca.InvokeHostFunction(host, auth=[entry])
        ca.validate_auth(operation, network="testnet")
        raw = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_operation(ca.InvokeHostFunction(host)).set_timeout(0).build()
        def assemble(arguments, input_data=None):
            prepared = TransactionEnvelope.from_xdr(input_data, wa.PASSPHRASE["testnet"])
            prepared.transaction.operations[0].auth = [copy.deepcopy(entry)]
            prepared.transaction.fee += 123
            prepared.transaction.soroban_data = xdr.SorobanTransactionData(xdr.SorobanTransactionDataExt(0), xdr.SorobanResources(xdr.LedgerFootprint([], []), xdr.Uint32(100), xdr.Uint32(0), xdr.Uint32(0)), xdr.Int64(123))
            return prepared.to_xdr()
        with patch.object(ca, "cli_run", side_effect=assemble):
            assembled = TransactionEnvelope.from_xdr(ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", now=1000, expected_wasm="06" * 32), wa.PASSPHRASE["testnet"])
        self.assertEqual(assembled.transaction.operations[0].auth, [entry])
        self.assertEqual(assembled.signatures, [])
        with patch.object(ca, "cli_run") as simulated:
            with self.assertRaises(ValueError):
                ca.prepare_xdr(raw.to_xdr(), KEYS[0], "testnet", expected_wasm="07" * 32)
            simulated.assert_not_called()
        with self.assertRaises(ValueError):
            ca.validate_auth(operation, network="mainnet")
        for mutation in ("address", "name", "args", "deep", "candidate", "duplicate", "extra", "missing"):
            altered = copy.deepcopy(operation)
            node = altered.auth[0].root_invocation.sub_invocations[0]
            if mutation == "address":
                node.function.contract_fn.contract_address = Address(StrKey.encode_contract(bytes([9]) * 32)).to_xdr_sc_address()
            elif mutation == "name":
                node.function.contract_fn.function_name = xdr.SCSymbol(b"transfer")
            elif mutation == "args":
                node.function.contract_fn.args = []
            elif mutation == "deep":
                node.sub_invocations = [copy.deepcopy(child)]
            elif mutation == "candidate":
                altered.auth[0].credentials = xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS, address=xdr.SorobanAddressCredentials(Address(KEYS[1]).to_xdr_sc_address(), xdr.Int64(1), xdr.Uint32(100), xdr.SCVal(xdr.SCValType.SCV_VOID)))
            elif mutation == "duplicate":
                altered.auth.append(copy.deepcopy(entry))
            elif mutation == "extra":
                altered.auth[0].root_invocation.sub_invocations.append(copy.deepcopy(child))
            else:
                altered.auth[0].root_invocation.sub_invocations = []
            with self.assertRaises(ValueError, msg=mutation):
                ca.validate_auth(altered, candidate=KEYS[1], network="testnet")

    def test_simulated_authorization_scope(self):
        contract = StrKey.encode_contract(bytes([8]) * 32)
        tx = TransactionBuilder(Account(KEYS[0], 42), wa.PASSPHRASE["testnet"]).append_invoke_contract_function_op(contract, "set_paused", []).set_timeout(0).build()
        op = tx.transaction.operations[0]
        root = xdr.SorobanAuthorizedInvocation(xdr.SorobanAuthorizedFunction(xdr.SorobanAuthorizedFunctionType.SOROBAN_AUTHORIZED_FUNCTION_TYPE_CONTRACT_FN, contract_fn=op.host_function.invoke_contract), [])
        source = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_SOURCE_ACCOUNT), root)
        op.auth = [source]
        ca.validate_auth(op)
        candidate = xdr.SorobanAuthorizationEntry(xdr.SorobanCredentials(xdr.SorobanCredentialsType.SOROBAN_CREDENTIALS_ADDRESS, address=xdr.SorobanAddressCredentials(Address(KEYS[1]).to_xdr_sc_address(), xdr.Int64(1), xdr.Uint32(100), xdr.SCVal(xdr.SCValType.SCV_VOID))), copy.deepcopy(root))
        op.auth.append(candidate)
        ca.validate_auth(op, KEYS[1])
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        with self.assertRaises(ValueError):
            ca.validate_auth(op, KEYS[2])
        op.auth = [source, source]
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        op.auth = [source]
        source.root_invocation.sub_invocations = [copy.deepcopy(root)]
        with self.assertRaises(ValueError):
            ca.validate_auth(op)
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.checked_args("set_admin", {"owner": contract, "version": 0}, "parent")
        with self.assertRaises(ValueError):
            ca.checked_args("recover", {"recipient": KEYS[1], "amount": 0, "version": 0}, "wallet")

    def test_cli_preparation_cannot_submit(self):
        args = SimpleNamespace(network="testnet", allow_mainnet=False, action="upload", source=KEYS[0], wasm="artifact.wasm")
        command = ca.command(args)
        self.assertIn("--build-only", command)
        self.assertNotIn("--send=yes", command)
        args.network = "mainnet"
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.command(args)
        args.allow_mainnet = True
        self.assertIn("--build-only", ca.command(args))

    def test_deployment_requires_matching_local_wasm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.wasm"
            path.write_bytes(b"test-wasm")
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            options = SimpleNamespace(action="deploy-parent", network="testnet", allow_mainnet=False, source=KEYS[0],
                wasm=str(path), wasm_hash=expected, owner=KEYS[0], engine_wasm="11" * 32)
            command = ca.command(options)
            self.assertIn("--wasm", command)
            self.assertNotIn("--wasm-hash", command)
            options.wasm_hash = "00" * 32
            with self.assertRaises(ValueError):
                ca.command(options)
            options.wasm = None
            with self.assertRaises(ValueError):
                ca.command(options)

    def test_wallet_constructor_requires_explicit_nonzero_policy_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wallet.wasm"
            path.write_bytes(b"reviewed-artifact")
            asset = StrKey.encode_contract(bytes([2]) * 32)
            engine = StrKey.encode_contract(bytes([3]) * 32)
            values = {"expires_at": 2000000000}
            config = {"owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "asset": asset,
                "source_digest": "22" * 32, "rules": [], "params": values, "x402_enabled": False, "policy_instance": "11" * 32}
            policy = Path(directory) / "policy.rs"
            policy.write_text(source(""))
            args = SimpleNamespace(action="deploy-wallet", network="testnet", allow_mainnet=False, tier="simple", policy_source=str(policy),
                source=KEYS[0], config=json.dumps(config), wasm=str(path), wasm_hash=hashlib.sha256(path.read_bytes()).hexdigest())
            command = ca.command(args)
            self.assertEqual(json.loads(command[command.index("--config") + 1])["policy_instance"], "11" * 32)
            for identity in (None, "", "00" * 32, "not-a-policy-id"):
                config["policy_instance"] = identity
                args.config = json.dumps(config)
                with self.assertRaises(ValueError):
                    ca.command(args)

    def test_owner_packets_bind_rules_derived_from_the_policy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            text = source("    allowit::destinations(ctx, &ctx.params[allowit::DESTINATIONS])?;\n    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;\n")
            policy.write_text(text)
            digest = hashlib.sha256(text.encode()).hexdigest()
            packet = {"rules": ["destinations", "expires_at"], "source_digest": "22" * 32}
            self.assertEqual(ca.policy_rules(packet, "common", str(policy)), packet)
            for tier, rules, source_digest in (("common", ["destinations"], "22" * 32), ("common", ["expires_at", "destinations"], "22" * 32),
                                               ("simple", ["destinations", "expires_at"], "22" * 32), ("custom", [], "22" * 32),
                                               (None, ["destinations", "expires_at"], "22" * 32)):
                with self.assertRaises(ValueError):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": digest}, "custom", str(policy))["rules"], [])
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": "22" * 32}, "simple", str(policy))["rules"], [])
            with self.assertRaises(ValueError):
                ca.policy_rules(packet, "common", None)
            # Simple and Common store only standard state: a policy that writes state needs Custom.
            writer = source(CALL("destinations") + "    allowit::set_state(ctx, \"seen\", 1u64)?;\n")
            # A raw identifier names the same function and compiles on the host.
            raw = source(CALL("destinations") + "    allowit::r#set_state(ctx, \"seen\", 1u64)?;\n")
            for body in (raw, writer):
                policy.write_text(body)
                for tier in ("common", "simple"):
                    rules = ["destinations"] if tier == "common" else []
                    with self.subTest(tier=tier, source=body), self.assertRaisesRegex(ValueError, "set_state"):
                        ca.policy_rules({"rules": rules, "source_digest": "22" * 32}, tier, str(policy))
            writer_digest = hashlib.sha256(writer.encode()).hexdigest()
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": writer_digest}, "custom", str(policy))["rules"], [])
            # Simple and Common admit only canonical params; Custom admits its own keys.
            custom_key = {"rules": [], "source_digest": writer_digest, "params": {"vendor_limit": 5}}
            self.assertEqual(ca.policy_rules(custom_key, "custom", str(policy)), custom_key)
            policy.write_text(text)
            with self.assertRaisesRegex(ValueError, "canonical keys"):
                ca.policy_rules(dict(packet, params={"vendor_limit": 5}), "common", str(policy))
            # The admin packet path applies the same binding.
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expires_at"], "params": {}, "x402_enabled": False, "wasm_hash": None}
            args = SimpleNamespace(action="admin", network="testnet", allow_mainnet=False, source=KEYS[0], family="wallet",
                                   contract=StrKey.encode_contract(bytes([2]) * 32), method="deploy_policy", tier="common",
                                   policy_source=str(policy), arguments=json.dumps({"deployment": deployment}))
            with self.assertRaisesRegex(ValueError, "standard prefix"):
                ca.command(args)
            # Every tier refuses a source that the portable gate rejects.
            policy.write_text(text + "use std::fs;\n")
            other = hashlib.sha256(policy.read_bytes()).hexdigest()
            for tier, rules, source_digest in (("common", ["destinations", "expires_at"], "22" * 32), ("custom", [], other), ("simple", [], "22" * 32)):
                with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "self-contained"):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
            policy.write_text(text)
            # An unset prefix field is valid configuration. Only the standard preflight skips it, so
            # the tooling warns without rejecting.
            deployment["rules"] = ["destinations", "expires_at"]
            args.arguments = json.dumps({"deployment": deployment})
            with patch("sys.stderr", new=StringIO()) as stderr:
                self.assertIn("deploy_policy", ca.command(args))
            self.assertIn("absent: destinations, expires_at", stderr.getvalue())
            deployment["params"] = {"destinations": [KEYS[3]], "expires_at": 2000000000}
            args.arguments = json.dumps({"deployment": deployment})
            with patch("sys.stderr", new=StringIO()) as stderr:
                self.assertIn("deploy_policy", ca.command(args))
            self.assertEqual(stderr.getvalue(), "")

    def test_policy_source_passes_the_std_only_compile_of_the_offchain_server(self):
        call = CALL
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"

            def compiled(text):
                policy.write_text(text)
                ca.host_compile(policy)

            compiled(source(call("destinations") + call("expires_at")))
            # A policy that reaches the Soroban SDK fails the lexical gate and the std-only compile.
            sdk = source("    let e = soroban_sdk::Env::default();\n    let _ = e;\n")
            with self.assertRaisesRegex(ValueError, "self-contained"):
                ca.checked_code(sdk)
            with self.assertRaisesRegex(ValueError, "std-only compile"):
                compiled(sdk)
            # Soroban methods of an aliased environment or an address and std prelude items are
            # off the allowlist.
            for body in ("    let _ = allowit::lifetime_spending_limit(ctx, &ctx.params[allowit::LIFETIME_SPENDING_LIMIT]);\n    let e = &ctx.env;\n"
                         "    e.storage().temporary().has(&0u32);\n",
                         "    ctx.request.recipient.require_auth();\n",
                         "    let _ = Box::new(ctx.request.amount);\n",
                         "    let _ = ctx.request.recipient.to_string();\n"):
                with self.subTest(body=body), self.assertRaisesRegex(ValueError, "allowlist"):
                    ca.checked_code(source(body))
            # Address order passes the allowlist; the std-only compile rejects it, because the
            # host `Address` has no order.
            for body in ("    if ctx.request.asset < ctx.request.recipient {\n        return Err(AllowitError::DestinationNotAllowed);\n    }\n",
                         "    let _ = ctx.request.asset.clone().max(ctx.request.recipient.clone());\n"):
                text = source(body)
                with self.subTest(body=body):
                    ca.checked_code(text)
                    with self.assertRaisesRegex(ValueError, "std-only compile"):
                        compiled(text)
            # A loop over a list binds owned items, as the onchain `Vec` does, also when the list
            # borrows from `ctx.params[key]`, so a dereference fails. The crate doc tests of
            # `allowit` build the same loops onchain.
            loops = (
                ("item", "    let wanted = AllowitValue::Addr(ctx.request.recipient.clone());\n"
                         '    if let AllowitValue::List(items) = &ctx.params["vendors"] {{\n'
                         "        for item in items {{\n            if {} == wanted {{\n"
                         "                return Ok(());\n            }}\n        }}\n    }}\n"),
                ("vendor", '    let vendors: Vec<Address> = allowit::param(ctx, "vendors");\n'
                           "    for vendor in &vendors {{\n        if {} == ctx.request.recipient {{\n"
                           "            return Ok(());\n        }}\n    }}\n"),
            )
            for name, body in loops:
                with self.subTest(body=body):
                    compiled(source(body.format(name)))
                    text = source(body.format("*" + name))
                    ca.checked_code(text)
                    with self.assertRaisesRegex(ValueError, "std-only compile"):
                        compiled(text)
            # The owner packet path of every tier runs the same compile.
            policy.write_text(source("    let _ = ctx.request.asset < ctx.request.recipient;\n"))
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            for tier, rules, source_digest in (("common", [], "22" * 32), ("custom", [], digest), ("simple", [], "22" * 32)):
                with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "std-only compile"):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))

    def test_checker_enums_name_every_core_variant(self):
        import re
        import policy_source
        from core_sources import core_root
        core = (core_root() / "crates/allowit-core/src/portable/core.rs").read_text()
        for enum, variants in policy_source.ENUMS.items():
            body = re.search(r"pub enum " + enum + r" \{(.*?)\n\s*\}", core, re.S)
            self.assertIsNotNone(body, enum)
            names = re.findall(r"^\s*([A-Za-z_]\w*)\s*(?:[(,=]|$)", re.sub(r"\s*//.*", "", body.group(1)), re.M)
            with self.subTest(enum=enum):
                self.assertEqual(tuple(names), variants)

    def test_wallet_code_changes_require_custody_layout_3(self):
        self.assertEqual(ca.custody_layout(meta_wasm((b"rsver", b"1.98.0"), (ca.CUSTODY_LAYOUT_KEY, b"3"))), 3)
        # The version 1 release declares only SDK metadata.
        self.assertIsNone(ca.custody_layout(meta_wasm((b"rsver", b"1.98.0"))))
        self.assertIsNone(ca.custody_layout(b"\0asm\x01\0\0\0"))
        for invalid in (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"2"), (ca.CUSTODY_LAYOUT_KEY, b"2")),
                        meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"02")), meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"x")),
                        meta_wasm((b"rsver", b"1"))[:-2], b"not-wasm"):
            with self.subTest(wasm=invalid), self.assertRaises(ValueError):
                ca.custody_layout(invalid)
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(source("    allowit::expires_at(ctx, &ctx.params[allowit::EXPIRES_AT])?;\n"))
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expires_at"], "params": {}, "x402_enabled": False, "wasm_hash": None}
            args = SimpleNamespace(action="admin", network="testnet", allow_mainnet=False, source=KEYS[0], family="wallet",
                                   contract=StrKey.encode_contract(bytes([2]) * 32), method="deploy_policy", tier="common",
                                   policy_source=str(policy), wasm=None)

            def prepare(wasm_bytes, wasm_hash=None):
                path = Path(directory) / "wallet.wasm"
                path.write_bytes(wasm_bytes)
                deployment["wasm_hash"] = wasm_hash or hashlib.sha256(wasm_bytes).hexdigest()
                args.wasm, args.arguments = str(path), json.dumps({"deployment": deployment})
                return ca.command(args)

            self.assertIn("deploy_policy", prepare(meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"4"))))
            # The releases of layouts 1 to 3, a future layout and an unpinned file reject.
            for wasm_bytes, wasm_hash in ((meta_wasm((b"rsver", b"1.98.0")), None), (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"1")), None),
                                          (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"3")), None), (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"5")), None),
                                          (meta_wasm((ca.CUSTODY_LAYOUT_KEY, b"4")), "11" * 32)):
                with self.subTest(wasm=wasm_bytes), self.assertRaises(ValueError):
                    prepare(wasm_bytes, wasm_hash)
            args.wasm = None
            with self.assertRaisesRegex(ValueError, "--wasm"):
                ca.command(args)
            # Unchanged code needs no Wasm.
            deployment["wasm_hash"] = None
            args.arguments = json.dumps({"deployment": deployment})
            self.assertIn("deploy_policy", ca.command(args))

    @unittest.skipUnless((ROOT / "target/wasm32v1-none/release/allowit_common_policy_engine.wasm").exists(), "contracts not built")
    def test_built_wallet_wasm_declares_the_current_custody_layout(self):
        for name in ("simple_policy_engine", "common_policy_engine", "custom_policy"):
            wasm = (ROOT / "target/wasm32v1-none/release" / ("allowit_" + name + ".wasm")).read_bytes()
            self.assertEqual(ca.custody_layout(wasm), ca.WALLET_CONTRACT_VERSION)
        self.assertIsNone(ca.custody_layout((ROOT / "target/wasm32v1-none/release/allowit_wallet_engine.wasm").read_bytes()))

    def test_secrets_and_hashes_reject(self):
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.account("owner-key-alias")
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.code_hash("123")
        self.assertEqual(ca.serialize({"paused": False}), ["--paused", "false"])


if __name__ == "__main__":
    unittest.main()
