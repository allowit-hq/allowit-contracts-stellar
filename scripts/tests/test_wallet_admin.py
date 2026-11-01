import copy
import argparse
import subprocess
from io import BytesIO, StringIO
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
from stellar_sdk import Keypair, TransactionEnvelope, Account, TransactionBuilder, Address, StrKey, xdr, scval

KEYS = [Keypair.from_raw_ed25519_seed(bytes([n]) * 32).public_key for n in range(1, 6)]
ROOT = Path(__file__).resolve().parents[2]
HEAD = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n"


def source(body, head=HEAD):
    return head + body + "    Ok(())\n}\n"


def CALL(rule):
    """One canonical prefix statement: the rule on its own canonical param key."""
    return "    allowit::{0}(ctx, ctx.params.get(allowit::{1}))?;\n".format(rule, rule.upper())


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

    def test_setup_unsigned_atomic_exact(self):
        envelope = wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], now=1000)
        tx = TransactionEnvelope.from_xdr(envelope.to_xdr(), wa.PASSPHRASE["testnet"])
        self.assertEqual(tx.signatures, [])
        self.assertEqual(tx.transaction.sequence, 43)
        self.assertEqual(tx.transaction.fee, 300)
        self.assertEqual(tx.transaction.preconditions.time_bounds.min_time, 0)
        self.assertEqual(tx.transaction.preconditions.time_bounds.max_time, 1300)
        ops = tx.transaction.operations
        self.assertEqual(len(ops), 3)
        self.assertEqual(ops[0].signer, wa.Signer.ed25519_public_key(KEYS[1], 1))
        self.assertEqual(ops[1].signer, wa.Signer.ed25519_public_key(KEYS[2], 1))
        self.assertEqual((ops[2].master_weight, ops[2].low_threshold, ops[2].med_threshold, ops[2].high_threshold), (3, 2, 2, 3))
        self.assertTrue(all(op.source is None for op in ops))

    def test_setup_rejects_existing_authority(self):
        for malformed in ("threshold", "signer", "preauth", "duplicate"):
            value = state()
            if malformed == "threshold":
                value["thresholds"]["high_threshold"] = 1
            else:
                extra = {"key": KEYS[3], "weight": 1, "type": "ed25519_public_key"}
                if malformed == "preauth":
                    extra["type"] = "preauth_tx"
                if malformed == "duplicate":
                    extra["key"] = KEYS[0]
                value["signers"].append(extra)
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                wa.prepare(value, "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2])

    def test_shutdown_removes_both_and_raises_thresholds(self):
        value = state()
        value["signers"][0]["weight"] = 3
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        wa.wallet(value, KEYS[1], KEYS[2])
        tx = wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2])
        self.assertEqual([op.signer.weight for op in tx.transaction.operations[:2]], [0, 0])
        self.assertEqual(tx.transaction.operations[-1].med_threshold, 3)
        value["signers"].append({"key": KEYS[4], "weight": 1, "type": "ed25519_public_key"})
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.wallet(value, KEYS[1], KEYS[2])

    def test_shutdown_separate_sequence_and_operation_source(self):
        value = state()
        value["signers"][0]["weight"] = 3
        value["signers"] += [{"key": k, "weight": 1, "type": "ed25519_public_key"} for k in KEYS[1:3]]
        value["thresholds"] = dict(zip(("low_threshold", "med_threshold", "high_threshold"), (2, 2, 3)))
        fee_source = state()
        fee_source["account_id"] = KEYS[4]
        fee_source["sequence"] = "100"
        fee_source["signers"][0]["key"] = KEYS[4]
        tx = wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], source_state=fee_source)
        self.assertEqual(tx.transaction.source.account_id, KEYS[4])
        self.assertEqual(tx.transaction.sequence, 101)
        self.assertTrue(all(op.source.account_id == KEYS[0] for op in tx.transaction.operations))
        for delegated in KEYS[1:3]:
            fee_source["account_id"] = delegated
            fee_source["signers"][0]["key"] = delegated
            with self.assertRaises(ValueError):
                wa.prepare(value, "shutdown-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], source_state=fee_source)

    def test_offer_admission(self):
        for records in ([], [{"id": "1"}]):
            payload = json.dumps({"_embedded": {"records": records}}).encode()
            with patch.object(wa, "urlopen", return_value=BytesIO(payload)):
                if records:
                    with self.assertRaises(ValueError):
                        wa.no_offers("testnet", KEYS[0])
                else:
                    wa.no_offers("testnet", KEYS[0])
            if records:
                with patch.object(wa, "urlopen", return_value=BytesIO(payload)), patch.object(sys, "stderr", new_callable=StringIO) as warnings:
                    wa.no_offers("testnet", KEYS[0], reject=False)
                    self.assertIn("Revoke signers first", warnings.getvalue())

    def test_admin_distinct_master_disabled(self):
        tx = wa.prepare(state(), "setup-admin", "testnet", members=KEYS[1:4])
        self.assertEqual(len(tx.transaction.operations), 4)
        last = tx.transaction.operations[-1]
        self.assertEqual((last.master_weight, last.low_threshold, last.med_threshold, last.high_threshold), (0, 2, 2, 2))
        tx2 = wa.prepare(state(), "setup-admin", "testnet", members=KEYS[:3])
        self.assertEqual(tx2.transaction.operations[-1].master_weight, 1)
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-admin", "testnet", members=[KEYS[1]] * 3)

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

    def test_bad_identity_and_fee(self):
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[0], engine=KEYS[2])
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            wa.prepare(state(), "setup-wallet", "testnet", agent=KEYS[1], engine=KEYS[2], fee=1_000_000)


class ContractAdmin(unittest.TestCase):
    def test_exact_allowlist_and_types(self):
        self.assertEqual(ca.checked_args("set_pause", {"paused": True, "deployment_version": 3}, "wallet")["paused"], True)
        for value in ({"paused": "false", "deployment_version": 3}, {"paused": True, "deployment_version": True}, {"paused": True, "deployment_version": 3, "target": KEYS[1]}):
            with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                ca.checked_args("set_pause", value, "wallet")
        self.assertNotIn("transfer", ca.WALLET)
        self.assertNotIn("approve", ca.WALLET)
        self.assertNotIn("set_params", ca.PARENT)

    def test_params_encode_typed_values_and_standard_tiers_admit_only_canonical_keys(self):
        values = {"spent_cap": 2**127 - 1, "call_cap": 0, "recipients": [KEYS[1]], "tokens": []}
        self.assertEqual(ca.params(values, "common"), {"spent_cap": {"Int": str(2**127 - 1)}, "call_cap": {"Int": "0"},
                                                       "recipients": {"List": [{"Addr": KEYS[1]}]}, "tokens": {"List": []}})
        self.assertEqual(ca.params({}, "simple"), {})
        tagged = json.loads(ca.serialize({"deployment": {"params": values}})[1])["params"]
        self.assertEqual(tagged["spent_cap"], {"Int": str(2**127 - 1)})
        self.assertNotIn("expiry", tagged)
        # Custom params: inferred or explicitly typed values within the contract's bounds.
        custom = {"vendor_cap": -5, "note": "pay invoices", "vendor": KEYS[2], "as_text": {"Str": KEYS[2]}, "urgent": True,
                  "pairs": [[1, KEYS[1]]]}
        self.assertEqual(ca.params(custom, "custom"), {"vendor_cap": {"Int": "-5"}, "note": {"Str": "pay invoices"},
                                                        "vendor": {"Addr": KEYS[2]}, "as_text": {"Str": KEYS[2]},
                                                        "urgent": {"Bool": True}, "pairs": {"List": [{"List": [{"Int": "1"}, {"Addr": KEYS[1]}]}]}})
        for invalid in ({"per_transfer": 1}, {"max_calls": 1}, {"vendor_cap": 1}, {"spent_cap": -1}, {"spent_cap": 2**127},
                        {"call_cap": 2**64}, {"expiry": True}, {"transaction_cap": "1"}, {"recipients": KEYS[1]},
                        {"tokens": ["not-an-address"]}, {"recipients": [[KEYS[1]]]}):
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
        full = {key: 0 for key in ca.PARAM_KEYS} | {"recipients": [KEYS[1]] * 64, "tokens": [KEYS[2]] * 64,
                                                    "operations": ["custom:C" + "A" * 55 + "." + "f" * 32] * 28}
        self.assertEqual(len(ca.params(full, "common")), 9)
        with self.assertRaisesRegex(ValueError, "16384 bytes"):
            ca.params(dict(full, operations=full["operations"] * 2), "common")
        # The count error names the limit of the tier.
        for tier, limit in (("common", 9), ("simple", 9), ("custom", 32)):
            with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "at most {} keys".format(limit)):
                ca.params({"k" + str(i): i for i in range(limit + 1)}, tier)
        deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                      "rules": ["spent_cap", "recipients"], "params": values, "x402_enabled": False, "wasm_hash": None}
        ca.deployment(deployment)
        for removed in ("set_cap_per_day", "cap_per_transaction", "require_recipient", "require_asset", "allow_actions", "state_remove", "fail", "daily_cap"):
            with self.assertRaises(ValueError):
                ca.deployment(dict(deployment, rules=[removed]))
        with self.assertRaises(ValueError):
            ca.public_json('{"custom":1,"custom":2}')
        # Owner packets encode the current layout only; earlier and later layouts are refused.
        self.assertEqual(ca.wallet_layout({"contract_version": 4})["contract_version"], 4)
        for state in ({"contract_version": 1}, {"contract_version": 3}, {"contract_version": 5}, {}):
            with self.assertRaisesRegex(ValueError, "layout"):
                ca.wallet_layout(state)

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

    def test_cli_address_errors_do_not_echo_input(self):
        scripts = Path(__file__).resolve().parents[1]
        invalid_input = "invalid-private-input-for-test"
        cases = [
            ("wallet_admin.py", ["inspect", "--account", invalid_input]),
            ("wallet_admin.py", ["setup-wallet", "--account", KEYS[0], "--agent", invalid_input]),
            ("wallet_admin.py", ["setup-admin", "--account", KEYS[0], "--member", invalid_input]),
            ("contract_admin.py", ["read", "--source", invalid_input]),
            ("contract_admin.py", ["deploy-parent", "--source", KEYS[0], "--member", invalid_input]),
        ]
        for script, arguments in cases:
            result = subprocess.run([sys.executable, str(scripts / script)] + arguments, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(invalid_input, result.stdout + result.stderr)
            self.assertIn("Expected a public Stellar G address", result.stderr)

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

    def test_parent_arguments_use_owner_and_version(self):
        values = {"owner": KEYS[1], "version": 0}
        self.assertEqual(ca.checked_args("set_admin", values, "parent"), values)
        for old in ({"new_admin": KEYS[1], "expected_revision": 0},
                    {"owner": KEYS[1], "version": -1},
                    {"owner": KEYS[1], "version": 2**64}):
            with self.assertRaises(ValueError):
                ca.checked_args("set_admin", old, "parent")

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
            values = {"expiry": 2000000000}
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

    def test_standard_prefix_is_derived_from_policy_source_statements(self):
        sample = (ROOT / "crates/custom-policy/policy/policy.rs").read_text()
        self.assertEqual(ca.standard_prefix(sample), list(ca.PARAM_KEYS))
        call = CALL
        vectors = [
            # A rule that reads another key ends the prefix; later calls run offchain or in Custom.
            (call("recipients") + "    allowit::spent_cap(ctx, ctx.params.get(allowit::DAY_SPENT_CAP))?;\n" + call("expiry"), ["recipients"]),
            (call("recipients") + "    allowit::spent_cap(ctx, ctx.params.get(\"vendor_cap\"))?;\n" + call("expiry"), ["recipients"]),
            # Statements, not lines: a split call, two calls on one line and comments.
            ("    allowit::spent_cap(\n        ctx,\n        ctx.params.get(allowit::SPENT_CAP),\n    )?;\n" + call("expiry").rstrip() + call("tokens"), ["spent_cap", "expiry", "tokens"]),
            ("    allowit::spent_cap(\n        ctx,\n        ctx.params.get(\n            allowit::SPENT_CAP,\n        ),\n    )?;\n", ["spent_cap"]),
            ("    // limits\n" + call("call_cap") + "    /* then */ " + call("call_cap"), ["call_cap", "call_cap"]),
            # Any other statement ends the prefix.
            ("    let left = allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;\n" + call("expiry"), []),
            (call("expiry") + "    if ctx.request.operation == AllowitOperation::deposit {\n" + call("spent_cap") + "    }\n", ["expiry"]),
            (call("expiry") + "    allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP));\n" + call("tokens"), ["expiry"]),
        ]
        for body, expected in vectors:
            with self.subTest(body=body):
                self.assertEqual(ca.standard_prefix(source(body)), expected)
        # Removed rule names are not on the allowlist.
        for name in ("set_cap_per_day", "cap_per_transaction", "require_recipient", "require_asset", "allow_actions", "state_remove", "fail"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "allowlist"):
                ca.standard_prefix(source(call(name) + call("expiry")))
        explicit = HEAD.replace("allowit::Result {", "allowit::Result<()> {")
        self.assertEqual(ca.standard_prefix(source(call("tokens"), explicit)), ["tokens"])
        # Calls in other functions are not part of execute.
        helper = "fn helper(ctx: &AllowitContext) -> allowit::Result {\n" + call("tokens") + "    Ok(())\n}\n"
        self.assertEqual(ca.standard_prefix(helper + source(call("expiry"))), ["expiry"])
        for invalid in (helper, source("") + source("")):
            with self.assertRaisesRegex(ValueError, "execute"):
                ca.standard_prefix(invalid)

    def test_standard_prefix_lexes_comments_and_literals_like_rust(self):
        call = CALL
        # Block comments nest: the whole span is a comment, so recipients runs first.
        nested = "    /* outer /* inner */ allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?; */\n" + call("recipients")
        self.assertEqual(ca.standard_prefix(source(nested)), ["recipients"])
        # Literals cannot add, hide or end calls; a quote char and lifetimes are not strings.
        helper = "fn quote<'a>(x: &'a str) -> char { let _ = x; '\"' }\nconst C: char = '\\'';\n"
        raw = 'const R: &str = r#"*/ /* "quoted" "#;\nconst B: &[u8] = b"//";\n'
        self.assertEqual(ca.standard_prefix(helper + raw + source(call("expiry") + "    let s = \"/*\";\n" + call("tokens"))), ["expiry"])
        self.assertEqual(ca.standard_prefix(helper + source("    // \" /*\n" + call("expiry"))), ["expiry"])
        # A header inside a literal is not code. With the real header in prelude form, none matches.
        fake = 'const S: &str = "pub fn execute(ctx: &AllowitContext) -> allowit::Result { ' + call("spent_cap").strip() + '";\n'
        for invalid in (fake + source(call("recipients"), HEAD.replace("allowit::Result {", "Result {")),
                        fake.replace('"', "r#\"", 1).replace('";', '"#;') + source("", HEAD.replace("allowit::Result {", "Result {")),
                        "/* pub fn execute(ctx: &AllowitContext) -> allowit::Result {\n" + call("spent_cap") + "*/\npub fn r#execute(ctx: &AllowitContext) -> Result {\n    Ok(())\n}\n",
                        source(call("expiry")) + "pub use execute as r#execute;\n"):
            with self.subTest(source=invalid), self.assertRaisesRegex(ValueError, "execute"):
                ca.standard_prefix(invalid)
        for unterminated in ("/* /* */", 'const S: &str = "', 'const R: &str = r#"x"'):
            with self.subTest(source=unterminated), self.assertRaisesRegex(ValueError, "unterminated"):
                ca.standard_prefix(source(call("expiry")) + unterminated)

    def test_owner_packets_bind_rules_derived_from_the_policy_source(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            text = source("    allowit::recipients(ctx, ctx.params.get(allowit::RECIPIENTS))?;\n    allowit::expiry(ctx, ctx.params.get(allowit::EXPIRY))?;\n")
            policy.write_text(text)
            digest = hashlib.sha256(text.encode()).hexdigest()
            packet = {"rules": ["recipients", "expiry"], "source_digest": "22" * 32}
            self.assertEqual(ca.policy_rules(packet, "common", str(policy)), packet)
            for tier, rules, source_digest in (("common", ["recipients"], "22" * 32), ("common", ["expiry", "recipients"], "22" * 32),
                                               ("simple", ["recipients", "expiry"], "22" * 32), ("custom", [], "22" * 32),
                                               (None, ["recipients", "expiry"], "22" * 32)):
                with self.assertRaises(ValueError):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": digest}, "custom", str(policy))["rules"], [])
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": "22" * 32}, "simple", str(policy))["rules"], [])
            with self.assertRaises(ValueError):
                ca.policy_rules(packet, "common", None)
            # Simple and Common store only standard state: a policy that writes state needs Custom.
            writer = source(CALL("recipients") + "    allowit::set_state(ctx, \"seen\", 1u64)?;\n")
            # A raw identifier names the same function and compiles on the host.
            raw = source(CALL("recipients") + "    allowit::r#set_state(ctx, \"seen\", 1u64)?;\n")
            for body in (raw, writer):
                policy.write_text(body)
                for tier in ("common", "simple"):
                    rules = ["recipients"] if tier == "common" else []
                    with self.subTest(tier=tier, source=body), self.assertRaisesRegex(ValueError, "set_state"):
                        ca.policy_rules({"rules": rules, "source_digest": "22" * 32}, tier, str(policy))
            writer_digest = hashlib.sha256(writer.encode()).hexdigest()
            self.assertEqual(ca.policy_rules({"rules": [], "source_digest": writer_digest}, "custom", str(policy))["rules"], [])
            # Simple and Common admit only canonical params; Custom admits its own keys.
            custom_key = {"rules": [], "source_digest": writer_digest, "params": {"vendor_cap": 5}}
            self.assertEqual(ca.policy_rules(custom_key, "custom", str(policy)), custom_key)
            policy.write_text(text)
            with self.assertRaisesRegex(ValueError, "canonical keys"):
                ca.policy_rules(dict(packet, params={"vendor_cap": 5}), "common", str(policy))
            # The admin packet path applies the same binding.
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expiry"], "params": {}, "x402_enabled": False, "wasm_hash": None}
            args = SimpleNamespace(action="admin", network="testnet", allow_mainnet=False, source=KEYS[0], family="wallet",
                                   contract=StrKey.encode_contract(bytes([2]) * 32), method="deploy_policy", tier="common",
                                   policy_source=str(policy), arguments=json.dumps({"deployment": deployment}))
            with self.assertRaisesRegex(ValueError, "standard prefix"):
                ca.command(args)
            # An unset prefix field is valid configuration. Only the standard preflight skips it, so
            # the tooling warns without rejecting.
            deployment["rules"] = ["recipients", "expiry"]
            args.arguments = json.dumps({"deployment": deployment})
            with patch("sys.stderr", new=StringIO()) as stderr:
                self.assertIn("deploy_policy", ca.command(args))
            self.assertIn("absent: recipients, expiry", stderr.getvalue())
            deployment["params"] = {"recipients": [KEYS[3]], "expiry": 2000000000}
            args.arguments = json.dumps({"deployment": deployment})
            with patch("sys.stderr", new=StringIO()) as stderr:
                self.assertIn("deploy_policy", ca.command(args))
            self.assertEqual(stderr.getvalue(), "")

    def test_policy_source_cannot_rebind_allowit(self):
        call = CALL
        body = call("recipients") + call("expiry")
        self.assertEqual(ca.standard_prefix(source(body)), ["recipients", "expiry"])
        # A local `allowit` would make the trusted prefix call a different function.
        fake = "pub fn recipients(_: &AllowitContext, _: &Option<()>) -> allowit::Result<()> { Ok(()) }"
        rebinds = (
            "mod allowit { " + fake + " }\n",
            "pub mod allowit {}\n",
            "mod r#allowit {}\n",
            "use core as allowit;\n",
            "use core::{self as allowit};\n",
            "use self::inner::allowit;\n",
            "use inner::{allowit, other};\n",
            "extern crate core as allowit;\n",
            "macro_rules! allowit { () => {} }\n",
            "fn allowit() {}\n",
            "struct allowit;\n",
            "enum allowit {}\n",
            "trait allowit {}\n",
            "type allowit = u8;\n",
            "const allowit: u8 = 0;\n",
            "static allowit: u8 = 0;\n",
            "macro_rules! m { ($i:ident) => { mod $i {} } }\nm!(allowit);\n",
        )
        for rebind in rebinds:
            for text in (rebind + source(body), source(body) + rebind):
                with self.subTest(source=text), self.assertRaisesRegex(ValueError, "rebind"):
                    ca.standard_prefix(text)
        # Inside execute too, and through the owner packet path of every tier.
        with self.assertRaisesRegex(ValueError, "rebind"):
            ca.standard_prefix(source("    let allowit = 0;\n" + body))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(rebinds[0] + source(body))
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            for tier, rules, source_digest in (("common", ["recipients", "expiry"], "22" * 32), ("custom", [], digest), ("simple", [], "22" * 32)):
                with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "rebind"):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
        # Comments, literals and longer identifiers are not bindings.
        allowed = '// mod allowit {}\nconst S: &str = "use x as allowit;";\nfn allowit_helper() {}\n'
        self.assertEqual(ca.standard_prefix(allowed + source(body)), ["recipients", "expiry"])

    def test_policy_source_is_one_self_contained_file(self):
        call = CALL
        body = call("expiry")
        outside = (
            'include!("more.rs");\n',
            'const S: &str = include_str!("secret.txt");\n',
            'const B: &[u8] = core::include_bytes!("data.bin");\n',
            'const E: &str = env!("HOME");\n',
            'const O: Option<&str> = option_env!("POLICY");\n',
            "use core::include as inline;\n",
            "use core::env as e;\n",
            'const E: &str = core::env!("HOME");\n',
            'fn g() -> usize { (0..env!("HOME").len()).count() }\n',
            'fn g(c: &AllowitContext) { let env = c.env.clone(); }\n',
            "fn g() { let AllowitContext { env, .. } = todo!(); }\n",
            '#[path = "other.rs"]\nmod other {}\n',
            '#[cfg_attr(all(), path = "other.rs")]\nmod other {}\n',
            "mod other;\n",
            "pub(crate) mod r#other ;\n",
            "macro_rules! m { ($i:ident) => { mod $i; } }\n",
            "extern crate core;\n",
            # Code that can behave differently in `AllowitCustomPolicy` and on the host.
            'const W: bool = cfg!(target_family = "wasm");\n',
            '#[cfg(target_family = "wasm")]\nconst W: bool = true;\n',
            "#[ cfg (test)]\nfn t() {}\n",
            "const M: &str = module_path!();\n",
            "const F: &str = file ! ();\n",
            "fn n() -> &'static str { core::any::type_name::<AllowitContext>() }\n",
            "fn n(c: &AllowitContext) -> &str { core::any::type_name_of_val(c) }\n",
            "use core::any::type_name as n;\n",
            # Paths into the including crate, and global paths.
            "const H: [u8; 32] = super::SOURCE_HASH;\n",
            "use crate::policy as p;\n",
            "fn s() -> u8 { self :: inner() }\n",
            "macro_rules! m { () => { $crate::x } }\n",
            "const N: u32 = ::core::u32::MAX;\n",
            "fn g(x: ::core::primitive::u8) {}\n",
            "fn g() -> u8 { (|| ::core::primitive::u8::MAX)() }\n",
            "use ::core::mem as m;\n",
            "fn g() -> Result<(), ()> { return ::core::result::Result::Ok(()); }\n",
            "fn g(x: u8) -> u8 { match x { _ => ::core::primitive::u8::MAX } }\n",
            "fn g() -> u8 { if true { 0 } else { ::core::primitive::u8::MAX } }\n",
            "fn g() { for _ in ::core::iter::empty::<u8>() {} }\n",
            "fn g(x: u16) -> u8 { x as ::core::primitive::u8 }\n",
            "fn g() -> u8 { let x = ::core::primitive::u8::MAX; x }\n",
            "fn g() -> u8 { loop { break ::core::primitive::u8::MAX; } }\n",
            "fn g() -> bool { true && ::core::primitive::bool::default() }\n",
            # Location, width, type, layout and pointer introspection that differs between the backends.
            "fn g() -> u32 { core::panic::Location::caller().line() }\n",
            "use core::panic::Location as L;\nfn g() -> u32 { L::caller().line() }\n",
            "const W: usize = core::mem::size_of::<usize>();\n",
            "fn g(c: &AllowitContext) -> u64 { core::mem::size_of_val(&c.request) as u64 }\n",
            "fn g() -> u64 { core::mem::align_of::<Address>() as u64 }\n",
            "const W: u32 = usize::BITS;\n",
            "const W: u32 = u32::BITS;\n",
            "const W: u64 = usize::MAX as u64;\n",
            "fn g(x: isize) -> bool { x > 0 }\n",
            "fn g() -> bool { core::any::TypeId::of::<AllowitContext>() == core::any::TypeId::of::<u8>() }\n",
            "fn g(c: &AllowitContext) -> bool { core::any::Any::type_id(&c.state) == core::any::Any::type_id(&0u8) }\n",
            "fn g() -> bool { core::mem::needs_drop::<Address>() }\n",
            "use core::mem::needs_drop as n;\nfn g() -> bool { n::<Address>() }\n",
            "fn g() -> u64 { core::alloc::Layout::new::<Address>().size() as u64 }\n",
            "fn g() -> u64 { core::mem::offset_of!(AllowitRequest, amount) as u64 }\n",
            "fn g(x: &u8) -> bool { (x as *const u8).is_null() }\n",
            "fn g(x: &[u8]) -> bool { x.as_ptr().addr() > 0 }\n",
            "fn g(x: &u8) -> bool { core::ptr::addr_of!(*x).is_aligned() }\n",
            # Formatting exposes backend Debug output, and pointer formatting exposes addresses.
            "fn g(w: &mut dyn core::fmt::Write, c: &AllowitContext) { let _ = write!(w, \"{:?}\", c.request.asset); }\n",
            "fn g(c: &AllowitContext) { let _ = format_args!(\"{:p}\", c); }\n",
            # Debug-only assertions run in the plain-rustc smoke and native tests, not in release Wasm.
            "fn g(c: &AllowitContext) { debug_assert!(c.request.amount > 0); }\n",
            "fn g(c: &AllowitContext) { debug_assert_eq!(c.request.amount, 1); }\n",
            "fn g(c: &AllowitContext) { debug_assert_ne!(c.request.amount, 1); }\n",
            # Mutable statics keep values across host evaluations and start again in every contract instance.
            "static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);\n",
            "fn g() -> u32 { static N: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0); N.fetch_add(1, core::sync::atomic::Ordering::Relaxed) }\n",
            # Soroban-only calls through the environment: methods of ctx.env and of values.
            "fn g(ctx: &AllowitContext) { ctx.env.storage().temporary().remove(&0u32); }\n",
            "fn g(ctx: &AllowitContext) -> u32 { ctx . env . ledger().sequence() }\n",
            "fn g(ctx: &AllowitContext) { let _ = ctx.request.asset.env(); }\n",
            "fn g(ctx: &AllowitContext) { let _ = ctx.request.asset.env (); }\n",
            # Dependencies of the including crate, host functions and assembled paths.
            "fn g() { let e = soroban_sdk::Env::default(); e.storage().instance().set(&1u32, &1u32); }\n",
            "fn g() { <soroban_sdk::Env>::default(); }\n",
            "fn g() { r#soroban_sdk::Env::default(); }\n",
            "use soroban_sdk as Sdk;\n",
            "use {soroban_sdk::Env};\n",
            "fn g() { allowit_policy_wallet::policy_wallet(); }\n",
            "fn g() { std::process::exit(0) }\n",
            "fn g() { alloc::vec::Vec::<u8>::new(); }\n",
            "mod helpers { pub fn one() {} }\nfn g() { helpers::one() }\n",
            'unsafe extern "C" { fn put(k: u64) -> u64; }\n',
            "fn g() { unsafe { core::hint::unreachable_unchecked() } }\n",
            "macro_rules! m { ($($x:ident),*) => { $($x)::*::default() } }\n",
        )
        for code in outside:
            for text in (code + source(body), source(body) + code):
                with self.subTest(source=text), self.assertRaisesRegex(ValueError, "self-contained"):
                    ca.standard_prefix(text)
        with self.assertRaisesRegex(ValueError, "self-contained"):
            ca.standard_prefix(source('    let _ = include_str!("x");\n' + body))
        for inner in ("#![allow(unused)]\n", "# ! [allow(unused)]\n", "//! Policy\n", "/*! Policy */\n"):
            with self.subTest(source=inner), self.assertRaisesRegex(ValueError, "inner"):
                ca.standard_prefix(inner + source(body))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(source(body) + outside[0])
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "self-contained"):
                ca.policy_rules({"rules": [], "source_digest": digest}, "custom", str(policy))
        # Helper functions, constants and mentions in comments or literals stay valid.
        allowed = ('fn one() -> u8 { 1 }\n// include!("x")\nconst S: &str = "mod other;";\n'
                   "const T: &str = \"crate::x cfg!(test) ::core\";\npub fn two() -> u8 { one() + 2 }\n"
                   "fn three(file: u8, x: u8) -> u8 { u8::from(true) + file + x }\n"
                   "fn four(x: i128) -> i128 { x.saturating_add(i128::MAX.min(0)) + Option::None.unwrap_or(0) }\n"
                   "use allowit::{AllowitError, DAY};\nfn five() -> AllowitError { AllowitError::MissingParam }\n"
                   "const LIMIT: u64 = DAY * 2;\n"
                   "fn six(ctx: &AllowitContext) -> AllowitContext { let c = &ctx . env; let _ = c; ctx.clone() }\n"
                   "fn seven<'a>(x: &'static str, y: &'a str) -> bool { x != y && 0u32 != 1 && LIMIT > 1 }\n")
        self.assertEqual(ca.standard_prefix(allowed + source(body)), ["expiry"])
        # The `AllowitCustomPolicy` sources pass the same check.
        for path in ("crates/custom-policy/policy/policy.rs", "crates/custom-policy/src/branch_policy.rs",
                     "crates/custom-policy/src/catching_policy.rs"):
            ca.checked_code((ROOT / path).read_text())
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check-policy-bindings.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_policy_source_passes_the_std_only_compile_of_the_offchain_server(self):
        call = CALL
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"

            def compiled(text):
                policy.write_text(text)
                ca.host_compile(policy)

            compiled(source(call("recipients") + call("expiry")))
            # A policy that reaches the Soroban SDK fails the lexical gate and the std-only compile.
            sdk = source("    let e = soroban_sdk::Env::default();\n    let _ = e;\n")
            with self.assertRaisesRegex(ValueError, "self-contained"):
                ca.checked_code(sdk)
            with self.assertRaisesRegex(ValueError, "std-only compile"):
                compiled(sdk)
            # Soroban methods of an aliased environment or an address and std prelude items are
            # off the allowlist.
            for body in ("    let _ = allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP));\n    let e = &ctx.env;\n"
                         "    e.storage().temporary().has(&0u32);\n",
                         "    ctx.request.recipient.require_auth();\n",
                         "    let _ = Box::new(ctx.request.amount);\n",
                         "    let _ = ctx.request.recipient.to_string();\n"):
                with self.subTest(body=body), self.assertRaisesRegex(ValueError, "allowlist"):
                    ca.checked_code(source(body))
            # Address order passes the allowlist; the std-only compile rejects it, because the
            # host `Address` has no order.
            for body in ("    if ctx.request.asset < ctx.request.recipient {\n        return Err(AllowitError::RecipientNotAllowed);\n    }\n",
                         "    let _ = ctx.request.asset.clone().max(ctx.request.recipient.clone());\n"):
                text = source(body)
                with self.subTest(body=body):
                    ca.checked_code(text)
                    with self.assertRaisesRegex(ValueError, "std-only compile"):
                        compiled(text)
            # The owner packet path of every tier runs the same compile.
            policy.write_text(source("    let _ = ctx.request.asset < ctx.request.recipient;\n"))
            digest = hashlib.sha256(policy.read_bytes()).hexdigest()
            for tier, rules, source_digest in (("common", [], "22" * 32), ("custom", [], digest), ("simple", [], "22" * 32)):
                with self.subTest(tier=tier), self.assertRaisesRegex(ValueError, "std-only compile"):
                    ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))

    def test_policy_source_rejects_code_that_diverges_between_backends(self):
        call = CALL
        head = HEAD + call("recipients")
        diverging = (
            # Native code that runs inside the offchain evaluator process before `main`.
            'core::arch::global_asm!(".section __DATA,__mod_init_func", ".quad _p", "_p:", "mov x0, #42", "bl _exit");\n',
            'fn g() { core::arch::asm!("nop"); }\n',
            "use core::arch::global_asm as assert;\n",
            'use core::arch::global_asm;\nglobal_asm! { "nop" }\n',
            "use core::concat as panic;\n",
            'fn g() { let _ = vec![1u8]; }\n',
            'fn g() -> u32 { line!() }\n',
            "#[track_caller]\nfn g() {}\n",
            '#[doc = "x"]\nfn g() {}\n',
            '#[unsafe(no_mangle)]\nfn g() {}\n',
            # A replaced or borrowed environment.
            "fn g(ctx: &AllowitContext) { let mut d = ctx.clone(); d.env = allowit::AllowitEnv::new(); let _ = d; }\n",
            "fn g(ctx: &AllowitContext, e: &AllowitContext) { let mut d = ctx.clone(); d.env = e.env.clone(); let _ = d; }\n",
            "fn g(ctx: &AllowitContext, e: &AllowitContext) { let mut d = ctx.clone(); core::mem::swap(&mut d.env, &mut e.clone().env); }\n",
            "fn g(ctx: &AllowitContext) { let _ = core::mem::replace(&mut ctx.clone().env, ctx.env.clone()); }\n",
            "fn g() { let _: Option<allowit::AllowitEnv> = None; }\n",
            # The backend maps and lists behind params, and pointer-width values.
            "fn g(ctx: &AllowitContext) -> bool { ctx.params.recipients.is_some() }\n",
            "fn g(ctx: &AllowitContext) -> bool { ctx.params.0.is_empty() }\n",
            "fn g(ctx: &AllowitContext) { for _ in ctx.request.args . 0.clone() {} }\n",
            "fn g(ctx: &AllowitContext) { let p = allowit::AllowitParams(ctx.request.args.clone().0); let _ = p; }\n",
            "fn g(ctx: &AllowitContext) -> bool { matches!(ctx.params.get(\"k\"), Some(AllowitValue::List(v)) if v.get(0).is_some()) }\n",
            "fn g(ctx: &AllowitContext) -> bool { matches!(allowit::param::<AllowitValue>(ctx, \"k\"), AllowitValue::Str(v) if v.len() > 1) }\n",
            "fn g(ctx: &AllowitContext) -> bool { let v: Vec<Address> = allowit::param(ctx, \"k\"); v.len() > 1 }\n",
            "fn g(ctx: &AllowitContext) -> bool { ctx.params.get(\"k\").map(AllowitValue::List).is_some() }\n",
            "use allowit::recipients;\nfn g(ctx: &AllowitContext) { let _ = recipients(ctx, ctx.params.get(allowit::RECIPIENTS)); }\n",
            "fn g(ctx: &AllowitContext) { let AllowitContext { state, .. } = ctx.clone(); let _ = state; }\n",
            "fn g(ctx: &AllowitContext) -> AllowitRequest { AllowitRequest { amount: 1, ..ctx.request.clone() } }\n",
            "fn g() -> bool { [0u8; 1].len().count_zeros() > 40 }\n",
            "fn g() -> bool { let i = 0; let _ = [1u8][i]; (!i) as u64 > 1 << 40 }\n",
            "fn g(x: [u8; 2]) -> u8 { x[1] }\n",
            "fn g() -> bool { (0..3).map(|x| x).count() > 1 }\n",
            "fn g() -> u8 { core::array::from_fn::<u8, 2, _>(|i| i as u8)[0] }\n",
            "fn g() -> u64 { core::array::from_fn::<u64, 2, _>(|i| i as u64).iter().sum() }\n",
            "fn g() { for (_i, _) in [1u8].iter().enumerate() {} }\n",
            "fn g() -> bool { 'a'.len_utf8() > 0 }\n",
            "fn g(ctx: &AllowitContext) -> bool { ctx.request.recipient.as_str() > \"G\" }\n",
        )
        for code in diverging:
            for text in (code + source("", head), source("", head) + code):
                with self.subTest(source=text), self.assertRaisesRegex(ValueError, "self-contained"):
                    ca.standard_prefix(text)
        # The detaching probe passes the std-only compile, so only the gate rejects it.
        detach = source("    let mut d = ctx.clone();\n    d.env = allowit::AllowitEnv::new();\n"
                        "    if let Err(e) = allowit::spent_cap(&d, d.params.get(allowit::SPENT_CAP)) {\n        let _ = e;\n    }\n", head)
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for text in (detach, source("", head) + diverging[0]):
                policy.write_text(text)
                ca.host_compile(policy)
                digest = hashlib.sha256(text.encode()).hexdigest()
                for tier, rules, source_digest in (("common", ["recipients"], "22" * 32), ("custom", [], digest), ("simple", [], "22" * 32)):
                    with self.subTest(tier=tier, source=text), self.assertRaisesRegex(ValueError, "self-contained"):
                        ca.policy_rules({"rules": rules, "source_digest": source_digest}, tier, str(policy))
        # Portable code beside them stays valid.
        allowed = ("fn a(x: bool) -> bool { if !x { return !x; } assert!(x != !x); matches!(Some(1u8), Some(_)) }\n"
                   "#[inline]\n#[allow(dead_code)]\nfn b(c: &AllowitContext) -> Option<AllowitValue> { c.params.get(allowit::SPENT_CAP).or(c.request.args.get(\"memo\")) }\n"
                   "fn d(c: &AllowitContext) -> &AllowitContext { c }\n"
                   "use allowit::AllowitRule;\nfn e(r: AllowitRule) -> bool { r == AllowitRule::tokens || r == allowit::AllowitRule::recipients }\n"
                   "fn f(ctx: &AllowitContext) -> allowit::Result { let c = ctx.clone(); allowit::tokens(&c, c.params.get(allowit::TOKENS))?; Ok(()) }\n"
                   "fn vendor_cap_of(c: &AllowitContext) -> allowit::Result<i128> { allowit::recipients(c, c.params.get(allowit::TOKENS))?; match allowit::param(c, \"vendor_cap\") "
                   "{ AllowitValue::Int(cap) => Ok(cap), AllowitValue::List(items) => { let mut n = 0i128; for _ in items { n += 1; } Ok(n) } _ => Err(AllowitError::InvalidParam) } }\n"
                   "fn typed(c: &AllowitContext) -> bool { let v: Vec<Address> = allowit::param(c, \"vendors\"); let memo: String = allowit::arg(c, \"memo\"); "
                   "let n: u32 = allowit::arg(c, \"n\"); for vendor in v { if vendor == c.request.recipient { return memo == memo.clone() && n > 0u32; } } false }\n"
                   "fn ask(c: &AllowitContext) -> allowit::Result<u32> { allowit::systemone(c, &allowit::AllowitSystemOne { id: \"a\", query: \"b\", deny_below: 1u32, allow_above: 2u32 }) }\n"
                   "fn h(pair: [u8; 2]) -> u64 { let [x, y] = pair; u64::from(x) + u64::from(y) }\n"
                   "fn i(c: &AllowitContext) -> u64 { let held = &c.env; let _ = held; let mut n = 0u64; for x in 0..3u64 { n = n.max(x + c.request.now); } n }\n"
                   "fn j(c: &AllowitContext) -> allowit::Result<u64> { let n: Option<u64> = allowit::get_state(c, \"seen\")?; "
                   "allowit::set_state(c, \"seen\", n.unwrap_or(0).saturating_add(1))?; Ok(n.unwrap_or(0)) }\n"
                   "fn k(c: &AllowitContext) -> bool { c.request.spent_units.checked_add(c.request.gas_units).is_some() && !c.request.unpriced }\n"
                   "fn m(c: &AllowitContext) { let n = 1u8; assert!(n > 0u8, \"{{n}} {} left, {:?} \\\\x7b\", n, c.request.now); panic!(\"plain\") }\n")
        self.assertEqual(ca.standard_prefix(allowed + source("", head)), ["recipients"])
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(allowed + source("", head))
            ca.host_compile(policy)

    def test_policy_source_admits_literal_panic_messages_and_the_documented_per_op_policy(self):
        head = HEAD + CALL("recipients")
        # A message is optional; when present it is one string literal, followed by format arguments.
        for body in ('    panic!();\n', '    panic!("swap above swap_cap");\n', '    unreachable!("op {}", ctx.request.amount);\n',
                     '    assert!(ctx.request.amount > 0i128);\n', '    assert!(ctx.request.amount > 0i128, "amount {:?}", ctx.request.amount,);\n',
                     '    assert_eq!(ctx.request.amount, 1i128, "one");\n', '    assert_ne!(ctx.request.now, 0u64);\n'):
            with self.subTest(body=body):
                self.assertEqual(ca.standard_prefix(source(body, head)), ["recipients"])
        for body in ('    let m = "x";\n    panic!(m);\n', '    panic!(ctx.request.amount);\n',
                     '    assert!(ctx.request.unpriced, ctx.request.amount);\n', '    unreachable!(r#panic());\n',
                     '    assert_eq!(ctx.request.amount, 1i128, ctx.request.now);\n', '    assert_ne!(1u8, 2u8, ("x"));\n'):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "string literal"):
                ca.standard_prefix(source(body, head))
        pool = "custom:" + StrKey.encode_contract(bytes([3]) * 32)
        documented = (HEAD.replace("allowit::Result {\n", "allowit::Result {\n")
                      + "    match allowit::operations(ctx, ctx.params.get(allowit::OPERATIONS))? {\n"
                      + '        "' + pool + '.swap" => {\n'
                      + '            // "at most 50 XLM per swap"\n'
                      + '            let amount: i128 = allowit::arg(ctx, "amount");\n'
                      + '            let cap: i128 = allowit::param(ctx, "swap_cap");\n'
                      + '            if amount > cap { panic!("swap above swap_cap"); }\n'
                      + "        }\n"
                      + '        "' + pool + '.claim" => {}\n'
                      + "        _ => {}\n    }\n    Ok(())\n}\n")
        self.assertEqual(ca.standard_prefix(documented), [])
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(documented)
            ca.host_compile(policy)
            # The standard prefix statement compiles too.
            policy.write_text(source(CALL("operations")))
            ca.host_compile(policy)

    def test_policy_source_rejects_pointer_width_and_address_probes(self):
        call = CALL
        head = HEAD + call("recipients")
        # The review probe: a 64-bit host skips the cap that a 32-bit contract enforces.
        probe = ("    let wide = core::num::NonZeroUsize::MAX.ilog2() == 63;\n    if !wide {\n"
                 "        allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;\n    }\n")
        # A format width or precision count is `usize`, so it infers `a: usize` without naming it.
        cap = "    let wide = a.checked_mul(a).is_some();\n    if !wide {\n        allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;\n    }\n"
        guard = "    let a = 65_536;\n    if ctx.request.amount < 0i128 {{ {} }}\n".format
        formats = (
            guard('panic!("{:1$}", 0u8, a);') + cap,
            guard('assert!(false, "{:.*}", a, 0u8);') + cap,
            guard('assert!(false, "{:a$}", 0u8);') + cap,
            guard('unreachable!("{:>a$}", 0u8);') + cap,
            guard('panic!(r"{:.a$}", 0u8);') + cap,
            # Escapes spell the braces without writing them.
            guard('panic!("\\x7b:1$\\x7d", 0u8, a);') + cap,
            guard('panic!("\\u{7b}:1$\\u{7d}", 0u8, a);') + cap,
        )
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for body in (probe,) + formats:
                with self.subTest(compiles=body):
                    policy.write_text(source(body, head))
                    # Each passes the std-only compile, so only the allowlist rejects it.
                    ca.host_compile(policy)
        probes = (
            probe,
            "    let _ = core::num::NonZeroIsize::MAX.ilog10();\n",
            "    let _ = u64::MAX.ilog2() + u64::MAX.checked_ilog10().unwrap_or(0);\n",
            "    let _ = u64::MAX.ilog(3);\n",
            "    let _ = core::str::from_utf8(&[0xffu8]).unwrap_err().valid_up_to();\n",
            "    let _ = u8::MAX.count_ones();\n",
            "    let _ = 1usize;\n",
            "    let _ = 1.5;\n",
            "    let _ = 1e3;\n",
            "    let _ = ctx.request.amount as u64;\n",
            # Function values and non-capturing closures coerce to pointers whose order is code layout.
            "    let a = if true { |x: u8| x } else { |x: u8| x + 1 };\n",
            "    let _ = ctx.request.amount.checked_add(1).map(|x| x);\n",
            "    let f = allowit::spent_cap;\n",
            "    let _ = [i128::from, i128::from];\n",
            "    let p: fn(&AllowitContext) -> allowit::Result = execute;\n",
            "    let _ = if true { execute } else { execute };\n",
            "    let _ = core::cmp::max::<u8>;\n",
            # Raw pointers expose addresses.
            "    let _ = &raw const ctx.request.amount;\n",
            "    let _: *const i128 = &ctx.request.amount;\n",
            # Generic and qualified paths reach APIs beyond the allowlist.
            "    let _ = <u64>::MAX.leading_zeros();\n",
            "    let _ = Option::<u64>::None;\n",
            "    let _ = ctx.state.clone();\n",
        ) + formats
        for body in probes:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "self-contained"):
                ca.standard_prefix(source(body, head))

    def test_policy_source_checks_placeholders_only_in_macro_messages(self):
        head = HEAD + CALL("recipients")
        # Data strings are not format strings: JSON bodies and braces in values pass the gate.
        data = ('    let payload = r#"{"amount":1}"#;\n    let body = "{\\"to\\":{x}}";\n'
                '    if payload == body { panic!("{} {:?} {{}}", "{x}", r"{:1$}"); }\n'
                '    assert!(true, "{}", "{y}");\n    assert_eq!(1u8, 1u8, "{:?}", "{0}");\n')
        self.assertEqual(ca.standard_prefix(source(data, head)), ["recipients"])
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(source(data, head))
            ca.host_compile(policy)
        # A message placeholder other than `{}` or `{:?}` still rejects, at every message position.
        for body in ('    panic!("{x}");\n', '    unreachable!(r#"{x}"#);\n', '    assert!(true, "{0}");\n',
                     '    assert_eq!(1u8, 1u8, "{x}");\n', '    assert_ne!(1u8, 2u8, "\\x7bx\\x7d");\n'):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "format placeholder"):
                ca.standard_prefix(source(body, head))

    def test_policy_source_rejects_raw_function_values_and_lowered_pointer_lints(self):
        # Review probe: identical functions may merge in release Wasm only, so `a == b` is false on
        # the host and true onchain, and the spending cap runs on one backend only.
        same = ("fn r#one() {}\nfn r#two() {}\n#[allow(unpredictable_function_pointer_comparisons)]\n"
                "fn same() -> bool { let a = if true { r#one } else { r#two }; "
                "let b = if true { r#two } else { r#one }; a == b }\n")
        text = same + source("    if same() {\n        allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;\n    }\n",
                             HEAD + CALL("recipients"))
        # The gate reads `fn r#one` as the local function `one`, so its use as a value rejects.
        with self.assertRaisesRegex(ValueError, "the function `one` as a value"):
            ca.standard_prefix(text)
        # The std-only compile forbids the lint, so no source attribute lowers it.
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for attribute in ("allow", "expect", "warn"):
                with self.subTest(attribute=attribute), self.assertRaisesRegex(ValueError, "E0453"):
                    policy.write_text(text.replace("#[allow(", "#[{}(".format(attribute)))
                    ca.host_compile(policy)

    def test_policy_source_rejects_capitalized_local_function_values(self):
        # Review probe: local functions named for types escape a lowercase-only guard, and the
        # generic `min` avoids the pointer comparison lint, so the host stored probe=1 and release
        # Wasm probe=2.
        probe = ("fn String() -> u8 { 1 }\nfn Address() -> u8 { 2 }\n"
                 + source("    let a = if ctx.request.now > 0u64 { String } else { Address };\n"
                          "    let b = if ctx.request.now > 0u64 { Address } else { String };\n"
                          "    let selected = core::cmp::min(a, b);\n"
                          "    allowit::set_state(ctx, \"probe\", u64::from(selected()))?;\n",
                          HEAD + CALL("recipients")))
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            policy.write_text(probe)
            # It passes the std-only compile, so only the gate rejects it.
            ca.host_compile(policy)
        with self.assertRaisesRegex(ValueError, "the function `String` as a value"):
            ca.checked_code(probe)

    def test_policy_source_reads_params_and_args_only_through_their_context_fields(self):
        head = HEAD + CALL("recipients")
        # Review probes: a list bound to `args` or `params` takes a pointer-width index, so the
        # host stores width=Int(4294967296) where the chain stores Int(0).
        probes = (
            "    if let Some(AllowitValue::List(args)) = ctx.params.get(\"vendors\") {\n"
            "        let i = 65_536;\n        let _ = args.get(i);\n        let wide = i.checked_mul(65_536).unwrap_or(0);\n"
            "        allowit::set_state(ctx, \"width\", u64::try_from(wide).unwrap_or(0))?;\n    }\n",
            "    match ctx.params.get(\"vendors\") {\n        Some(AllowitValue::List(params)) => {\n"
            "            let n = 65536;\n            let _ = params.get(n);\n"
            "            if n.checked_mul(n).is_some() {\n                return Err(AllowitError::Expired);\n            }\n"
            "        }\n        _ => {}\n    }\n",
        )
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for body in probes:
                with self.subTest(body=body):
                    policy.write_text(source(body, head))
                    # Each passes the std-only compile, so only the gate rejects it.
                    ca.host_compile(policy)
                    with self.assertRaisesRegex(ValueError, "self-contained"):
                        ca.standard_prefix(source(body, head))
        # Any other binding named for the fields, or `get` on a value that is no field access.
        for body in ("    let params = ctx.params.clone();\n    let _ = params.get(\"k\");\n",
                     "    let p = ctx.request.args.clone();\n    let _ = p.get(\"k\");\n",
                     "    for args in [0u8] {\n        let _ = args;\n    }\n"):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "self-contained"):
                ca.standard_prefix(source(body, head))
        fn = "fn f(params: &AllowitContext) -> bool {{ {} }}\n".format
        with self.assertRaisesRegex(ValueError, "self-contained"):
            ca.standard_prefix(fn("params.request.args.get(\"k\").is_some()") + source("", head))
        # The map inside params or args is private on the host, through a clone or a binding too.
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for body in ("    for (_, v) in ctx.params.clone().0 {\n        let _ = v;\n    }\n",
                         "    let p = ctx.request.args.clone();\n    for (_, w) in p.0 {\n        let _ = w;\n    }\n"):
                with self.subTest(body=body):
                    policy.write_text(source(body, head))
                    with self.assertRaisesRegex(ValueError, "std-only compile"):
                        ca.host_compile(policy)
        # Field reads stay valid.
        valid = "    let _ = ctx.params.get(\"k\").or(ctx.request.args.get(\"memo\"));\n"
        self.assertEqual(ca.standard_prefix(source(valid, head)), ["recipients"])

    def test_policy_source_rejects_closure_pointer_and_layout_probes(self):
        call = CALL
        head = HEAD + call("recipients")
        cap = "    if {} {{\n        allowit::spent_cap(ctx, ctx.params.get(allowit::SPENT_CAP))?;\n    }}\n".format
        # Closures after `break` coerce to function pointers whose equality depends on the build.
        pointers = ("    let a = loop { break |x: u64| x; };\n    let b = loop { break |x: u64| x; };\n"
                    "    let p = if ctx.request.now > 0u64 { a } else { b };\n"
                    "    let q = if ctx.request.now > 0u64 { b } else { a };\n" + cap("p == q"))
        # Prelude layout functions differ: the host `Address` is a 24-byte string, onchain an 8-byte handle.
        size = "    let wide = size_of_val(&ctx.request) > 100;\n" + cap("!wide")
        align = cap("align_of_val(&ctx.request.asset) == 8")
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.rs"
            for probe in (size, align):
                # Each passes the std-only compile, so only the allowlist rejects it.
                policy.write_text(source(probe, head))
                ca.host_compile(policy)
            # The std-only compile itself denies function pointer comparisons.
            policy.write_text(source(pointers, head))
            with self.assertRaisesRegex(ValueError, "function-pointer-comparisons"):
                ca.host_compile(policy)
        probes = (
            pointers, size, align,
            "    let a = { if true {} |x: u64| x };\n",
            "    let a = 'l: loop { break 'l |x: u64| x; };\n",
            "    let a = ctx.request.now | |x: u64| x;\n",
            "    let f = || 1u64;\n",
            "    let a = size_of::<u64>();\n",
            "    let a = align_of::<u64>();\n",
            "    drop(ctx.request.amount);\n",
            # Tuple constructors as values coerce to function pointers.
            "    let a: fn(u64) -> Option<u64> = Some;\n",
            "    let a = if true { Ok } else { Err };\n",
            "    let a = AllowitOperation::custom;\n",
            "    let a = Option::Some;\n",
            # A name the file does not declare.
            "    let a = undeclared;\n",
        )
        for body in probes:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "self-contained"):
                ca.standard_prefix(source(body, head))
        # Operators, pattern alternatives and declared bindings still pass.
        allowed = ("    let n: u64 = ctx.request.now | 1u64;\n    let mut m = n;\n    m |= 2u64;\n"
                   "    let ok = n > 0u64 || m > 0u64;\n"
                   "    match ctx.request.operation {\n"
                   "        AllowitOperation::transfer | AllowitOperation::deposit if ok => {}\n"
                   "        AllowitOperation::custom(_, _) => {}\n"
                   "        other => {\n            let _ = other;\n        }\n    }\n"
                   "    for k in 0u64..n.min(2u64) {\n        if let Some(v) = k.checked_add(m) {\n"
                   "            let _ = Some(v);\n        }\n    }\n")
        self.assertEqual(ca.standard_prefix(source(allowed, head)), ["recipients"])

    def test_checker_enums_name_every_core_variant(self):
        import re
        import policy_source
        core = (ROOT / "crates" / "allowit" / "src" / "core.rs").read_text()
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
            policy.write_text(source("    allowit::expiry(ctx, ctx.params.get(allowit::EXPIRY))?;\n"))
            deployment = {"deployment_version": 1, "owner": KEYS[0], "agent": KEYS[1], "server": KEYS[2], "source_digest": "22" * 32,
                          "rules": ["expiry"], "params": {}, "x402_enabled": False, "wasm_hash": None}
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

    def test_recover_prepares_without_reading_state(self):
        contract = StrKey.encode_contract(bytes([2]) * 32)
        calls = []

        def cli(args, input_data=None):
            calls.append(args)
            if args[-1] == "state":
                # A version 1 State under version 2 code: state() fails with InvalidState.
                raise subprocess.CalledProcessError(1, args, stderr="Error(Contract, #1)")
            return "raw-xdr"

        argv = ["contract_admin.py", "admin", "--source", KEYS[0], "--contract", contract, "--method", "recover",
                "--arguments", json.dumps({"recipient": KEYS[1], "amount": 5})]
        with patch.object(sys, "argv", argv), patch.object(ca, "fetch", return_value=state()), \
                patch.object(ca, "cli_run", side_effect=cli), patch.object(ca, "prepare_xdr", return_value="assembled") as prepared, \
                patch.object(sys, "stdout", new_callable=StringIO) as output:
            ca.main()
        self.assertEqual(output.getvalue().strip(), "assembled")
        self.assertEqual([call[-1] for call in calls], ["5"])
        self.assertEqual(prepared.call_args.kwargs["candidate"], None)
        # Other owner methods still check the current state and fail closed.
        argv[argv.index("recover")] = "set_pause"
        argv[-1] = json.dumps({"paused": True, "deployment_version": 1})
        with patch.object(sys, "argv", argv), patch.object(ca, "fetch", return_value=state()), \
                patch.object(ca, "cli_run", side_effect=cli), self.assertRaises(subprocess.CalledProcessError):
            ca.main()

    def test_secrets_and_hashes_reject(self):
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.account("owner-key-alias")
        with self.assertRaises((ValueError, argparse.ArgumentTypeError)):
            ca.code_hash("123")
        self.assertEqual(ca.serialize({"paused": False}), ["--paused", "false"])


if __name__ == "__main__":
    unittest.main()
