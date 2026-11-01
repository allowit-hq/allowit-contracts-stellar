"""Real CLI spec encoding against a local, read-only RPC fixture."""
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract_admin as ca
from stellar_sdk import Address, Keypair, Network, StrKey, TransactionEnvelope, xdr, scval

CLI = os.environ.get("STELLAR_BIN") or shutil.which("stellar")
WASM = Path(__file__).resolve().parents[2] / "target/wasm32v1-none/release/allowit_common_policy_engine.wasm"


@unittest.skipUnless(CLI and WASM.exists(), "Build policy wallet Wasm and set STELLAR_BIN to test CLI encoding")
class RealCliEncoding(unittest.TestCase):
    def test_params_exact_native_encoding(self):
        code = WASM.read_bytes()
        digest = hashlib.sha256(code).digest()
        account = Keypair.from_raw_ed25519_seed(bytes([1]) * 32).public_key
        contract = StrKey.encode_contract(bytes([2]) * 32)
        recipient = Keypair.from_raw_ed25519_seed(bytes([3]) * 32).public_key
        big = 2**127 - 1
        params = {"payment_limit": big, "lifetime_spending_limit": 0, "call_limit": 0, "expires_at": 2**64 - 1, "destinations": [recipient, contract], "tokens": []}
        methods = []
        class Rpc(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                method = request["method"]
                methods.append(method)
                if method == "getNetwork":
                    result = {"passphrase": Network.TESTNET_NETWORK_PASSPHRASE, "protocolVersion": 28}
                elif method == "getLedgerEntries":
                    entries = []
                    for key_xdr in request["params"]["keys"]:
                        key = xdr.LedgerKey.from_xdr(key_xdr)
                        if key.type == xdr.LedgerEntryType.CONTRACT_DATA:
                            instance = xdr.SCContractInstance(xdr.ContractExecutable(xdr.ContractExecutableType.CONTRACT_EXECUTABLE_WASM, wasm_hash=xdr.Hash(digest)), None)
                            data = xdr.LedgerEntryData(key.type, contract_data=xdr.ContractDataEntry(xdr.ExtensionPoint(0), key.contract_data.contract, key.contract_data.key, key.contract_data.durability, xdr.SCVal(xdr.SCValType.SCV_CONTRACT_INSTANCE, instance=instance)))
                        elif key.type == xdr.LedgerEntryType.CONTRACT_CODE:
                            data = xdr.LedgerEntryData(key.type, contract_code=xdr.ContractCodeEntry(xdr.ContractCodeEntryExt(0), xdr.Hash(digest), code))
                        elif key.type == xdr.LedgerEntryType.ACCOUNT:
                            entry = xdr.AccountEntry(key.account.account_id, xdr.Int64(1000000000), xdr.SequenceNumber(xdr.Int64(42)), xdr.Uint32(0), None, xdr.Uint32(0), xdr.String32(b""), xdr.Thresholds(bytes([1,0,0,0])), [], xdr.AccountEntryExt(0))
                            data = xdr.LedgerEntryData(key.type, account=entry)
                        else:
                            raise AssertionError("Unexpected RPC ledger key")
                        entries.append({"key": key_xdr, "xdr": data.to_xdr(), "lastModifiedLedgerSeq": 10, "liveUntilLedgerSeq": 100000})
                    result = {"entries": entries, "latestLedger": 20}
                else:
                    raise AssertionError("No simulation, signing or submission is expected: " + method)
                body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = HTTPServer(("127.0.0.1", 0), Rpc)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as config:
                policy = Path(config) / "policy.rs"
                policy.write_text("use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n"
                                  "    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    Ok(())\n}\n")
                cmd = [CLI, "--config-dir", config, "contract", "invoke", "--id", contract, "--source-account", account, "--rpc-url", f"http://127.0.0.1:{server.server_port}", "--network-passphrase", Network.TESTNET_NETWORK_PASSPHRASE, "--build-only", "--", "deploy_policy"]
                result = subprocess.run(cmd + ca.serialize({"deployment": {"deployment_version": 1, "owner": account, "agent": recipient, "server": Keypair.from_raw_ed25519_seed(bytes([4]) * 32).public_key, "source_digest": "22" * 32, "rules": ["payment_limit"], "params": params, "x402_enabled": False, "wasm_hash": None}}), check=True, capture_output=True, text=True, timeout=30)
                tx = TransactionEnvelope.from_xdr(result.stdout.strip(), Network.TESTNET_NETWORK_PASSPHRASE)
                self.assertEqual(tx.signatures, [])
                args = tx.transaction.operations[0].host_function.invoke_contract.args
                packet = {entry.key.sym.sc_symbol.decode(): entry.val for entry in args[0].map.sc_map}
                self.assertEqual(packet["deployment_version"].u64.uint64, 1)
                # Vec<AllowitRule>: each unit enum variant encodes as a one-symbol vector.
                self.assertEqual(packet["rules"], scval.to_vec([scval.to_vec([scval.to_symbol("payment_limit")])]))
                # Map<Symbol, AllowitValue>: only present keys; each value is a variant vector.
                values = {entry.key.sym.sc_symbol.decode(): entry.val for entry in packet["params"].map.sc_map}
                self.assertEqual(list(values), sorted(params))
                variant = lambda name, value: scval.to_vec([scval.to_symbol(name), value])
                self.assertEqual(values["payment_limit"], variant("Int", scval.to_int128(big)))
                self.assertEqual(values["lifetime_spending_limit"], variant("Int", scval.to_int128(0)))
                self.assertEqual(values["call_limit"], variant("Int", scval.to_int128(0)))
                self.assertEqual(values["expires_at"], variant("Int", scval.to_int128(2**64 - 1)))
                addresses = [variant("Addr", scval.to_address(a)) for a in (recipient, contract)]
                self.assertEqual(values["destinations"], variant("List", scval.to_vec(addresses)))
                self.assertEqual(values["tokens"], variant("List", scval.to_vec([])))
                for action, wasm in (("deploy-parent", WASM.with_name("allowit_engine_parent.wasm")), ("deploy-wallet", WASM)):
                    with self.subTest(action=action):
                        expected = hashlib.sha256(wasm.read_bytes()).hexdigest()
                        options = SimpleNamespace(action=action, network="testnet", allow_mainnet=False, source=account,
                            wasm=str(wasm), wasm_hash=expected, engine_wasm="11" * 32, tier="common", policy_source=str(policy),
                            owner=account, config=json.dumps({"owner": account, "agent": recipient,
                                "server": Keypair.from_raw_ed25519_seed(bytes([4]) * 32).public_key, "asset": contract,
                                "source_digest": "22" * 32, "rules": ["payment_limit"], "params": params, "x402_enabled": False, "policy_instance": "11" * 32}))
                        prepared = ca.command(options)
                        self.assertIn("--wasm", prepared)
                        self.assertNotIn("--wasm-hash", prepared)
                        network_index = prepared.index("--network")
                        prepared[network_index:network_index + 2] = ["--rpc-url", f"http://127.0.0.1:{server.server_port}", "--network-passphrase", Network.TESTNET_NETWORK_PASSPHRASE]
                        result = subprocess.run([CLI, "--config-dir", config] + prepared, check=True, capture_output=True, text=True, timeout=30)
                        deployed = TransactionEnvelope.from_xdr(result.stdout.strip(), Network.TESTNET_NETWORK_PASSPHRASE)
                        self.assertEqual(deployed.signatures, [])
                        host = deployed.transaction.operations[0].host_function
                        self.assertEqual(host.type, xdr.HostFunctionType.HOST_FUNCTION_TYPE_CREATE_CONTRACT_V2)
                        self.assertEqual(host.create_contract_v2.executable.wasm_hash.hash.hex(), expected)
                        self.assertEqual(len(host.create_contract_v2.constructor_args), 2 if action == "deploy-parent" else 1)
                self.assertTrue(methods)
                self.assertTrue(set(methods) <= {"getNetwork", "getLedgerEntries"})
                self.assertNotIn("sendTransaction", methods)
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
