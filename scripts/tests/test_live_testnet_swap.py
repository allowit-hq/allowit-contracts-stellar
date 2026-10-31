"""Live testnet swap through a Common policy wallet and the Soroswap router. Skipped by default.

The agent sends the plain `router.swap_exact_tokens_for_tokens(..., to=wallet, ...)` call that a
simple wallet would sign. The wallet's `__check_auth` intercepts it, verifies the agent and server
signatures and runs its onchain rules. The test makes a fresh classic test asset with its Stellar
Asset Contract, adds XLM liquidity for it on Soroswap, deploys and funds a wallet from the local
build, swaps once, and checks that a swap above the wallet's `transaction_cap` does not simulate.

Run it from the repository root after `scripts/build-contracts.sh`, with a funded testnet account:

    ALLOWIT_LIVE_TESTNET_SECRET=S... python -m unittest scripts/tests/test_live_testnet_swap.py -v

The account pays every fee and becomes the wallet owner. It needs about 160 XLM. Testnet only.
"""
import hashlib
import os
import secrets
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mainnet_release as release  # noqa: E402
from stellar_sdk import Asset, Keypair, Network, SorobanServer, TransactionBuilder, scval, xdr  # noqa: E402
from stellar_sdk.auth import authorization_payload_hash, authorize_entry  # noqa: E402
from stellar_sdk.soroban_rpc import GetTransactionStatus  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SECRET = os.environ.get("ALLOWIT_LIVE_TESTNET_SECRET")
RPC = os.environ.get("ALLOWIT_LIVE_RPC", "https://soroban-testnet.stellar.org")
# Soroswap testnet router: soroswap/core public/testnet.contracts.json.
ROUTER = os.environ.get("ALLOWIT_LIVE_ROUTER", "CCJUD55AG6W5HAI5LRVNKAE5WDP5XGZBUDS5WNTIVDU7O264UZZE7BRD")
PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE
WASM = ROOT / "target/wasm32v1-none/release/allowit_common_policy_engine.wasm"
RULES = ["recipients", "tokens", "transaction_cap", "operations"]
XLM = 10_000_000


def value(kind, inner):
    """An `AllowitValue` variant."""
    return scval.to_vec([scval.to_symbol(kind), inner])


def addresses(items):
    return value("List", scval.to_vec([value("Addr", scval.to_address(item)) for item in items]))


def sorted_map(entries):
    """A Soroban map of symbol keys, in key order."""
    return scval.to_map({scval.to_symbol(key): entries[key] for key in sorted(entries)})


@unittest.skipUnless(SECRET, "set ALLOWIT_LIVE_TESTNET_SECRET to run the live testnet swap")
class LiveTestnetSwap(unittest.TestCase):
    def setUp(self):
        if not WASM.is_file():
            self.skipTest("run scripts/build-contracts.sh first")
        self.server = SorobanServer(RPC)
        self.owner = Keypair.from_secret(SECRET)
        self.hashes = {}

    def submit(self, name, source, build, signers=(), soroban=True):
        """Build, prepare, sign and send one transaction; return its hash. A transaction that the
        network did not take is rebuilt with a fresh sequence number, at most three times."""
        for _ in range(3):
            account = self.server.load_account(source.public_key)
            builder = TransactionBuilder(account, PASSPHRASE, base_fee=1_000_000).set_timeout(300)
            tx = build(builder).build()
            if soroban:
                tx = self.server.prepare_transaction(tx)
            for signer in (source, *signers):
                tx.sign(signer)
            if self.settle(name, tx):
                return self.hashes[name]
        self.fail(f"{name}: not taken")

    def settle(self, name, tx):
        """Send `tx` and wait for its result. False when the network did not take it."""
        sent = self.server.send_transaction(tx)
        status = sent.status.value
        print(f"{name}: {sent.hash} {status}", flush=True)
        self.assertNotEqual(status, "ERROR", f"{name}: {sent.error_result_xdr}")
        if status == "TRY_AGAIN_LATER":
            time.sleep(6)
            return False
        for _ in range(45):
            result = self.server.get_transaction(sent.hash)
            if result.status != GetTransactionStatus.NOT_FOUND:
                self.assertEqual(result.status, GetTransactionStatus.SUCCESS, f"{name}: {sent.hash}")
                self.hashes[name] = sent.hash
                return True
            time.sleep(2)
        return False

    def read(self, contract, function, args=()):
        """The native result of a read-only call."""
        account = self.server.load_account(self.owner.public_key)
        tx = (TransactionBuilder(account, PASSPHRASE, base_fee=100).set_timeout(60)
              .append_invoke_contract_function_op(contract, function, list(args)).build())
        result = self.server.simulate_transaction(tx)
        self.assertIsNone(result.error, result.error)
        return scval.to_native(xdr.SCVal.from_xdr(result.results[0].xdr))

    def balance(self, token, owner):
        return self.read(token, "balance", [scval.to_address(owner)])

    def test_intercepted_swap_through_soroswap(self):
        owner, agent, server, issuer = self.owner, Keypair.random(), Keypair.random(), Keypair.random()
        native = Asset.native().contract_id(PASSPHRASE)
        test_asset = Asset("AWT" + secrets.token_hex(2).upper(), issuer.public_key)
        token = test_asset.contract_id(PASSPHRASE)

        # A classic test asset with its Stellar Asset Contract and Soroswap XLM liquidity.
        self.submit("accounts", owner, lambda b: b.append_create_account_op(agent.public_key, "20")
                    .append_create_account_op(issuer.public_key, "5"), soroban=False)
        self.submit("issue", owner, lambda b: b.append_change_trust_op(test_asset)
                    .append_payment_op(owner.public_key, test_asset, "100000", source=issuer.public_key),
                    signers=[issuer], soroban=False)
        self.submit("asset_contract", owner, lambda b: b.append_create_stellar_asset_contract_from_asset_op(test_asset))
        deadline = int(time.time()) + 900
        self.submit("add_liquidity", owner, lambda b: b.append_invoke_contract_function_op(ROUTER, "add_liquidity", [
            scval.to_address(native), scval.to_address(token), scval.to_int128(100 * XLM), scval.to_int128(1000 * XLM),
            scval.to_int128(0), scval.to_int128(0), scval.to_address(owner.public_key), scval.to_uint64(deadline)]))

        # A Common wallet from the local build: swaps only, through this router, of these tokens,
        # at most 20 XLM each, with intercepted authorization enabled.
        wasm = WASM.read_bytes()
        module = hashlib.sha256(wasm).hexdigest()
        self.submit("upload_wallet", owner, lambda b: b.append_upload_contract_wasm_op(wasm))
        policy_instance = secrets.token_bytes(32)
        params = sorted_map({
            "operations": value("List", scval.to_vec([value("Str", scval.to_string("swap"))])),
            "recipients": addresses([ROUTER]),
            "tokens": addresses([native, token]),
            "transaction_cap": value("Int", scval.to_int128(20 * XLM)),
        })
        config = scval.to_struct({
            "owner": scval.to_address(owner.public_key),
            "agent": scval.to_address(agent.public_key),
            "server": scval.to_address(server.public_key),
            "asset": scval.to_address(native),
            "policy_instance": scval.to_bytes(policy_instance),
            "source_digest": scval.to_bytes(bytes.fromhex(release.prefix_digest("common_policy_engine", module, native, RULES))),
            "rules": scval.to_vec([scval.to_vec([scval.to_symbol(rule)]) for rule in RULES]),
            "params": params,
            "x402_enabled": scval.to_bool(True),
        })
        salt = secrets.token_bytes(32)
        create = lambda b: b.append_create_contract_op(bytes.fromhex(module), owner.public_key, [config], salt)  # noqa: E731
        account = self.server.load_account(owner.public_key)
        simulated = self.server.simulate_transaction(
            create(TransactionBuilder(account, PASSPHRASE, base_fee=100).set_timeout(60)).build())
        self.assertIsNone(simulated.error, simulated.error)
        wallet = scval.to_native(xdr.SCVal.from_xdr(simulated.results[0].xdr)).address
        self.submit("deploy_wallet", owner, create)
        self.submit("fund_wallet", owner, lambda b: b.append_invoke_contract_function_op(native, "transfer", [
            scval.to_address(owner.public_key), scval.to_address(wallet), scval.to_int128(50 * XLM)]))

        amount_in = 10 * XLM
        path = scval.to_vec([scval.to_address(native), scval.to_address(token)])
        quote = self.read(ROUTER, "router_get_amounts_out", [scval.to_int128(amount_in), path])[-1]
        amount_out_min = quote * 95 // 100

        def swap(amount, operation_id):
            """The agent's plain router call with the wallet's intercepted authorization signed."""
            expires = int(time.time()) + 600
            call = [scval.to_int128(amount), scval.to_int128(amount_out_min), path, scval.to_address(wallet),
                    scval.to_uint64(expires)]
            account = self.server.load_account(agent.public_key)
            tx = (TransactionBuilder(account, PASSPHRASE, base_fee=1_000_000).set_timeout(300)
                  .append_invoke_contract_function_op(ROUTER, "swap_exact_tokens_for_tokens", call).build())
            recorded = self.server.simulate_transaction(tx)
            self.assertIsNone(recorded.error, recorded.error)
            entries = [xdr.SorobanAuthorizationEntry.from_xdr(raw) for raw in recorded.results[0].auth]
            arguments = scval.to_struct({
                "router": scval.to_address(ROUTER), "amount_in": scval.to_int128(amount),
                "amount_out_min": scval.to_int128(amount_out_min), "path": path,
                "to": scval.to_address(wallet), "deadline": scval.to_uint64(expires)}).to_xdr_bytes()
            schema = hashlib.sha256(release.SWAP_SCHEMA).digest()
            execution = scval.to_struct({
                "policy_instance": scval.to_bytes(policy_instance),
                "source_hash": scval.to_bytes(hashlib.sha256(b"live swap policy source").digest()),
                "operation_id": scval.to_bytes(operation_id),
                "nonce": scval.to_uint64(0),
                "deployment_version": scval.to_uint64(0),
                "expires_at": scval.to_uint64(expires),
                "invocation": scval.to_struct({
                    "module_digest": scval.to_bytes(bytes.fromhex(module)), "entrypoint": scval.to_symbol("execute"),
                    "argument_schema_digest": scval.to_bytes(schema), "arguments": scval.to_bytes(arguments)}),
                "expense": scval.to_void(),
                "args": scval.to_map({}),
            })

            def sign(preimage):
                payload = authorization_payload_hash(preimage)
                digest = hashlib.sha256(scval.to_vec([
                    scval.to_symbol("allowit_wallet_v1"), scval.to_bytes(payload), execution]).to_xdr_bytes()).digest()
                return scval.to_struct({"execution": execution, "agent_signature": scval.to_bytes(agent.sign(digest)),
                                        "server_signature": scval.to_bytes(server.sign(digest))})

            valid_until = self.server.get_latest_ledger().sequence + 100
            signed = [authorize_entry(entry, sign, valid_until, PASSPHRASE) for entry in entries]
            tx.transaction.operations[0].auth = signed
            return tx

        # Over the wallet's 20 XLM transaction cap: the enforcing simulation fails in `__check_auth`.
        denied = self.server.simulate_transaction(swap(30 * XLM, secrets.token_bytes(32)))
        self.assertIsNotNone(denied.error)
        self.assertEqual(self.read(wallet, "state")["nonce"], 0)

        before = self.balance(native, wallet)
        for _ in range(3):
            tx = self.server.prepare_transaction(swap(amount_in, secrets.token_bytes(32)))
            tx.sign(agent)
            if self.settle("intercepted_swap", tx):
                break
        self.assertIn("intercepted_swap", self.hashes)
        self.assertEqual(before - self.balance(native, wallet), amount_in)
        self.assertGreaterEqual(self.balance(token, wallet), amount_out_min)
        state = self.read(wallet, "state")
        self.assertEqual(state["nonce"], 1)
        print(f"wallet: {wallet}", flush=True)


if __name__ == "__main__":
    unittest.main()
