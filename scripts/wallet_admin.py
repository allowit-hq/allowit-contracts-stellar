"""Native account admission checks of the release scripts. The command-line tool is the Rust binary
`allowit-stellar-admin` (see docs/admin.md)."""
import argparse
import json
from urllib.request import urlopen
from stellar_sdk import Keypair, Network

HORIZON = {"testnet": "https://horizon-testnet.stellar.org", "mainnet": "https://horizon.stellar.org"}
PASSPHRASE = {"testnet": Network.TESTNET_NETWORK_PASSPHRASE, "mainnet": Network.PUBLIC_NETWORK_PASSPHRASE}


def public(value):
    try:
        Keypair.from_public_key(value)
    except Exception:
        raise argparse.ArgumentTypeError("Expected a public Stellar G address") from None
    return value


def signers(state):
    result = {}
    for entry in state["signers"]:
        key = entry["key"]
        if entry["type"] != "ed25519_public_key" or key in result:
            raise ValueError("Only unique Ed25519 signers are admitted")
        public(key)
        result[key] = entry["weight"]
    return result


def thresholds(state):
    t = state["thresholds"]
    return tuple(t[key] for key in ("low_threshold", "med_threshold", "high_threshold"))


def owner_only(state):
    """Admit a native master-key owner, never an agent/evaluator quorum."""
    account = public(state["account_id"])
    active = []
    for signer in state["signers"]:
        weight = signer["weight"]
        if type(weight) is not int or not 0 <= weight <= 255:
            raise ValueError("Invalid signer weight")
        if weight > 0:
            active.append(signer)
    if len(active) != 1 or active[0]["type"] != "ed25519_public_key" or active[0]["key"] != account:
        raise ValueError("Policy wallet owner must have only its master key active; delegated native quorums are unsafe")
    weight = active[0]["weight"]
    if any(type(t) is not int or not 0 <= t <= weight for t in thresholds(state)):
        raise ValueError("Owner thresholds must remain satisfiable by its master key")
    return account


def admin(state, members):
    members = [public(key) for key in members]
    if len(set(members)) != 3:
        raise ValueError("Three distinct admin members are required")
    expected = dict.fromkeys(members, 1)
    expected.setdefault(state["account_id"], 0)
    if signers(state) != expected or thresholds(state) != (2, 2, 2):
        raise ValueError("Account is not the exact three-member 2-of-3 profile")
    return expected


def fetch(network, account):
    with urlopen(HORIZON[network] + "/accounts/" + public(account), timeout=20) as response:
        state = json.load(response)
    if state["account_id"] != account:
        raise ValueError("Account response mismatch")
    return state
