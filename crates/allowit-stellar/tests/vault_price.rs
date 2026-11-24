//! The `price` evidence function on a SEP-56 vault, through a fixture Stellar RPC on loopback
//! HTTP: the host names its RPC in `facts.rpc`, and every read is a read-only simulation.
use allowit_stellar::{provider::price, read, xdr};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use stellar_xdr::{HostFunction, Int128Parts, OperationBody, ScVal, TransactionEnvelope};

const NETWORK: &str = "stellar:testnet";

fn request(stream: &mut TcpStream) -> Value {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn i128(v: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (v >> 64) as i64,
        lo: v as u64,
    })
}

/// A fixture RPC for a vault whose share is worth 0.94 of its asset, and a holder of 100
/// shares. It answers `requests` calls and records the contract functions it was asked.
fn fixture(
    asset: String,
    requests: usize,
) -> (String, Arc<Mutex<Vec<String>>>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/rpc", listener.local_addr().unwrap());
    let asked = Arc::new(Mutex::new(Vec::new()));
    let log = asked.clone();
    let task = thread::spawn(move || {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let call = request(&mut stream);
            let result = match call["method"].as_str().unwrap() {
                "getNetwork" => json!({"passphrase": "Test SDF Network ; September 2015"}),
                "getLatestLedger" => {
                    json!({"id": "00", "protocolVersion": 30, "sequence": 5795932, "closeTime": "1795003303"})
                }
                "simulateTransaction" => {
                    let envelope: TransactionEnvelope =
                        read(call["params"]["transaction"].as_str().unwrap()).unwrap();
                    let TransactionEnvelope::Tx(envelope) = envelope else {
                        panic!("a version 1 envelope")
                    };
                    let OperationBody::InvokeHostFunction(op) = &envelope.tx.operations[0].body
                    else {
                        panic!("one contract call")
                    };
                    let HostFunction::InvokeContract(c) = &op.host_function else {
                        panic!("one contract call")
                    };
                    let function = String::from_utf8(c.function_name.0.to_vec()).unwrap();
                    log.lock().unwrap().push(function.clone());
                    let value = match function.as_str() {
                        "query_asset" => ScVal::Address(allowit_stellar::address(&asset).unwrap()),
                        "decimals" => ScVal::U32(7),
                        "preview_redeem" => {
                            let ScVal::I128(p) = &c.args[0] else {
                                panic!("shares")
                            };
                            i128(((i128::from(p.hi) << 64) | i128::from(p.lo)) * 94 / 100)
                        }
                        "balance" => i128(1_000_000_000),
                        other => panic!("unexpected read {other}"),
                    };
                    json!({"latestLedger": 5795931, "results": [{"auth": [], "xdr": xdr(&value).unwrap()}]})
                }
                other => panic!("unexpected method {other}"),
            };
            let body =
                serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": call["id"], "result": result}))
                    .unwrap();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(&body);
        }
    });
    (endpoint, asked, task)
}

#[test]
#[cfg_attr(not(feature = "e2e"), ignore = "end-to-end: run with --features e2e")]
fn the_price_of_a_vault_share_and_a_holders_position_come_from_the_vault_itself() {
    let asset = allowit_stellar::sac_address(NETWORK, &stellar_xdr::Asset::Native).unwrap();
    let vault = stellar_strkey::Contract([9; 32]).to_string();
    let holder = stellar_strkey::ed25519::PublicKey([3; 32]).to_string();
    // Each read checks the network first: query_asset, decimals, preview_redeem, balance and
    // the holder's preview_redeem, then the ledger time.
    let (endpoint, asked, task) = fixture(asset.clone(), 11);
    let seen = price::price(
        &json!({"network": NETWORK, "from": vault, "to": "native", "holder": holder}),
        &json!({"network": NETWORK, "rpc": endpoint}),
    )
    .unwrap();
    task.join().unwrap();
    assert_eq!(seen["price"], "9400000");
    assert_eq!(seen["depth"], "10000000");
    assert_eq!(seen["observedAt"], 1_795_003_303u64);
    assert_eq!(seen["vault"]["asset"], asset);
    assert_eq!(seen["vault"]["assetCode"], "XLM");
    assert_eq!(seen["vault"]["held"], "1000000000");
    assert_eq!(seen["vault"]["heldValue"], "940000000");
    assert_eq!(
        asked.lock().unwrap().as_slice(),
        [
            "query_asset",
            "decimals",
            "preview_redeem",
            "balance",
            "preview_redeem"
        ]
    );
}
