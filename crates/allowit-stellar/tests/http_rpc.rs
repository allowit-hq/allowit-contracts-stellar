//! Native protocol adapter coverage through actual loopback HTTP.
use allowit_stellar_wallet::rpc::{HttpRpc, Rpc};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

fn request(stream: &mut TcpStream) -> Value {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        assert!(headers.len() < 16_384);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).unwrap();
    assert!(headers.starts_with("POST /rpc HTTP/1.1\r\n"));
    let length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, v)| v.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length < 2_097_152);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}
fn reply(stream: &mut TcpStream, body: &[u8]) {
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(body);
}
fn with_reply(
    response: impl FnOnce(Value) -> Value + Send + 'static,
) -> (HttpRpc, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}/rpc", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let value = request(&mut stream);
        reply(&mut stream, &serde_json::to_vec(&response(value)).unwrap());
    });
    (HttpRpc::new(&endpoint).unwrap(), task)
}

#[test]
fn native_error_results_and_exact_auth_tree_payloads_are_preserved() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/stellar-policy-wallet-revalidation-rpc.json"
    ))
    .unwrap();
    let params = fixture["calls"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["method"] == "simulateTransaction")
        .max_by_key(|v| v["params"]["transaction"].as_str().unwrap().len())
        .unwrap()["params"]
        .clone();
    assert!(params["transaction"].as_str().unwrap().len() > 1_000);
    for result in [
        json!({"error":"HostError: Error(Contract, #101)","events":[]}),
        json!({"error":"FeeTooLow","minResourceFee":"2645894"}),
    ] {
        let expected_params = params.clone();
        let expected_result = result.clone();
        let (client, task) = with_reply(move |body| {
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], 1);
            assert_eq!(body["method"], "simulateTransaction");
            assert_eq!(body["params"], expected_params);
            json!({"jsonrpc":"2.0","id":body["id"],"result":expected_result})
        });
        assert_eq!(
            client.call("simulateTransaction", params.clone()).unwrap(),
            result
        );
        task.join().unwrap();
    }
}

#[test]
fn malformed_envelopes_and_top_level_rpc_refusals_do_not_become_results() {
    for response in [
        json!({"jsonrpc":"2.0","id":2,"result":{}}),
        json!({"jsonrpc":"1.0","id":1,"result":{}}),
        json!({"jsonrpc":"2.0","id":1,"result":{},"error":null}),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"native refusal"}}),
        json!({"jsonrpc":"2.0","id":1}),
    ] {
        let label = response.to_string();
        let (client, task) = with_reply(move |_| response);
        assert!(client.call("getNetwork", json!({})).is_err(), "{label}");
        task.join().unwrap();
    }
}

#[test]
fn bounded_response_and_lost_send_never_trigger_an_automatic_write_retry() {
    let (client, task) =
        with_reply(|_| json!({"jsonrpc":"2.0","id":1,"result":"x".repeat(1_048_576)}));
    assert!(
        client
            .call("getLedgerEntries", json!({}))
            .unwrap_err()
            .contains("exceeds limit")
    );
    task.join().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = HttpRpc::new(&format!("http://{}/rpc", listener.local_addr().unwrap())).unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let body = request(&mut stream);
        assert_eq!(body["method"], "sendTransaction");
        drop(stream);
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(150);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok(_) => panic!("ambiguous write was automatically retried"),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("{e}"),
            }
        }
    });
    assert!(
        client
            .call(
                "sendTransaction",
                json!({"transaction":"original-signed-bytes"})
            )
            .unwrap_err()
            .contains("unknown")
    );
    task.join().unwrap();
}

#[test]
fn common_endpoint_rules_preserve_the_native_https_or_exact_loopback_boundary() {
    for endpoint in [
        "http://stellar.example/rpc",
        "http://127.0.0.2/rpc",
        "https://user:secret@stellar.example/rpc",
        "https://stellar.example/rpc#fragment",
    ] {
        assert!(HttpRpc::new(endpoint).is_err(), "{endpoint}");
    }
    for endpoint in [
        "https://stellar.example/rpc",
        "http://127.0.0.1:1234/rpc",
        "http://localhost:1234/rpc",
        "http://127.1:1234/rpc",
        "http://[::1]:1234/rpc",
    ] {
        HttpRpc::new(endpoint).unwrap();
    }
}
