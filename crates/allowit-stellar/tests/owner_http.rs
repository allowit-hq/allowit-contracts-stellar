//! Native Horizon and Friendbot semantics over the common HTTP transport.
use allowit_stellar_wallet::{account_for_seed, owner, passphrase};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn service(replies: Vec<(String, Value)>) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        for (path, value) in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 16_384);
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            assert!(
                String::from_utf8(request)
                    .unwrap()
                    .starts_with(&format!("GET {path} HTTP/1.1\r\n"))
            );
            let body = serde_json::to_vec(&value).unwrap();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (origin, task)
}

#[test]
fn horizon_requires_the_testnet_identity_and_fresh_owner_authority() {
    let owner = account_for_seed(&[1; 32]);
    let state = json!({"account_id":owner,"sequence":"42","subentry_count":0,
        "signers":[{"key":owner,"type":"ed25519_public_key","weight":1}],
        "thresholds":{"low_threshold":0,"med_threshold":0,"high_threshold":0}});
    for field in [
        None,
        Some("account_id"),
        Some("subentry_count"),
        Some("thresholds"),
    ] {
        let mut value = state.clone();
        match field {
            Some("account_id") => value["account_id"] = json!(account_for_seed(&[2; 32])),
            Some("subentry_count") => value["subentry_count"] = json!(1),
            Some("thresholds") => value["thresholds"]["high_threshold"] = json!(1),
            _ => {}
        }
        let (origin, task) = service(vec![
            (
                "/".into(),
                json!({"network_passphrase":passphrase("stellar:testnet").unwrap()}),
            ),
            (format!("/accounts/{owner}"), value),
        ]);
        let result = owner::fresh_testnet_owner_account(&owner, Some(&origin));
        if field.is_none() {
            let state = result.unwrap();
            assert_eq!(state.sequence, 42);
            owner::check_fresh(&state).unwrap();
        } else {
            assert!(result.is_err());
        }
        task.join().unwrap();
    }
    let (origin, task) = service(vec![(
        "/".into(),
        json!({"network_passphrase":passphrase("stellar:mainnet").unwrap()}),
    )]);
    assert!(
        owner::fresh_testnet_owner_account(&owner, Some(&origin))
            .unwrap_err()
            .contains("network differs")
    );
    task.join().unwrap();
}

#[test]
fn friendbot_accepts_only_an_actual_native_transaction_hash() {
    let account = account_for_seed(&[1; 32]);
    for (value, accepted) in [
        (json!({"hash":"ab".repeat(32)}), true),
        (json!({"hash":"not-a-hash"}), false),
        (json!({"successful":true}), false),
    ] {
        let (origin, task) = service(vec![(format!("/?addr={account}"), value)]);
        let result = owner::fund_testnet_account(&account, Some(&origin));
        assert_eq!(result.is_ok(), accepted);
        task.join().unwrap();
    }
}
