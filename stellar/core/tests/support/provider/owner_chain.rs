//! Generic loopback and caller wiring around native-owned owner fixtures.
#![allow(dead_code)]
use super::wire;
use crate as native;
use crate::provider::runtime::owner_client::OwnerSigner;
pub(crate) use crate::test_support::owner::*;
use native::rpc::Rpc;
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
pub(crate) struct Key<'a> {
    pub(crate) calls: AtomicUsize,
    pub(crate) bad: bool,
    pub(crate) before: Option<&'a dyn Fn()>,
}
impl OwnerSigner for Key<'_> {
    fn account(&self) -> &str {
        std::sync::OnceLock::get_or_init(&OWNER_ACCOUNT, || account(11))
    }
    fn sign_hash(&self, digest: &[u8; 32]) -> native::Result<[u8; 64]> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = self.before {
            f();
        }
        Ok(if self.bad {
            [0; 64]
        } else {
            native::test_support::sign_digest([11; 32], digest)
        })
    }
}
static OWNER_ACCOUNT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
pub(crate) fn key() -> Key<'static> {
    Key {
        calls: AtomicUsize::new(0),
        bad: false,
        before: None,
    }
}

pub(crate) struct Chain {
    ledger: native::test_support::owner::OwnerLedger,
    pub(crate) server: Option<Arc<Mutex<wire::State>>>,
}
impl Chain {
    pub(crate) fn new(config: native::WalletConfig) -> Self {
        Self {
            ledger: native::test_support::owner::OwnerLedger::new(config),
            server: None,
        }
    }
}
impl std::ops::Deref for Chain {
    type Target = native::test_support::owner::OwnerLedger;
    fn deref(&self) -> &Self::Target {
        &self.ledger
    }
}
impl std::ops::DerefMut for Chain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ledger
    }
}
impl Rpc for Chain {
    fn call(&self, method: &str, params: Value) -> native::Result<Value> {
        let submissions = self
            .server
            .as_ref()
            .map(|state| state.lock().unwrap().owner_submissions.clone())
            .unwrap_or_default();
        self.ledger.call(method, params, &submissions)
    }
}
/// The CLI exercises actual Core HTTP/RPC against the synthetic native fixture.
pub(crate) struct RpcServer {
    pub(crate) url: String,
    pub(crate) chain: Arc<Chain>,
    pub(crate) stop: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) task: Option<std::thread::JoinHandle<()>>,
}
impl RpcServer {
    pub(crate) fn new(chain: Chain) -> Self {
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
            time::Duration,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let chain = Arc::new(chain);
        let actor = chain.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let quitting = stop.clone();
        let task = thread::spawn(move || {
            while !quitting.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut headers = vec![];
                while !headers.ends_with(b"\r\n\r\n") {
                    assert!(headers.len() < 16_384);
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    headers.push(b[0]);
                }
                let headers = String::from_utf8(headers).unwrap();
                let len = headers
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                    .unwrap()
                    .1
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).unwrap();
                let request: Value = serde_json::from_slice(&body).unwrap();
                let result = actor.call(
                    request["method"].as_str().unwrap(),
                    request["params"].clone(),
                );
                let value = match result {
                    Ok(result) => json!({"jsonrpc":"2.0","id":request["id"],"result":result}),
                    Err(message) => {
                        json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":message}})
                    }
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        Self {
            url,
            chain,
            stop,
            task: Some(task),
        }
    }
}
impl Drop for RpcServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let done = self.task.take().unwrap().join();
        if !std::thread::panicking() {
            done.expect("native RPC fixture failed");
        }
    }
}
