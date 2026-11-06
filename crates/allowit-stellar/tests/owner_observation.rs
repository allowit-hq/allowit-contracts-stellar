//! Native owner observations use independently built XDR and explicit malformed/stale RPC fixtures.
use allowit_stellar_wallet::{
    self as native,
    rpc::{self, Rpc},
};
use serde_json::{Value, json};
use std::sync::Mutex;
use stellar_xdr as x;
use x::{ReadXdr, WriteXdr};
fn account() -> String {
    native::account_for_seed(&[11; 32])
}
fn enc(value: &impl WriteXdr) -> String {
    value.to_xdr_base64(x::Limits::none()).unwrap()
}
fn address(value: &str) -> x::ScAddress {
    native::address(value).unwrap()
}
fn value(amount: i128) -> x::ScVal {
    x::ScVal::I128(x::Int128Parts {
        hi: (amount >> 64) as i64,
        lo: amount as u64,
    })
}
fn native_account() -> Value {
    let key = native::account_key(&account()).unwrap();
    let data = x::LedgerEntryData::Account(x::AccountEntry {
        account_id: x::AccountId(x::PublicKey::PublicKeyTypeEd25519(x::Uint256(key))),
        balance: 1_000_000_000,
        seq_num: x::SequenceNumber(41),
        num_sub_entries: 0,
        inflation_dest: None,
        flags: 0,
        home_domain: Default::default(),
        thresholds: x::Thresholds([1, 0, 0, 0]),
        signers: Default::default(),
        ext: x::AccountEntryExt::V0,
    });
    json!({"entries":[{"xdr":enc(&data)}]})
}
struct Balance {
    response: Value,
    passphrase: &'static str,
    heads: Mutex<Vec<u32>>,
    calls: Mutex<Vec<(String, Value)>>,
}
impl Balance {
    fn new(amount: i128) -> Self {
        Self {
            response: json!({"latestLedger":120,"results":[{"xdr":enc(&value(amount)),"auth":[]}]}),
            passphrase: "Test SDF Network ; September 2015",
            heads: Mutex::new(vec![120, 120]),
            calls: Mutex::new(vec![]),
        }
    }
}
impl Rpc for Balance {
    fn call(&self, method: &str, params: Value) -> native::Result<Value> {
        self.calls.lock().unwrap().push((method.into(), params));
        match method {
            "getNetwork" => Ok(json!({"passphrase":self.passphrase})),
            "getLedgerEntries" => Ok(native_account()),
            "getLatestLedger" => Ok(json!({"sequence":self.heads.lock().unwrap().remove(0)})),
            "simulateTransaction" => Ok(self.response.clone()),
            _ => Err("unexpected observation RPC".into()),
        }
    }
}
fn asset() -> String {
    native::sac_address("stellar:testnet", &x::Asset::Native).unwrap()
}
#[test]
fn balance_observes_explicit_zero_and_positive_i128_and_exact_unsigned_native_call() {
    for amount in [0, 17_000_001] {
        let rpc = Balance::new(amount);
        let observed = rpc::asset_balance(
            &rpc,
            "stellar:testnet",
            &asset(),
            &stellar_strkey::Contract([9; 32]).to_string(),
            &account(),
        )
        .unwrap();
        assert_eq!(observed.amount, amount);
        assert_eq!(observed.ledger, 120);
        let calls = rpc.calls.lock().unwrap();
        let params = &calls
            .iter()
            .find(|(method, _)| method == "simulateTransaction")
            .unwrap()
            .1;
        let x::TransactionEnvelope::Tx(envelope) = x::TransactionEnvelope::from_xdr_base64(
            params["transaction"].as_str().unwrap(),
            x::Limits::none(),
        )
        .unwrap() else {
            panic!()
        };
        assert!(envelope.signatures.is_empty());
        assert_eq!(
            envelope.tx.source_account,
            x::MuxedAccount::Ed25519(x::Uint256(native::account_key(&account()).unwrap()))
        );
        assert_eq!(envelope.tx.seq_num.0, 42);
        let [op] = envelope.tx.operations.as_slice() else {
            panic!()
        };
        assert!(op.source_account.is_none());
        let x::OperationBody::InvokeHostFunction(op) = &op.body else {
            panic!()
        };
        assert!(op.auth.is_empty());
        let x::HostFunction::InvokeContract(call) = &op.host_function else {
            panic!()
        };
        assert_eq!(call.contract_address, address(&asset()));
        assert_eq!(call.function_name.0.as_slice(), b"balance");
        assert_eq!(
            call.args.as_slice(),
            [x::ScVal::Address(address(
                &stellar_strkey::Contract([9; 32]).to_string()
            ))]
        );
        assert!(!calls.iter().any(|(method, _)| method == "sendTransaction"));
    }
}
#[test]
fn missing_malformed_authorized_restored_and_stale_balances_never_become_zero() {
    for variant in 0..13 {
        let mut rpc = Balance::new(0);
        match variant {
            0 => rpc.response["results"] = json!([]),
            1 => rpc.response["results"][0]["xdr"] = json!(enc(&x::ScVal::U64(0))),
            2 => rpc.response["results"][0]["xdr"] = json!(enc(&value(-1))),
            3 => rpc.response["results"][0]["auth"] = json!(["unexpected"]),
            4 => {
                rpc.response["results"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("auth");
            }
            5 => {
                rpc.response["restorePreamble"] =
                    json!({"minResourceFee":"1","transactionData":"unknown"})
            }
            6 => rpc.response["error"] = json!("native contract error"),
            7 => {
                rpc.response.as_object_mut().unwrap().remove("latestLedger");
            }
            8 => rpc.response["latestLedger"] = json!(119),
            9 => rpc.response["latestLedger"] = json!(121),
            10 => *rpc.heads.lock().unwrap() = vec![120, 119],
            11 => *rpc.heads.lock().unwrap() = vec![120, 122],
            _ => rpc.response["results"][0]["xdr"] = json!("malformed"),
        }
        assert!(
            rpc::asset_balance(&rpc, "stellar:testnet", &asset(), &account(), &account()).is_err(),
            "variant {variant}"
        );
    }
    let mut rpc = Balance::new(1);
    rpc.passphrase = "Public Global Stellar Network ; September 2015";
    assert!(rpc::asset_balance(&rpc, "stellar:testnet", &asset(), &account(), &account()).is_err());
    assert!(
        !rpc.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(m, _)| m == "simulateTransaction")
    );
}
fn wallet() -> String {
    stellar_strkey::Contract([9; 32]).to_string()
}
fn lifetime_entries() -> ([u8; 32], Value) {
    let code = b"explicit reviewed code fixture".to_vec();
    let hash = native::hash(&code);
    let archival = x::LedgerEntryData::ConfigSetting(x::ConfigSettingEntry::StateArchival(
        x::StateArchivalSettings {
            max_entry_ttl: 1000,
            ..Default::default()
        },
    ));
    let instance = x::LedgerEntryData::ContractData(x::ContractDataEntry {
        ext: x::ExtensionPoint::V0,
        contract: address(&wallet()),
        key: x::ScVal::LedgerKeyContractInstance,
        durability: x::ContractDataDurability::Persistent,
        val: x::ScVal::ContractInstance(x::ScContractInstance {
            executable: x::ContractExecutable::Wasm(x::Hash(hash)),
            storage: None,
        }),
    });
    let executable = x::LedgerEntryData::ContractCode(x::ContractCodeEntry {
        ext: x::ContractCodeEntryExt::V0,
        hash: x::Hash(hash),
        code: code.try_into().unwrap(),
    });
    (
        hash,
        json!({"latestLedger":120,"entries":[{"xdr":enc(&executable),"liveUntilLedgerSeq":1119},{"xdr":enc(&archival)},{"xdr":enc(&instance),"liveUntilLedgerSeq":520}]}),
    )
}
struct Lifetime {
    entries: Value,
    head: u32,
}
impl Rpc for Lifetime {
    fn call(&self, method: &str, params: Value) -> native::Result<Value> {
        match method {
            "getNetwork" => Ok(json!({"passphrase":"Test SDF Network ; September 2015"})),
            "getLatestLedger" => Ok(json!({"sequence":self.head})),
            "getLedgerEntries" => {
                assert_eq!(params["keys"].as_array().unwrap().len(), 3);
                Ok(self.entries.clone())
            }
            _ => Err("unexpected lifetime RPC".into()),
        }
    }
}
#[test]
fn lifetime_reads_exact_shuffled_entries_and_relative_maximum_without_absolute_ledger_confusion() {
    let (hash, entries) = lifetime_entries();
    let rpc = Lifetime { entries, head: 120 };
    let result = rpc::wallet_lifetime(&rpc, "stellar:testnet", &wallet(), &hash).unwrap();
    assert_eq!(result.ledger, 120);
    assert_eq!(result.extend_to().unwrap(), 999);
    assert_ne!(result.extend_to().unwrap(), 1119);
    assert_eq!(result.instance_live_until, 520);
    assert_eq!(result.code_live_until, 1119);
    assert!(result.needs_renewal().unwrap());
    let at_max = rpc::WalletLifetime {
        instance_live_until: 1119,
        ..result
    };
    assert!(!at_max.needs_renewal().unwrap());
}
#[test]
fn lifetime_rejects_missing_expired_foreign_duplicate_and_inconsistent_entries() {
    for variant in 0..7 {
        let (hash, mut entries) = lifetime_entries();
        match variant {
            0 => {
                entries["entries"].as_array_mut().unwrap().pop();
            }
            1 => entries["entries"][2]["liveUntilLedgerSeq"] = json!(119),
            2 => entries["entries"][0]["liveUntilLedgerSeq"] = json!(1120),
            3 => entries["entries"][0]["key"] = json!("other-key"),
            4 => entries["entries"][2] = entries["entries"][0].clone(),
            5 => entries["latestLedger"] = json!(119),
            _ => entries["entries"][0]["xdr"] = json!("malformed"),
        };
        let rpc = Lifetime { entries, head: 120 };
        assert!(
            rpc::wallet_lifetime(&rpc, "stellar:testnet", &wallet(), &hash).is_err(),
            "variant {variant}"
        );
    }
}
