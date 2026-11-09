//! Current native observations needed by owner workflows. These functions grant no signing authority.
use super::*;

/// An explicit nonnegative SEP-41 balance observed at a checked current ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetBalance {
    pub ledger: u32,
    pub amount: i128,
}
/// Exact lifetime of the selected wallet instance and executable, with the network's archival limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletLifetime {
    pub ledger: u32,
    pub max_entry_ttl: u32,
    pub instance_live_until: u32,
    pub code_live_until: u32,
}
impl WalletLifetime {
    /// The same maximum target used by the wallet's own instance/code renewal.
    pub fn extend_to(&self) -> Result<u32> {
        self.max_entry_ttl
            .checked_sub(1)
            .filter(|v| *v > 0)
            .ok_or_else(|| "Invalid network lifetime limit".into())
    }
    pub fn needs_renewal(&self) -> Result<bool> {
        let target = self.extend_to()?;
        let threshold = (target / 2).saturating_add(17_280).min(target);
        Ok(
            self.instance_live_until.saturating_sub(self.ledger) < threshold
                || self.code_live_until.saturating_sub(self.ledger) < threshold,
        )
    }
}
pub(crate) fn ledger(value: &Value) -> Result<u32> {
    value
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0)
        .ok_or_else(|| "Missing or invalid current ledger".into())
}
pub(crate) fn network(rpc: &dyn Rpc, selected: &str) -> Result<()> {
    if rpc.call("getNetwork", json!({}))?["passphrase"].as_str() != Some(passphrase(selected)?) {
        return Err("Owner observation RPC network differs".into());
    }
    Ok(())
}
pub(crate) fn head(rpc: &dyn Rpc) -> Result<u32> {
    ledger(&rpc.call("getLatestLedger", json!({}))?["sequence"])
}
/// The observation crossed more than one ledger, or the RPC ledgers disagree. A new
/// observation can succeed.
pub(crate) const STALE_OBSERVATION: &str =
    "Owner observation ledger is stale, future or inconsistent";
/// The most ledgers that an observation may trail the closing head. After the observed read,
/// a bracket makes up to two more RPC calls. A public RPC call can take as long as a ledger
/// close (about 5 s, slow calls near 8 s), so two calls can span 4 closes; one more ledger
/// absorbs an RPC node that trails its peers. The window is about 25 s.
pub(crate) const MAX_OBSERVATION_LAG: u32 = 5;
/// The closing head after an observation dated `observed`. The observation is current: it is
/// not older than the head read before it, not newer than the closing head and at most
/// [`MAX_OBSERVATION_LAG`] ledgers behind it.
pub(crate) fn current(rpc: &dyn Rpc, before: u32, observed: u32) -> Result<u32> {
    let after = head(rpc)?;
    if after < before
        || observed < before
        || observed > after
        || after.saturating_sub(observed) > MAX_OBSERVATION_LAG
    {
        return Err(STALE_OBSERVATION.into());
    }
    Ok(after)
}

/// Observe `balance(holder)` on the selected SEP-41 asset using an independent G simulation source.
/// Reject missing results, errors, requested authorizations, restoration, negative values and stale ledgers.
/// A zero balance must be an explicit native i128 zero. No transaction is signed or submitted.
/// Before reporting post-transaction funding, callers also require a ledger at or after their verified receipt.
pub fn asset_balance(
    rpc: &dyn Rpc,
    selected_network: &str,
    asset: &str,
    holder: &str,
    source: &str,
) -> Result<AssetBalance> {
    network(rpc, selected_network)?;
    Contract::from_string(asset).map_err(err)?;
    let holder = address(holder)?;
    let account = get_account(rpc, source)?;
    account.validate_structure()?;
    let before = head(rpc)?;
    let call = InvokeContractArgs {
        contract_address: address(asset)?,
        function_name: ScSymbol(b"balance".to_vec().try_into().map_err(err)?),
        args: vec![ScVal::Address(holder)].try_into().map_err(err)?,
    };
    let tx = Transaction {
        source_account: muxed(source)?,
        fee: 100,
        seq_num: SequenceNumber(
            account
                .sequence
                .checked_add(1)
                .ok_or("Simulation source sequence overflow")?,
        ),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: HostFunction::InvokeContract(call),
                auth: VecM::default(),
            }),
        }]
        .try_into()
        .map_err(err)?,
        ext: TransactionExt::V0,
    };
    let response=rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx,signatures:VecM::default()}))?}))?;
    reject_restoration(&response)?;
    let observed = ledger(&response["latestLedger"])?;
    let results = response["results"]
        .as_array()
        .ok_or("Missing native asset balance result")?;
    let [result] = results.as_slice() else {
        return Err("Expected one native asset balance result".into());
    };
    if result
        .get("auth")
        .and_then(Value::as_array)
        .is_none_or(|entries| !entries.is_empty())
    {
        return Err("Balance observation unexpectedly requests authorization".into());
    }
    let amount = wide(&readonly_result(&response)?)?;
    if amount < 0 {
        return Err("Native asset balance must be nonnegative".into());
    }
    current(rpc, before, observed)?;
    Ok(AssetBalance {
        ledger: observed,
        amount,
    })
}

pub(crate) fn lifetime_keys(wallet: &str, code: &[u8; 32]) -> Result<[LedgerKey; 2]> {
    Contract::from_string(wallet).map_err(err)?;
    if *code == [0; 32] {
        return Err("Selected wallet executable identity is missing".into());
    }
    Ok([
        LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(wallet)?,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        }),
        LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(*code) }),
    ])
}
/// Read and bind both selected lifetime entries and the exact current network archival limit.
/// Missing/expired entries require a separate restoration flow; they never become a zero lifetime.
pub fn wallet_lifetime(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Result<WalletLifetime> {
    network(rpc, selected_network)?;
    let [instance_key, code_key] = lifetime_keys(wallet, code)?;
    let config_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let keys = [config_key.clone(), instance_key.clone(), code_key.clone()];
    let encoded = keys.iter().map(xdr).collect::<Result<Vec<_>>>()?;
    let before = head(rpc)?;
    let response = rpc.call("getLedgerEntries", json!({"keys":encoded}))?;
    let observed = ledger(&response["latestLedger"])?;
    let entries = response["entries"]
        .as_array()
        .ok_or("Missing wallet lifetime entries")?;
    if entries.len() != 3 {
        return Err("Expected the archival setting and both wallet lifetime entries".into());
    }
    let mut max = None;
    let mut instance = None;
    let mut executable = None;
    for entry in entries {
        let data: LedgerEntryData =
            read(entry["xdr"].as_str().ok_or("Missing wallet lifetime XDR")?)?;
        let (expected, slot, ttl) = match data {
            LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) => {
                if max.replace(settings.max_entry_ttl).is_some() || settings.max_entry_ttl <= 1 {
                    return Err("Invalid or duplicate archival lifetime setting".into());
                }
                (&config_key, 0, None)
            }
            LedgerEntryData::ContractData(data)
                if data.contract == address(wallet)?
                    && data.key == ScVal::LedgerKeyContractInstance
                    && data.durability == ContractDataDurability::Persistent =>
            {
                let ScVal::ContractInstance(state) = data.val else {
                    return Err("Invalid selected wallet instance".into());
                };
                if state.executable != ContractExecutable::Wasm(Hash(*code)) {
                    return Err("Wallet lifetime instance names another executable".into());
                }
                (
                    &instance_key,
                    1,
                    Some(ledger(&entry["liveUntilLedgerSeq"])?),
                )
            }
            LedgerEntryData::ContractCode(data)
                if data.hash == Hash(*code) && hash(data.code.as_slice()) == *code =>
            {
                (&code_key, 2, Some(ledger(&entry["liveUntilLedgerSeq"])?))
            }
            _ => return Err("Wallet lifetime entry differs from the exact selected keys".into()),
        };
        if entry
            .get("key")
            .is_some_and(|key| key.as_str() != xdr(expected).ok().as_deref())
        {
            return Err("Wallet lifetime response ledger key differs".into());
        }
        match slot {
            1 if instance.replace(ttl.unwrap()).is_some() => {
                return Err("Duplicate wallet instance lifetime".into());
            }
            2 if executable.replace(ttl.unwrap()).is_some() => {
                return Err("Duplicate wallet code lifetime".into());
            }
            _ => {}
        }
    }
    let max = max.ok_or("Missing archival lifetime setting")?;
    let instance = instance.ok_or("Missing wallet instance lifetime")?;
    let code = executable.ok_or("Missing wallet code lifetime")?;
    if observed.checked_add(max - 1).is_none()
        || instance < observed
        || code < observed
        || instance - observed >= max
        || code - observed >= max
    {
        return Err("Wallet lifetime is expired or exceeds the network limit".into());
    }
    let closing = current(rpc, before, observed)?;
    if instance < closing || code < closing {
        return Err("Wallet lifetime expired before the closing observation".into());
    }
    Ok(WalletLifetime {
        ledger: observed,
        max_entry_ttl: max,
        instance_live_until: instance,
        code_live_until: code,
    })
}
