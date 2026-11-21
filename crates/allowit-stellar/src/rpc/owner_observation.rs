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
/// The refusal of a lifetime read whose instance runs other code than the code that was asked
/// for: the wallet's owner installed that code outside Allowit.
pub const OTHER_EXECUTABLE: &str = "Wallet lifetime instance names another executable";
/// A live-until ledger as an entry's lifetime reply gives it: 0 for an archived entry served
/// without one.
fn live_until(value: &Value) -> Result<u32> {
    match value {
        Value::Null => Ok(0),
        value if value.as_u64() == Some(0) => Ok(0),
        value => ledger(value),
    }
}
/// The lifetime entries of a wallet as one current reply gives them, with no judgement of a
/// lapse: the last live ledger of the instance and of the code that was asked for, 0 for an
/// archived entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifetimeEntries {
    /// The ledger of the reply.
    pub ledger: u32,
    /// The head that closed the read: at or after `ledger`, by at most [`MAX_OBSERVATION_LAG`].
    pub closing: u32,
    pub max_entry_ttl: u32,
    pub instance_live_until: u32,
    pub code_live_until: u32,
}
/// What one current reply says of a wallet's lifetime entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifetimeRead {
    /// The instance runs the code that was asked for: both entries, of one ledger.
    Entries(LifetimeEntries),
    /// The instance runs other code than the code that was asked for: its own entry alone, of
    /// the reply's ledger. The reply says nothing of the lifetime of the code that it runs.
    OtherExecutable {
        ledger: u32,
        instance_live_until: u32,
    },
}
/// One entry of a lifetime reply after its validating decode.
struct ValidEntry {
    data: LedgerEntryData,
    /// The key that the reply gives for the entry, when it gives one.
    key: Option<String>,
    /// The entry's last live ledger; 0 for an archived entry and for an entry without a lifetime,
    /// as the network's setting.
    live_until: u32,
}
/// The validating decode of a lifetime reply: its ledger, the network's archival limit that it
/// holds, and its entries. Every entry of every lifetime reply passes it before any caller
/// sees the entry, and nothing else reads an entry of such a reply. An entry is valid only with
/// all of: its change ledger; a change ledger that is not after the reply's ledger; a change
/// ledger that is not after the entry's last live ledger; a last live ledger within the
/// network's limit, counted from the reply's ledger. A reply with an entry that fails is an
/// invalid reply: an error, never a decision.
fn valid_lifetime_reply(response: &Value) -> Result<(u32, u32, Vec<ValidEntry>)> {
    let observed = ledger(&response["latestLedger"])?;
    let listed = response["entries"]
        .as_array()
        .ok_or("Missing wallet lifetime entries")?;
    if listed.len() > 3 {
        return Err("Expected the archival setting and both wallet lifetime entries".into());
    }
    let mut max = None;
    let mut entries = Vec::new();
    for entry in listed {
        let changed = match entry.get("lastModifiedLedgerSeq") {
            Some(changed) if !changed.is_null() => ledger(changed)?,
            _ => return Err("Wallet lifetime entry has no change ledger".into()),
        };
        if changed > observed {
            return Err("Wallet lifetime entry is newer than its reply".into());
        }
        let live_until = live_until(&entry["liveUntilLedgerSeq"])?;
        // An entry is live at the ledger that changes it. An archived entry and an entry
        // without a lifetime have no last live ledger.
        if live_until > 0 && changed > live_until {
            return Err("Wallet lifetime entry changed after its last live ledger".into());
        }
        let data: LedgerEntryData =
            read(entry["xdr"].as_str().ok_or("Missing wallet lifetime XDR")?)?;
        if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) = &data
            && (max.replace(settings.max_entry_ttl).is_some() || settings.max_entry_ttl <= 1)
        {
            return Err("Invalid or duplicate archival lifetime setting".into());
        }
        entries.push(ValidEntry {
            data,
            key: entry
                .get("key")
                .map(|key| key.as_str().unwrap_or("").into()),
            live_until,
        });
    }
    let max = max.ok_or("Missing archival lifetime setting")?;
    let beyond = |entry: &ValidEntry| entry.live_until.saturating_sub(observed) >= max;
    if observed.checked_add(max - 1).is_none() || entries.iter().any(beyond) {
        return Err("Wallet lifetime exceeds the network limit".into());
    }
    Ok((observed, max, entries))
}
/// Read the instance of `wallet`, the entry of `code` and the network's archival limit in one
/// reply, and bind each returned entry to the key that was asked for. Every entry passes the
/// validating decode first ([`valid_lifetime_reply`]). The reply is current ([`current`]) before
/// it decides anything: a reply that is older than the head before it, or that trails the
/// closing head by more than [`MAX_OBSERVATION_LAG`], is a stale observation. A missing entry
/// and an entry of another key are errors of their own. Nothing here says that an entry lapsed:
/// the caller compares the last live ledgers with the ledger that it decides for.
pub fn lifetime_read(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Result<LifetimeRead> {
    network(rpc, selected_network)?;
    let [instance_key, code_key] = lifetime_keys(wallet, code)?;
    let config_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let keys = [config_key.clone(), instance_key.clone(), code_key.clone()];
    let encoded = keys.iter().map(xdr).collect::<Result<Vec<_>>>()?;
    let before = head(rpc)?;
    let response = rpc.call("getLedgerEntries", json!({"keys":encoded}))?;
    let (observed, max, entries) = valid_lifetime_reply(&response)?;
    let mut setting = false;
    let mut instance = None;
    let mut executable = None;
    let mut other = false;
    for entry in entries {
        let (expected, slot) = match entry.data {
            LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(_)) => {
                setting = true;
                (&config_key, 0)
            }
            LedgerEntryData::ContractData(data)
                if data.contract == address(wallet)?
                    && data.key == ScVal::LedgerKeyContractInstance
                    && data.durability == ContractDataDurability::Persistent =>
            {
                let ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash(running)),
                    ..
                }) = data.val
                else {
                    return Err("Invalid selected wallet instance".into());
                };
                other = running != *code;
                (&instance_key, 1)
            }
            LedgerEntryData::ContractCode(data)
                if data.hash == Hash(*code) && hash(data.code.as_slice()) == *code =>
            {
                (&code_key, 2)
            }
            _ => return Err("Wallet lifetime entry differs from the exact selected keys".into()),
        };
        if entry
            .key
            .is_some_and(|key| Some(key.as_str()) != xdr(expected).ok().as_deref())
        {
            return Err("Wallet lifetime response ledger key differs".into());
        }
        match slot {
            1 if instance.replace(entry.live_until).is_some() => {
                return Err("Duplicate wallet instance lifetime".into());
            }
            2 if executable.replace(entry.live_until).is_some() => {
                return Err("Duplicate wallet code lifetime".into());
            }
            _ => {}
        }
    }
    if !setting {
        return Err("Missing archival lifetime setting".into());
    }
    let instance = instance.ok_or("Missing wallet instance lifetime")?;
    let closing = current(rpc, before, observed)?;
    if other {
        // The code that was asked for is not the wallet's: its entry, present or not, says
        // nothing of the wallet.
        return Ok(LifetimeRead::OtherExecutable {
            ledger: observed,
            instance_live_until: instance,
        });
    }
    let code = executable.ok_or("Missing wallet code lifetime")?;
    Ok(LifetimeRead::Entries(LifetimeEntries {
        ledger: observed,
        closing,
        max_entry_ttl: max,
        instance_live_until: instance,
        code_live_until: code,
    }))
}
/// Read and bind both selected lifetime entries and the exact current network archival limit
/// ([`lifetime_read`]). A wallet whose instance or code is past its lifetime at the head that
/// closes the read is refused with `CONTRACT_EXPIRED`: nothing restores it. An archived entry
/// that the RPC serves without a live-until ledger has lapsed. A wallet whose instance runs other
/// code is [`OTHER_EXECUTABLE`].
pub fn wallet_lifetime(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Result<WalletLifetime> {
    let entries = match lifetime_read(rpc, selected_network, wallet, code)? {
        LifetimeRead::Entries(entries) => entries,
        LifetimeRead::OtherExecutable { .. } => return Err(OTHER_EXECUTABLE.into()),
    };
    if entries.instance_live_until < entries.closing || entries.code_live_until < entries.closing {
        return Err(super::CONTRACT_EXPIRED.into());
    }
    Ok(WalletLifetime {
        ledger: entries.ledger,
        max_entry_ttl: entries.max_entry_ttl,
        instance_live_until: entries.instance_live_until,
        code_live_until: entries.code_live_until,
    })
}
