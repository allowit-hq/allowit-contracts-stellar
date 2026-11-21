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
    /// Whether the validating decode found the instance and the code live at `ledger`.
    pub instance_live: bool,
    pub code_live: bool,
}
/// What one current reply says of a wallet's lifetime entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifetimeRead {
    /// The instance runs the code that was asked for: both entries, of one ledger.
    Entries(LifetimeEntries),
    /// The instance runs other code than the code that was asked for: its own entry alone,
    /// live or not at the reply's ledger by the validating decode. The reply says nothing of
    /// the lifetime of the code that it runs.
    OtherExecutable { instance_live: bool },
}
/// What the validating decode says of an entry with a lifetime, at the reply's ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    /// Live at the reply's ledger.
    Live,
    /// Past its lifetime at the reply's ledger, or archived.
    Archived,
}
/// One entry of a lifetime reply after its validating decode.
struct ValidEntry {
    data: LedgerEntryData,
    /// The key that the reply gives for the entry, when it gives one.
    key: Option<String>,
    /// The entry's last live ledger; 0 for an archived entry and for an entry without a lifetime,
    /// as the network's setting.
    live_until: u32,
    /// `None` for the network's setting, which has no lifetime.
    life: Option<Life>,
}
/// The validating decode of a lifetime reply: its ledger, the network's archival limit that it
/// holds, and its entries. Every entry of every lifetime reply passes it before any caller
/// sees the entry, and nothing else reads an entry of such a reply. An entry is valid only with
/// all of: its change ledger; a change ledger that is not after the reply's ledger; a change
/// ledger that is not after the entry's last live ledger; a last live ledger within the
/// network's limit, counted from the reply's ledger. An entry with a lifetime is then live at
/// the reply's ledger, or archived: past its last live ledger there, or without one. A reply
/// with an entry that fails is an invalid reply: an error, never a decision. The truth table of
/// the test module `decode_table` states every row, and the decode says nothing else.
fn valid_lifetime_reply(response: &Value) -> Result<(u32, u32, Vec<ValidEntry>)> {
    // An invalid reply keeps its kind for every caller: an uncertain error at the rail's
    // boundary, at a preparation as at a send.
    decoded_lifetime_reply(response).map_err(|invalid| format!("{INVALID_REPLY}: {invalid}"))
}
/// The first words of the error of an invalid lifetime reply ([`valid_lifetime_reply`]).
pub const INVALID_REPLY: &str = "Invalid wallet lifetime reply";
fn decoded_lifetime_reply(response: &Value) -> Result<(u32, u32, Vec<ValidEntry>)> {
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
        // Zero stands for no last live ledger, as a missing or null one does.
        let live_until = live_until(&entry["liveUntilLedgerSeq"])?;
        let data: LedgerEntryData =
            read(entry["xdr"].as_str().ok_or("Missing wallet lifetime XDR")?)?;
        if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) = &data
            && (max.replace(settings.max_entry_ttl).is_some() || settings.max_entry_ttl <= 1)
        {
            return Err("Invalid or duplicate archival lifetime setting".into());
        }
        // The rows of the decode's truth table (`decode_table`), in its order.
        let life = match &data {
            // The network's setting has no lifetime.
            LedgerEntryData::ConfigSetting(_) if live_until > 0 => {
                return Err("The archival setting has a last live ledger".into());
            }
            LedgerEntryData::ConfigSetting(_) => None,
            // An entry is live at the ledger that changes it: without a last live ledger it
            // cannot have changed at the reply's own ledger.
            _ if live_until == 0 && changed == observed => {
                return Err("Wallet lifetime entry changed at its reply's ledger and has no last live ledger".into());
            }
            _ if live_until == 0 => Some(Life::Archived),
            _ if changed > live_until => {
                return Err("Wallet lifetime entry changed after its last live ledger".into());
            }
            _ if live_until >= observed => Some(Life::Live),
            _ => Some(Life::Archived),
        };
        entries.push(ValidEntry {
            data,
            key: entry
                .get("key")
                .map(|key| key.as_str().unwrap_or("").into()),
            live_until,
            life,
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
            1 if instance.replace((entry.live_until, entry.life)).is_some() => {
                return Err("Duplicate wallet instance lifetime".into());
            }
            2 if executable.replace((entry.live_until, entry.life)).is_some() => {
                return Err("Duplicate wallet code lifetime".into());
            }
            _ => {}
        }
    }
    if !setting {
        return Err("Missing archival lifetime setting".into());
    }
    let (instance, instance_life) = instance.ok_or("Missing wallet instance lifetime")?;
    let closing = current(rpc, before, observed)?;
    let live = |life: Option<Life>| life == Some(Life::Live);
    if other {
        // The code that was asked for is not the wallet's: its entry, present or not, says
        // nothing of the wallet.
        return Ok(LifetimeRead::OtherExecutable {
            instance_live: live(instance_life),
        });
    }
    let (code, code_life) = executable.ok_or("Missing wallet code lifetime")?;
    Ok(LifetimeRead::Entries(LifetimeEntries {
        ledger: observed,
        closing,
        max_entry_ttl: max,
        instance_live_until: instance,
        code_live_until: code,
        instance_live: live(instance_life),
        code_live: live(code_life),
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

#[cfg(test)]
mod decode_table {
    //! The truth table of the validating decode of a lifetime reply. The table is the test's
    //! data: the decode is correct when every row passes, and a row that is not here does not
    //! exist. The reply is of ledger 120, and the network's limit is 1,000 ledgers, so the last
    //! valid last live ledger is 1,119.
    use super::*;
    const LEDGER: u32 = 120;
    const LIMIT: u32 = 1_000;
    /// A field of an entry as a reply can give it.
    #[derive(Clone, Copy, Debug)]
    enum Field {
        Absent,
        Null,
        At(u32),
        Text,
    }
    use Field::{Absent, At, Null, Text};
    /// What the decode says of a row.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Says {
        Live,
        Archived,
        /// The reply is invalid: an error, never a decision.
        Invalid,
        /// The network's setting is valid; it has no lifetime.
        Setting,
    }
    /// An entry with a lifetime, the wallet's instance or its code: its change ledger, its last
    /// live ledger, and what the decode says.
    const WITH_LIFETIME: &[(&str, Field, Field, Says)] = &[
        // No change ledger: invalid, whatever else the entry says.
        (
            "no change ledger, a live last ledger",
            Absent,
            At(520),
            Says::Invalid,
        ),
        (
            "no change ledger, no last live ledger",
            Absent,
            Absent,
            Says::Invalid,
        ),
        ("a null change ledger", Null, At(520), Says::Invalid),
        (
            "a change ledger that is no number",
            Text,
            At(520),
            Says::Invalid,
        ),
        ("change ledger zero", At(0), At(520), Says::Invalid),
        // A change after the reply's own ledger contradicts the reply.
        (
            "changed after the reply, a live last ledger",
            At(121),
            At(520),
            Says::Invalid,
        ),
        (
            "changed after the reply, no last live ledger",
            At(121),
            Absent,
            Says::Invalid,
        ),
        // An entry is live at the ledger that changes it: one that changed at the reply's
        // ledger and has no last live ledger contradicts itself.
        (
            "changed at the reply's ledger, no last live ledger",
            At(120),
            Absent,
            Says::Invalid,
        ),
        (
            "changed at the reply's ledger, a null last live ledger",
            At(120),
            Null,
            Says::Invalid,
        ),
        (
            "changed at the reply's ledger, last live ledger zero",
            At(120),
            At(0),
            Says::Invalid,
        ),
        // Changed before the reply and without a last live ledger: archived.
        (
            "changed before the reply, no last live ledger",
            At(100),
            Absent,
            Says::Archived,
        ),
        (
            "changed before the reply, a null last live ledger",
            At(100),
            Null,
            Says::Archived,
        ),
        (
            "changed before the reply, last live ledger zero",
            At(100),
            At(0),
            Says::Archived,
        ),
        (
            "a last live ledger that is no number",
            At(100),
            Text,
            Says::Invalid,
        ),
        // A last live ledger before the change contradicts the change.
        (
            "last live ledger before the change",
            At(100),
            At(99),
            Says::Invalid,
        ),
        (
            "changed at the reply's ledger, last live ledger before it",
            At(120),
            At(119),
            Says::Invalid,
        ),
        // A last live ledger from the change on and before the reply: past its lifetime.
        (
            "last live ledger at the change, before the reply",
            At(100),
            At(100),
            Says::Archived,
        ),
        (
            "last live ledger one before the reply",
            At(100),
            At(119),
            Says::Archived,
        ),
        // A last live ledger from the reply's ledger on, within the limit: live.
        (
            "last live ledger at the reply's ledger",
            At(100),
            At(120),
            Says::Live,
        ),
        (
            "changed and last live at the reply's ledger",
            At(120),
            At(120),
            Says::Live,
        ),
        ("a live last ledger", At(100), At(520), Says::Live),
        (
            "last live ledger at the network's limit",
            At(100),
            At(1_119),
            Says::Live,
        ),
        (
            "last live ledger beyond the network's limit",
            At(100),
            At(1_120),
            Says::Invalid,
        ),
    ];
    /// The network's setting, which has no lifetime: its change ledger, a last live ledger that
    /// a reply gives it, and what the decode says.
    const SETTING: &[(&str, Field, Field, Says)] = &[
        (
            "the setting with its change ledger",
            At(100),
            Absent,
            Says::Setting,
        ),
        (
            "the setting changed at the reply's ledger",
            At(120),
            Absent,
            Says::Setting,
        ),
        (
            "the setting with a null last live ledger",
            At(100),
            Null,
            Says::Setting,
        ),
        (
            "the setting without its change ledger",
            Absent,
            Absent,
            Says::Invalid,
        ),
        (
            "the setting with a null change ledger",
            Null,
            Absent,
            Says::Invalid,
        ),
        (
            "the setting changed after the reply",
            At(121),
            Absent,
            Says::Invalid,
        ),
        (
            "the setting with a last live ledger",
            At(100),
            At(520),
            Says::Invalid,
        ),
        // Zero is no last live ledger, as for an entry with a lifetime.
        (
            "the setting with last live ledger zero",
            At(100),
            At(0),
            Says::Setting,
        ),
    ];
    fn field(entry: &mut Value, name: &str, field: Field) {
        match field {
            Absent => {}
            Null => entry[name] = Value::Null,
            At(ledger) => entry[name] = json!(ledger),
            Text => entry[name] = json!("soon"),
        }
    }
    fn entry(data: &LedgerEntryData, changed: Field, until: Field) -> Value {
        let mut entry = json!({"xdr": xdr(data).unwrap()});
        field(&mut entry, "lastModifiedLedgerSeq", changed);
        field(&mut entry, "liveUntilLedgerSeq", until);
        entry
    }
    fn setting(limit: u32) -> LedgerEntryData {
        LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(StateArchivalSettings {
            max_entry_ttl: limit,
            ..Default::default()
        }))
    }
    fn code() -> LedgerEntryData {
        let code = b"the code of the table".to_vec();
        LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash: Hash(hash(&code)),
            code: code.try_into().unwrap(),
        })
    }
    fn instance() -> LedgerEntryData {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: ContractExecutable::Wasm(Hash([7; 32])),
                storage: None,
            }),
        })
    }
    /// A valid entry of each kind.
    fn valid(data: &LedgerEntryData) -> Value {
        match data {
            LedgerEntryData::ConfigSetting(_) => entry(data, At(100), Absent),
            _ => entry(data, At(100), At(520)),
        }
    }
    /// What the decode says of the entry at `at` of `entries`, in a reply of ledger 120.
    fn says(entries: Vec<Value>, at: usize) -> Says {
        match valid_lifetime_reply(&json!({"latestLedger": LEDGER, "entries": entries})) {
            Err(_) => Says::Invalid,
            Ok((ledger, limit, entries)) => {
                assert_eq!((ledger, limit), (LEDGER, LIMIT));
                match entries[at].life {
                    None => Says::Setting,
                    Some(Life::Live) => Says::Live,
                    Some(Life::Archived) => Says::Archived,
                }
            }
        }
    }
    /// Every row of the table, for the instance and for the code, and every row of the setting.
    /// The failing rows are named together.
    #[test]
    fn the_decode_says_what_the_table_says() {
        let mut wrong = Vec::new();
        for (kind, data) in [("instance", instance()), ("code", code())] {
            for (row, changed, until, expected) in WITH_LIFETIME {
                let entries = vec![
                    valid(&setting(LIMIT)),
                    entry(&data, *changed, *until),
                    valid(&if kind == "instance" {
                        code()
                    } else {
                        instance()
                    }),
                ];
                let said = says(entries, 1);
                if said != *expected {
                    wrong.push(format!("{kind}: {row}: {said:?}, not {expected:?}"));
                }
            }
        }
        for (row, changed, until, expected) in SETTING {
            let entries = vec![
                entry(&setting(LIMIT), *changed, *until),
                valid(&instance()),
                valid(&code()),
            ];
            let said = says(entries, 0);
            if said != *expected {
                wrong.push(format!("setting: {row}: {said:?}, not {expected:?}"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
    /// The rows of the reply itself: its ledger and the network's limit, present or absent. Each
    /// row is invalid by one rule alone: its entries are otherwise valid, and those of the limit
    /// rows are in their last live ledger, so that no entry is beyond the limit. The failing rows
    /// are named together.
    #[test]
    fn a_reply_without_its_ledger_or_its_limit_is_invalid() {
        let last = |data: &LedgerEntryData| entry(data, At(100), At(LEDGER));
        let entries = || vec![valid(&setting(LIMIT)), valid(&instance()), valid(&code())];
        let limited = |limit| vec![valid(&setting(limit)), last(&instance()), last(&code())];
        let invalid = |reply: Value| valid_lifetime_reply(&reply).is_err();
        assert!(!invalid(
            json!({"latestLedger": LEDGER, "entries": entries()})
        ));
        assert!(!invalid(
            json!({"latestLedger": LEDGER, "entries": limited(2)})
        ));
        let mut wrong = Vec::new();
        for (row, reply) in [
            (
                "the reply without its ledger",
                json!({"entries": entries()}),
            ),
            (
                "a reply ledger that is no number",
                json!({"latestLedger": "soon", "entries": entries()}),
            ),
            (
                "reply ledger zero",
                json!({"latestLedger": 0, "entries": entries()}),
            ),
            (
                "the reply without the network's setting",
                json!({"latestLedger": LEDGER, "entries": [valid(&instance()), valid(&code())]}),
            ),
            (
                "two settings",
                json!({"latestLedger": LEDGER, "entries": [valid(&setting(LIMIT)), valid(&setting(LIMIT)), valid(&code())]}),
            ),
            (
                "a limit of one ledger",
                json!({"latestLedger": LEDGER, "entries": limited(1)}),
            ),
            (
                "a limit that no ledger number can hold",
                json!({"latestLedger": LEDGER, "entries": limited(u32::MAX)}),
            ),
            (
                "four entries",
                json!({"latestLedger": LEDGER, "entries": [valid(&setting(LIMIT)), valid(&instance()), valid(&code()), valid(&code())]}),
            ),
        ] {
            if !invalid(reply) {
                wrong.push(format!("reply: {row}: valid, not Invalid"));
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
}
