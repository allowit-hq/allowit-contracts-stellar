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
/// The class of an exit of the lifetime read. Each class has one answer of the rail at a
/// preparation and one at a send (`provider::server`: `at_preparation`, `at_send`), and no exit
/// is answered by its text.
///
/// | Class | At a preparation | At a send |
/// | --- | --- | --- |
/// | `Configuration` | a configuration error | a configuration error |
/// | `Transport` | an uncertain error | an uncertain error |
/// | `InvalidReply` | an uncertain error | an uncertain error |
/// | `NotCurrent` | the typed refusal `stale_owner_observation`: the caller prepares once more | an uncertain error |
/// | `NotHeld` | the rail's refusal: the network does not hold the entry | an uncertain error: an absence is no lapse |
///
/// A transport error keeps what the transport says of itself: an endpoint that gave no answer
/// keeps its code. The definite answers that are no exit (live, archived, an instance that
/// runs other code) are values of the read ([`LifetimeRead`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// The caller's own input causes it. Nothing that a reply says is a configuration error.
    Configuration,
    /// A call of the transport gave no reply.
    Transport,
    /// A reply that decides nothing: it contradicts itself, the request or the network's rules.
    InvalidReply,
    /// A valid reply that is not current: the heads around it moved too far.
    NotCurrent,
    /// A definite answer: the network does not hold the entry.
    NotHeld,
}
/// Every exit of the lifetime read that gives no entries: one variant for each place where the
/// read ends, from the caller's input and the transport's calls to the checks after the decode.
/// Each place builds its own variant once ([`exit`]); the table of the test module
/// `decode_table` holds a row for each variant, with its class and the reply that reaches it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// The network's name is none that this rail knows.
    UnknownNetwork,
    /// The wallet is no contract address.
    WalletAddress,
    /// The code's identity is missing.
    CodeIdentity,
    /// The call for the endpoint's network gave no reply.
    NetworkCall,
    /// The endpoint answers for another network.
    NetworkDiffers,
    /// The call for the head before the read gave no reply.
    HeadBeforeCall,
    /// The head before the read is no ledger.
    HeadBefore,
    /// The call for the entries gave no reply.
    EntriesCall,
    /// The reply has no ledger.
    ReplyLedger,
    /// The reply has no list of entries.
    EntriesMissing,
    /// The reply has more than the three entries that were asked for.
    EntriesTooMany,
    /// An entry has no change ledger.
    ChangeLedgerMissing,
    /// An entry's change ledger is no ledger.
    ChangeLedgerInvalid,
    /// An entry changed after the reply's own ledger.
    ChangedAfterReply,
    /// An entry's last live ledger is no ledger.
    LastLiveInvalid,
    /// An entry has no XDR.
    EntryXdrMissing,
    /// An entry's XDR does not decode.
    EntryXdrInvalid,
    /// A second archival setting, or a limit of at most one ledger.
    SettingInvalid,
    /// The archival setting has a last live ledger.
    SettingHasLifetime,
    /// An entry changed at the reply's ledger and has no last live ledger.
    ChangedAtReplyWithoutLastLive,
    /// An entry changed after its last live ledger.
    ChangedAfterLastLive,
    /// The reply has no archival setting.
    SettingMissing,
    /// A last live ledger beyond the network's limit, or a limit that no ledger can hold.
    BeyondLimit,
    /// The wallet's instance is no code instance.
    InstanceNotWasm,
    /// An entry of none of the keys that were asked for.
    ForeignEntry,
    /// An entry under another key than its own.
    KeyDiffers,
    /// A second entry of the wallet's instance.
    InstanceRepeated,
    /// A second entry of the code.
    CodeRepeated,
    /// The network does not hold the wallet's instance.
    InstanceNotHeld,
    /// The call for the head after the read gave no reply.
    HeadAfterCall,
    /// The head after the read is no ledger.
    HeadAfter,
    /// The reply is not current: the heads around it moved too far, or back.
    NotCurrent,
    /// The network does not hold the code that the instance runs.
    CodeNotHeld,
}
impl Exit {
    /// The class of the exit. One arm for each exit, and no other arm.
    pub const fn class(self) -> Class {
        match self {
            Exit::UnknownNetwork | Exit::WalletAddress | Exit::CodeIdentity => Class::Configuration,
            Exit::NetworkCall | Exit::HeadBeforeCall | Exit::EntriesCall | Exit::HeadAfterCall => {
                Class::Transport
            }
            Exit::NetworkDiffers
            | Exit::HeadBefore
            | Exit::ReplyLedger
            | Exit::EntriesMissing
            | Exit::EntriesTooMany
            | Exit::ChangeLedgerMissing
            | Exit::ChangeLedgerInvalid
            | Exit::ChangedAfterReply
            | Exit::LastLiveInvalid
            | Exit::EntryXdrMissing
            | Exit::EntryXdrInvalid
            | Exit::SettingInvalid
            | Exit::SettingHasLifetime
            | Exit::ChangedAtReplyWithoutLastLive
            | Exit::ChangedAfterLastLive
            | Exit::SettingMissing
            | Exit::BeyondLimit
            | Exit::InstanceNotWasm
            | Exit::ForeignEntry
            | Exit::KeyDiffers
            | Exit::InstanceRepeated
            | Exit::CodeRepeated
            | Exit::HeadAfter => Class::InvalidReply,
            Exit::NotCurrent => Class::NotCurrent,
            Exit::InstanceNotHeld | Exit::CodeNotHeld => Class::NotHeld,
        }
    }
}
/// An exit of the lifetime read, with its text for a reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadExit {
    pub exit: Exit,
    pub text: String,
}
impl std::fmt::Display for ReadExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}
/// The one constructor of an exit of the read.
fn exit(exit: Exit, text: impl Into<String>) -> ReadExit {
    ReadExit {
        exit,
        text: text.into(),
    }
}
type Read<T> = std::result::Result<T, ReadExit>;
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
/// with an entry that fails is an invalid reply, never a decision. The truth table of the
/// test module `decode_table` states every row, and the decode says nothing else.
fn valid_lifetime_reply(response: &Value) -> Read<(u32, u32, Vec<ValidEntry>)> {
    let observed =
        ledger(&response["latestLedger"]).map_err(|text| exit(Exit::ReplyLedger, text))?;
    let listed = response["entries"]
        .as_array()
        .ok_or_else(|| exit(Exit::EntriesMissing, "Missing wallet lifetime entries"))?;
    if listed.len() > 3 {
        return Err(exit(
            Exit::EntriesTooMany,
            "Expected the archival setting and both wallet lifetime entries",
        ));
    }
    let mut max = None;
    let mut entries = Vec::new();
    for entry in listed {
        let changed = match entry.get("lastModifiedLedgerSeq") {
            Some(changed) if !changed.is_null() => {
                ledger(changed).map_err(|text| exit(Exit::ChangeLedgerInvalid, text))?
            }
            _ => {
                return Err(exit(
                    Exit::ChangeLedgerMissing,
                    "Wallet lifetime entry has no change ledger",
                ));
            }
        };
        if changed > observed {
            return Err(exit(
                Exit::ChangedAfterReply,
                "Wallet lifetime entry is newer than its reply",
            ));
        }
        // Zero stands for no last live ledger, as a missing or null one does.
        let live_until = live_until(&entry["liveUntilLedgerSeq"])
            .map_err(|text| exit(Exit::LastLiveInvalid, text))?;
        let encoded = entry["xdr"]
            .as_str()
            .ok_or_else(|| exit(Exit::EntryXdrMissing, "Missing wallet lifetime XDR"))?;
        let data: LedgerEntryData =
            read(encoded).map_err(|text| exit(Exit::EntryXdrInvalid, text))?;
        if let LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(settings)) = &data
            && (max.replace(settings.max_entry_ttl).is_some() || settings.max_entry_ttl <= 1)
        {
            return Err(exit(
                Exit::SettingInvalid,
                "Invalid or duplicate archival lifetime setting",
            ));
        }
        // The rows of the decode's truth table (`decode_table`), in its order.
        let life = match &data {
            // The network's setting has no lifetime.
            LedgerEntryData::ConfigSetting(_) if live_until > 0 => {
                return Err(exit(
                    Exit::SettingHasLifetime,
                    "The archival setting has a last live ledger",
                ));
            }
            LedgerEntryData::ConfigSetting(_) => None,
            // An entry is live at the ledger that changes it: without a last live ledger it
            // cannot have changed at the reply's own ledger.
            _ if live_until == 0 && changed == observed => {
                return Err(exit(
                    Exit::ChangedAtReplyWithoutLastLive,
                    "Wallet lifetime entry changed at its reply's ledger and has no last live ledger",
                ));
            }
            _ if live_until == 0 => Some(Life::Archived),
            _ if changed > live_until => {
                return Err(exit(
                    Exit::ChangedAfterLastLive,
                    "Wallet lifetime entry changed after its last live ledger",
                ));
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
    let max = max.ok_or_else(|| exit(Exit::SettingMissing, "Missing archival lifetime setting"))?;
    let beyond = |entry: &ValidEntry| entry.live_until.saturating_sub(observed) >= max;
    if observed.checked_add(max - 1).is_none() || entries.iter().any(beyond) {
        return Err(exit(
            Exit::BeyondLimit,
            "Wallet lifetime exceeds the network limit",
        ));
    }
    Ok((observed, max, entries))
}
/// Read the instance of `wallet`, the entry of `code` and the network's archival limit in one
/// reply, and bind each returned entry to the key that was asked for. Every entry passes the
/// validating decode first ([`valid_lifetime_reply`]). The reply is current before it decides
/// anything: a reply that is older than the head before it, or that trails the closing head
/// by more than [`MAX_OBSERVATION_LAG`], is not current. Every place where the read ends
/// without entries is one [`Exit`]. Nothing here says that an entry lapsed: the caller takes
/// the decode's verdict, or compares the last live ledgers with the ledger that it decides for.
pub fn lifetime_read(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Read<LifetimeRead> {
    // The caller's input.
    let expected = passphrase(selected_network).map_err(|text| exit(Exit::UnknownNetwork, text))?;
    let Ok(contract) = Contract::from_string(wallet) else {
        return Err(exit(
            Exit::WalletAddress,
            "The wallet is no contract address",
        ));
    };
    if *code == [0; 32] {
        return Err(exit(
            Exit::CodeIdentity,
            "Selected wallet executable identity is missing",
        ));
    }
    let wallet = ScAddress::Contract(ContractId(Hash(contract.0)));
    let config_key = LedgerKey::ConfigSetting(LedgerKeyConfigSetting {
        config_setting_id: ConfigSettingId::StateArchival,
    });
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: wallet.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });
    let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(*code) });
    // A ledger key of these three shapes always encodes.
    let encoded = |key: &LedgerKey| xdr(key).unwrap_or_default();
    let keys = [
        encoded(&config_key),
        encoded(&instance_key),
        encoded(&code_key),
    ];
    // The endpoint's network, the head before the read, and the read.
    let served = rpc
        .call("getNetwork", json!({}))
        .map_err(|text| exit(Exit::NetworkCall, text))?;
    if served["passphrase"].as_str() != Some(expected) {
        return Err(exit(
            Exit::NetworkDiffers,
            "Owner observation RPC network differs",
        ));
    }
    let head_before = rpc
        .call("getLatestLedger", json!({}))
        .map_err(|text| exit(Exit::HeadBeforeCall, text))?;
    let before = ledger(&head_before["sequence"]).map_err(|text| exit(Exit::HeadBefore, text))?;
    let response = rpc
        .call("getLedgerEntries", json!({"keys": keys}))
        .map_err(|text| exit(Exit::EntriesCall, text))?;
    let (observed, max, entries) = valid_lifetime_reply(&response)?;
    let mut instance = None;
    let mut executable = None;
    let mut other = false;
    for entry in entries {
        let (expected, slot) = match entry.data {
            LedgerEntryData::ConfigSetting(ConfigSettingEntry::StateArchival(_)) => (&keys[0], 0),
            LedgerEntryData::ContractData(data)
                if data.contract == wallet
                    && data.key == ScVal::LedgerKeyContractInstance
                    && data.durability == ContractDataDurability::Persistent =>
            {
                let ScVal::ContractInstance(ScContractInstance {
                    executable: ContractExecutable::Wasm(Hash(running)),
                    ..
                }) = data.val
                else {
                    return Err(exit(
                        Exit::InstanceNotWasm,
                        "Invalid selected wallet instance",
                    ));
                };
                other = running != *code;
                (&keys[1], 1)
            }
            LedgerEntryData::ContractCode(data)
                if data.hash == Hash(*code) && hash(data.code.as_slice()) == *code =>
            {
                (&keys[2], 2)
            }
            _ => {
                return Err(exit(
                    Exit::ForeignEntry,
                    "Wallet lifetime entry differs from the exact selected keys",
                ));
            }
        };
        if entry.key.is_some_and(|key| key != *expected) {
            return Err(exit(
                Exit::KeyDiffers,
                "Wallet lifetime response ledger key differs",
            ));
        }
        match slot {
            1 if instance.replace((entry.live_until, entry.life)).is_some() => {
                return Err(exit(
                    Exit::InstanceRepeated,
                    "Duplicate wallet instance lifetime",
                ));
            }
            2 if executable.replace((entry.live_until, entry.life)).is_some() => {
                return Err(exit(Exit::CodeRepeated, "Duplicate wallet code lifetime"));
            }
            _ => {}
        }
    }
    let (instance, instance_life) =
        instance.ok_or_else(|| exit(Exit::InstanceNotHeld, "Missing wallet instance lifetime"))?;
    // The head after the read: the reply is current, or it decides nothing.
    let head_after = rpc
        .call("getLatestLedger", json!({}))
        .map_err(|text| exit(Exit::HeadAfterCall, text))?;
    let closing = ledger(&head_after["sequence"]).map_err(|text| exit(Exit::HeadAfter, text))?;
    if closing < before
        || observed < before
        || observed > closing
        || closing.saturating_sub(observed) > MAX_OBSERVATION_LAG
    {
        return Err(exit(Exit::NotCurrent, STALE_OBSERVATION));
    }
    let live = |life: Option<Life>| life == Some(Life::Live);
    if other {
        // The code that was asked for is not the wallet's: its entry, present or not, says
        // nothing of the wallet.
        return Ok(LifetimeRead::OtherExecutable {
            instance_live: live(instance_life),
        });
    }
    let (code, code_life) =
        executable.ok_or_else(|| exit(Exit::CodeNotHeld, "Missing wallet code lifetime"))?;
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
/// What the lifetime read answers for a preparation: the entries of a wallet that is live at
/// the head that closes the read, or one of the two definite refusals.
#[derive(Clone, Debug)]
pub enum PreparedLifetime {
    Live(WalletLifetime),
    /// The instance or the code is past its lifetime at the head that closes the read:
    /// nothing restores it (`CONTRACT_EXPIRED`).
    Lapsed,
    /// The instance runs other code ([`OTHER_EXECUTABLE`]).
    OtherExecutable,
}
/// Read and bind both selected lifetime entries and the exact current network archival limit
/// ([`lifetime_read`]), for a preparation. A wallet whose instance or code is past its lifetime
/// at the head that closes the read is lapsed. An archived entry that the RPC serves without a
/// live-until ledger has lapsed.
pub fn prepared_lifetime(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Read<PreparedLifetime> {
    let entries = match lifetime_read(rpc, selected_network, wallet, code)? {
        LifetimeRead::Entries(entries) => entries,
        LifetimeRead::OtherExecutable { .. } => return Ok(PreparedLifetime::OtherExecutable),
    };
    if entries.instance_live_until < entries.closing || entries.code_live_until < entries.closing {
        return Ok(PreparedLifetime::Lapsed);
    }
    Ok(PreparedLifetime::Live(WalletLifetime {
        ledger: entries.ledger,
        max_entry_ttl: entries.max_entry_ttl,
        instance_live_until: entries.instance_live_until,
        code_live_until: entries.code_live_until,
    }))
}
/// [`prepared_lifetime`] with its answers as texts, for a caller outside the provider: a lapsed
/// wallet is `CONTRACT_EXPIRED`, a wallet whose instance runs other code is
/// [`OTHER_EXECUTABLE`], and an exit of the read is its text.
pub fn wallet_lifetime(
    rpc: &dyn Rpc,
    selected_network: &str,
    wallet: &str,
    code: &[u8; 32],
) -> Result<WalletLifetime> {
    match prepared_lifetime(rpc, selected_network, wallet, code) {
        Ok(PreparedLifetime::Live(lifetime)) => Ok(lifetime),
        Ok(PreparedLifetime::Lapsed) => Err(super::CONTRACT_EXPIRED.into()),
        Ok(PreparedLifetime::OtherExecutable) => Err(OTHER_EXECUTABLE.into()),
        Err(exit) => Err(exit.text),
    }
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
                executable: ContractExecutable::Wasm(Hash(hash(b"the code of the table"))),
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
            Err(exit) => {
                assert_eq!(exit.exit.class(), Class::InvalidReply);
                Says::Invalid
            }
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

    /// The transport of the exits table: one reply for each call of the read.
    type Reply = std::result::Result<Value, String>;
    struct Script {
        network: Reply,
        before: Reply,
        entries: Reply,
        after: Reply,
        heads: std::sync::Mutex<usize>,
    }
    impl Rpc for Script {
        fn call(&self, method: &str, _: Value) -> Result<Value> {
            match method {
                "getNetwork" => self.network.clone(),
                "getLatestLedger" => {
                    let mut heads = self.heads.lock().unwrap();
                    *heads += 1;
                    if *heads == 1 {
                        self.before.clone()
                    } else {
                        self.after.clone()
                    }
                }
                "getLedgerEntries" => self.entries.clone(),
                other => Err(format!("unexpected call {other}")),
            }
        }
    }
    /// The caller's input and the transport's replies of one read.
    struct Case {
        network: &'static str,
        wallet: String,
        code: [u8; 32],
        script: Script,
    }
    fn reply(entries: Vec<Value>) -> Reply {
        Ok(json!({"latestLedger": LEDGER, "entries": entries}))
    }
    fn head(ledger: u32) -> Reply {
        Ok(json!({"sequence": ledger}))
    }
    /// A read that gives its entries: a live wallet on the test network, between two heads of
    /// the reply's own ledger.
    fn live() -> Case {
        Case {
            network: "stellar:testnet",
            wallet: Contract([9; 32]).to_string(),
            code: hash(b"the code of the table"),
            script: Script {
                network: Ok(json!({"passphrase": "Test SDF Network ; September 2015"})),
                before: head(LEDGER),
                entries: reply(vec![
                    valid(&setting(LIMIT)),
                    valid(&instance()),
                    valid(&code()),
                ]),
                after: head(LEDGER),
                heads: std::sync::Mutex::new(0),
            },
        }
    }
    fn read(case: &Case) -> Read<LifetimeRead> {
        lifetime_read(&case.script, case.network, &case.wallet, &case.code)
    }
    /// A read whose reply holds `entries`.
    fn with(entries: Vec<Value>) -> Case {
        let mut case = live();
        case.script.entries = reply(entries);
        case
    }
    /// A read whose instance entry is `instance`.
    fn with_instance(instance: Value) -> Case {
        with(vec![valid(&setting(LIMIT)), instance, valid(&code())])
    }
    /// The exits of the read, in the order of [`row`]. `every_exit_is_built_once` counts the
    /// exits that the code builds against this list.
    const EXITS: &[Exit] = &[
        Exit::UnknownNetwork,
        Exit::WalletAddress,
        Exit::CodeIdentity,
        Exit::NetworkCall,
        Exit::NetworkDiffers,
        Exit::HeadBeforeCall,
        Exit::HeadBefore,
        Exit::EntriesCall,
        Exit::ReplyLedger,
        Exit::EntriesMissing,
        Exit::EntriesTooMany,
        Exit::ChangeLedgerMissing,
        Exit::ChangeLedgerInvalid,
        Exit::ChangedAfterReply,
        Exit::LastLiveInvalid,
        Exit::EntryXdrMissing,
        Exit::EntryXdrInvalid,
        Exit::SettingInvalid,
        Exit::SettingHasLifetime,
        Exit::ChangedAtReplyWithoutLastLive,
        Exit::ChangedAfterLastLive,
        Exit::SettingMissing,
        Exit::BeyondLimit,
        Exit::InstanceNotWasm,
        Exit::ForeignEntry,
        Exit::KeyDiffers,
        Exit::InstanceRepeated,
        Exit::CodeRepeated,
        Exit::InstanceNotHeld,
        Exit::HeadAfterCall,
        Exit::HeadAfter,
        Exit::NotCurrent,
        Exit::CodeNotHeld,
    ];
    /// The table of the exits: for each exit its class and a read that ends there. One arm for
    /// each exit and no other arm, so an exit without a row does not compile.
    fn row(exit: Exit) -> (Class, Case) {
        let silent = || Err::<Value, String>("the endpoint gave no reply".into());
        let mut case = live();
        match exit {
            Exit::UnknownNetwork => {
                case.network = "stellar:nowhere";
                (Class::Configuration, case)
            }
            Exit::WalletAddress => {
                case.wallet = "not an address".into();
                (Class::Configuration, case)
            }
            Exit::CodeIdentity => {
                case.code = [0; 32];
                (Class::Configuration, case)
            }
            Exit::NetworkCall => {
                case.script.network = silent();
                (Class::Transport, case)
            }
            Exit::NetworkDiffers => {
                case.script.network =
                    Ok(json!({"passphrase": "Public Global Stellar Network ; September 2015"}));
                (Class::InvalidReply, case)
            }
            Exit::HeadBeforeCall => {
                case.script.before = silent();
                (Class::Transport, case)
            }
            Exit::HeadBefore => {
                case.script.before = head(0);
                (Class::InvalidReply, case)
            }
            Exit::EntriesCall => {
                case.script.entries = silent();
                (Class::Transport, case)
            }
            Exit::ReplyLedger => {
                case.script.entries = Ok(json!({"entries": []}));
                (Class::InvalidReply, case)
            }
            Exit::EntriesMissing => {
                case.script.entries = Ok(json!({"latestLedger": LEDGER}));
                (Class::InvalidReply, case)
            }
            Exit::EntriesTooMany => (
                Class::InvalidReply,
                with(vec![
                    valid(&setting(LIMIT)),
                    valid(&instance()),
                    valid(&code()),
                    valid(&code()),
                ]),
            ),
            Exit::ChangeLedgerMissing => (
                Class::InvalidReply,
                with_instance(entry(&instance(), Absent, At(520))),
            ),
            Exit::ChangeLedgerInvalid => (
                Class::InvalidReply,
                with_instance(entry(&instance(), Text, At(520))),
            ),
            Exit::ChangedAfterReply => (
                Class::InvalidReply,
                with_instance(entry(&instance(), At(121), At(520))),
            ),
            Exit::LastLiveInvalid => (
                Class::InvalidReply,
                with_instance(entry(&instance(), At(100), Text)),
            ),
            Exit::EntryXdrMissing => (
                Class::InvalidReply,
                with_instance(json!({"lastModifiedLedgerSeq": 100, "liveUntilLedgerSeq": 520})),
            ),
            Exit::EntryXdrInvalid => (
                Class::InvalidReply,
                with_instance(
                    json!({"xdr": "malformed", "lastModifiedLedgerSeq": 100, "liveUntilLedgerSeq": 520}),
                ),
            ),
            Exit::SettingInvalid => (
                Class::InvalidReply,
                with(vec![valid(&setting(1)), valid(&instance()), valid(&code())]),
            ),
            Exit::SettingHasLifetime => (
                Class::InvalidReply,
                with(vec![
                    entry(&setting(LIMIT), At(100), At(520)),
                    valid(&instance()),
                    valid(&code()),
                ]),
            ),
            Exit::ChangedAtReplyWithoutLastLive => (
                Class::InvalidReply,
                with_instance(entry(&instance(), At(LEDGER), Absent)),
            ),
            Exit::ChangedAfterLastLive => (
                Class::InvalidReply,
                with_instance(entry(&instance(), At(100), At(99))),
            ),
            Exit::SettingMissing => (
                Class::InvalidReply,
                with(vec![valid(&instance()), valid(&code())]),
            ),
            Exit::BeyondLimit => (
                Class::InvalidReply,
                with_instance(entry(&instance(), At(100), At(1_120))),
            ),
            Exit::InstanceNotWasm => {
                let asset = LedgerEntryData::ContractData(ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: ScAddress::Contract(ContractId(Hash([9; 32]))),
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                    val: ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::StellarAsset,
                        storage: None,
                    }),
                });
                (Class::InvalidReply, with_instance(valid(&asset)))
            }
            Exit::ForeignEntry => {
                let other = LedgerEntryData::ContractData(ContractDataEntry {
                    ext: ExtensionPoint::V0,
                    contract: ScAddress::Contract(ContractId(Hash([8; 32]))),
                    key: ScVal::LedgerKeyContractInstance,
                    durability: ContractDataDurability::Persistent,
                    val: ScVal::ContractInstance(ScContractInstance {
                        executable: ContractExecutable::Wasm(Hash(hash(b"the code of the table"))),
                        storage: None,
                    }),
                });
                (Class::InvalidReply, with_instance(valid(&other)))
            }
            Exit::KeyDiffers => {
                let mut instance = valid(&instance());
                instance["key"] = json!("another key");
                (Class::InvalidReply, with_instance(instance))
            }
            Exit::InstanceRepeated => (
                Class::InvalidReply,
                with(vec![
                    valid(&setting(LIMIT)),
                    valid(&instance()),
                    valid(&instance()),
                ]),
            ),
            Exit::CodeRepeated => (
                Class::InvalidReply,
                with(vec![valid(&setting(LIMIT)), valid(&code()), valid(&code())]),
            ),
            Exit::InstanceNotHeld => (
                Class::NotHeld,
                with(vec![valid(&setting(LIMIT)), valid(&code())]),
            ),
            Exit::HeadAfterCall => {
                case.script.after = silent();
                (Class::Transport, case)
            }
            Exit::HeadAfter => {
                case.script.after = Ok(json!({"sequence": "soon"}));
                (Class::InvalidReply, case)
            }
            Exit::NotCurrent => {
                case.script.after = head(LEDGER + MAX_OBSERVATION_LAG + 1);
                (Class::NotCurrent, case)
            }
            Exit::CodeNotHeld => (
                Class::NotHeld,
                with(vec![valid(&setting(LIMIT)), valid(&instance())]),
            ),
        }
    }
    /// Every exit of the read has its row: the read of the row ends at exactly that exit, and
    /// the exit has the row's class. The read that the rows start from gives its entries. The
    /// failing rows are named together.
    #[test]
    fn every_exit_of_the_read_has_its_row_and_its_class() {
        assert!(matches!(
            read(&live()),
            Ok(LifetimeRead::Entries(LifetimeEntries {
                instance_live: true,
                code_live: true,
                ..
            }))
        ));
        let mut wrong = Vec::new();
        for exit in EXITS {
            let (class, case) = row(*exit);
            match read(&case) {
                Err(ended) if ended.exit == *exit && exit.class() == class => {}
                Err(ended) => wrong.push(format!(
                    "exit: {exit:?}: ended at {:?} of class {:?}, not at {exit:?} of class {class:?}",
                    ended.exit,
                    ended.exit.class()
                )),
                Ok(_) => wrong.push(format!("exit: {exit:?}: gave entries")),
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }
    /// The code builds each exit of the table in exactly one place, and no exit that the table
    /// lacks: the places that build an exit are counted in this file's own text.
    #[test]
    fn every_exit_is_built_once() {
        let source = include_str!("owner_observation.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        for exit in EXITS {
            let built = code.matches(&format!("exit(Exit::{exit:?},")).count();
            assert_eq!(built, 1, "{exit:?}");
        }
        assert_eq!(code.matches("exit(Exit::").count(), EXITS.len());
        // The list names each exit once.
        let names: std::collections::BTreeSet<String> =
            EXITS.iter().map(|exit| format!("{exit:?}")).collect();
        assert_eq!(names.len(), EXITS.len());
    }
}
