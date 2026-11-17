//! Public per-agent Native wallet setup and owner administration. No owner or agent secret
//! enters preparation.
//!
//! A Native wallet is its own classic account, one per agent. The owner creates it with one
//! transaction from the owner's account. The account's own key signs that transaction once and
//! then has weight 0. Afterwards the account has three signers:
//!
//! - the owner, weight 3: payments, signer changes and the account merge, alone;
//! - the agent, weight 1, and the server, weight 1: payments, only together.
//!
//! The thresholds are 2 (low), 2 (medium) and 3 (high). Agent and server together reach the
//! payment threshold and never the high threshold, so they cannot change signers or merge the
//! account. A paused wallet has no agent signer.
use crate::*;

pub const OWNER_PROFILE: &str = "allowit-stellar-owner-v2";
/// The profile of the setup of a fee account: the same account structure as a wallet account,
/// for the account that sends the operations of one policy wallet and pays their fees.
pub const FEE_ACCOUNT_PROFILE: &str = "allowit-stellar-fee-account-v1";
/// The action name of the owner step that creates a fee account.
pub const CREATE_FEE_ACCOUNT: &str = "create_fee_account";
/// The action name of the owner step that returns the fee float of a fee account.
pub const RETURN_FEES: &str = "return_fees";
/// The weight of the owner signer: every threshold, alone.
pub const OWNER_WEIGHT: u32 = 3;
/// The weight of the agent signer and of the server signer.
pub const AUTOMATED_WEIGHT: u32 = 1;
/// The low and medium thresholds: agent and server together.
pub const PAYMENT_THRESHOLD: u32 = 2;
/// The high threshold: the owner alone.
pub const OWNER_THRESHOLD: u32 = 3;
/// The network's base reserve, in stroops. An account keeps two base reserves and one more for
/// each signer and each trustline.
pub const BASE_RESERVE_STROOPS: i64 = 5_000_000;
/// The XLM that a new wallet holds above its reserve to pay the network fees of its payments.
pub const FEE_FLOAT_STROOPS: i64 = 5_000_000;
/// The XLM that a new fee account holds above its reserve: the float that pays the network
/// fees of the agent's operations on the policy wallet. The owner refills it.
pub const FEE_ACCOUNT_FLOAT_STROOPS: i64 = 50_000_000;
const SIGNERS: i64 = 3;
const MAX_STARTING_BALANCE: i64 = 1_000_000_000_000_000;

/// The balance that the network locks in a wallet account: the account, its three signers and
/// its trustline.
pub fn wallet_reserve(trustline: bool) -> i64 {
    (2 + SIGNERS + i64::from(trustline)) * BASE_RESERVE_STROOPS
}
/// The starting balance of a wallet when the owner names none: the reserve and the fee float.
pub fn default_starting_balance(trustline: bool) -> i64 {
    wallet_reserve(trustline) + FEE_FLOAT_STROOPS
}

/// The balance that a new fee account starts with: its reserve and the fee float.
pub fn fee_account_starting_balance() -> i64 {
    wallet_reserve(false) + FEE_ACCOUNT_FLOAT_STROOPS
}
/// Whether a fee account holds too little to see its owner through: less than two operations
/// at the fee ceiling of its policy wallet. `spendable` is its XLM above the reserve.
pub fn fee_account_low(spendable: i64, max_fee_stroops: u32) -> bool {
    spendable < 2 * i64::from(max_fee_stroops)
}
/// The request identity of the setup of the fee account of one policy wallet.
pub fn fee_account_request_id(policy_instance: &[u8; 32]) -> String {
    format!("fee-account-{}", hex(&policy_instance[..16]))
}
/// The one-time setup key of a new wallet account or fee account. The owner's client makes it
/// from the operating system's random source, holds it in memory, signs the creation of its
/// account with it once and drops it. The creation transaction sets its weight to 0 and makes
/// the owner a signer that reaches every threshold alone, so nothing needs this key again and
/// nothing stores, derives or recovers it.
pub struct WalletKey(SigningKey);
impl WalletKey {
    /// A new random key. It exists only in the memory of the caller.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn random() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|_| "The operating system gave no random bytes for the setup key")?;
        let key = SigningKey::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        Ok(Self(key))
    }
    /// A key from a seed that the caller holds. The owner's client never uses it: a test keeps
    /// the seed to show that the key has no authority after setup.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }
    /// The address of the wallet account.
    pub fn account(&self) -> String {
        account_for_public_key(&self.0.verifying_key().to_bytes())
    }
    pub fn sign_hash(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.0.sign(digest).to_bytes()
    }
}

/// The issued asset that a wallet holds. Setup adds its trustline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Trustline {
    pub code: String,
    pub issuer: String,
}
impl Trustline {
    fn asset(&self) -> Result<Asset> {
        asset_from_identity(&self.code, Some(&self.issuer))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSetup {
    pub version: u32,
    pub profile: String,
    pub request_id: String,
    pub network: String,
    pub owner: String,
    /// The new wallet account.
    pub wallet: String,
    pub agent: String,
    pub engine: String,
    /// The XLM that the owner's account sends to the new account, in stroops. The reserve of
    /// the account stays locked in it.
    pub starting_balance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trustline: Option<Trustline>,
    pub sequence: String,
    pub fee_stroops: u32,
    pub expires_at: u64,
    pub transaction_xdr: String,
    pub transaction_hash: String,
    pub intent_digest: String,
}

/// The owner's choices for one wallet setup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetupTerms<'a> {
    pub wallet: &'a str,
    pub agent: &'a str,
    pub engine: &'a str,
    pub request_id: &'a str,
    pub network: &'a str,
    pub fee_per_operation: u32,
    /// Stroops. `None` is the reserve and the fee float.
    pub starting_balance: Option<i64>,
    pub trustline: Option<&'a Trustline>,
}

/// The owner's account pays for setup and signs it alone, so its own key must reach its own
/// low threshold, which admits the transaction, and its medium threshold, which admits a
/// payment.
pub fn check_owner_source(state: &AccountState) -> Result<()> {
    state.validate_structure()?;
    if state.master_weight == 0
        || state.master_weight < state.low_threshold
        || state.master_weight < state.medium_threshold
    {
        return Err("The owner's account key cannot sign a payment alone".into());
    }
    Ok(())
}

fn wallet_source(wallet: &str) -> Result<Option<MuxedAccount>> {
    muxed(wallet).map(Some)
}
fn signer_operation(wallet: &str, key: [u8; 32], weight: u32) -> Result<Operation> {
    Ok(Operation {
        source_account: wallet_source(wallet)?,
        body: OperationBody::SetOptions(SetOptionsOp {
            signer: Some(stellar_xdr::Signer {
                key: SignerKey::Ed25519(Uint256(key)),
                weight,
            }),
            ..Default::default()
        }),
    })
}
fn operation_count(v: &NativeSetup) -> u32 {
    4 + u32::from(v.trustline.is_some())
}

fn transaction(v: &NativeSetup) -> Result<Transaction> {
    match v.profile.as_str() {
        OWNER_PROFILE => {
            if v.network != "stellar:testnet" {
                return Err("Native wallet setup supports Stellar Testnet only".into());
            }
        }
        // A fee account holds XLM only, and starts with exactly its reserve and the float.
        FEE_ACCOUNT_PROFILE => {
            passphrase(&v.network)?;
            if v.trustline.is_some()
                || v.starting_balance != fee_account_starting_balance().to_string()
            {
                return Err("A fee account holds its reserve and the fee float in XLM".into());
            }
        }
        _ => return Err("Invalid native setup identity or fee".into()),
    }
    let owner = account_key(&v.owner)?;
    let wallet = account_key(&v.wallet)?;
    let agent = account_key(&v.agent)?;
    let engine = account_key(&v.engine)?;
    let roles = [owner, wallet, agent, engine];
    if roles
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != 4
    {
        return Err("Owner, wallet, agent and engine must be distinct".into());
    }
    let count = operation_count(v);
    if v.version != 2
        || !(8..=100).contains(&v.request_id.len())
        || !v
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        || v.expires_at == 0
        || v.expires_at > 9_007_199_254_740_991
        || !(100 * count..=100_000 * count).contains(&v.fee_stroops)
        || !v.fee_stroops.is_multiple_of(count)
    {
        return Err("Invalid native setup identity or fee".into());
    }
    let sequence: i64 = v.sequence.parse().map_err(err)?;
    if sequence <= 0 || sequence.to_string() != v.sequence {
        return Err("Invalid native setup sequence".into());
    }
    let starting: i64 = v.starting_balance.parse().map_err(err)?;
    if starting.to_string() != v.starting_balance
        || starting < wallet_reserve(v.trustline.is_some()) + 100
        || starting > MAX_STARTING_BALANCE
    {
        return Err(format!(
            "The starting balance must cover the wallet reserve of {} stroops",
            wallet_reserve(v.trustline.is_some())
        ));
    }
    let mut operations = vec![Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(wallet))),
            starting_balance: starting,
        }),
    }];
    if let Some(trustline) = &v.trustline {
        operations.push(Operation {
            source_account: wallet_source(&v.wallet)?,
            body: OperationBody::ChangeTrust(ChangeTrustOp {
                line: change_trust_asset(&trustline.asset()?)?,
                limit: i64::MAX,
            }),
        });
    }
    operations.push(signer_operation(&v.wallet, owner, OWNER_WEIGHT)?);
    operations.push(signer_operation(&v.wallet, agent, AUTOMATED_WEIGHT)?);
    // The last operation adds the server and takes every authority from the account's own key.
    operations.push(Operation {
        source_account: wallet_source(&v.wallet)?,
        body: OperationBody::SetOptions(SetOptionsOp {
            master_weight: Some(0),
            low_threshold: Some(PAYMENT_THRESHOLD),
            med_threshold: Some(PAYMENT_THRESHOLD),
            high_threshold: Some(OWNER_THRESHOLD),
            signer: Some(stellar_xdr::Signer {
                key: SignerKey::Ed25519(Uint256(engine)),
                weight: AUTOMATED_WEIGHT,
            }),
            ..Default::default()
        }),
    });
    Ok(Transaction {
        source_account: muxed(&v.owner)?,
        fee: v.fee_stroops,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(v.expires_at),
        }),
        memo: Memo::Hash(Hash(hash(v.request_id.as_bytes()))),
        operations: operations.try_into().map_err(err)?,
        ext: TransactionExt::V0,
    })
}
fn change_trust_asset(asset: &Asset) -> Result<ChangeTrustAsset> {
    match asset {
        Asset::CreditAlphanum4(a) => Ok(ChangeTrustAsset::CreditAlphanum4(a.clone())),
        Asset::CreditAlphanum12(a) => Ok(ChangeTrustAsset::CreditAlphanum12(a.clone())),
        Asset::Native => Err("XLM needs no trustline".into()),
    }
}

pub fn intent_digest(v: &NativeSetup) -> Result<String> {
    Ok(hex(&hash(
        serde_json::to_vec(&serde_json::json!([
            v.profile,
            v.request_id,
            v.network,
            v.owner,
            v.wallet,
            v.agent,
            v.engine,
            v.starting_balance,
            v.trustline,
            v.sequence,
            v.fee_stroops,
            v.expires_at,
            v.transaction_hash
        ]))
        .map_err(err)?,
    )))
}

/// Prepare the one transaction that creates a wallet account for one agent. `state` is the
/// owner's account, which pays the starting balance and the fee.
pub fn prepare_native_setup(
    state: &AccountState,
    terms: &SetupTerms<'_>,
    now: u64,
) -> Result<NativeSetup> {
    prepare_setup(OWNER_PROFILE, state, terms, now)
}
/// The owner's choices for the setup of one fee account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeeAccountTerms<'a> {
    /// The new fee account.
    pub account: &'a str,
    pub agent: &'a str,
    pub engine: &'a str,
    pub request_id: &'a str,
    pub network: &'a str,
    pub fee_per_operation: u32,
}
/// Prepare the one transaction that creates the fee account of one policy wallet: the account
/// that sends the agent's operations on that wallet and pays their network fees. It has the
/// signers and thresholds of a wallet account, so the agent and the server pay from it only
/// together and its owner refills, withdraws from and closes it alone. It starts with its
/// reserve and the fee float. `state` is the owner's account, which pays both and the fee.
pub fn prepare_fee_account_setup(
    state: &AccountState,
    terms: &FeeAccountTerms<'_>,
    now: u64,
) -> Result<NativeSetup> {
    prepare_setup(
        FEE_ACCOUNT_PROFILE,
        state,
        &SetupTerms {
            wallet: terms.account,
            agent: terms.agent,
            engine: terms.engine,
            request_id: terms.request_id,
            network: terms.network,
            fee_per_operation: terms.fee_per_operation,
            starting_balance: Some(fee_account_starting_balance()),
            trustline: None,
        },
        now,
    )
}
/// The owner step of a setup: its unsigned transaction under the action name of its profile.
pub fn setup_transaction(v: &NativeSetup) -> Result<owner_intent::OwnerTransaction> {
    validate_native_setup(v)?;
    Ok(owner_intent::OwnerTransaction {
        network: v.network.clone(),
        action: match v.profile.as_str() {
            FEE_ACCOUNT_PROFILE => CREATE_FEE_ACCOUNT,
            _ => "native_setup",
        }
        .into(),
        transaction_xdr: v.transaction_xdr.clone(),
        transaction_hash: unhex(&v.transaction_hash)?,
        expires_at: v.expires_at,
    })
}
fn prepare_setup(
    profile: &str,
    state: &AccountState,
    terms: &SetupTerms<'_>,
    now: u64,
) -> Result<NativeSetup> {
    check_owner_source(state)?;
    let trustline = terms.trustline.is_some();
    let mut v = NativeSetup {
        version: 2,
        profile: profile.into(),
        request_id: terms.request_id.into(),
        network: terms.network.into(),
        owner: state.address.clone(),
        wallet: terms.wallet.into(),
        agent: terms.agent.into(),
        engine: terms.engine.into(),
        starting_balance: terms
            .starting_balance
            .unwrap_or_else(|| default_starting_balance(trustline))
            .to_string(),
        trustline: terms.trustline.cloned(),
        sequence: state
            .sequence
            .checked_add(1)
            .ok_or("Account sequence overflow")?
            .to_string(),
        fee_stroops: 0,
        expires_at: now.checked_add(300).ok_or("Expiry overflow")?,
        transaction_xdr: String::new(),
        transaction_hash: String::new(),
        intent_digest: String::new(),
    };
    v.fee_stroops = terms
        .fee_per_operation
        .checked_mul(operation_count(&v))
        .ok_or("Fee overflow")?;
    let tx = transaction(&v)?;
    v.transaction_hash = hex(&transaction_hash(terms.network, &tx)?);
    v.transaction_xdr = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: Vec::new().try_into().map_err(err)?,
    }))?;
    v.intent_digest = intent_digest(&v)?;
    Ok(v)
}

/// Rebuild the complete unsigned XDR. Metadata cannot conceal additional authority or transfers.
pub fn validate_native_setup(v: &NativeSetup) -> Result<()> {
    let tx = transaction(v)?;
    let expected = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: Vec::new().try_into().map_err(err)?,
    }))?;
    if expected != v.transaction_xdr
        || hex(&transaction_hash(&v.network, &tx)?) != v.transaction_hash
        || intent_digest(v)? != v.intent_digest
    {
        return Err("Native setup bytes or identity differ".into());
    }
    Ok(())
}

/// The roles of one wallet account.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletRoles<'a> {
    pub wallet: &'a str,
    pub owner: &'a str,
    pub agent: &'a str,
    pub engine: &'a str,
}
/// One owner action on a wallet account. The owner's account is the transaction source and
/// pays the fee; one owner signature authorizes every operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletAction {
    /// Send funds from the owner's account to the wallet.
    Fund { units: i64 },
    /// Remove the agent signer: the server alone cannot pay, so no payment settles.
    Pause,
    /// Restore the agent signer.
    Resume,
    /// Send funds from the wallet to the owner, or to `recipient`.
    Withdraw {
        units: i64,
        recipient: Option<String>,
    },
    /// Remove every signer and merge the account into the owner's account. `token_balance`
    /// is the wallet's balance of its issued asset, which returns to the owner first.
    Close { token_balance: i64 },
    /// Send the fee float of a fee account back to the owner. The account stays.
    ReturnFees { units: i64 },
}
impl WalletAction {
    /// The action name of the owner step.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fund { .. } => "fund",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Withdraw { .. } => "withdraw",
            Self::Close { .. } => "close",
            Self::ReturnFees { .. } => RETURN_FEES,
        }
    }
}

/// The unsigned transaction of one owner action on a wallet. `owner_state` is the owner's
/// account, and `wallet_state` the wallet as the ledger holds it: an account whose signers or
/// thresholds differ from its roles is refused.
#[allow(clippy::too_many_arguments)]
pub fn prepare_wallet_action(
    owner_state: &AccountState,
    wallet_state: &AccountState,
    roles: WalletRoles<'_>,
    action: &WalletAction,
    asset: &Asset,
    network: &str,
    fee_per_operation: u32,
    now: u64,
) -> Result<owner_intent::OwnerTransaction> {
    passphrase(network)?;
    if owner_state.address != roles.owner || wallet_state.address != roles.wallet {
        return Err("Owner action accounts differ from the wallet roles".into());
    }
    check_owner_source(owner_state)?;
    let status = wallet_state.wallet_status(roles.owner, roles.agent, roles.engine)?;
    if !(100..=100_000).contains(&fee_per_operation) {
        return Err("Fee must be 100..100000 stroops per operation".into());
    }
    let wallet = wallet_source(roles.wallet)?;
    let positive = |units: i64| -> Result<i64> {
        if units <= 0 {
            return Err("Enter a positive amount".into());
        }
        Ok(units)
    };
    let operations = match action {
        WalletAction::Fund { units } => vec![Operation {
            source_account: None,
            body: OperationBody::Payment(PaymentOp {
                destination: muxed(roles.wallet)?,
                asset: asset.clone(),
                amount: positive(*units)?,
            }),
        }],
        WalletAction::Pause => {
            if status == WalletStatus::Paused {
                return Err("This wallet is already paused".into());
            }
            vec![signer_operation(
                roles.wallet,
                account_key(roles.agent)?,
                0,
            )?]
        }
        WalletAction::Resume => {
            if status == WalletStatus::Active {
                return Err("This wallet is not paused".into());
            }
            vec![signer_operation(
                roles.wallet,
                account_key(roles.agent)?,
                AUTOMATED_WEIGHT,
            )?]
        }
        WalletAction::Withdraw { units, recipient } => {
            let recipient = recipient.as_deref().unwrap_or(roles.owner);
            if recipient == roles.wallet {
                return Err("The wallet cannot be its own recipient".into());
            }
            vec![Operation {
                source_account: wallet.clone(),
                body: OperationBody::Payment(PaymentOp {
                    destination: muxed(recipient)?,
                    asset: asset.clone(),
                    amount: positive(*units)?,
                }),
            }]
        }
        WalletAction::ReturnFees { units } => vec![Operation {
            source_account: wallet.clone(),
            body: OperationBody::Payment(PaymentOp {
                destination: muxed(roles.owner)?,
                asset: Asset::Native,
                amount: positive(*units)?,
            }),
        }],
        WalletAction::Close { token_balance } => {
            let mut operations = Vec::new();
            if *asset != Asset::Native {
                if *token_balance < 0 {
                    return Err("Invalid issued asset balance".into());
                }
                if *token_balance > 0 {
                    operations.push(Operation {
                        source_account: wallet.clone(),
                        body: OperationBody::Payment(PaymentOp {
                            destination: muxed(roles.owner)?,
                            asset: asset.clone(),
                            amount: *token_balance,
                        }),
                    });
                }
                operations.push(Operation {
                    source_account: wallet.clone(),
                    body: OperationBody::ChangeTrust(ChangeTrustOp {
                        line: change_trust_asset(asset)?,
                        limit: 0,
                    }),
                });
            }
            // The network checks every signature before the first operation, so the owner's
            // signature also authorizes the merge after its own signer is removed. An account
            // with a signer cannot merge.
            if status == WalletStatus::Active {
                operations.push(signer_operation(
                    roles.wallet,
                    account_key(roles.agent)?,
                    0,
                )?);
            }
            operations.push(signer_operation(
                roles.wallet,
                account_key(roles.engine)?,
                0,
            )?);
            operations.push(signer_operation(
                roles.wallet,
                account_key(roles.owner)?,
                0,
            )?);
            operations.push(Operation {
                source_account: wallet.clone(),
                body: OperationBody::AccountMerge(muxed(roles.owner)?),
            });
            operations
        }
    };
    let count = u32::try_from(operations.len()).map_err(err)?;
    let expires_at = now.checked_add(300).ok_or("Expiry overflow")?;
    let tx = Transaction {
        source_account: muxed(roles.owner)?,
        fee: fee_per_operation.checked_mul(count).ok_or("Fee overflow")?,
        seq_num: SequenceNumber(
            owner_state
                .sequence
                .checked_add(1)
                .ok_or("Account sequence overflow")?,
        ),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(expires_at),
        }),
        memo: Memo::None,
        operations: operations.try_into().map_err(err)?,
        ext: TransactionExt::V0,
    };
    Ok(owner_intent::OwnerTransaction {
        network: network.into(),
        action: action.name().into(),
        transaction_hash: transaction_hash(network, &tx)?,
        transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: Vec::new().try_into().map_err(err)?,
        }))?,
        expires_at,
    })
}

/// Whether the agent of a wallet can sign with the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletStatus {
    Active,
    /// The owner removed the agent signer.
    Paused,
}

/// Ask the Testnet faucet once. An uncertain response is not permission to repeat funding blindly.
#[cfg(not(target_arch = "wasm32"))]
pub fn fund_testnet_account(account: &str, endpoint: Option<&str>) -> Result<String> {
    account_key(account)?;
    let origin = service_origin(endpoint, "https://friendbot.stellar.org")?;
    let response = service_json(&format!("{origin}/?addr={account}"))?;
    let hash = response["hash"]
        .as_str()
        .ok_or("Friendbot did not return a transaction hash; check the account balance")?;
    unhex::<32>(hash)?;
    Ok(hash.into())
}
#[cfg(not(target_arch = "wasm32"))]
fn service_origin(endpoint: Option<&str>, default: &str) -> Result<String> {
    allowit_core::client::config::parse_origin(
        endpoint.filter(|v| !v.is_empty()).unwrap_or(default),
    )
    .map_err(|_| "Stellar service endpoint must be an HTTPS or local HTTP origin".into())
}
#[cfg(not(target_arch = "wasm32"))]
fn service_json(url: &str) -> Result<serde_json::Value> {
    use allowit_core::transport::{
        http::{HttpClient, Method, Request},
        rpc::Options,
    };
    let client = HttpClient::new(Options {
        timeout: std::time::Duration::from_secs(30),
        max_response_bytes: 1_048_576,
        no_proxy: false,
        connect_timeout: None,
    })
    .map_err(|_| "Cannot initialize Stellar service transport")?;
    let response = client
        .send_success_body(
            Request {
                method: Method::Get,
                url,
                headers: &[],
                body: None,
            },
            None,
        )
        .map_err(|_| "Stellar service result is unavailable or uncertain")?;
    if !(200..300).contains(&response.status) {
        return Err(format!(
            "Stellar service refused the request (HTTP {})",
            response.status
        ));
    }
    serde_json::from_slice(&response.body).map_err(|_| "Invalid Stellar service response".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    const NETWORK: &str = "stellar:testnet";
    fn owner_state() -> AccountState {
        AccountState {
            address: account_for_seed(&[1; 32]),
            sequence: 10,
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        }
    }
    fn agent(n: u8) -> String {
        account_for_seed(&[n; 32])
    }
    fn engine() -> String {
        account_for_seed(&[3; 32])
    }
    /// A fixed setup key for `agent`, so the tests name the same wallet account each time.
    fn wallet_key(agent: &str, index: u32) -> WalletKey {
        WalletKey::from_seed(&hash(format!("wallet {agent} {index}").as_bytes()))
    }
    fn terms<'a>(wallet: &'a str, agent: &'a str, engine: &'a str) -> SetupTerms<'a> {
        SetupTerms {
            wallet,
            agent,
            engine,
            request_id: "stellar-setup-001",
            network: NETWORK,
            fee_per_operation: 100,
            starting_balance: None,
            trustline: None,
        }
    }
    fn setup(agent: &str) -> NativeSetup {
        let wallet = wallet_key(agent, 0).account();
        prepare_native_setup(
            &owner_state(),
            &terms(&wallet, agent, &engine()),
            1_800_000_000,
        )
        .unwrap()
    }
    /// The account that the setup transaction of `v` leaves on the ledger.
    fn created(v: &NativeSetup) -> AccountState {
        let TransactionEnvelope::Tx(envelope) = read(&v.transaction_xdr).unwrap() else {
            panic!()
        };
        let mut state = AccountState {
            address: v.wallet.clone(),
            sequence: 0,
            master_weight: 1,
            low_threshold: 0,
            medium_threshold: 0,
            high_threshold: 0,
            signers: vec![],
        };
        for operation in envelope.tx.operations.iter() {
            apply(&mut state, operation);
        }
        state
    }
    /// Apply the signer and threshold changes of one operation on `state`'s account.
    fn apply(state: &mut AccountState, operation: &Operation) {
        let OperationBody::SetOptions(options) = &operation.body else {
            return;
        };
        assert_eq!(
            operation.source_account,
            Some(muxed(&state.address).unwrap())
        );
        if let Some(weight) = options.master_weight {
            state.master_weight = weight;
        }
        if let Some(threshold) = options.low_threshold {
            state.low_threshold = threshold;
        }
        if let Some(threshold) = options.med_threshold {
            state.medium_threshold = threshold;
        }
        if let Some(threshold) = options.high_threshold {
            state.high_threshold = threshold;
        }
        if let Some(signer) = &options.signer {
            let SignerKey::Ed25519(key) = &signer.key else {
                panic!()
            };
            let key = account_for_public_key(&key.0);
            state.signers.retain(|s| s.key != key);
            if signer.weight > 0 {
                state.signers.push(AccountSigner {
                    key,
                    weight: signer.weight,
                });
            }
        }
    }
    fn weight_of(state: &AccountState, signers: &[&str]) -> u32 {
        signers
            .iter()
            .map(|signer| state.signer_weight(signer).unwrap())
            .sum()
    }

    #[test]
    fn setup_is_one_transaction_that_creates_the_account_and_its_exact_roles() {
        let agent = agent(2);
        let v = setup(&agent);
        validate_native_setup(&v).unwrap();
        let TransactionEnvelope::Tx(tx) = read(&v.transaction_xdr).unwrap() else {
            panic!()
        };
        assert_eq!(tx.tx.operations.len(), 4);
        assert_eq!(tx.tx.fee, 400);
        assert!(tx.signatures.is_empty());
        assert_eq!(tx.tx.source_account, muxed(&v.owner).unwrap());
        let OperationBody::CreateAccount(create) = &tx.tx.operations[0].body else {
            panic!()
        };
        assert_eq!(tx.tx.operations[0].source_account, None);
        assert_eq!(create.starting_balance, 30_000_000);
        assert_eq!(v.starting_balance, "30000000");
        assert_eq!(wallet_reserve(false), 25_000_000);
        let state = created(&v);
        state.validate_roles(&v.owner, &agent, &engine()).unwrap();
        let encoded = serde_json::to_string(&v).unwrap();
        assert!(!encoded.contains("seed"));
        for change in [
            |v: &mut NativeSetup| v.engine = account_for_seed(&[4; 32]),
            |v: &mut NativeSetup| v.wallet = account_for_seed(&[5; 32]),
            |v: &mut NativeSetup| v.network = "stellar:mainnet".into(),
            |v: &mut NativeSetup| v.fee_stroops = 401,
            |v: &mut NativeSetup| v.starting_balance = "30000001".into(),
        ] {
            let mut changed = v.clone();
            change(&mut changed);
            assert!(validate_native_setup(&changed).is_err());
        }
    }
    #[test]
    fn agent_and_server_pay_only_together_and_the_owner_does_everything_alone() {
        let agent = agent(2);
        let v = setup(&agent);
        let state = created(&v);
        let server = engine();
        // A payment needs the medium threshold, a signer change or a merge the high one.
        assert!(weight_of(&state, &[&agent]) < state.medium_threshold);
        assert!(weight_of(&state, &[&server]) < state.medium_threshold);
        assert!(weight_of(&state, &[&agent, &server]) >= state.medium_threshold);
        assert!(weight_of(&state, &[&agent, &server]) >= state.low_threshold);
        assert!(weight_of(&state, &[&agent, &server]) < state.high_threshold);
        assert!(weight_of(&state, &[&v.owner]) >= state.high_threshold);
        assert!(
            state
                .validate_signer_quorum(&[&agent], state.medium_threshold)
                .is_err()
        );
        assert!(
            state
                .validate_signer_quorum(&[&server], state.medium_threshold)
                .is_err()
        );
        state
            .validate_signer_quorum(&[&agent, &server], state.medium_threshold)
            .unwrap();
        state
            .validate_signer_quorum(&[&v.owner], state.high_threshold)
            .unwrap();
    }
    #[test]
    fn the_derived_key_has_no_authority_after_setup() {
        let agent = agent(2);
        let v = setup(&agent);
        let state = created(&v);
        assert_eq!(state.master_weight, 0);
        assert_eq!(state.signer_weight(&v.wallet).unwrap(), 0);
        assert!(
            state
                .validate_signer_quorum(&[&v.wallet], state.low_threshold)
                .is_err()
        );
    }
    #[test]
    fn each_setup_key_is_new_and_names_another_account() {
        let (a, b) = (WalletKey::random().unwrap(), WalletKey::random().unwrap());
        assert_ne!(a.account(), b.account());
        // The key signs for its own account and for no other.
        let digest = [7; 32];
        signing::verify_digest(&a.account(), &digest, &a.sign_hash(&digest)).unwrap();
        assert!(signing::verify_digest(&b.account(), &digest, &a.sign_hash(&digest)).is_err());
    }
    #[test]
    fn reused_roles_and_a_shared_owner_account_are_refused() {
        let agent = agent(2);
        let owner = owner_state();
        let wallet = wallet_key(&agent, 0).account();
        // The owner's own account is never the wallet.
        for (wallet, agent, engine) in [
            (owner.address.clone(), agent.clone(), engine()),
            (wallet.clone(), owner.address.clone(), engine()),
            (wallet.clone(), agent.clone(), agent.clone()),
            (wallet.clone(), wallet.clone(), engine()),
        ] {
            assert!(prepare_native_setup(&owner, &terms(&wallet, &agent, &engine), 1).is_err());
        }
        // An owner account whose key cannot pay alone cannot set up a wallet with one signature.
        for raise in [
            |a: &mut AccountState| a.medium_threshold = 2,
            |a: &mut AccountState| a.low_threshold = 2,
            |a: &mut AccountState| a.master_weight = 0,
        ] {
            let mut shared = owner.clone();
            raise(&mut shared);
            assert!(prepare_native_setup(&shared, &terms(&wallet, &agent, &engine()), 1).is_err());
        }
        let mut low = terms(&wallet, &agent, "");
        let server = engine();
        low.engine = &server;
        low.starting_balance = Some(wallet_reserve(false));
        assert!(prepare_native_setup(&owner, &low, 1).is_err());
    }
    #[test]
    fn an_issued_asset_adds_its_trustline_and_its_reserve() {
        let agent = agent(2);
        let wallet = wallet_key(&agent, 0).account();
        let trustline = Trustline {
            code: "USDC".into(),
            issuer: account_for_seed(&[7; 32]),
        };
        let server = engine();
        let mut terms = terms(&wallet, &agent, &server);
        terms.trustline = Some(&trustline);
        let v = prepare_native_setup(&owner_state(), &terms, 1).unwrap();
        validate_native_setup(&v).unwrap();
        let TransactionEnvelope::Tx(tx) = read(&v.transaction_xdr).unwrap() else {
            panic!()
        };
        assert_eq!(tx.tx.operations.len(), 5);
        assert_eq!(tx.tx.fee, 500);
        assert!(matches!(
            tx.tx.operations[1].body,
            OperationBody::ChangeTrust(_)
        ));
        assert_eq!(v.starting_balance, "35000000");
        created(&v)
            .validate_roles(&v.owner, &agent, &server)
            .unwrap();
    }
    #[test]
    fn the_owner_pauses_resumes_withdraws_and_closes_with_one_signature() {
        let agent = agent(2);
        let v = setup(&agent);
        let server = engine();
        let roles = WalletRoles {
            wallet: &v.wallet,
            owner: &v.owner,
            agent: &agent,
            engine: &server,
        };
        let owner = owner_state();
        let mut state = created(&v);
        let run = |state: &AccountState, action: WalletAction| {
            prepare_wallet_action(
                &owner,
                state,
                roles,
                &action,
                &Asset::Native,
                NETWORK,
                100,
                5,
            )
        };
        let operations = |packet: &owner_intent::OwnerTransaction| {
            let TransactionEnvelope::Tx(envelope) = read(&packet.transaction_xdr).unwrap() else {
                panic!()
            };
            // The owner's account is the source and pays; no signature is attached.
            assert_eq!(envelope.tx.source_account, muxed(&v.owner).unwrap());
            assert_eq!(envelope.tx.seq_num.0, 11);
            assert!(envelope.signatures.is_empty());
            owner_intent::validate_retained_owner_transaction(packet).unwrap();
            envelope.tx.operations.to_vec()
        };
        let pause = run(&state, WalletAction::Pause).unwrap();
        assert_eq!(pause.action, "pause");
        for operation in operations(&pause) {
            apply(&mut state, &operation);
        }
        // A paused wallet has no agent signer: the server alone is below the payment threshold.
        assert_eq!(
            state.wallet_status(&v.owner, &agent, &server).unwrap(),
            WalletStatus::Paused
        );
        assert!(state.validate_roles(&v.owner, &agent, &server).is_err());
        assert!(weight_of(&state, &[&agent, &server]) < state.medium_threshold);
        assert!(run(&state, WalletAction::Pause).is_err());
        let resume = run(&state, WalletAction::Resume).unwrap();
        for operation in operations(&resume) {
            apply(&mut state, &operation);
        }
        state.validate_roles(&v.owner, &agent, &server).unwrap();
        assert!(run(&state, WalletAction::Resume).is_err());

        let withdraw = run(
            &state,
            WalletAction::Withdraw {
                units: 7,
                recipient: None,
            },
        )
        .unwrap();
        let [payment] = operations(&withdraw).try_into().unwrap();
        let OperationBody::Payment(body) = &payment.body else {
            panic!()
        };
        assert_eq!(payment.source_account, Some(muxed(&v.wallet).unwrap()));
        assert_eq!(body.destination, muxed(&v.owner).unwrap());
        assert_eq!(body.amount, 7);
        assert!(
            run(
                &state,
                WalletAction::Withdraw {
                    units: 0,
                    recipient: None
                }
            )
            .is_err()
        );

        let fund = run(&state, WalletAction::Fund { units: 9 }).unwrap();
        let [payment] = operations(&fund).try_into().unwrap();
        assert_eq!(payment.source_account, None);

        let close = run(&state, WalletAction::Close { token_balance: 0 }).unwrap();
        let closing = operations(&close);
        assert_eq!(closing.len(), 4);
        for operation in &closing {
            apply(&mut state, operation);
        }
        // Every signer is gone before the merge returns the balance and the reserve.
        assert!(state.signers.is_empty());
        let OperationBody::AccountMerge(destination) = &closing[3].body else {
            panic!()
        };
        assert_eq!(*destination, muxed(&v.owner).unwrap());
    }
    #[test]
    fn an_owner_action_refuses_an_account_with_other_authority() {
        let agent = agent(2);
        let v = setup(&agent);
        let server = engine();
        let roles = WalletRoles {
            wallet: &v.wallet,
            owner: &v.owner,
            agent: &agent,
            engine: &server,
        };
        let mut foreign = created(&v);
        foreign.signers.push(AccountSigner {
            key: account_for_seed(&[9; 32]),
            weight: 1,
        });
        let mut drifted = created(&v);
        drifted.high_threshold = 2;
        let mut revived = created(&v);
        revived.master_weight = 1;
        for state in [foreign, drifted, revived] {
            assert!(
                prepare_wallet_action(
                    &owner_state(),
                    &state,
                    roles,
                    &WalletAction::Pause,
                    &Asset::Native,
                    NETWORK,
                    100,
                    5,
                )
                .is_err()
            );
        }
    }

    // A fee account: the account that sends the agent's operations on one policy wallet.
    /// A fixed setup key of the fee account for `agent`.
    fn fee_key(agent: &str) -> WalletKey {
        WalletKey::from_seed(&hash(format!("fee account {agent}").as_bytes()))
    }
    fn fee_setup(agent: &str) -> NativeSetup {
        let account = fee_key(agent).account();
        prepare_fee_account_setup(
            &owner_state(),
            &FeeAccountTerms {
                account: &account,
                agent,
                engine: &engine(),
                request_id: &fee_account_request_id(&[7; 32]),
                network: NETWORK,
                fee_per_operation: 100,
            },
            1_800_000_000,
        )
        .unwrap()
    }
    #[test]
    fn a_fee_account_setup_creates_the_exact_roles_with_the_reserve_and_the_float() {
        let agent = agent(2);
        let v = fee_setup(&agent);
        validate_native_setup(&v).unwrap();
        assert_eq!(v.profile, FEE_ACCOUNT_PROFILE);
        let packet = setup_transaction(&v).unwrap();
        assert_eq!(packet.action, CREATE_FEE_ACCOUNT);
        owner_intent::validate_retained_owner_transaction(&packet).unwrap();
        let TransactionEnvelope::Tx(tx) = read(&v.transaction_xdr).unwrap() else {
            panic!()
        };
        // One transaction from the owner's account: the creation and three signer operations.
        assert_eq!(tx.tx.operations.len(), 4);
        assert_eq!(tx.tx.source_account, muxed(&v.owner).unwrap());
        let OperationBody::CreateAccount(create) = &tx.tx.operations[0].body else {
            panic!()
        };
        assert_eq!(create.starting_balance, 75_000_000);
        assert_eq!(
            fee_account_starting_balance(),
            wallet_reserve(false) + FEE_ACCOUNT_FLOAT_STROOPS
        );
        let state = created(&v);
        let server = engine();
        state.validate_roles(&v.owner, &agent, &server).unwrap();
        // The account's own key has no authority. The agent alone and the server alone reach
        // no threshold; together they reach the payment threshold and never the high one,
        // which a signer change, a threshold change and a merge need. The owner reaches all.
        assert_eq!(state.master_weight, 0);
        assert!(weight_of(&state, &[&v.wallet]) < state.low_threshold);
        assert!(weight_of(&state, &[&agent]) < state.low_threshold);
        assert!(weight_of(&state, &[&server]) < state.low_threshold);
        assert!(weight_of(&state, &[&agent, &server]) >= state.medium_threshold);
        assert!(weight_of(&state, &[&agent, &server]) < state.high_threshold);
        assert!(weight_of(&state, &[&v.owner]) >= state.high_threshold);
        // Another balance, a trustline, another role or another network is another setup.
        for change in [
            |v: &mut NativeSetup| v.starting_balance = "75000001".into(),
            |v: &mut NativeSetup| v.starting_balance = "30000000".into(),
            |v: &mut NativeSetup| {
                v.trustline = Some(Trustline {
                    code: "USDC".into(),
                    issuer: account_for_seed(&[7; 32]),
                })
            },
            |v: &mut NativeSetup| v.agent = account_for_seed(&[5; 32]),
            |v: &mut NativeSetup| v.engine = account_for_seed(&[5; 32]),
            |v: &mut NativeSetup| v.profile = OWNER_PROFILE.into(),
            |v: &mut NativeSetup| v.profile = "other".into(),
        ] {
            let mut changed = v.clone();
            change(&mut changed);
            assert!(validate_native_setup(&changed).is_err());
        }
    }
    #[test]
    fn a_fee_account_is_set_up_on_every_network_and_a_wallet_account_on_testnet_only() {
        let agent = agent(2);
        let account = fee_key(&agent).account();
        let server = engine();
        let terms = FeeAccountTerms {
            account: &account,
            agent: &agent,
            engine: &server,
            request_id: "fee-account-0001",
            network: "stellar:pubnet",
            fee_per_operation: 100,
        };
        prepare_fee_account_setup(&owner_state(), &terms, 1).unwrap();
        let mut native = self::terms(&account, &agent, &server);
        native.network = "stellar:pubnet";
        assert!(prepare_native_setup(&owner_state(), &native, 1).is_err());
    }
    #[test]
    fn the_owner_alone_refills_withdraws_from_and_closes_a_fee_account() {
        let agent = agent(2);
        let v = fee_setup(&agent);
        let server = engine();
        let roles = WalletRoles {
            wallet: &v.wallet,
            owner: &v.owner,
            agent: &agent,
            engine: &server,
        };
        let owner = owner_state();
        let mut state = created(&v);
        let run = |state: &AccountState, action: WalletAction| {
            prepare_wallet_action(
                &owner,
                state,
                roles,
                &action,
                &Asset::Native,
                NETWORK,
                100,
                5,
            )
        };
        let operations = |packet: &owner_intent::OwnerTransaction| {
            let TransactionEnvelope::Tx(envelope) = read(&packet.transaction_xdr).unwrap() else {
                panic!()
            };
            // The owner's account is the source and pays; one owner signature authorizes it.
            assert_eq!(envelope.tx.source_account, muxed(&v.owner).unwrap());
            assert!(envelope.signatures.is_empty());
            owner_intent::validate_retained_owner_transaction(packet).unwrap();
            envelope.tx.operations.to_vec()
        };
        let refill = run(&state, WalletAction::Fund { units: 9 }).unwrap();
        let [payment] = operations(&refill).try_into().unwrap();
        let OperationBody::Payment(body) = &payment.body else {
            panic!()
        };
        assert_eq!(payment.source_account, None);
        assert_eq!(body.destination, muxed(&v.wallet).unwrap());
        let returned = run(&state, WalletAction::ReturnFees { units: 7 }).unwrap();
        assert_eq!(returned.action, RETURN_FEES);
        let [payment] = operations(&returned).try_into().unwrap();
        let OperationBody::Payment(body) = &payment.body else {
            panic!()
        };
        assert_eq!(payment.source_account, Some(muxed(&v.wallet).unwrap()));
        assert_eq!(body.destination, muxed(&v.owner).unwrap());
        assert_eq!((body.amount, &body.asset), (7, &Asset::Native));
        assert!(run(&state, WalletAction::ReturnFees { units: 0 }).is_err());
        let close = run(&state, WalletAction::Close { token_balance: 0 }).unwrap();
        let closing = operations(&close);
        for operation in &closing {
            apply(&mut state, operation);
        }
        assert!(state.signers.is_empty());
        let OperationBody::AccountMerge(destination) = &closing.last().unwrap().body else {
            panic!()
        };
        assert_eq!(*destination, muxed(&v.owner).unwrap());
    }
}
