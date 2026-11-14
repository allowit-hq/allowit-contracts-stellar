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
const SIGNERS: i64 = 3;
const MAX_STARTING_BALANCE: i64 = 1_000_000_000_000_000;
const DERIVATION_TITLE: &str = "Allowit Native wallet key v1";
const SEED_DOMAIN: &[u8] = b"allowit-stellar-native-wallet-seed-v1";

/// The balance that the network locks in a wallet account: the account, its three signers and
/// its trustline.
pub fn wallet_reserve(trustline: bool) -> i64 {
    (2 + SIGNERS + i64::from(trustline)) * BASE_RESERVE_STROOPS
}
/// The starting balance of a wallet when the owner names none: the reserve and the fee float.
pub fn default_starting_balance(trustline: bool) -> i64 {
    wallet_reserve(trustline) + FEE_FLOAT_STROOPS
}

/// The message whose owner signature derives the wallet account's one-time key. It names the
/// network, the agent and a wallet index, so each agent of one owner gets its own account and
/// the owner can compute the address again from the same three values.
pub fn wallet_derivation_message(network: &str, agent: &str, index: u32) -> Result<String> {
    let network = passphrase(network)?;
    account_key(agent)?;
    Ok(format!(
        "{DERIVATION_TITLE}\nNetwork: {network}\nAgent: {agent}\nWallet index: {index}\n\nThis signature derives the one-time setup key of this agent's wallet account. It does not authorize spending or move funds."
    ))
}
/// The digest that the owner signs for the derivation: the SEP-53 digest of the message, the
/// one that the owner sign-in signs.
pub fn wallet_derivation_digest(network: &str, agent: &str, index: u32) -> Result<[u8; 32]> {
    Ok(signing::signed_message_digest(&wallet_derivation_message(
        network, agent, index,
    )?))
}
/// The one-time key of a wallet account, from the owner's signature over the derivation
/// message. It signs the creation of its account once. Setup sets its weight to 0.
pub struct WalletKey(SigningKey);
impl WalletKey {
    pub fn from_signature(signature: &[u8; 64]) -> Self {
        let mut bytes = SEED_DOMAIN.to_vec();
        bytes.extend_from_slice(signature);
        let mut seed = hash(&bytes);
        let key = SigningKey::from_bytes(&seed);
        zeroize::Zeroize::zeroize(&mut seed);
        zeroize::Zeroize::zeroize(&mut bytes);
        Self(key)
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
/// medium threshold.
pub fn check_owner_source(state: &AccountState) -> Result<()> {
    state.validate_structure()?;
    if state.master_weight == 0 || state.master_weight < state.medium_threshold {
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
    if v.network != "stellar:testnet" {
        return Err("Native wallet setup supports Stellar Testnet only".into());
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
        || v.profile != OWNER_PROFILE
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
            OWNER_PROFILE,
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
    check_owner_source(state)?;
    let trustline = terms.trustline.is_some();
    let mut v = NativeSetup {
        version: 2,
        profile: OWNER_PROFILE.into(),
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
    /// The wallet key that the owner of seed 1 derives for `agent`.
    fn wallet_key(agent: &str, index: u32) -> WalletKey {
        let digest = wallet_derivation_digest(NETWORK, agent, index).unwrap();
        WalletKey::from_signature(&SigningKey::from_bytes(&[1; 32]).sign(&digest).to_bytes())
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
    fn two_agents_of_one_owner_get_two_accounts_and_the_owner_computes_each_again() {
        let (first, second) = (agent(2), agent(4));
        let a = wallet_key(&first, 0).account();
        let b = wallet_key(&second, 0).account();
        assert_ne!(a, b);
        assert_eq!(a, wallet_key(&first, 0).account());
        assert_ne!(a, wallet_key(&first, 1).account());
        // Another network or another owner derives another account.
        let digest = wallet_derivation_digest("stellar:pubnet", &first, 0).unwrap();
        let other =
            WalletKey::from_signature(&SigningKey::from_bytes(&[1; 32]).sign(&digest).to_bytes());
        assert_ne!(a, other.account());
        let digest = wallet_derivation_digest(NETWORK, &first, 0).unwrap();
        let stranger =
            WalletKey::from_signature(&SigningKey::from_bytes(&[9; 32]).sign(&digest).to_bytes());
        assert_ne!(a, stranger.account());
        let message = wallet_derivation_message(NETWORK, &first, 0).unwrap();
        assert!(message.starts_with("Allowit Native wallet key v1\nNetwork: Test SDF Network"));
        assert!(message.contains(&first) && message.contains("Wallet index: 0"));
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
        let mut shared = owner.clone();
        shared.medium_threshold = 2;
        assert!(prepare_native_setup(&shared, &terms(&wallet, &agent, &engine()), 1).is_err());
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
}
