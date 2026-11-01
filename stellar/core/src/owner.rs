//! Public native-account setup. No owner or agent secret enters preparation.
use crate::*;

pub const OWNER_PROFILE: &str = "allowit-stellar-owner-v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeSetup {
    pub version: u32,
    pub profile: String,
    pub request_id: String,
    pub network: String,
    pub owner: String,
    pub agent: String,
    pub engine: String,
    pub sequence: String,
    pub fee_stroops: u32,
    pub expires_at: u64,
    pub transaction_xdr: String,
    pub transaction_hash: String,
    pub intent_digest: String,
}

/// Preserve live-wallet admission elsewhere. Setup admits only an unused master-key account.
pub fn check_fresh(state: &AccountState) -> Result<()> {
    state.validate_structure()?;
    if state.master_weight != 1
        || !state.signers.is_empty()
        || state.low_threshold != 0
        || state.medium_threshold != 0
        || state.high_threshold != 0
    {
        return Err(
            "Native setup requires a fresh owner-master account with default thresholds".into(),
        );
    }
    Ok(())
}

fn transaction(v: &NativeSetup) -> Result<Transaction> {
    if v.network != "stellar:testnet" {
        return Err("Native browser setup supports Stellar Testnet only".into());
    }
    let owner = account_key(&v.owner)?;
    let agent = account_key(&v.agent)?;
    let engine = account_key(&v.engine)?;
    if owner == agent || owner == engine || agent == engine {
        return Err("Owner, agent and engine must be distinct".into());
    }
    if v.version != 1
        || v.profile != OWNER_PROFILE
        || !(8..=100).contains(&v.request_id.len())
        || !v
            .request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        || v.expires_at == 0
        || v.expires_at > 9_007_199_254_740_991
        || !(300..=300_000).contains(&v.fee_stroops)
        || !v.fee_stroops.is_multiple_of(3)
    {
        return Err("Invalid native setup identity or fee".into());
    }
    let sequence: i64 = v.sequence.parse().map_err(err)?;
    if sequence <= 0 || sequence.to_string() != v.sequence {
        return Err("Invalid native setup sequence".into());
    }
    let mut operations = Vec::new();
    for key in [agent, engine] {
        operations.push(Operation {
            source_account: None,
            body: OperationBody::SetOptions(SetOptionsOp {
                signer: Some(stellar_xdr::Signer {
                    key: SignerKey::Ed25519(Uint256(key)),
                    weight: 1,
                }),
                ..Default::default()
            }),
        });
    }
    operations.push(Operation {
        source_account: None,
        body: OperationBody::SetOptions(SetOptionsOp {
            master_weight: Some(3),
            low_threshold: Some(2),
            med_threshold: Some(2),
            high_threshold: Some(3),
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

pub fn intent_digest(v: &NativeSetup) -> Result<String> {
    Ok(hex(&hash(
        serde_json::to_vec(&serde_json::json!([
            OWNER_PROFILE,
            v.request_id,
            v.network,
            v.owner,
            v.agent,
            v.engine,
            v.sequence,
            v.fee_stroops,
            v.expires_at,
            v.transaction_hash
        ]))
        .map_err(err)?,
    )))
}

pub fn prepare_native_setup(
    state: &AccountState,
    agent: &str,
    engine: &str,
    request_id: &str,
    network: &str,
    fee_per_operation: u32,
    now: u64,
) -> Result<NativeSetup> {
    check_fresh(state)?;
    let mut v = NativeSetup {
        version: 1,
        profile: OWNER_PROFILE.into(),
        request_id: request_id.into(),
        network: network.into(),
        owner: state.address.clone(),
        agent: agent.into(),
        engine: engine.into(),
        sequence: state
            .sequence
            .checked_add(1)
            .ok_or("Account sequence overflow")?
            .to_string(),
        fee_stroops: fee_per_operation.checked_mul(3).ok_or("Fee overflow")?,
        expires_at: now.checked_add(300).ok_or("Expiry overflow")?,
        transaction_xdr: String::new(),
        transaction_hash: String::new(),
        intent_digest: String::new(),
    };
    let tx = transaction(&v)?;
    v.transaction_hash = hex(&transaction_hash(network, &tx)?);
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

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> AccountState {
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
    #[test]
    fn exact_three_operation_template_and_public_only_roundtrip() {
        let v = prepare_native_setup(
            &state(),
            &account_for_seed(&[2; 32]),
            &account_for_seed(&[3; 32]),
            "stellar-setup-001",
            "stellar:testnet",
            100,
            1_800_000_000,
        )
        .unwrap();
        validate_native_setup(&v).unwrap();
        let TransactionEnvelope::Tx(tx) = read(&v.transaction_xdr).unwrap() else {
            panic!()
        };
        assert_eq!(tx.tx.operations.len(), 3);
        assert_eq!(tx.tx.fee, 300);
        assert!(tx.signatures.is_empty());
        let encoded = serde_json::to_string(&v).unwrap();
        assert!(!encoded.contains("seed"));
        let mut changed = v.clone();
        changed.engine = account_for_seed(&[4; 32]);
        assert!(validate_native_setup(&changed).is_err());
        changed = v.clone();
        changed.network = "stellar:mainnet".into();
        assert!(validate_native_setup(&changed).is_err());
        changed = v;
        changed.fee_stroops = 301;
        assert!(validate_native_setup(&changed).is_err());
    }
    #[test]
    fn delegated_wallet_and_reused_roles_rejected() {
        let mut s = state();
        s.signers.push(AccountSigner {
            key: account_for_seed(&[9; 32]),
            weight: 1,
        });
        assert!(
            prepare_native_setup(
                &s,
                &account_for_seed(&[2; 32]),
                &account_for_seed(&[3; 32]),
                "stellar-setup-001",
                "stellar:testnet",
                100,
                1
            )
            .is_err()
        );
        assert!(
            prepare_native_setup(
                &state(),
                &state().address,
                &account_for_seed(&[3; 32]),
                "stellar-setup-001",
                "stellar:testnet",
                100,
                1
            )
            .is_err()
        );
    }
}
