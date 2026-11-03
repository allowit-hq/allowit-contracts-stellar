//! Native installation derivation and unsigned owner actions. Callers own admission and storage.
use super::*;
use crate::owner_intent::{ExpectedOwnerIntent, OwnerAction, OwnerLimits, OwnerTransaction};

/// Public native installation inputs after caller admission. Derived XDR and chain identities
/// belong here; private policy generation, source approval and persistence belong to the caller.
#[derive(Clone, Debug)]
pub struct PolicyInstallation {
    pub network: String,
    pub policy_instance: [u8; 32],
    pub owner: String,
    pub agent: String,
    pub server: String,
    pub tier: PolicyTier,
    pub params: PolicyParams,
    pub asset_symbol: String,
    pub asset_issuer: Option<String>,
    pub policy_source: String,
    pub module_digest: [u8; 32],
    pub max_fee_stroops: u32,
}
impl PolicyInstallation {
    pub fn wallet_config(&self) -> Result<WalletConfig> {
        let asset = sac_address(
            &self.network,
            &asset_from_identity(&self.asset_symbol, self.asset_issuer.as_deref())?,
        )?;
        let rules = policy::tier_rules(self.tier, &self.policy_source)?;
        let config = WalletConfig {
            network: self.network.clone(),
            policy_instance: self.policy_instance,
            wallet: wallet_address(
                &self.network,
                &self.owner,
                &wallet_salt(&self.policy_instance),
            )?,
            owner: self.owner.clone(),
            agent: self.agent.clone(),
            server: self.server.clone(),
            route: WalletRoute::PolicyWallet,
            tier: Some(self.tier),
            language: PolicyLanguage::Portable,
            source_digest: policy::installed_source_digest(
                self.tier,
                &self.module_digest,
                &asset,
                &rules,
                &self.policy_source,
            )?,
            rules,
            params: self.params.clone(),
            asset,
            asset_symbol: self.asset_symbol.clone(),
            asset_issuer: self.asset_issuer.clone(),
            policy_source: self.policy_source.clone(),
            source_hash: hash(&self.policy_source),
            module_digest: self.module_digest,
            max_fee_stroops: self.max_fee_stroops,
        };
        PolicyConfig::for_policy(&config, false)?;
        Ok(config)
    }
}
/// Preserve the existing policy-instance address domain and bytes across repeated preparation.
pub fn wallet_salt(policy_instance: &[u8; 32]) -> [u8; 32] {
    let mut bytes = b"allowit-stellar-wallet-salt-v1\0".to_vec();
    bytes.extend_from_slice(policy_instance);
    hash(bytes)
}
impl PreparedOwnerOperation {
    /// Return an owner-ready packet only after all additional address authorizations completed.
    /// This conversion supplies no new signing authority or caller intent.
    pub fn owner_transaction(&self) -> Result<OwnerTransaction> {
        if !self.pending_authorizers.is_empty() {
            return Err("Owner action still requires another owner's authorization".into());
        }
        Ok(OwnerTransaction {
            network: self.network.clone(),
            action: self.function.clone(),
            transaction_xdr: self.transaction_xdr.clone(),
            transaction_hash: self.transaction_hash,
            expires_at: self.expires_at,
        })
    }
}
impl Deployer<'_> {
    fn owner_packet(
        &self,
        account: &AccountState,
        tx: Transaction,
        action: OwnerAction,
    ) -> Result<OwnerTransaction> {
        let expires_at = match tx.cond {
            Preconditions::Time(ref bounds) => bounds.max_time.0,
            _ => return Err("Owner action has no time bound".into()),
        };
        let name = match &action {
            OwnerAction::Fund { .. } => "fund",
            OwnerAction::Extend { .. } => "extend",
            _ => return Err("Unsupported owner preparation".into()),
        };
        let packet = OwnerTransaction {
            network: self.network.into(),
            action: name.into(),
            transaction_hash: transaction_hash(self.network, &tx)?,
            transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx,
                signatures: VecM::default(),
            }))?,
            expires_at,
        };
        crate::owner_intent::validate_owner_transaction(
            &packet,
            &ExpectedOwnerIntent {
                limits: OwnerLimits {
                    network: self.network.into(),
                    owner: account.address.clone(),
                    next_sequence: account.sequence.checked_add(1).ok_or("Sequence overflow")?,
                    max_fee_stroops: self.max_fee_stroops,
                    valid_until: expires_at,
                },
                action,
            },
            self.now,
        )?;
        Ok(packet)
    }
    /// Prepare one exact SEP-41 owner-to-wallet transfer. Nothing is signed or sent.
    pub fn fund(&self, config: &WalletConfig, units: i128) -> Result<OwnerTransaction> {
        if self.network != config.network || config.route != WalletRoute::PolicyWallet || units <= 0
        {
            return Err(
                "Funding requires a positive amount on the selected policy-wallet network".into(),
            );
        }
        validate_config(config)?;
        if self.max_fee_stroops > config.max_fee_stroops {
            return Err("Funding fee ceiling exceeds the installed ceiling".into());
        }
        let source = self.account(&config.owner)?;
        source.validate_owner_only()?;
        let host = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: address(&config.asset)?,
            function_name: ScSymbol(b"transfer".to_vec().try_into().map_err(err)?),
            args: vec![
                ScVal::Address(address(&config.owner)?),
                ScVal::Address(address(&config.wallet)?),
                i128_value(units),
            ]
            .try_into()
            .map_err(err)?,
        });
        let (tx, value) = self.assemble(&source, host, None)?;
        if value != ScVal::Void {
            return Err("Funding simulation returned another effect result".into());
        }
        self.owner_packet(
            &source,
            tx,
            OwnerAction::Fund {
                asset: config.asset.clone(),
                from: config.owner.clone(),
                to: config.wallet.clone(),
                amount: units,
            },
        )
    }
    /// Renew exactly the current instance and code to the independently observed native limit.
    pub fn extend_wallet(&self, config: &WalletConfig, extend_to: u32) -> Result<OwnerTransaction> {
        if self.network != config.network || config.route != WalletRoute::PolicyWallet {
            return Err("Lifetime renewal requires the selected policy-wallet network".into());
        }
        let lifetime = rpc::wallet_lifetime(
            self.rpc,
            self.network,
            &config.wallet,
            &config.module_digest,
        )?;
        if lifetime.extend_to()? != extend_to {
            return Err("Renewal target differs from the current network limit".into());
        }
        let source = self.account(&config.owner)?;
        source.validate_owner_only()?;
        let footprint = SorobanTransactionData {
            ext: SorobanTransactionDataExt::V0,
            resources: SorobanResources {
                footprint: LedgerFootprint {
                    read_only: rpc::owner_observation::lifetime_keys(
                        &config.wallet,
                        &config.module_digest,
                    )?
                    .to_vec()
                    .try_into()
                    .map_err(err)?,
                    read_write: VecM::default(),
                },
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
        };
        let mut tx = Transaction {
            source_account: muxed(&source.address)?,
            fee: 100,
            seq_num: SequenceNumber(source.sequence.checked_add(1).ok_or("Sequence overflow")?),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(self.now.checked_add(300).ok_or("Expiry overflow")?),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::ExtendFootprintTtl(ExtendFootprintTtlOp {
                    ext: ExtensionPoint::V0,
                    extend_to,
                }),
            }]
            .try_into()
            .map_err(err)?,
            ext: TransactionExt::V1(footprint),
        };
        let response = self.rpc.call("simulateTransaction", json!({"transaction": xdr(&TransactionEnvelope::Tx(TransactionV1Envelope { tx:tx.clone(),signatures:VecM::default() }))?}))?;
        if response.get("error").is_some_and(|v| !v.is_null()) {
            return Err("Wallet lifetime simulation failed".into());
        }
        rpc::reject_restoration(&response)?;
        let data: SorobanTransactionData = read(
            response["transactionData"]
                .as_str()
                .ok_or("Missing renewal resources")?,
        )?;
        let fee = response["minResourceFee"]
            .as_str()
            .ok_or("Missing renewal fee")?
            .parse::<u32>()
            .map_err(err)?
            .checked_add(100)
            .ok_or("Renewal fee overflow")?;
        if data.resource_fee < 0
            || u64::try_from(data.resource_fee).map_err(err)? + 100 != u64::from(fee)
        {
            return Err("Renewal resource fee differs from simulation".into());
        }
        tx.fee = fee;
        tx.ext = TransactionExt::V1(data);
        self.owner_packet(
            &source,
            tx,
            OwnerAction::Extend {
                wallet: config.wallet.clone(),
                wasm_hash: config.module_digest,
                extend_to,
            },
        )
    }
}
