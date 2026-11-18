//! Owner preparation for the layout 5 policy wallet interface: Wasm upload, the deployer's one-call
//! creation and funding, and owner calls. Preparation simulates and checks every authorization; it
//! never signs. The owner validates its business intent with `owner_intent` before signing through
//! a caller capability. SDK engine submits and observes the exact native hash.
use crate::*;
use allowit_core::admin::{DeployPolicy, DeploymentVersion, RecoverFunds, SetPause};
use serde_json::json;
mod host;
pub use host::{PolicyInstallation, wallet_salt};

/// Complete owner-approved configuration. The version is supplied to deploy_policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeployment {
    /// Native address of the desired policy owner; a changed owner must authorize too.
    pub owner: String,
    /// The agent's key, as an account address. The agent needs no account.
    pub agent: String,
    /// The server's signing key, as an account address.
    pub server: String,
    /// SHA-256 of the owner's full policy source, which the owner's policy signature binds.
    pub source_hash: [u8; 32],
    /// The most that the wallet repays for one request's network fee, in stroops.
    pub gas_cap: i128,
    /// Ordered canonical rules: the standard prefix for Common, none otherwise.
    pub rules: Vec<String>,
    /// Replacement owner params; changing only them needs no code redeployment.
    pub params: PolicyParams,
    /// Optional uploaded policy executable hash to install atomically.
    pub wasm_hash: Option<[u8; 32]>,
}
impl PolicyDeployment {
    /// The deployment that keeps the installed code and binds `source` and `params` to the
    /// installed tier: `contract_admin.py` `policy_rules` for an owner packet.
    pub fn for_source(
        c: &WalletConfig,
        source: &str,
        params: PolicyParams,
    ) -> Result<(Self, policy::PolicyCheck)> {
        let tier = c.tier.ok_or("Selected policy tier is required")?;
        let rules = policy::tier_rules(tier, source)?;
        let source_hash = hash(source.as_bytes());
        if tier == PolicyTier::Custom && source_hash != c.source_hash {
            return Err(
                "A Custom wallet binds its compiled source; new source needs new code".into(),
            );
        }
        let source_digest =
            policy::installed_source_digest(tier, &c.module_digest, &c.asset, &rules, source)?;
        let check = policy::policy_rules(tier, source, &rules, &source_digest, &params)?;
        Ok((
            Self {
                owner: c.owner.clone(),
                agent: c.agent.clone(),
                server: c.server.clone(),
                source_hash,
                gas_cap: i128::from(c.max_fee_stroops),
                rules,
                params,
                wasm_hash: None,
            },
            check,
        ))
    }
    /// Field checks of `contract_admin.py` `deployment`.
    pub fn validate(&self, version: DeploymentVersion) -> Result<()> {
        if version.0 == 0 || version.0 > u64::from(u32::MAX) {
            return Err("Invalid deployment version".into());
        }
        address(&self.owner)?;
        // The wallet stores the agent and server as raw Ed25519 keys.
        account_key(&self.agent).map_err(|_| "The agent is an Ed25519 key")?;
        account_key(&self.server).map_err(|_| "The server is an Ed25519 key")?;
        if [&self.agent, &self.server].contains(&&self.owner) || self.agent == self.server {
            return Err("Owner, agent and server must differ".into());
        }
        if self.source_hash == [0; 32] {
            return Err("Source hash must be nonzero".into());
        }
        if self.gas_cap < 0 {
            return Err("The gas cap is not negative".into());
        }
        policy::parse_rules(&self.rules)?;
        self.params.check(PolicyTier::Custom)?;
        Ok(())
    }
    /// The exact `AllowitPolicyUpdate` argument.
    pub fn scval(&self, version: DeploymentVersion) -> Result<ScVal> {
        self.validate(version)?;
        contract::policy_update(contract::PolicyUpdate {
            deployment_version: u32::try_from(version.0).map_err(err)?,
            owner: &self.owner,
            agent: &self.agent,
            server: &self.server,
            source_hash: &self.source_hash,
            gas_cap: self.gas_cap,
            rules: &self.rules,
            params: &self.params,
            wasm_hash: self.wasm_hash.as_ref(),
        })
    }
}

/// Exact policy-wallet constructor packet: `AllowitPolicyConfig`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub owner: String,
    pub agent: String,
    pub server: String,
    pub asset: String,
    pub source_hash: [u8; 32],
    pub gas_cap: i128,
    pub rules: Vec<String>,
    pub params: PolicyParams,
}
impl PolicyConfig {
    /// The constructor packet of a validated installation. `config.wallet` is the address that
    /// `wallet_address` derives, and `config.module_digest` the uploaded Wasm hash.
    pub fn for_policy(c: &WalletConfig) -> Result<Self> {
        validate_config(c)?;
        if c.route != WalletRoute::PolicyWallet {
            return Err("A contract policy-wallet rail is required".into());
        }
        let tier = c.tier.ok_or("Selected policy tier is required")?;
        policy::policy_rules(
            tier,
            &c.policy_source,
            &c.rules,
            &c.source_digest,
            &c.params,
        )?;
        let config = Self {
            owner: c.owner.clone(),
            agent: c.agent.clone(),
            server: c.server.clone(),
            asset: c.asset.clone(),
            source_hash: c.source_hash,
            gas_cap: i128::from(c.max_fee_stroops),
            rules: c.rules.clone(),
            params: c.params.clone(),
        };
        config.validate()?;
        Ok(config)
    }
    /// Checks of `contract_admin.py` `deploy-wallet`: roles, identities, rules and params.
    pub fn validate(&self) -> Result<()> {
        PolicyDeployment {
            owner: self.owner.clone(),
            agent: self.agent.clone(),
            server: self.server.clone(),
            source_hash: self.source_hash,
            gas_cap: self.gas_cap,
            rules: self.rules.clone(),
            params: self.params.clone(),
            wasm_hash: None,
        }
        .validate(DeploymentVersion(1))?;
        Contract::from_string(&self.asset).map_err(err)?;
        account_key(&self.owner)
            .map_err(|_| "Policy wallet deployment source must be its G-account owner")?;
        Ok(())
    }
    /// The single constructor argument.
    pub fn constructor_args(&self) -> Result<Vec<ScVal>> {
        self.validate()?;
        Ok(vec![contract::policy_config(contract::PolicyConfig {
            owner: &self.owner,
            agent: &self.agent,
            server: &self.server,
            asset: &self.asset,
            source_hash: &self.source_hash,
            gas_cap: self.gas_cap,
            rules: &self.rules,
            params: &self.params,
        })?])
    }
}

/// Unsigned native transaction for owner review and native-wallet authorization.
/// It is not a deployment receipt, a signing URL or permission to broadcast.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedOwnerOperation {
    pub network: String,
    pub wallet: String,
    pub owner: String,
    pub function: String,
    /// Target deployment version, or the unchanged observed version for recovery.
    pub deployment_version: u64,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub expires_at: u64,
    pub required_authorizers: Vec<String>,
    /// Owners whose address authorization entry is still unsigned (the new owner of an owner
    /// handoff). While this is not empty, the transaction cannot be submitted and
    /// `transaction_hash` is provisional. Call [`OwnerAdmin::complete_owner_handoff`] with the
    /// new owner's signed entry first. The current owner signs only the returned transaction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_authorizers: Vec<String>,
    /// Owner-visible warnings of `contract_admin.py` `policy_rules`, such as prefix rules whose
    /// param is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Bound vendor implementation. Native account ownership is required for this
/// preparation route. Contract-owner authorization needs its own native adapter.
pub struct OwnerAdmin<'a> {
    pub rpc: &'a dyn rpc::Rpc,
    pub config: &'a WalletConfig,
    pub now: u64,
}
/// How much of the installed wallet an owner call checks before preparation. Each level
/// matches what the contract entrypoint itself reads, so an owner can always prepare a call that
/// the contract would accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    /// `recover` and `stop`: the fixed header of this or a later layout and the owner-only
    /// account. A wallet whose code or policy binding is broken stays recoverable.
    Kept,
    /// `set_pause` and `deploy_policy` with new code: also the whole configuration of this
    /// layout.
    Layout,
    /// Packets bound to the installed code: also the owner-approved executable, the policy
    /// binding and the custody fields.
    Bound,
}
struct Snapshot {
    owner: AccountState,
    deployment_version: DeploymentVersion,
    state: Option<packed::Configuration>,
}
impl AccountState {
    /// `wallet_admin.py` `owner_only`: only the master key is active and it meets every
    /// threshold. A delegated native quorum cannot own a policy wallet.
    pub fn validate_owner_only(&self) -> Result<()> {
        self.validate_structure()?;
        if self.master_weight == 0
            || self.signers.iter().any(|s| s.weight > 0)
            || [
                self.low_threshold,
                self.medium_threshold,
                self.high_threshold,
            ]
            .iter()
            .any(|t| *t > self.master_weight)
        {
            return Err("Policy wallet owner must have only its master key active; delegated native quorums are unsafe".into());
        }
        Ok(())
    }
}
impl OwnerAdmin<'_> {
    fn snapshot(&self, reach: Reach) -> Result<Snapshot> {
        let c = self.config;
        validate_config(c)?;
        if c.route != WalletRoute::PolicyWallet {
            return Err("Owner administration requires policy wallet custody".into());
        }
        if self.rpc.call("getNetwork", json!({}))?["passphrase"] != passphrase(&c.network)? {
            return Err("Stellar RPC network differs from installation".into());
        }
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: address(&c.wallet)?,
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let entries = self
            .rpc
            .call("getLedgerEntries", json!({"keys":[xdr(&key)?]}))?;
        let list = entries["entries"]
            .as_array()
            .ok_or("Missing policy wallet instance")?;
        if list.len() != 1 {
            return Err("The policy wallet instance is not on the ledger. A lapsed instance is read whatever its lifetime; if the RPC serves no archived entry, restore the wallet's instance first (for example with stellar contract restore).".into());
        }
        let LedgerEntryData::ContractData(data) =
            read(list[0]["xdr"].as_str().ok_or("Missing instance XDR")?)?
        else {
            return Err("Unexpected policy wallet ledger entry".into());
        };
        if data.contract != address(&c.wallet)?
            || data.key != ScVal::LedgerKeyContractInstance
            || data.durability != ContractDataDurability::Persistent
        {
            return Err("policy wallet instance key differs".into());
        }
        let ScVal::ContractInstance(instance) = data.val else {
            return Err("Missing policy wallet instance".into());
        };
        if reach == Reach::Bound
            && instance.executable != ContractExecutable::Wasm(Hash(c.module_digest))
        {
            return Err("policy wallet executable differs from owner-approved code".into());
        }
        let storage = instance.storage.ok_or("Missing policy wallet storage")?;
        let Some(ScVal::Bytes(raw)) = storage
            .iter()
            .find(|e| e.key == value_symbol("c").unwrap_or(ScVal::Void))
            .map(|e| &e.val)
        else {
            return Err("Missing policy wallet configuration".into());
        };
        // The owner calls read the fixed header, which every later layout keeps; the others
        // need the whole configuration of this layout.
        let header = packed::header(raw.as_slice())?;
        if header.layout < packed::LAYOUT {
            return Err(format!(
                "Unsupported policy wallet layout {}; this crate reads layout {} or a later one",
                header.layout,
                packed::LAYOUT
            ));
        }
        if header.owner != c.owner {
            return Err("Current owner differs from the bound owner".into());
        }
        if header.asset != c.asset {
            return Err("Stored asset differs from the installation".into());
        }
        account_key(&header.owner)
            .map_err(|_| "Contract owners require a separate native authorization adapter")?;
        let owner = rpc::get_account(self.rpc, &header.owner)?;
        owner.validate_owner_only()?;
        let state = if reach == Reach::Kept {
            None
        } else {
            Some(packed::configuration(raw.as_slice())?)
        };
        if reach == Reach::Bound {
            let state = state
                .as_ref()
                .ok_or("Missing policy wallet configuration")?;
            rpc::verify_configuration(c, state)?;
        }
        Ok(Snapshot {
            owner,
            deployment_version: DeploymentVersion(u64::from(header.deployment_version)),
            state,
        })
    }
    fn transaction(
        &self,
        source: &AccountState,
        contract: &str,
        function: &str,
        args: Vec<ScVal>,
        expiry: u64,
    ) -> Result<Transaction> {
        let call = InvokeContractArgs {
            contract_address: address(contract)?,
            function_name: ScSymbol(function.as_bytes().to_vec().try_into().map_err(err)?),
            args: args.try_into().map_err(err)?,
        };
        Ok(Transaction {
            source_account: muxed(&source.address)?,
            fee: 100,
            seq_num: SequenceNumber(source.sequence.checked_add(1).ok_or("Sequence overflow")?),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(expiry),
            }),
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
        })
    }
    fn prepare(
        &self,
        snapshot: Snapshot,
        function: &str,
        args: Vec<ScVal>,
        version: DeploymentVersion,
        authorizers: Vec<String>,
    ) -> Result<PreparedOwnerOperation> {
        let expires = self.now.checked_add(300).ok_or("Expiry overflow")?;
        let mut tx = self.transaction(
            &snapshot.owner,
            &self.config.wallet,
            function,
            args,
            expires,
        )?;
        // Record every authorization the contract requires, including a new owner's for an
        // owner handoff. Enforce mode would fail on an entry the transaction does not yet have.
        // The recorded entries are checked against `authorizers` and then become the unsigned
        // transaction's entries for the owners to sign.
        let response=self.rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx:tx.clone(),signatures:VecM::default()}))?,"authMode":"record"}))?;
        if response.get("error").is_some() {
            return Err("Owner operation simulation rejected".into());
        }
        let results = response["results"]
            .as_array()
            .ok_or("Missing simulation result")?;
        if results.len() != 1 {
            return Err("Unexpected owner simulation result count".into());
        }
        let auth = results[0]["auth"]
            .as_array()
            .ok_or("Missing owner authorization entries")?;
        let parsed = auth
            .iter()
            .map(|v| {
                read::<SorobanAuthorizationEntry>(v.as_str().ok_or("Invalid authorization XDR")?)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut operations = tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(ref mut op) = operations[0].body else {
            unreachable!()
        };
        let HostFunction::InvokeContract(call) = &op.host_function else {
            unreachable!()
        };
        let mut seen = Vec::new();
        let mut pending = Vec::new();
        for entry in &parsed {
            if entry.root_invocation.function != SorobanAuthorizedFunction::ContractFn(call.clone())
                || !entry.root_invocation.sub_invocations.is_empty()
            {
                return Err("Owner authorization scope differs".into());
            }
            let who = match &entry.credentials {
                SorobanCredentials::SourceAccount => snapshot.owner.address.clone(),
                // `complete_owner_handoff` and the account signature check sign and verify the
                // classic address payload only, so a recorded `AddressV2` entry is refused here.
                SorobanCredentials::Address(c) => {
                    let who = address_text(&c.address)?;
                    pending.push(who.clone());
                    who
                }
                _ => return Err("Unsupported owner credentials".into()),
            };
            if !authorizers.contains(&who) || seen.contains(&who) {
                return Err("Unexpected owner authorizer".into());
            }
            seen.push(who);
        }
        if authorizers.iter().any(|who| !seen.contains(who)) {
            return Err("Missing required owner authorizer".into());
        }
        op.auth = parsed.try_into().map_err(err)?;
        tx.operations = operations.try_into().map_err(err)?;
        self.apply_resources(&mut tx, &response)?;
        Ok(PreparedOwnerOperation {
            network: self.config.network.clone(),
            wallet: self.config.wallet.clone(),
            owner: snapshot.owner.address,
            function: function.into(),
            deployment_version: version.0,
            transaction_hash: transaction_hash(&self.config.network, &tx)?,
            transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx,
                signatures: VecM::default(),
            }))?,
            expires_at: expires,
            required_authorizers: authorizers,
            pending_authorizers: pending,
            warnings: Vec::new(),
        })
    }
    /// Set the fee and resource data from a simulation, within the configured fee ceiling.
    fn apply_resources(&self, tx: &mut Transaction, response: &serde_json::Value) -> Result<()> {
        let fee = response["minResourceFee"]
            .as_str()
            .ok_or("Missing resource fee")?
            .parse::<u32>()
            .map_err(err)?
            .checked_add(100)
            .ok_or("Fee overflow")?;
        if fee > self.config.max_fee_stroops {
            return Err("Owner operation exceeds configured fee ceiling".into());
        }
        let data: SorobanTransactionData = read(
            response["transactionData"]
                .as_str()
                .ok_or("Missing owner resource data")?,
        )?;
        if data.resource_fee < 0
            || u64::try_from(data.resource_fee).map_err(err)? + 100 != u64::from(fee)
        {
            return Err("Owner resource fee differs from simulation".into());
        }
        tx.fee = fee;
        tx.ext = TransactionExt::V1(data);
        Ok(())
    }
    /// Complete an owner handoff prepared by `deploy_policy`.
    ///
    /// `signed_entry_xdr` is the new owner's recorded authorization entry from
    /// `prepared.transaction_xdr`, signed by the new owner's G-address key with a
    /// `signature_expiration_ledger` after the latest ledger. This checks that only the
    /// expiration ledger and the signature changed, verifies the signature, simulates the
    /// transaction again in enforce mode for the final fee and resources, and returns the final
    /// unsigned transaction and its hash. The current owner signs only that transaction.
    pub fn complete_owner_handoff(
        &self,
        prepared: &PreparedOwnerOperation,
        signed_entry_xdr: &str,
    ) -> Result<PreparedOwnerOperation> {
        validate_config(self.config)?;
        if prepared.network != self.config.network
            || prepared.wallet != self.config.wallet
            || prepared.owner != self.config.owner
            || prepared.function != "deploy_policy"
        {
            return Err("Owner handoff differs from the bound wallet".into());
        }
        let [new_owner] = prepared.pending_authorizers.as_slice() else {
            return Err("Owner handoff requires exactly one pending new owner".into());
        };
        if prepared.required_authorizers != [prepared.owner.clone(), new_owner.clone()] {
            return Err("Owner handoff authorizers differ".into());
        }
        if self.now >= prepared.expires_at {
            return Err("Owner handoff is stale".into());
        }
        let TransactionEnvelope::Tx(envelope) = read(&prepared.transaction_xdr)? else {
            return Err("Expected an owner transaction".into());
        };
        if !envelope.signatures.is_empty() {
            return Err("Owner handoff transaction is already signed".into());
        }
        let mut tx = envelope.tx;
        let Preconditions::Time(bounds) = &tx.cond else {
            return Err("Owner handoff time bounds differ".into());
        };
        if transaction_hash(&self.config.network, &tx)? != prepared.transaction_hash
            || bounds.max_time.0 != prepared.expires_at
        {
            return Err("Owner handoff transaction identity differs".into());
        }
        if tx.operations.len() != 1 {
            return Err("One owner invocation is required".into());
        }
        let mut operations = tx.operations.to_vec();
        let OperationBody::InvokeHostFunction(ref mut op) = operations[0].body else {
            return Err("Expected owner invocation".into());
        };
        let mut auth = op.auth.to_vec();
        let new_owner_address = address(new_owner)?;
        let mut slots = auth.iter().enumerate().filter(|(_, entry)| {
            matches!(&entry.credentials, SorobanCredentials::Address(c) if c.address == new_owner_address)
        });
        let (Some((index, _)), None) = (slots.next(), slots.next()) else {
            return Err("Owner handoff needs one new owner address entry".into());
        };
        let SorobanCredentials::Address(recorded) = &auth[index].credentials else {
            unreachable!()
        };
        if recorded.signature != ScVal::Void {
            return Err("New owner entry is already signed".into());
        }
        let signed: SorobanAuthorizationEntry = read(signed_entry_xdr)?;
        let SorobanCredentials::Address(credentials) = &signed.credentials else {
            return Err("New owner address authorization is required".into());
        };
        let mut unsigned = signed.clone();
        if let SorobanCredentials::Address(c) = &mut unsigned.credentials {
            c.signature = ScVal::Void;
            c.signature_expiration_ledger = recorded.signature_expiration_ledger;
        }
        if unsigned != auth[index] {
            return Err("New owner authorization scope differs".into());
        }
        let latest = self.rpc.call("getLatestLedger", json!({}))?["sequence"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or("Missing latest ledger")?;
        if credentials.signature_expiration_ledger <= latest {
            return Err("New owner authorization has expired".into());
        }
        authorization::verify_account_signature(&self.config.network, &signed, new_owner)?;
        auth[index] = signed;
        op.auth = auth.try_into().map_err(err)?;
        tx.operations = operations.try_into().map_err(err)?;
        // The signed entry changes the transaction, and verifying the new owner's signature
        // changes the resources. Enforce mode checks every entry and returns the final resources.
        let response=self.rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx:tx.clone(),signatures:VecM::default()}))?,"authMode":"enforce"}))?;
        if response.get("error").is_some() {
            return Err("Owner handoff simulation rejected".into());
        }
        if response["results"].as_array().map(Vec::len) != Some(1) {
            return Err("Unexpected owner simulation result count".into());
        }
        self.apply_resources(&mut tx, &response)?;
        let mut out = prepared.clone();
        out.transaction_hash = transaction_hash(&self.config.network, &tx)?;
        out.transaction_xdr = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        }))?;
        out.pending_authorizers = Vec::new();
        Ok(out)
    }
}
impl DeployPolicy for OwnerAdmin<'_> {
    type Artifact = PolicyDeployment;
    type Output = PreparedOwnerOperation;
    type Error = String;
    /// Prepare a complete owner update at the next version without a code change, bound to the
    /// installed policy source. Use `deploy_policy_source` to bind a new source, and
    /// `deploy_code` to install new code.
    fn deploy_policy(
        &mut self,
        version: DeploymentVersion,
        artifact: PolicyDeployment,
    ) -> Result<PreparedOwnerOperation> {
        let source = self.config.policy_source.clone();
        self.deploy_policy_source(version, artifact, &source)
    }
}
impl OwnerAdmin<'_> {
    /// Prepare a complete owner update at the next version without a code change, bound to the
    /// target policy `source`, as `contract_admin.py` binds an owner packet to
    /// `--policy-source`. The packet keeps the installed code: a Common packet carries the
    /// standard prefix digest of the installed code over the target source's prefix, so a
    /// rules-only Common update needs no new code. A Custom wallet binds its compiled source, so
    /// its target source must be the installed source. `config` still describes the installed
    /// binding, which the snapshot verifies on chain.
    pub fn deploy_policy_source(
        &mut self,
        version: DeploymentVersion,
        artifact: PolicyDeployment,
        source: &str,
    ) -> Result<PreparedOwnerOperation> {
        if artifact.wasm_hash.is_some() {
            return Err("Use deploy_code with the Wasm bytes to install new code".into());
        }
        let tier = self.config.tier.ok_or("Selected policy tier is required")?;
        let digest = policy::installed_source_digest(
            tier,
            &self.config.module_digest,
            &self.config.asset,
            &artifact.rules,
            source,
        )?;
        if artifact.source_hash != hash(source.as_bytes())
            || (tier != PolicyTier::Common && !artifact.rules.is_empty())
        {
            return Err(
                "Deployment rules and source hash differ from the installed tier and source".into(),
            );
        }
        if tier == PolicyTier::Custom && artifact.source_hash != self.config.source_hash {
            return Err(
                "A Custom wallet binds its compiled source; new source needs new code".into(),
            );
        }
        // The Common rules are the standard prefix of the target source, and standard tiers
        // write no state.
        let check = policy::policy_rules(tier, source, &artifact.rules, &digest, &artifact.params)?;
        let mut prepared = self.prepare_deployment(version, artifact, Reach::Bound)?;
        prepared.warnings = check.warnings;
        Ok(prepared)
    }
}
impl OwnerAdmin<'_> {
    /// Prepare an owner update that installs uploaded code `wasm` atomically. The new code must
    /// declare custody layout 4, so it can read the stored State; the new code validates its own
    /// rules and params on its next call.
    ///
    /// The packet is bound to `config.tier` and `config.policy_source` as `contract_admin.py`
    /// binds it to `--tier` and `--policy-source`: pass the configuration of the target tier and
    /// source when they change. A Simple or Common packet must carry the standard prefix digest
    /// of the new code, so its binding verifies after the upgrade. A Custom digest is the
    /// source's SHA-256, which the new code checks against its own compiled source. The installed
    /// executable and binding are not required, so this also repairs a broken binding.
    pub fn deploy_code(
        &mut self,
        version: DeploymentVersion,
        mut artifact: PolicyDeployment,
        wasm: &[u8],
    ) -> Result<PreparedOwnerOperation> {
        let hash = check_wallet_code(wasm)?;
        if artifact.wasm_hash.is_some_and(|h| h != hash) {
            return Err("Deployment Wasm hash differs from the supplied code".into());
        }
        let tier = self.config.tier.ok_or("Selected policy tier is required")?;
        let digest = policy::installed_source_digest(
            tier,
            &hash,
            &self.config.asset,
            &artifact.rules,
            &self.config.policy_source,
        )?;
        if artifact.source_hash != crate::hash(self.config.policy_source.as_bytes()) {
            return Err("Deployment source hash differs from the selected source".into());
        }
        let check = policy::policy_rules(
            tier,
            &self.config.policy_source,
            &artifact.rules,
            &digest,
            &artifact.params,
        )?;
        artifact.wasm_hash = Some(hash);
        let mut prepared = self.prepare_deployment(version, artifact, Reach::Layout)?;
        prepared.warnings = check.warnings;
        Ok(prepared)
    }
    fn prepare_deployment(
        &mut self,
        version: DeploymentVersion,
        artifact: PolicyDeployment,
        reach: Reach,
    ) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot(reach)?;
        if !version.follows(s.deployment_version) {
            return Err("Policy deployment must target the next version".into());
        }
        if [&artifact.owner, &artifact.agent, &artifact.server].contains(&&self.config.wallet) {
            return Err("Owner, agent, server and policy wallet must be distinct".into());
        }
        let mut authorizers = vec![s.owner.address.clone()];
        if artifact.owner != s.owner.address {
            account_key(&artifact.owner).map_err(|_| "A new owner must be a native G-account")?;
            rpc::get_account(self.rpc, &artifact.owner)?.validate_owner_only()?;
            authorizers.push(artifact.owner.clone());
        }
        let arguments = artifact.scval(version)?;
        self.prepare(s, "deploy_policy", vec![arguments], version, authorizers)
    }
    /// Recover `amount` of the wallet asset to `recipient`. Like the contract's `recover`, this
    /// reads only the fixed header: no whole configuration, executable or source.
    pub fn recover_to(&mut self, recipient: &str, amount: i128) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot(Reach::Kept)?;
        if amount <= 0 {
            return Err("Recovery amount must be positive".into());
        }
        if recipient == self.config.wallet || self.config.asset_issuer.as_deref() == Some(recipient)
        {
            return Err("Recovery cannot pay the wallet or burn at the issuer".into());
        }
        let version = s.deployment_version;
        let owner = s.owner.address.clone();
        self.prepare(
            s,
            "recover",
            vec![
                ScVal::Address(address(&self.config.asset)?),
                ScVal::Address(address(recipient)?),
                i128_value(amount),
            ],
            version,
            vec![owner],
        )
    }
    /// The owner's stop: one call that pauses the wallet at the next deployment version and
    /// returns its whole asset and XLM balance to the owner. It reads only the fixed header.
    pub fn stop(&mut self, version: DeploymentVersion) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot(Reach::Kept)?;
        if !version.follows(s.deployment_version) {
            return Err("A stop must target the next deployment version".into());
        }
        let owner = s.owner.address.clone();
        let next = u32::try_from(version.0).map_err(err)?;
        self.prepare(s, "stop", vec![ScVal::U32(next)], version, vec![owner])
    }
    /// The current deployment version, read as `set_pause` reads the wallet: the exact layout 4
    /// State and the owner-only account. A changed executable, policy binding or service signer
    /// never blocks it, so the owner can always prepare a pause or resume.
    pub fn deployment_version(&self) -> Result<DeploymentVersion> {
        Ok(self.snapshot(Reach::Layout)?.deployment_version)
    }
    /// The current decoded configuration, read as owner preparation does.
    pub fn custody(&self) -> Result<packed::Configuration> {
        self.snapshot(Reach::Bound)?
            .state
            .ok_or_else(|| "Missing policy wallet configuration".into())
    }
}
impl SetPause for OwnerAdmin<'_> {
    type Output = PreparedOwnerOperation;
    type Error = String;
    fn set_pause(
        &mut self,
        paused: bool,
        version: DeploymentVersion,
    ) -> Result<PreparedOwnerOperation> {
        // The contract's `set_pause` needs only the exact current State, not the binding.
        let s = self.snapshot(Reach::Layout)?;
        if !version.follows(s.deployment_version) {
            return Err("Pause must target the next deployment version".into());
        }
        let authorizers = vec![s.owner.address.clone()];
        self.prepare(
            s,
            "set_pause",
            vec![
                ScVal::Bool(paused),
                ScVal::U32(u32::try_from(version.0).map_err(err)?),
            ],
            version,
            authorizers,
        )
    }
}
impl RecoverFunds for OwnerAdmin<'_> {
    type Output = PreparedOwnerOperation;
    type Error = String;
    /// Recover the full balance observed at preparation. The amount is fixed in the
    /// transaction, so an agent payment or x402 transfer that settles before the recovery makes
    /// it fail with `InsufficientFunds`, and the owner still pays the fee. Pause automation
    /// with `set_pause` and let that transaction settle before preparing a recovery.
    fn recover_funds(&mut self, token: &str) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot(Reach::Kept)?;
        // The installed asset, or the XLM that the wallet holds for its gas.
        if token != self.config.asset
            && token != crate::sac_address(&self.config.network, &stellar_xdr::Asset::Native)?
        {
            return Err("A policy wallet recovers only its installed asset or XLM".into());
        }
        let amount = self.balance_of(&s, token)?;
        if amount <= 0 {
            return Err(NO_RECOVERABLE_BALANCE.into());
        }
        let owner = s.owner.address.clone();
        let version = s.deployment_version;
        self.prepare(
            s,
            "recover",
            vec![
                ScVal::Address(address(token)?),
                ScVal::Address(address(&owner)?),
                i128_value(amount),
            ],
            version,
            vec![owner],
        )
    }
}
/// The refusal of a recovery of a token that the wallet holds none of.
pub const NO_RECOVERABLE_BALANCE: &str = "Selected token has no recoverable balance";
/// The token that a recovery of everything returns next, one balance per call: the installed
/// asset while the wallet holds some, then the XLM that a wallet of another asset holds for its
/// gas. `None` when nothing is left.
pub fn next_recovery<'a>(
    asset: &'a str,
    xlm: &'a str,
    asset_balance: i128,
    xlm_balance: i128,
) -> Option<&'a str> {
    if asset_balance > 0 {
        Some(asset)
    } else if asset != xlm && xlm_balance > 0 {
        Some(xlm)
    } else {
        None
    }
}
impl OwnerAdmin<'_> {
    /// Return everything to the owner, one balance per call: see [`next_recovery`].
    pub fn recover_all(&mut self) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot(Reach::Kept)?;
        let asset = self.config.asset.clone();
        let xlm = crate::sac_address(&self.config.network, &stellar_xdr::Asset::Native)?;
        let asset_balance = self.balance_of(&s, &asset)?;
        let xlm_balance = if asset == xlm {
            asset_balance
        } else {
            self.balance_of(&s, &xlm)?
        };
        let token = next_recovery(&asset, &xlm, asset_balance, xlm_balance)
            .ok_or(NO_RECOVERABLE_BALANCE)?
            .to_owned();
        self.recover_funds(&token)
    }
    /// The balance of `token` that the wallet holds, read through the owner's simulation.
    fn balance_of(&self, s: &Snapshot, token: &str) -> Result<i128> {
        let tx = self.transaction(
            &s.owner,
            token,
            "balance",
            vec![ScVal::Address(address(&self.config.wallet)?)],
            self.now.checked_add(300).ok_or("Expiry overflow")?,
        )?;
        let response=self.rpc.call("simulateTransaction",json!({"transaction":xdr(&TransactionEnvelope::Tx(TransactionV1Envelope{tx,signatures:VecM::default()}))?}))?;
        if response.get("error").is_some() {
            return Err("Owner balance observation failed".into());
        }
        let values = response["results"]
            .as_array()
            .ok_or("Missing token balance result")?;
        if values.len() != 1 {
            return Err("Unexpected token balance result count".into());
        }
        rpc::wide(&read(
            values[0]["xdr"]
                .as_str()
                .ok_or("Missing token balance XDR")?,
        )?)
    }
}

/// The custody layout that a policy wallet Wasm declares in its `contractmetav0` section, or
/// `None`: `contract_admin.py` `custody_layout`. The version 1 release declares none.
pub fn custody_layout(wasm: &[u8]) -> Result<Option<u32>> {
    const KEY: &[u8] = b"allowit_custody_layout";
    if wasm.get(..8) != Some(b"\0asm\x01\0\0\0".as_slice()) {
        return Err("Expected a Wasm module".into());
    }
    let malformed = || "Malformed Wasm module".to_string();
    let leb128 = |data: &[u8], mut pos: usize| -> Result<(usize, usize)> {
        let (mut value, mut shift) = (0usize, 0u32);
        loop {
            let byte = *data.get(pos).ok_or_else(malformed)?;
            if shift >= usize::BITS {
                return Err(malformed());
            }
            value |= usize::from(byte & 0x7f) << shift;
            shift += 7;
            pos += 1;
            if byte < 0x80 {
                return Ok((value, pos));
            }
        }
    };
    let u32be = |data: &[u8], at: usize| -> Result<usize> {
        let bytes: [u8; 4] = data
            .get(at..at + 4)
            .ok_or_else(malformed)?
            .try_into()
            .unwrap();
        Ok(u32::from_be_bytes(bytes) as usize)
    };
    let mut found = vec![];
    let mut pos = 8;
    while pos < wasm.len() {
        let (size, start) = leb128(wasm, pos + 1)?;
        let end = start.checked_add(size).ok_or_else(malformed)?;
        if end > wasm.len() {
            return Err(malformed());
        }
        if wasm[pos] == 0 {
            let (length, name) = leb128(wasm, start)?;
            let name_end = name.checked_add(length).ok_or_else(malformed)?;
            if wasm.get(name..name_end) == Some(b"contractmetav0".as_slice()) {
                let meta = wasm.get(name_end..end).ok_or_else(malformed)?;
                let mut at = 0;
                while at < meta.len() {
                    if u32be(meta, at)? != 0 {
                        return Err("Unsupported Wasm metadata entry".into());
                    }
                    at += 4;
                    let mut fields = vec![];
                    for _ in 0..2 {
                        let count = u32be(meta, at)?;
                        fields.push(
                            meta.get(at + 4..(at + 4 + count).min(meta.len()))
                                .unwrap_or(&[]),
                        );
                        at += 4 + count.div_ceil(4) * 4;
                    }
                    if at > meta.len() {
                        return Err(malformed());
                    }
                    if fields[0] == KEY {
                        found.push(fields[1].to_vec());
                    }
                }
            }
        }
        pos = end;
    }
    let valid =
        |v: &[u8]| (1..=9).contains(&v.len()) && v[0] != b'0' && v.iter().all(u8::is_ascii_digit);
    match found.as_slice() {
        [] => Ok(None),
        [value] if valid(value) => Ok(Some(
            std::str::from_utf8(value).unwrap().parse().map_err(err)?,
        )),
        _ => Err("Wasm custody layout metadata is invalid".into()),
    }
}
/// Refuse wallet code of another custody layout: that code, including a rollback to the
/// version 1 release, cannot read the stored State and locks custody. Returns the Wasm hash.
pub fn check_wallet_code(wasm: &[u8]) -> Result<[u8; 32]> {
    if custody_layout(wasm)? != Some(CONTRACT_VERSION) {
        return Err(format!(
            "New wallet code must declare custody layout {CONTRACT_VERSION}; recover funds before any layout change"
        ));
    }
    Ok(hash(wasm))
}
/// The contract address that `CreateContractV2` derives from `deployer` and `salt`.
pub fn wallet_address(network: &str, deployer: &str, salt: &[u8; 32]) -> Result<String> {
    Ok(Contract(contract_id(network, &preimage(deployer, salt)?)?).to_string())
}
fn preimage(deployer: &str, salt: &[u8; 32]) -> Result<ContractIdPreimage> {
    Ok(ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: address(deployer)?,
        salt: Uint256(*salt),
    }))
}
fn contract_id(network: &str, preimage: &ContractIdPreimage) -> Result<[u8; 32]> {
    Ok(hash(
        HashIdPreimage::ContractId(HashIdPreimageContractId {
            network_id: Hash(network_id(network)?),
            contract_id_preimage: preimage.clone(),
        })
        .to_xdr(limits())
        .map_err(err)?,
    ))
}

/// `contract_admin.py` `validate_auth`: simulation may request only the exact scope of the
/// host function. An invocation admits at most one source-account entry and one unsigned entry
/// of `candidate`, without children. A wallet creation admits one source-account entry whose only
/// child is the exact `__constructor` call of the derived address.
pub fn validate_auth(
    network: &str,
    host: &HostFunction,
    auth: &[SorobanAuthorizationEntry],
    candidate: Option<&str>,
) -> Result<()> {
    let mut seen_source = false;
    let mut seen_candidate = false;
    for entry in auth {
        let root = &entry.root_invocation;
        let scope = match (host, &root.function) {
            (HostFunction::InvokeContract(call), SorobanAuthorizedFunction::ContractFn(f)) => {
                f == call
            }
            (
                HostFunction::CreateContract(create),
                SorobanAuthorizedFunction::CreateContractHostFn(f),
            ) => f == create,
            (
                HostFunction::CreateContractV2(create),
                SorobanAuthorizedFunction::CreateContractV2HostFn(f),
            ) => f == create,
            _ => false,
        };
        if !scope {
            return Err("Simulation requested unexpected authorization scope".into());
        }
        if let HostFunction::InvokeContract(call) = host
            && call.function_name.0.as_slice() == b"deploy"
        {
            if entry.credentials != SorobanCredentials::SourceAccount {
                return Err("A deployment through the deployer is the owner's own call".into());
            }
            validate_deployer_tree(network, call, root)?;
        } else if let HostFunction::CreateContractV2(create) = host {
            if entry.credentials != SorobanCredentials::SourceAccount
                || root.sub_invocations.len() != 1
            {
                return Err(
                    "Deployment requires one exact source-authorized constructor child".into(),
                );
            }
            let child = &root.sub_invocations[0];
            let SorobanAuthorizedFunction::ContractFn(constructor) = &child.function else {
                return Err("Unexpected deployment constructor authorization shape".into());
            };
            if !child.sub_invocations.is_empty() {
                return Err("Unexpected deployment constructor authorization shape".into());
            }
            let derived = ScAddress::Contract(ContractId(Hash(contract_id(
                network,
                &create.contract_id_preimage,
            )?)));
            if constructor.contract_address != derived
                || constructor.function_name.0.as_slice() != b"__constructor"
                || constructor.args != create.constructor_args
            {
                return Err("Deployment constructor authorization does not match its preimage and arguments".into());
            }
        } else if !root.sub_invocations.is_empty() {
            return Err("Invocation authorization must not contain children".into());
        }
        match &entry.credentials {
            SorobanCredentials::SourceAccount => {
                if seen_source {
                    return Err("Duplicate source authorization".into());
                }
                seen_source = true;
            }
            SorobanCredentials::Address(c) => {
                let expected = candidate.map(address).transpose()?;
                if seen_candidate || expected.as_ref() != Some(&c.address) {
                    return Err("Simulation requested an unexpected authorization address".into());
                }
                if c.signature != ScVal::Void {
                    return Err("Simulation supplied unexpected authorization signatures".into());
                }
                seen_candidate = true;
            }
            _ => return Err("Unsupported authorization credential type".into()),
        }
    }
    if matches!(host, HostFunction::CreateContractV2(_)) && !seen_source {
        return Err("Deployment requires source-account constructor authorization".into());
    }
    Ok(())
}
/// The deployer contract of `network`: stateless, with no funds and no authority. The owner's
/// signature binds only the creation and funding that the owner's client checks, so the address
/// is public configuration, not trust.
pub fn deployer_address(network: &str) -> Result<String> {
    if passphrase(network)? == passphrase("stellar:testnet")? {
        Ok("CDQZA6UPOF6CH7H45GTBNH2O3AO7DH3CDD2JJNHHBO4GT4WJEQ7GUY5P".into())
    } else {
        Err(format!(
            "No policy wallet deployer is installed on {network}"
        ))
    }
}
/// The owner's authorization of `deployer.deploy(owner, wasm_hash, salt, [config], funding)`: the
/// call itself, then exactly the creation of the wallet at the owner's address and salt with the
/// pinned code and the constructor's argument, and one transfer from the owner to that wallet for
/// each funding item, in order. Nothing else is signed.
fn validate_deployer_tree(
    network: &str,
    call: &InvokeContractArgs,
    root: &SorobanAuthorizedInvocation,
) -> Result<()> {
    let [owner, wasm, salt, constructor_args, funding] = call.args.as_slice() else {
        return Err("The deployer call has five arguments".into());
    };
    let (ScVal::Address(owner), ScVal::Bytes(wasm), ScVal::Bytes(salt)) = (owner, wasm, salt)
    else {
        return Err("Unexpected deployer arguments".into());
    };
    let (ScVal::Vec(Some(constructor_args)), ScVal::Vec(Some(funding))) =
        (constructor_args, funding)
    else {
        return Err("Unexpected deployer arguments".into());
    };
    let wasm: [u8; 32] = wasm
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid Wasm hash")?;
    let salt: [u8; 32] = salt.as_slice().try_into().map_err(|_| "Invalid salt")?;
    let preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: owner.clone(),
        salt: Uint256(salt),
    });
    let wallet = ScAddress::Contract(ContractId(Hash(contract_id(network, &preimage)?)));
    let create = CreateContractArgsV2 {
        contract_id_preimage: preimage,
        executable: ContractExecutable::Wasm(Hash(wasm)),
        constructor_args: constructor_args.clone().into(),
    };
    let constructor = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: wallet.clone(),
            function_name: ScSymbol(b"__constructor".to_vec().try_into().map_err(err)?),
            args: constructor_args.clone().into(),
        }),
        sub_invocations: VecM::default(),
    };
    let mut expected = vec![SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::CreateContractV2HostFn(create),
        sub_invocations: vec![constructor].try_into().map_err(err)?,
    }];
    for item in funding.iter() {
        let ScVal::Vec(Some(pair)) = item else {
            return Err("A funding item is an asset and an amount".into());
        };
        let [ScVal::Address(asset), amount @ ScVal::I128(_)] = pair.as_slice() else {
            return Err("A funding item is an asset and an amount".into());
        };
        expected.push(SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: asset.clone(),
                function_name: ScSymbol(b"transfer".to_vec().try_into().map_err(err)?),
                args: vec![
                    ScVal::Address(owner.clone()),
                    ScVal::Address(wallet.clone()),
                    amount.clone(),
                ]
                .try_into()
                .map_err(err)?,
            }),
            sub_invocations: VecM::default(),
        });
    }
    if root.sub_invocations.as_slice() != expected.as_slice() {
        return Err(
            "The owner's deployment authorization holds more than the creation and its funding"
                .into(),
        );
    }
    Ok(())
}
/// `contract_admin.py` `prepare_xdr` intent checks for an externally assembled transaction:
/// the raw transaction is unsigned v1 from `source` with one host function, and simulation added
/// only authorization, resources and their fee, within `max_fee`.
pub fn check_assembled(
    network: &str,
    raw_xdr: &str,
    assembled_xdr: &str,
    source: &str,
    max_fee: u32,
    candidate: Option<&str>,
    expected_wasm: Option<[u8; 32]>,
) -> Result<()> {
    let TransactionEnvelope::Tx(raw) = read(raw_xdr)? else {
        return Err("Expected unsigned v1 transaction with the selected native source".into());
    };
    if !raw.signatures.is_empty() || raw.tx.source_account != muxed(source)? {
        return Err("Expected unsigned v1 transaction with the selected native source".into());
    }
    let [op] = raw.tx.operations.as_slice() else {
        return Err("Expected exactly one Soroban host-function operation".into());
    };
    let OperationBody::InvokeHostFunction(invoke) = &op.body else {
        return Err("Expected exactly one Soroban host-function operation".into());
    };
    if let Some(wasm) = expected_wasm {
        let pinned = match &invoke.host_function {
            HostFunction::CreateContractV2(create) => {
                create.executable == ContractExecutable::Wasm(Hash(wasm))
            }
            // The deployer's call names the code hash; the owner's signature binds it.
            HostFunction::InvokeContract(call) => {
                call.function_name.0.as_slice() == b"deploy"
                    && call.args.get(1) == Some(&value_bytes(&wasm)?)
            }
            _ => false,
        };
        if !pinned {
            return Err("Deployment transaction does not use the pinned Wasm executable".into());
        }
    }
    if op
        .source_account
        .as_ref()
        .is_some_and(|s| *s != raw.tx.source_account)
    {
        return Err("Operation source differs from selected transaction source".into());
    }
    let TransactionEnvelope::Tx(assembled) = read(assembled_xdr)? else {
        return Err("Simulation must return unsigned assembled Soroban XDR".into());
    };
    let TransactionExt::V1(data) = &assembled.tx.ext else {
        return Err("Simulation must return unsigned assembled Soroban XDR".into());
    };
    if !assembled.signatures.is_empty() {
        return Err("Simulation must return unsigned assembled Soroban XDR".into());
    }
    let [result] = assembled.tx.operations.as_slice() else {
        return Err("Simulation changed the operation shape".into());
    };
    let OperationBody::InvokeHostFunction(result_op) = &result.body else {
        return Err("Simulation changed the operation shape".into());
    };
    if assembled.tx.fee > max_fee || data.resource_fee < 0 || data.resource_fee > i64::from(max_fee)
    {
        return Err("Simulated fee exceeds the explicitly selected ceiling".into());
    }
    validate_auth(
        network,
        &result_op.host_function,
        &result_op.auth,
        candidate,
    )?;
    let mut normalized = assembled.tx.clone();
    normalized.fee = raw.tx.fee;
    normalized.ext = raw.tx.ext.clone();
    let mut operations = normalized.operations.to_vec();
    if let OperationBody::InvokeHostFunction(o) = &mut operations[0].body {
        o.auth = invoke.auth.clone();
    }
    normalized.operations = operations.try_into().map_err(err)?;
    if normalized != raw.tx || assembled.tx.fee < raw.tx.fee {
        return Err("Simulation changed transaction intent".into());
    }
    Ok(())
}

/// What a simulated restoration of a code entry found: the decision between a restoration and an
/// upload, whatever a read of the entry showed. An RPC can serve no archived entry, and another
/// transaction can make the code live after it was read.
#[derive(Clone, Debug)]
pub enum CodeRestoration {
    /// The network's archive holds the code: this restoration of its entry makes it live.
    Prepared(PreparedDeployment),
    /// The code is live: nothing is needed.
    Live,
    /// Neither archived nor live: the code needs an upload of its bytes.
    Absent,
}
/// Unsigned Wasm upload or wallet creation for the source account to sign.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedDeployment {
    pub network: String,
    pub source: String,
    /// `upload_wasm` or `create_wallet`.
    pub function: String,
    pub wasm_hash: [u8; 32],
    /// The derived wallet address of a creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    pub transaction_xdr: String,
    pub transaction_hash: [u8; 32],
    pub expires_at: u64,
}
/// Wasm upload and policy wallet creation through Stellar RPC simulation.
pub struct Deployer<'a> {
    pub rpc: &'a dyn rpc::Rpc,
    pub network: &'a str,
    /// Current trusted preparation time, supplied by the caller rather than a prepared packet.
    pub now: u64,
    /// Total fee ceiling in stroops, simulation resources included.
    pub max_fee_stroops: u32,
}
impl Deployer<'_> {
    fn account(&self, source: &str) -> Result<AccountState> {
        Ok(rpc::observe_account(self.rpc, self.network, source)?.account)
    }
    // Date simulation resources and re-read the source. Neither this observation nor the
    // unsigned result replaces the caller's independent check immediately before signing.
    fn simulate(
        &self,
        source: &AccountState,
        transaction: &str,
        record: bool,
    ) -> Result<serde_json::Value> {
        let before = rpc::owner_observation::head(self.rpc)?;
        let mut params = json!({"transaction":transaction});
        if record {
            params["authMode"] = json!("record");
        }
        let response = self.rpc.call("simulateTransaction", params)?;
        let observed = rpc::owner_observation::ledger(&response["latestLedger"])?;
        // Bracket the simulation and its owner observation with the same heads.
        // Read the owner entry first so intervening RPC calls cannot age the simulation.
        let owner = rpc::read_account_observation(self.rpc, &source.address)?;
        let after = rpc::owner_observation::current(self.rpc, before, observed)?;
        if owner.account != *source || !(observed..=after).contains(&owner.ledger) {
            return Err("Owner account or simulation changed during native preparation".into());
        }
        rpc::owner_observation::network(self.rpc, self.network)?;
        Ok(response)
    }
    /// Simulate `host` from `source` in record mode, check the recorded authorization and the
    /// assembled intent, and return the assembled unsigned transaction and the simulated result.
    fn assemble(
        &self,
        source: &AccountState,
        host: HostFunction,
        expected_wasm: Option<[u8; 32]>,
    ) -> Result<(Transaction, ScVal)> {
        let expires = self.now.checked_add(300).ok_or("Expiry overflow")?;
        let raw = Transaction {
            source_account: muxed(&source.address)?,
            fee: 100,
            seq_num: SequenceNumber(source.sequence.checked_add(1).ok_or("Sequence overflow")?),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(expires),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: host,
                    auth: VecM::default(),
                }),
            }]
            .try_into()
            .map_err(err)?,
            ext: TransactionExt::V0,
        };
        let raw_xdr = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: raw.clone(),
            signatures: VecM::default(),
        }))?;
        let response = self.simulate(source, &raw_xdr, true)?;
        if response.get("error").is_some_and(|v| !v.is_null()) {
            return Err("Deployment simulation rejected the transaction".into());
        }
        // Archived code or deployer entries restore in the same transaction.
        rpc::restoring_in_place(&response)?;
        let results = response["results"]
            .as_array()
            .ok_or("Missing simulation result")?;
        let [result] = results.as_slice() else {
            return Err("Unexpected deployment simulation result count".into());
        };
        let auth = result["auth"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|v| {
                        read::<SorobanAuthorizationEntry>(
                            v.as_str().ok_or("Invalid authorization XDR")?,
                        )
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let value: ScVal = read(
            result["xdr"]
                .as_str()
                .ok_or("Missing simulation result XDR")?,
        )?;
        let fee = response["minResourceFee"]
            .as_str()
            .ok_or("Missing resource fee")?
            .parse::<u32>()
            .map_err(err)?
            .checked_add(100)
            .ok_or("Fee overflow")?;
        if fee > self.max_fee_stroops {
            return Err("Simulated fee exceeds the explicitly selected ceiling".into());
        }
        let data: SorobanTransactionData = read(
            response["transactionData"]
                .as_str()
                .ok_or("Missing resource data")?,
        )?;
        if data.resource_fee < 0
            || u64::try_from(data.resource_fee).map_err(err)? + 100 != u64::from(fee)
        {
            return Err("Resource fee differs from simulation".into());
        }
        let mut assembled = raw.clone();
        assembled.fee = fee;
        assembled.ext = TransactionExt::V1(data);
        let mut operations = assembled.operations.to_vec();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            unreachable!()
        };
        op.auth = auth.try_into().map_err(err)?;
        assembled.operations = operations.try_into().map_err(err)?;
        check_assembled(
            self.network,
            &raw_xdr,
            &xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: assembled.clone(),
                signatures: VecM::default(),
            }))?,
            &source.address,
            self.max_fee_stroops,
            None,
            expected_wasm,
        )?;
        Ok((assembled, value))
    }
    fn prepared(
        &self,
        source: &AccountState,
        function: &str,
        wasm_hash: [u8; 32],
        wallet: Option<String>,
        tx: Transaction,
    ) -> Result<PreparedDeployment> {
        let expires_at = match &tx.cond {
            Preconditions::Time(bounds) => bounds.max_time.0,
            _ => unreachable!(),
        };
        Ok(PreparedDeployment {
            network: self.network.into(),
            source: source.address.clone(),
            function: function.into(),
            wasm_hash,
            wallet,
            transaction_hash: transaction_hash(self.network, &tx)?,
            transaction_xdr: xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx,
                signatures: VecM::default(),
            }))?,
            expires_at,
        })
    }
    /// Prepare `UploadContractWasm` of policy wallet code that declares custody layout 4.
    pub fn upload_wasm(&self, source: &str, wasm: &[u8]) -> Result<PreparedDeployment> {
        let wasm_hash = check_wallet_code(wasm)?;
        let account = self.account(source)?;
        let host = HostFunction::UploadContractWasm(wasm.to_vec().try_into().map_err(err)?);
        let (tx, value) = self.assemble(&account, host, None)?;
        if value != value_bytes(&wasm_hash)? {
            return Err("Upload simulation returned another Wasm hash".into());
        }
        let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body else {
            unreachable!()
        };
        if !op.auth.is_empty() {
            return Err("Wasm upload needs no contract authorization".into());
        }
        // An upload whose simulation restores an archived entry in place would upload code that
        // the archive holds: lapsed code is restored, not uploaded (`restore_code`).
        if let TransactionExt::V1(data) = &tx.ext
            && matches!(&data.ext, SorobanTransactionDataExt::V1(ext) if !ext.archived_soroban_entries.is_empty())
        {
            return Err(
                "The upload restores an archived entry: lapsed code is restored, not uploaded"
                    .into(),
            );
        }
        self.prepared(&account, "upload_wasm", wasm_hash, None, tx)
    }
    /// Prepare `RestoreFootprint` of the code entry `wasm_hash` from `source` when the network's
    /// archive holds it. It names that entry alone and gives no authority; the simulation sets
    /// its fee, within the ceiling. A simulation that names no entry, or that refuses the
    /// restoration, leaves code that is live, read again, or absent.
    pub fn restore_code(&self, source: &str, wasm_hash: [u8; 32]) -> Result<CodeRestoration> {
        let account = self.account(source)?;
        let key = LedgerKey::ContractCode(LedgerKeyContractCode {
            hash: Hash(wasm_hash),
        });
        let mut tx = Transaction {
            source_account: muxed(&account.address)?,
            fee: 100,
            seq_num: SequenceNumber(account.sequence.checked_add(1).ok_or("Sequence overflow")?),
            cond: Preconditions::Time(TimeBounds {
                min_time: TimePoint(0),
                max_time: TimePoint(self.now.checked_add(300).ok_or("Expiry overflow")?),
            }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::RestoreFootprint(RestoreFootprintOp {
                    ext: ExtensionPoint::V0,
                }),
            }]
            .try_into()
            .map_err(err)?,
            ext: TransactionExt::V1(SorobanTransactionData {
                ext: SorobanTransactionDataExt::V0,
                resources: SorobanResources {
                    footprint: LedgerFootprint {
                        read_only: VecM::default(),
                        read_write: vec![key.clone()].try_into().map_err(err)?,
                    },
                    instructions: 0,
                    disk_read_bytes: 0,
                    write_bytes: 0,
                },
                resource_fee: 0,
            }),
        };
        let raw = xdr(&TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: tx.clone(),
            signatures: VecM::default(),
        }))?;
        // Code that is live, read again, needs nothing: another transaction restored or uploaded
        // it since it was read, from this account too, which then changed during the simulation.
        let live_or_absent = || match crate::rpc::code_state(self.rpc, self.network, &wasm_hash) {
            Ok(crate::rpc::CodeState::Live) => CodeRestoration::Live,
            _ => CodeRestoration::Absent,
        };
        let response = match self.simulate(&account, &raw, false) {
            Ok(response) if response.get("error").is_none_or(|v| v.is_null()) => response,
            // A refused restoration restores nothing. An upload of code that the archive holds
            // is refused in its own simulation.
            Ok(_) => return Ok(live_or_absent()),
            Err(error) => {
                return match live_or_absent() {
                    CodeRestoration::Live => Ok(CodeRestoration::Live),
                    _ => Err(error),
                };
            }
        };
        let data: SorobanTransactionData = read(
            response["transactionData"]
                .as_str()
                .ok_or("Missing restoration resources")?,
        )?;
        // The simulation restores only archived entries: it names none for code that is live or
        // absent.
        if data.resources.footprint.read_only.is_empty()
            && data.resources.footprint.read_write.is_empty()
        {
            return Ok(live_or_absent());
        }
        if !data.resources.footprint.read_only.is_empty()
            || data.resources.footprint.read_write.as_slice() != [key]
        {
            return Err("Restoration resources name another entry".into());
        }
        // Archived entries are named by their index in the read-write footprint: only the code
        // entry is there.
        crate::rpc::archived_in_footprint(&data)?;
        let fee = response["minResourceFee"]
            .as_str()
            .ok_or("Missing restoration fee")?
            .parse::<u32>()
            .map_err(err)?
            .checked_add(100)
            .ok_or("Restoration fee overflow")?;
        if fee > self.max_fee_stroops {
            return Err("Simulated fee exceeds the explicitly selected ceiling".into());
        }
        if data.resource_fee < 0
            || u64::try_from(data.resource_fee).map_err(err)? + 100 != u64::from(fee)
        {
            return Err("Restoration resource fee differs from simulation".into());
        }
        tx.fee = fee;
        tx.ext = TransactionExt::V1(data);
        self.prepared(&account, "restore_code", wasm_hash, None, tx)
            .map(CodeRestoration::Prepared)
    }
    /// Prepare the owner's one transaction that creates the policy wallet of `wasm` (uploaded by
    /// the server) through `deployer` and funds it with each `(asset, amount)` of `funding`. The
    /// owner signs it once: the creation, the constructor's owner check and the transfers are one
    /// authorization tree. The wallet address derives from the owner and `salt`.
    pub fn deploy_and_fund(
        &self,
        deployer: &str,
        config: &PolicyConfig,
        wasm: &[u8],
        salt: [u8; 32],
        funding: &[(String, i128)],
    ) -> Result<PreparedDeployment> {
        let wasm_hash = check_wallet_code(wasm)?;
        let account = self.account(&config.owner)?;
        account.validate_owner_only()?;
        let wallet = wallet_address(self.network, &config.owner, &salt)?;
        if [
            &config.owner,
            &config.agent,
            &config.server,
            &deployer.to_owned(),
        ]
        .contains(&&wallet)
        {
            return Err("Owner, agent, server, deployer and policy wallet must be distinct".into());
        }
        let mut items = Vec::new();
        for (asset, amount) in funding {
            if *amount <= 0 {
                return Err("A funding amount is positive".into());
            }
            items.push(ScVal::Vec(Some(
                vec![ScVal::Address(address(asset)?), i128_value(*amount)]
                    .try_into()
                    .map_err(err)?,
            )));
        }
        let host = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: address(deployer)?,
            function_name: ScSymbol(b"deploy".to_vec().try_into().map_err(err)?),
            args: vec![
                ScVal::Address(address(&config.owner)?),
                value_bytes(&wasm_hash)?,
                value_bytes(&salt)?,
                ScVal::Vec(Some(config.constructor_args()?.try_into().map_err(err)?)),
                ScVal::Vec(Some(items.try_into().map_err(err)?)),
            ]
            .try_into()
            .map_err(err)?,
        });
        let (tx, value) = self.assemble(&account, host, Some(wasm_hash))?;
        if value != ScVal::Address(address(&wallet)?) {
            return Err("Creation simulation returned another wallet address".into());
        }
        self.prepared(&account, "create_wallet", wasm_hash, Some(wallet), tx)
    }
}
/// The funding of a creation: `units` of the installed asset, then `fee_asset_units` of XLM, from
/// which the wallet repays the network fee of its operations. A zero amount moves nothing. A
/// wallet whose asset is XLM takes its funding as `units` alone.
pub fn creation_funding(
    c: &WalletConfig,
    units: i128,
    fee_asset_units: i128,
) -> Result<Vec<(String, i128)>> {
    if units < 0 || fee_asset_units < 0 {
        return Err("A funding amount is positive or zero".into());
    }
    let xlm = sac_address(&c.network, &Asset::Native)?;
    if c.asset == xlm && fee_asset_units != 0 {
        return Err("The wallet's asset is XLM: fund it with the amount alone".into());
    }
    Ok([(c.asset.clone(), units), (xlm, fee_asset_units)]
        .into_iter()
        .filter(|(_, amount)| *amount > 0)
        .collect())
}
/// The unsigned v1 transaction `transaction_xdr` with the source account's `signature` of its
/// hash, after checking that signature.
pub fn with_source_signature(
    network: &str,
    transaction_xdr: &str,
    signature: &[u8; 64],
) -> Result<String> {
    let TransactionEnvelope::Tx(mut envelope) = read(transaction_xdr)? else {
        return Err("Expected an unsigned v1 transaction".into());
    };
    let MuxedAccount::Ed25519(Uint256(key)) = envelope.tx.source_account.clone() else {
        return Err("The source is a plain account".into());
    };
    if !envelope.signatures.is_empty() {
        return Err("The transaction is signed already".into());
    }
    let digest = transaction_hash(network, &envelope.tx)?;
    signing::verify_digest(&account_for_public_key(&key), &digest, signature)?;
    envelope.signatures = vec![DecoratedSignature {
        hint: SignatureHint(key[28..].try_into().map_err(err)?),
        signature: stellar_xdr::Signature(signature.to_vec().try_into().map_err(err)?),
    }]
    .try_into()
    .map_err(err)?;
    xdr(&TransactionEnvelope::Tx(envelope))
}
/// Low-level source-account signing. This checks unsigned v1 envelope ownership only; it does
/// not validate the business intent, fees or expiry. Use [`crate::owner_intent`] to validate an
/// untrusted prepared packet against independently approved intent before requesting a signature.
pub fn sign_owner_transaction(
    network: &str,
    transaction_xdr: &str,
    seed: &[u8; 32],
) -> Result<String> {
    let TransactionEnvelope::Tx(mut envelope) = read(transaction_xdr)? else {
        return Err("Expected an unsigned v1 transaction".into());
    };
    let signer = account_for_seed(seed);
    if !envelope.signatures.is_empty() || envelope.tx.source_account != muxed(&signer)? {
        return Err("The seed does not own this unsigned transaction".into());
    }
    let key = account_key(&signer)?;
    let digest = transaction_hash(network, &envelope.tx)?;
    envelope.signatures = vec![DecoratedSignature {
        hint: SignatureHint(key[28..].try_into().unwrap()),
        signature: stellar_xdr::Signature(
            SigningKey::from_bytes(seed)
                .sign(&digest)
                .to_bytes()
                .to_vec()
                .try_into()
                .map_err(err)?,
        ),
    }]
    .try_into()
    .map_err(err)?;
    xdr(&TransactionEnvelope::Tx(envelope))
}
