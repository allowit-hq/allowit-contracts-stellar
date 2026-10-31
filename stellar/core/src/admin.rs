//! Owner preparation for the versioned policy wallet interface. No keys or submissions.
use crate::*;
use allowit_policy_sdk::admin::{DeployPolicy, DeploymentVersion, RecoverFunds, SetPause};
use serde_json::json;

pub use crate::NativeValues as Grant;

/// Complete owner-approved configuration. The version is supplied to deploy_policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDeployment {
    /// Native address of the desired policy owner; a changed owner must authorize too.
    pub owner: String,
    /// Desired delegated agent address. Enabling x402 requires a native G-account.
    pub agent: String,
    /// Independent service signer address.
    pub server: String,
    pub source_digest: [u8; 32],
    pub rules: Vec<String>,
    /// Complete native spending permissions for this deployment.
    pub grant: Grant,
    /// Owner opt-in to x402 using the configured native G-agent Ed25519 key.
    pub x402_enabled: bool,
    /// Optional uploaded policy executable hash to install atomically.
    pub wasm_hash: Option<[u8; 32]>,
}
impl PolicyDeployment {
    fn value(&self, version: DeploymentVersion) -> Result<ScVal> {
        value_map(vec![
            ("deployment_version", ScVal::U64(version.0)),
            ("owner", ScVal::Address(address(&self.owner)?)),
            ("agent", ScVal::Address(address(&self.agent)?)),
            ("server", ScVal::Address(address(&self.server)?)),
            ("source_digest", value_bytes(&self.source_digest)?),
            ("rules", rule_values(&self.rules)?),
            ("grant", self.grant.value()?),
            {
                if self.x402_enabled {
                    account_key(&self.agent)?;
                }
                ("x402_enabled", ScVal::Bool(self.x402_enabled))
            },
            (
                "wasm_hash",
                self.wasm_hash
                    .as_ref()
                    .map(|k| value_bytes(k))
                    .transpose()?
                    .unwrap_or(ScVal::Void),
            ),
        ])
    }
}

fn rule_values(rules: &[String]) -> Result<ScVal> {
    let mut seen = std::collections::BTreeSet::new();
    let values = rules
        .iter()
        .map(|name| {
            if ![
                "daily_cap",
                "transaction_cap",
                "total_cap",
                "call_cap",
                "recipient",
                "expiry",
                "token",
            ]
            .contains(&name.as_str())
                || !seen.insert(name)
            {
                return Err("Unknown or duplicate Common rule".into());
            }
            value_symbol(name)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ScVal::Vec(Some(values.try_into().map_err(err)?)))
}

/// Exact fixed or custom policy-wallet constructor packet, selected through the compiler.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub owner: String,
    pub agent: String,
    pub server: String,
    pub asset: String,
    pub policy_instance: [u8; 32],
    pub source_digest: [u8; 32],
    pub rules: Vec<String>,
    pub grant: Grant,
    pub x402_enabled: bool,
}
impl PolicyConfig {
    /// Bind complete source to the selected implementation. The caller selects its exact uploaded Wasm separately.
    pub fn for_policy(
        c: &WalletConfig,
        grant: Grant,
        x402_enabled: bool,
        require_onchain: bool,
    ) -> Result<Self> {
        validate_config(c)?;
        if c.route != WalletRoute::PolicyWallet {
            return Err("A contract policy-wallet rail is required".into());
        }
        let selected = allowit_policy_sdk::select_stellar_engine(
            &c.policy_source,
            allowit_policy_sdk::StellarRail::PolicyWallet,
            c.policy_engine.ok_or("Select a policy engine")?,
            require_onchain,
        )
        .map_err(err)?;
        Ok(Self {
            owner: c.owner.clone(),
            agent: c.agent.clone(),
            server: c.server.clone(),
            asset: c.asset.clone(),
            policy_instance: c.policy_instance,
            source_digest: c.source_hash,
            rules: selected.rules,
            grant,
            x402_enabled,
        })
    }
    pub fn constructor_args(&self) -> Result<Vec<ScVal>> {
        account_key(&self.agent)?;
        account_key(&self.server)?;
        Ok(vec![value_map(vec![
            ("owner", ScVal::Address(address(&self.owner)?)),
            ("agent", ScVal::Address(address(&self.agent)?)),
            ("server", ScVal::Address(address(&self.server)?)),
            ("asset", ScVal::Address(address(&self.asset)?)),
            ("policy_instance", value_bytes(&self.policy_instance)?),
            ("source_digest", value_bytes(&self.source_digest)?),
            ("rules", rule_values(&self.rules)?),
            ("grant", self.grant.value()?),
            ("x402_enabled", ScVal::Bool(self.x402_enabled)),
        ])?])
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
}

/// Bound vendor implementation. Native account ownership is required for this
/// preparation route. Contract-owner authorization needs its own native adapter.
pub struct OwnerAdmin<'a> {
    pub rpc: &'a dyn rpc::Rpc,
    pub config: &'a WalletConfig,
    pub now: u64,
}
struct Snapshot {
    owner: AccountState,
    deployment_version: DeploymentVersion,
}
impl OwnerAdmin<'_> {
    fn snapshot(&self) -> Result<Snapshot> {
        use rpc::{addr, digest_field, map_field};
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
            return Err("policy wallet instance not found".into());
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
        if instance.executable != ContractExecutable::Wasm(Hash(c.module_digest)) {
            return Err("policy wallet executable differs from owner-approved code".into());
        }
        let storage = instance.storage.ok_or("Missing policy wallet storage")?;
        let state = storage
            .iter()
            .find(|e| e.key == ScVal::U32(0))
            .map(|e| &e.val)
            .ok_or("Missing policy wallet custody state")?;
        let contract_version = rpc::current_contract_version(state)?;
        let current_owner = addr(map_field(state, "owner")?)?;
        if current_owner != c.owner {
            return Err("Current owner differs from the bound owner".into());
        }
        account_key(&current_owner)
            .map_err(|_| "Contract owners require a separate native authorization adapter")?;
        let owner = rpc::get_account(self.rpc, &current_owner)?;
        owner.validate_structure()?;
        let binding = rpc::readonly_call(self.rpc, c, &owner, "policy_binding")?;
        rpc::verify_policy_engine(c, state, &binding)?;
        if rpc::current_contract_version(&binding)? != contract_version
            || digest_field(map_field(&binding, "policy_instance")?)? != c.policy_instance
            || digest_field(map_field(&binding, "module_digest")?)? != c.module_digest
            || digest_field(map_field(&binding, "source_digest")?)? != c.source_hash
            || digest_field(map_field(&binding, "argument_schema_digest")?)?
                != hash(ARGUMENT_SCHEMA)
            || map_field(&binding, "entrypoint")? != &value_symbol("_execute")?
        {
            return Err("Owner contract release or policy binding differs".into());
        }
        if addr(map_field(state, "asset")?)? != c.asset {
            return Err("policy wallet asset differs from installation".into());
        }
        Ok(Snapshot {
            owner,
            deployment_version: DeploymentVersion(rpc::deployment_version_field(state)?),
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
        for entry in &parsed {
            if entry.root_invocation.function != SorobanAuthorizedFunction::ContractFn(call.clone())
                || !entry.root_invocation.sub_invocations.is_empty()
            {
                return Err("Owner authorization scope differs".into());
            }
            let who = match &entry.credentials {
                SorobanCredentials::SourceAccount => snapshot.owner.address.clone(),
                SorobanCredentials::Address(c) | SorobanCredentials::AddressV2(c) => {
                    address_text(&c.address)?
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
        tx.fee = fee;
        tx.ext = TransactionExt::V1(read(
            response["transactionData"]
                .as_str()
                .ok_or("Missing owner resource data")?,
        )?);
        if let TransactionExt::V1(ref data) = tx.ext
            && (data.resource_fee < 0
                || u64::try_from(data.resource_fee).map_err(err)? + 100 != u64::from(fee))
        {
            return Err("Owner resource fee differs from simulation".into());
        }
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
        })
    }
}
impl DeployPolicy for OwnerAdmin<'_> {
    type Artifact = PolicyDeployment;
    type Output = PreparedOwnerOperation;
    type Error = String;
    fn deploy_policy(
        &mut self,
        version: DeploymentVersion,
        artifact: PolicyDeployment,
    ) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot()?;
        if !version.follows(s.deployment_version) {
            return Err("Policy deployment must target the next version".into());
        }
        let mut authorizers = vec![s.owner.address.clone()];
        if artifact.owner != s.owner.address {
            authorizers.push(artifact.owner.clone());
        }
        let arguments = artifact.value(version)?;
        self.prepare(s, "deploy_policy", vec![arguments], version, authorizers)
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
        let s = self.snapshot()?;
        if !version.follows(s.deployment_version) {
            return Err("Pause must target the next deployment version".into());
        }
        let authorizers = vec![s.owner.address.clone()];
        self.prepare(
            s,
            "set_pause",
            vec![ScVal::Bool(paused), ScVal::U64(version.0)],
            version,
            authorizers,
        )
    }
}
impl RecoverFunds for OwnerAdmin<'_> {
    type Output = PreparedOwnerOperation;
    type Error = String;
    fn recover_funds(&mut self, token: &str) -> Result<PreparedOwnerOperation> {
        let s = self.snapshot()?;
        if token != self.config.asset {
            return Err("This policy wallet profile can recover only its installed asset".into());
        }
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
        let amount = rpc::wide(&read(
            values[0]["xdr"]
                .as_str()
                .ok_or("Missing token balance XDR")?,
        )?)?;
        if amount <= 0 {
            return Err("Selected token has no recoverable balance".into());
        }
        let owner = s.owner.address.clone();
        let version = s.deployment_version;
        self.prepare(
            s,
            "recover",
            vec![ScVal::Address(address(&owner)?), i128_value(amount)],
            version,
            vec![owner],
        )
    }
}
