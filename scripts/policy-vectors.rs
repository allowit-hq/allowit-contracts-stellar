// Shared backend-neutral vectors of the portability test. Plain Rust without dependencies, so the
// std-only host smoke (`policy-smoke.rs`) and the Soroban contract test in `allowit-policy-wallet`
// include the same file. Addresses are indices into a shared address universe.

/// Address universe indices.
pub const ASSET: usize = 0;
pub const RECIPIENT: usize = 1;
pub const VAULT: usize = 2;
pub const OTHER: usize = 3;
pub const EXCHANGE: usize = 4;
/// A second token, which a swap buys or sells against the asset.
pub const TOKEN: usize = 5;
/// Universe size.
pub const ADDRESSES: usize = 6;
/// UTC day length in seconds.
const SECONDS_PER_DAY: u64 = 86_400;
/// Request time of the base vector.
pub const NOW: u64 = 2 * SECONDS_PER_DAY + 100;
/// State key that the catching policy counts its caught daily cap errors in.
pub const OVER: &str = "over_day_cap";
/// Custom param key that the catching policy reads with `transaction_cap`.
pub const INVOICE_CAP: &str = "invoice_cap";
/// Execution param key that makes the catching policy apply its invoice cap.
pub const INVOICE: &str = "invoice";
/// `allowit::MAX_ARGS`: most execution params of one request.
pub const MAX_ARGS: usize = 16;
/// `allowit::MAX_STATE_KEYS` minus the seven standard keys: most policy keys in one state.
pub const MAX_POLICY_KEYS: usize = 32;
/// `allowit::MAX_STATE_BYTES`: most encoded bytes of one policy state.
pub const MAX_STATE_BYTES: usize = 16 * 1024;
/// State key of the filler texts of a vector.
pub const BLOB: &str = "blob";

/// Key of the `i`th filler execution param.
pub fn arg_key(i: usize) -> String {
    format!("arg_{i}")
}
/// Key of the `i`th filler policy state key.
pub fn state_key(i: usize) -> String {
    format!("key_{i}")
}

/// An `operations` param value.
#[derive(Clone, Debug)]
pub enum Ops {
    /// `Str`: `*` admits every op; any other text is invalid.
    Text(&'static str),
    /// `List` of `Str` op names.
    List(Vec<&'static str>),
}

/// The native operation of a vector.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    Transfer,
    Deposit,
    Swap,
    Redeem,
}

/// An `operations` entry for one function of one contract: `custom:<contract>.<function>`. The
/// contract text is rail-neutral, so both backends accept it.
pub const POOL_CLAIM: &str = "custom:pool.claim";

/// One rule input: params, current state before the operation, and request with its args.
/// A `None` param is absent.
#[derive(Clone, Debug)]
pub struct Vector {
    pub name: &'static str,
    /// `transaction_cap`, `spent_cap`, `day_spent_cap` and `day_total_cap`.
    pub caps: [Option<i128>; 4],
    pub call_cap: Option<u64>,
    pub recipients: Option<Vec<usize>>,
    pub tokens: Option<Vec<usize>>,
    pub expiry: Option<u64>,
    pub operations: Option<Ops>,
    /// The custom `invoice_cap` param, which only Custom wallets admit.
    pub invoice_cap: Option<i128>,
    pub calls: u64,
    pub spent: i128,
    pub unpriced: bool,
    pub day: u64,
    pub day_spent: i128,
    pub day_total: i128,
    pub day_unpriced: bool,
    /// The catching policy's own state key, if set.
    pub over: Option<u64>,
    pub op: Op,
    pub asset: usize,
    pub recipient: usize,
    pub amount: i128,
    /// The token that leaves the wallet and its exact units.
    pub token_in: usize,
    pub amount_in: i128,
    /// The token that the wallet receives back and its minimum units.
    pub token_out: Option<usize>,
    pub min_out: i128,
    pub now: u64,
    pub expires_at: u64,
    pub spent_units: i128,
    pub gas_units: i128,
    /// The request carries expense bounds.
    pub priced: bool,
    /// The agent's args carry the `invoice` execution param.
    pub invoice: bool,
    /// Filler execution params `arg_<i>` = `Int(i)` beside `invoice`.
    pub extra_args: usize,
    /// Filler policy state keys `key_<i>` = `Int(i)` in the current state.
    pub extra_state: usize,
    /// Byte lengths of the filler texts in the state's `blob` list; empty leaves `blob` unset.
    pub blob: Vec<usize>,
}

/// A transfer vector that passes every rule with headroom left. After it, spent and day_spent are
/// 45 and day_total is 43.
pub fn base() -> Vector {
    Vector {
        name: "base",
        caps: [Some(100), Some(1000), Some(500), Some(600)],
        call_cap: Some(3),
        recipients: Some(vec![RECIPIENT, VAULT]),
        tokens: Some(vec![ASSET]),
        expiry: Some(NOW + 1000),
        operations: Some(Ops::List(vec!["transfer"])),
        invoice_cap: None,
        calls: 0,
        spent: 5,
        unpriced: false,
        day: NOW / SECONDS_PER_DAY,
        day_spent: 5,
        day_total: 3,
        day_unpriced: false,
        over: None,
        op: Op::Transfer,
        asset: ASSET,
        recipient: RECIPIENT,
        amount: 40,
        token_in: ASSET,
        amount_in: 40,
        token_out: None,
        min_out: 0,
        now: NOW,
        expires_at: NOW + 400,
        spent_units: 40,
        gas_units: 0,
        priced: true,
        invoice: false,
        extra_args: 0,
        extra_state: 0,
        blob: Vec::new(),
    }
}

/// Make `v` a deposit of its amount into the vault.
fn deposit(v: &mut Vector) {
    v.op = Op::Deposit;
    v.recipient = VAULT;
    v.token_out = Some(VAULT);
    v.min_out = v.amount;
}

/// Make `v` a swap through the exchange that every rule admits: forward, 40 asset units for at
/// least 37 of `TOKEN`, or reverse, 100 `TOKEN` units for at least 40 asset units, which count as
/// its gross amount. A swap spends its 3-unit conversion bound.
fn swap(v: &mut Vector, reverse: bool) {
    v.op = Op::Swap;
    v.recipient = EXCHANGE;
    v.recipients = Some(vec![RECIPIENT, VAULT, EXCHANGE]);
    v.tokens = Some(vec![ASSET, TOKEN]);
    v.operations = Some(Ops::List(vec!["transfer", "swap", "redeem"]));
    v.spent_units = 3;
    (v.token_in, v.amount_in, v.token_out, v.min_out) = if reverse {
        (TOKEN, 100, Some(ASSET), 40)
    } else {
        (ASSET, 40, Some(TOKEN), 37)
    };
}

/// Make `v` a redeem of 30 vault shares for at least 40 asset units, its gross amount.
fn redeem(v: &mut Vector) {
    v.op = Op::Redeem;
    v.recipient = VAULT;
    v.operations = Some(Ops::List(vec!["redeem"]));
    v.spent_units = 0;
    (v.token_in, v.amount_in, v.token_out, v.min_out) = (VAULT, 30, Some(ASSET), 40);
}

fn edit(name: &'static str, change: fn(&mut Vector)) -> Vector {
    let mut v = base();
    v.name = name;
    change(&mut v);
    v
}

/// The shared vector set. Some vectors are host-only because the wallet kernel cannot produce
/// them, such as an expired request or a negative amount. The wallet portability test also
/// realizes only transfers; deposit, swap and redeem vectors run on the host backend there.
pub fn vectors() -> Vec<Vector> {
    vec![
        base(),
        edit("boundary", |v| {
            v.caps = [Some(40), Some(45), Some(45), Some(43)];
            v.call_cap = Some(1);
            v.expiry = Some(v.expires_at);
        }),
        edit("with_gas", |v| {
            v.gas_units = 3;
            v.spent_units = 43;
            v.caps = [Some(40), Some(48), Some(48), Some(46)];
        }),
        edit("with_gas_over_day_total_cap", |v| {
            v.gas_units = 3;
            v.spent_units = 43;
            v.caps[3] = Some(45);
        }),
        edit("to_vault", |v| v.recipient = VAULT),
        edit("deposit", deposit),
        edit("deposit_over_spent_cap", |v| {
            deposit(v);
            v.caps[1] = Some(44);
        }),
        edit("deposit_unset_spent_cap", |v| {
            deposit(v);
            v.caps[1] = None;
        }),
        edit("over_transaction_cap", |v| v.caps[0] = Some(39)),
        edit("over_spent_cap", |v| v.caps[1] = Some(44)),
        edit("over_day_spent_cap", |v| v.caps[2] = Some(44)),
        edit("over_day_spent_cap_counted_once", |v| {
            v.caps[2] = Some(44);
            v.over = Some(1);
        }),
        edit("over_day_spent_cap_counted_twice", |v| {
            v.caps[2] = Some(44);
            v.over = Some(2);
        }),
        edit("over_day_total_cap", |v| v.caps[3] = Some(42)),
        edit("zero_call_cap", |v| v.call_cap = Some(0)),
        edit("over_call_cap", |v| v.calls = 3),
        edit("unpriced_lifetime", |v| v.unpriced = true),
        edit("unpriced_today", |v| {
            v.unpriced = true;
            v.day_unpriced = true;
        }),
        edit("unpriced_request", |v| {
            v.priced = false;
            v.spent_units = 0;
        }),
        edit("unpriced_request_without_cost_caps", |v| {
            v.priced = false;
            v.spent_units = 0;
            v.caps = [Some(100), None, None, None];
        }),
        edit("earlier_day_rolls_over", |v| {
            v.day -= 1;
            v.day_spent = 499;
            v.day_total = 599;
            v.day_unpriced = true;
        }),
        edit("later_day", |v| v.day += 1),
        edit("empty_allowlists", |v| {
            v.recipients = Some(Vec::new());
            v.tokens = Some(Vec::new());
        }),
        edit("other_recipient", |v| v.recipient = OTHER),
        edit("other_asset", |v| v.asset = OTHER),
        edit("params_expired", |v| {
            v.now = NOW + 1000;
            v.expires_at = NOW + 1001;
        }),
        edit("request_outlives_params", |v| {
            v.expiry = Some(v.expires_at - 1)
        }),
        edit("negative_cap", |v| v.caps[0] = Some(-1)),
        edit("zero_amount", |v| v.amount = 0),
        edit("negative_spent", |v| v.spent = -1),
        edit("negative_request_units", |v| v.spent_units = -1),
        edit("unset_transaction_cap", |v| v.caps[0] = None),
        edit("unset_spent_cap", |v| v.caps[1] = None),
        edit("unset_day_spent_cap", |v| v.caps[2] = None),
        edit("unset_day_total_cap", |v| v.caps[3] = None),
        edit("unset_call_cap", |v| v.call_cap = None),
        edit("unset_recipients", |v| v.recipients = None),
        edit("unset_tokens", |v| v.tokens = None),
        edit("unset_expiry", |v| v.expiry = None),
        edit("unset_operations", |v| v.operations = None),
        edit("unset_everything", |v| {
            v.caps = [None; 4];
            v.call_cap = None;
            v.recipients = None;
            v.tokens = None;
            v.expiry = None;
            v.operations = None;
        }),
        // A policy that allows only deposits denies a transfer, and admits a deposit.
        edit("only_deposits", |v| {
            v.operations = Some(Ops::List(vec!["deposit"]))
        }),
        edit("deposit_only_deposits", |v| {
            deposit(v);
            v.operations = Some(Ops::List(vec!["deposit"]));
        }),
        // Swaps and redeems: the exchange and the vault are recipients, `tokens` also checks the
        // token a swap trades against the asset, and a reverse swap or redeem counts its minimum
        // asset output as its gross amount.
        edit("swap", |v| swap(v, false)),
        edit("reverse_swap", |v| swap(v, true)),
        edit("swap_unlisted_exchange", |v| {
            swap(v, false);
            v.recipients = Some(vec![RECIPIENT, VAULT]);
        }),
        edit("swap_other_token_not_allowed", |v| {
            swap(v, false);
            v.tokens = Some(vec![ASSET]);
        }),
        edit("reverse_swap_other_token_not_allowed", |v| {
            swap(v, true);
            v.tokens = Some(vec![ASSET, OTHER]);
        }),
        edit("swap_not_in_operations", |v| {
            swap(v, false);
            v.operations = Some(Ops::List(vec!["transfer", "redeem"]));
        }),
        edit("swap_over_transaction_cap", |v| {
            swap(v, false);
            v.caps[0] = Some(39);
        }),
        edit("reverse_swap_floor_over_transaction_cap", |v| {
            swap(v, true);
            v.caps[0] = Some(39);
        }),
        edit("redeem", redeem),
        edit("redeem_not_in_operations", |v| {
            redeem(v);
            v.operations = Some(Ops::List(vec!["transfer", "deposit", "swap"]));
        }),
        edit("only_swaps", |v| {
            v.operations = Some(Ops::List(vec!["swap"]))
        }),
        edit("any_operation", |v| v.operations = Some(Ops::Text("*"))),
        // Custom-call forms never admit a native transfer.
        edit("custom_calls_only", |v| {
            let names = vec!["custom", "custom.swap", POOL_CLAIM, "swap", "redeem"];
            v.operations = Some(Ops::List(names));
        }),
        edit("empty_operations", |v| {
            v.operations = Some(Ops::List(Vec::new()))
        }),
        edit("operations_not_a_list", |v| {
            v.operations = Some(Ops::Text("transfer"))
        }),
        edit("unknown_operation", |v| {
            v.operations = Some(Ops::List(vec!["transfer", "pay"]))
        }),
        edit("custom_contract_not_alphanumeric", |v| {
            v.operations = Some(Ops::List(vec!["transfer", "custom:po-ol.claim"]))
        }),
        // A custom param alone changes nothing; an `invoice` arg applies the invoice cap.
        edit("invoice_cap_without_invoice", |v| v.invoice_cap = Some(39)),
        edit("invoice_within_cap", |v| {
            v.invoice = true;
            v.invoice_cap = Some(40);
        }),
        edit("invoice_over_cap", |v| {
            v.invoice = true;
            v.invoice_cap = Some(39);
        }),
        edit("invoice_without_cap", |v| v.invoice = true),
        // A custom param beside fewer than nine canonical params: the standard tiers reject it.
        edit("invoice_cap_beside_few_params", |v| {
            v.caps = [Some(100), None, None, None];
            v.call_cap = None;
            v.recipients = None;
            v.tokens = None;
            v.expiry = None;
            v.operations = None;
            v.invoice_cap = Some(39);
        }),
        // Args at their bound pass; one more denies in `evaluate` as in the wallet kernel.
        edit("args_at_bound", |v| v.extra_args = MAX_ARGS),
        edit("args_over_bound", |v| v.extra_args = MAX_ARGS + 1),
        // The catching policy writes one new key: up to the state key bound it is stored, past
        // it every backend denies with `InvalidState`.
        edit("state_keys_at_bound", |v| {
            v.caps[2] = Some(44);
            v.extra_state = MAX_POLICY_KEYS - 1;
        }),
        edit("state_keys_over_bound", |v| {
            v.caps[2] = Some(44);
            v.extra_state = MAX_POLICY_KEYS;
        }),
        // The state's encoded size: the seven standard keys take 7 * 120 bytes, the catching
        // policy's key 120 and `blob` 40 + 80 + 45 * (80 + 256) + 80 + 104, exactly
        // `MAX_STATE_BYTES`. Four more bytes deny with `InvalidState` on every backend.
        edit("state_bytes_at_bound", |v| {
            v.caps[2] = Some(44);
            v.blob = blob(104);
        }),
        edit("state_bytes_over_bound", |v| {
            v.caps[2] = Some(44);
            v.blob = blob(105);
        }),
    ]
}

/// Filler text lengths: 45 texts of 256 bytes and one of `last` bytes.
fn blob(last: usize) -> Vec<usize> {
    let mut lengths = vec![256; 45];
    lengths.push(last);
    lengths
}

/// Text of one result, identical on both backends: `ok:<value>` or `err:<code>`.
pub fn show<T: std::fmt::Display>(result: Result<T, u32>) -> String {
    match result {
        Ok(value) => format!("ok:{value}"),
        Err(code) => format!("err:{code}"),
    }
}

/// Text of a state map's standard values and the catching policy's key, identical on both backends.
#[allow(clippy::too_many_arguments)]
pub fn state_line(
    calls: u64,
    spent: i128,
    unpriced: bool,
    day: u64,
    day_spent: i128,
    day_total: i128,
    day_unpriced: bool,
    over: Option<u64>,
) -> String {
    let over = over.map_or(String::from("-"), |n| format!("{n}"));
    format!("{calls}/{spent}/{unpriced}/{day}/{day_spent}/{day_total}/{day_unpriced}/{over}")
}

/// Every outcome a policy author can observe on one vector: the sample, branch and catching
/// policies, each rule, the standard preflight runner, the post-flight state without policy
/// writes, the Common and Simple evaluations, and the catching policy's evaluation for a Custom
/// and a standard wallet.
#[derive(Clone, Debug, PartialEq)]
pub struct Outcome {
    pub policy: Result<(), u32>,
    pub branch: Result<(), u32>,
    pub catching: Result<(), u32>,
    /// Rule results in canonical key order. Address pass values are `@<index>`.
    pub rules: Vec<Result<String, u32>>,
    /// Preflight results in canonical key order.
    pub preflight: Vec<Result<(), u32>>,
    /// `evaluate` with no policy writes for a Custom wallet, as `state_line`.
    pub next: Result<String, u32>,
    /// `evaluate` of every canonical preflight for a standard wallet: Common with the full prefix.
    pub common: Result<String, u32>,
    /// `evaluate` with no policy for a standard wallet: Simple.
    pub simple: Result<String, u32>,
    /// `evaluate` of the catching policy for a Custom wallet, which stores its key.
    pub catching_next: Result<String, u32>,
    /// `evaluate` of the catching policy for a standard wallet, which denies any write.
    pub catching_standard: Result<String, u32>,
}

impl Outcome {
    /// One output line of the host smoke.
    pub fn line(&self, name: &str) -> String {
        let list = |items: Vec<String>| items.join(",");
        let unit = |r: &Result<(), u32>| show(r.map(|()| "()"));
        format!(
            "vector {name} policy={} branch={} catching={} rules={} preflight={} next={} common={} simple={} catching_next={} catching_standard={}",
            unit(&self.policy),
            unit(&self.branch),
            unit(&self.catching),
            list(self.rules.iter().cloned().map(show).collect()),
            list(self.preflight.iter().map(unit).collect()),
            show(self.next.clone()),
            show(self.common.clone()),
            show(self.simple.clone()),
            show(self.catching_next.clone()),
            show(self.catching_standard.clone()),
        )
    }
}
