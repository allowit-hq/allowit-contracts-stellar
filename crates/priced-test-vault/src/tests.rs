extern crate std;
use super::*;
use soroban_sdk::{
    IntoVal,
    testutils::{Address as _, Ledger as _, MockAuth, MockAuthInvoke},
    token::{StellarAssetClient, TokenClient},
};

struct Fixture {
    env: Env,
    asset: Address,
    admin: Address,
    vault: Address,
}

impl Fixture {
    fn new(share_price: i128) -> Self {
        let env = Env::default();
        let asset = env
            .register_stellar_asset_contract_v2(Address::generate(&env))
            .address();
        let admin = Address::generate(&env);
        let vault = env.register(
            AllowitSep56PricedTestVault,
            (
                asset.clone(),
                admin.clone(),
                String::from_str(&env, "Vault A"),
                share_price,
            ),
        );
        Self {
            env,
            asset,
            admin,
            vault,
        }
    }
    fn vault(&self) -> AllowitSep56PricedTestVaultClient<'_> {
        AllowitSep56PricedTestVaultClient::new(&self.env, &self.vault)
    }
    fn holder(&self, assets: i128) -> Address {
        let holder = Address::generate(&self.env);
        self.env.mock_all_auths();
        StellarAssetClient::new(&self.env, &self.asset).mint(&holder, &assets);
        holder
    }
    fn assets(&self, of: &Address) -> i128 {
        TokenClient::new(&self.env, &self.asset).balance(of)
    }
}

#[test]
fn a_deposit_and_a_redeem_at_one_asset_per_share_move_exact_amounts() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let holder = f.holder(1_000);
    assert_eq!(v.preview_deposit(&400), 400);
    assert_eq!(v.deposit(&400, &holder, &holder, &holder), 400);
    assert_eq!((v.balance(&holder), f.assets(&holder)), (400, 600));
    assert_eq!(
        (v.total_supply(), v.total_assets(), f.assets(&f.vault)),
        (400, 400, 400)
    );
    assert_eq!(v.preview_redeem(&150), 150);
    assert_eq!(v.redeem(&150, &holder, &holder, &holder), 150);
    assert_eq!((v.balance(&holder), f.assets(&holder)), (250, 750));
    assert_eq!(v.query_asset(), f.asset);
    assert_eq!(
        (v.decimals(), v.name()),
        (7, String::from_str(&f.env, "Vault A"))
    );
}

#[test]
fn the_admin_moves_the_share_price_and_every_conversion_follows_it() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let holder = f.holder(100 * SHARE);
    v.deposit(&(100 * SHARE), &holder, &holder, &holder);
    // Down 4%, then 6%: what the shares are worth falls with the price.
    v.set_share_price(&9_600_000);
    assert_eq!(v.share_price(), 9_600_000);
    assert_eq!(v.preview_redeem(&SHARE), 9_600_000);
    assert_eq!(v.convert_to_assets(&(100 * SHARE)), 96 * SHARE);
    v.set_share_price(&9_400_000);
    assert_eq!(v.total_assets(), 94 * SHARE);
    // A redeem pays what the preview names; the vault keeps the difference.
    let paid = v.redeem(&(100 * SHARE), &holder, &holder, &holder);
    assert_eq!(
        (paid, f.assets(&holder), v.balance(&holder)),
        (94 * SHARE, 94 * SHARE, 0)
    );
    assert_eq!(f.assets(&f.vault), 6 * SHARE);
    // At a lower price a deposit buys more shares, rounded down.
    assert_eq!(v.preview_deposit(&SHARE), 10_638_297);
}

#[test]
fn only_the_admin_sets_the_price() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let stranger = Address::generate(&f.env);
    let invoke = MockAuthInvoke {
        contract: &f.vault,
        fn_name: "set_share_price",
        args: (9_000_000i128,).into_val(&f.env),
        sub_invokes: &[],
    };
    let call = |who| MockAuth {
        address: who,
        invoke: &invoke,
    };
    assert!(
        v.mock_auths(&[call(&stranger)])
            .try_set_share_price(&9_000_000)
            .is_err()
    );
    assert_eq!(v.share_price(), SHARE);
    v.mock_auths(&[call(&f.admin)]).set_share_price(&9_000_000);
    assert_eq!((v.share_price(), v.admin()), (9_000_000, f.admin.clone()));
    f.env.mock_all_auths();
    assert_eq!(
        v.try_set_share_price(&0),
        Err(Ok(VaultError::NotPositive.into()))
    );
}

#[test]
fn a_deposit_takes_exactly_one_transfer_that_its_depositor_authorizes() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let holder = f.holder(1_000);
    // The holder signs the deposit and the one asset transfer inside it, and nothing else.
    v.mock_auths(&[MockAuth {
        address: &holder,
        invoke: &MockAuthInvoke {
            contract: &f.vault,
            fn_name: "deposit",
            args: (40i128, holder.clone(), holder.clone(), holder.clone()).into_val(&f.env),
            sub_invokes: &[MockAuthInvoke {
                contract: &f.asset,
                fn_name: "transfer",
                args: (holder.clone(), f.vault.clone(), 40i128).into_val(&f.env),
                sub_invokes: &[],
            }],
        },
    }])
    .deposit(&40, &holder, &holder, &holder);
    assert_eq!(v.balance(&holder), 40);
}

#[test]
fn mint_and_withdraw_round_toward_the_vault() {
    let f = Fixture::new(25_000_000);
    let v = f.vault();
    let holder = f.holder(1_000);
    // 2.5 assets a share: a deposit of 10 buys 4 share units.
    assert_eq!(v.preview_deposit(&11), 4);
    // Minting 3 share units takes 8 assets (7.5 rounded up).
    assert_eq!(v.mint(&3, &holder, &holder, &holder), 8);
    // Withdrawing 1 asset burns 1 share unit (0.4 rounded up).
    assert_eq!(v.preview_withdraw(&1), 1);
    assert_eq!(v.withdraw(&1, &holder, &holder, &holder), 1);
    assert_eq!((v.balance(&holder), f.assets(&holder)), (2, 993));
    // A redeem that pays nothing is refused.
    f.env.mock_all_auths();
    let tiny = Fixture::new(1);
    let small = tiny.holder(100);
    tiny.vault().deposit(&1, &small, &small, &small);
    assert_eq!(
        tiny.vault().try_redeem(&1, &small, &small, &small),
        Err(Ok(VaultError::ZeroResult.into()))
    );
}

#[test]
fn another_operator_redeems_only_within_the_owners_share_allowance() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let owner = f.holder(100);
    let operator = Address::generate(&f.env);
    v.deposit(&100, &owner, &owner, &owner);
    assert_eq!(
        v.try_redeem(&10, &operator, &owner, &operator),
        Err(Ok(VaultError::InsufficientAllowance.into()))
    );
    let until = f.env.ledger().sequence() + 100;
    v.approve(&owner, &operator, &30, &until);
    assert_eq!(v.redeem(&20, &operator, &owner, &operator), 20);
    assert_eq!(
        (v.allowance(&owner, &operator), v.balance(&owner)),
        (10, 80)
    );
    f.env.ledger().with_mut(|l| l.sequence_number = until + 1);
    assert_eq!(v.allowance(&owner, &operator), 0);
}

#[test]
fn shares_move_as_a_sep41_token() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let a = f.holder(100);
    let b = Address::generate(&f.env);
    v.deposit(&100, &a, &a, &a);
    v.transfer(&a, MuxedAddress::from(b.clone()), &30);
    assert_eq!((v.balance(&a), v.balance(&b)), (70, 30));
    assert_eq!(
        v.try_transfer(&b, MuxedAddress::from(a.clone()), &31),
        Err(Ok(VaultError::InsufficientShares.into()))
    );
    v.burn(&b, &30);
    assert_eq!((v.balance(&b), v.total_supply()), (0, 70));
}

#[test]
fn a_redeem_fails_when_the_vault_cannot_pay() {
    let f = Fixture::new(SHARE);
    let v = f.vault();
    let holder = f.holder(100);
    v.deposit(&100, &holder, &holder, &holder);
    // Raised to two assets a share with no new assets: only half the shares can be redeemed.
    v.set_share_price(&(2 * SHARE));
    assert_eq!((v.max_redeem(&holder), v.max_withdraw(&holder)), (50, 100));
    assert!(v.try_redeem(&100, &holder, &holder, &holder).is_err());
    assert_eq!((v.balance(&holder), f.assets(&f.vault)), (100, 100));
    assert_eq!(v.redeem(&50, &holder, &holder, &holder), 100);
}
