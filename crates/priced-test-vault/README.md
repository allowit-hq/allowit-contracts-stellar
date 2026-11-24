# Priced SEP-56 test vault

`allowit-sep56-priced-test-vault` is a test fixture: a well-behaved SEP-56 vault whose admin sets the share
price. Use it in tests and on Testnet when a wallet needs an honest vault, or when a test must move a share price
on purpose. Never use it as a deployed asset vault: its admin decides what a share is worth.

The vault earns nothing. Every conversion uses the admin's price: the asset base units that one share
(10^7 share units) converts to, so `10000000` is one asset per share. A deposit and a redeem round down, a mint
and a withdraw round up, as ERC-4626 does. A deposit takes exactly one `transfer(from, vault, assets)` when the
operator is the depositor, the one transfer that a policy wallet authorizes. Another operator spends an allowance.

```
__constructor(asset, admin, name, share_price)
admin() / share_price() / set_share_price(share_price)           the admin signs the change
query_asset() / total_assets() / convert_to_shares / convert_to_assets
max_deposit / preview_deposit / deposit(assets, receiver, from, operator)
max_mint / preview_mint / mint(shares, receiver, from, operator)
max_withdraw / preview_withdraw / withdraw(assets, receiver, owner, operator)
max_redeem / preview_redeem / redeem(shares, receiver, owner, operator)
balance / total_supply / decimals / name / symbol / allowance / approve / transfer / transfer_from / burn / burn_from
```

The admin keeps the vault solvent. A redeem fails when the vault holds fewer assets than it pays, so move the
difference to the vault with a plain asset transfer before raising the price. Lowering the price leaves the
difference in the vault. Each call extends the vault's instance and the balances it touches to about seven days
of Testnet life; extend a long-lived instance and its code with `stellar contract extend`.

Deploy and move the price with the Stellar CLI:

```sh
stellar contract upload --wasm target/wasm32v1-none/release/allowit_sep56_priced_test_vault.wasm --source ADMIN --network testnet
stellar contract deploy --wasm-hash HASH --source ADMIN --network testnet -- \
  --asset "$(stellar contract id asset --asset native --network testnet)" --admin ADMIN --name "Vault A" --share_price 10000000
stellar contract invoke --id VAULT --source ADMIN --network testnet -- set_share_price --share_price 9400000
```
