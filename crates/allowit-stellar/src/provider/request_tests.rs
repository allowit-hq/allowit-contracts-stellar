//! Stellar request building, tested on the provider directly (moved from the SDK).
#[cfg(test)]
mod tests {
    use crate::host::execution::Request as ExecRequest;
    use crate::host::input::asset::{Amount, Asset, decimal_units};
    use crate::host::typed_request::operation_nonce;
    use crate::provider::request::{build, rebuild, state};
    use crate::workflow::ExecutionRequest;
    use crate::{self as sdk, WalletConfig, WalletRoute};
    use std::time::Duration;

    fn config(route: WalletRoute, usdc: bool) -> WalletConfig {
        sdk::test_support::request_config(route, usdc)
    }
    fn vault(n: u8) -> String {
        sdk::test_support::vault(n)
    }
    /// `CODE:DECIMAL` names a token in its decimals; a bare integer is base units of the
    /// installed asset.
    fn amount(text: &str) -> Amount {
        let tokens = crate::provider::tokens_for("stellar:testnet");
        match text.split_once(':') {
            Some((code, value)) => {
                let token = tokens.iter().find(|t| t.code == code).unwrap();
                Amount {
                    asset: if token.native {
                        Asset::Native { code: code.into() }
                    } else {
                        Asset::Token {
                            code: code.into(),
                            issuer: token.issuer.map(Into::into),
                        }
                    },
                    quantity: decimal_units(value, token.decimals).unwrap(),
                    decimals: Some(token.decimals),
                    text: text.into(),
                }
            }
            None => Amount {
                asset: Asset::Installed,
                quantity: text.parse().unwrap(),
                decimals: None,
                text: text.into(),
            },
        }
    }
    fn request(op: &str, to: &str, amount_text: &str, token_out: Option<&str>) -> ExecRequest {
        ExecRequest {
            op: op.into(),
            to: to.into(),
            amount: amount(amount_text),
            token_out: token_out.map(amount),
            args: None,
            request_id: "request-0001".into(),
            wait: Duration::ZERO,
            build_only: true,
            wallet: None,
        }
    }

    #[test]
    fn exec_flags_build_requests_that_decode_to_the_same_operation() {
        let to = sdk::account_for_seed(&[6; 32]);
        let usdc = config(WalletRoute::PolicyWallet, true);
        // The policy wallet's current agent account differs from the profile
        // agent; it pays the fee.
        let mut state = state(&config(WalletRoute::Native, false), None).unwrap();
        state.source.address = sdk::account_for_seed(&[8; 32]);
        let cases = [
            (
                config(WalletRoute::Native, false),
                request("transfer", &to, "XLM:0.1", None),
            ),
            (usdc.clone(), request("transfer", &to, "USDC:0.1", None)),
            (
                usdc.clone(),
                request("deposit", &vault(1), "USDC:5", Some("4900000")),
            ),
            (
                usdc.clone(),
                request("redeem", &vault(1), "2000000", Some("USDC:0.19")),
            ),
        ];
        for (c, r) in cases {
            let typed = build("policy-1", &c, &r, || Ok(state.clone())).unwrap();
            let expected = match r.op.as_str() {
                "transfer" => sdk::StellarOperation::Transfer(sdk::Transfer {
                    token: c.asset.clone(),
                    source: c.wallet.clone(),
                    recipient: to.clone(),
                    amount: 1_000_000,
                    native: c.route == WalletRoute::Native,
                }),
                "deposit" => sdk::StellarOperation::Deposit(sdk::Deposit {
                    vault: vault(1),
                    assets: 50_000_000,
                    min_shares: 4_900_000,
                }),
                _ => sdk::StellarOperation::Redeem(sdk::Redeem {
                    vault: vault(1),
                    shares: 2_000_000,
                    min_assets: 1_900_000,
                }),
            };
            assert_eq!(
                sdk::operation_from_request(&c, &typed.request).unwrap(),
                expected
            );
            let payer = if c.route == WalletRoute::Native {
                &c.wallet
            } else {
                &state.source.address
            };
            assert_eq!(
                fee_payer(&typed.request),
                sdk::request::account(payer).unwrap()
            );
            assert_eq!(
                typed.request.operation.nonce,
                operation_nonce("policy-1", "request-0001")
            );
        }
    }
    fn fee_payer(r: &ExecutionRequest) -> crate::workflow::AccountId {
        r.fee_bounds.as_ref().unwrap()[0].payer.clone()
    }

    #[test]
    fn a_retry_keeps_the_retained_fee_payer() {
        let c = config(WalletRoute::PolicyWallet, true);
        let r = request("deposit", &vault(1), "USDC:5", Some("4900000"));
        let mut first = state(&config(WalletRoute::Native, false), None).unwrap();
        first.source.address = sdk::account_for_seed(&[8; 32]);
        let old = build("policy-1", &c, &r, || Ok(first)).unwrap().request;
        // The agent account changed since; the same flags rebuild the same request.
        assert_eq!(rebuild("policy-1", &c, &r, &old).unwrap().request, old);
        let more = request("deposit", &vault(1), "USDC:6", Some("4900000"));
        assert_ne!(rebuild("policy-1", &c, &more, &old).unwrap().request, old);
    }
    #[test]
    fn build_only_never_opens_the_provider_journal() {
        let fixtures = sdk::test_support::portable_descriptors();
        let descriptor = serde_json::value::RawValue::from_string(
            serde_json::to_string(&fixtures[0]["bundle"]).unwrap(),
        )
        .unwrap();
        let (description, binding) =
            crate::provider::profiles::decode("stellar:testnet", descriptor.get().as_bytes())
                .unwrap();
        let profile = crate::host::profiles::Profile {
            description,
            binding,
            descriptor,
            backend: "http://localhost:8080".into(),
            authority: None,
        };
        let opened = std::cell::Cell::new(false);
        let store = || -> crate::host::error::Result<allowit_core::client::store::Store> {
            opened.set(true);
            Err(crate::host::error::Error::config(
                "the build must not open the store",
            ))
        };
        let request = request("transfer", &sdk::account_for_seed(&[6; 32]), "1", None);
        let wire = crate::provider::execution::build(&profile, &store, None, &request).unwrap();
        assert_eq!(wire["requestId"], request.request_id);
        assert!(
            !opened.get(),
            "A build-only request must not invoke the host store opener"
        );
    }
}
