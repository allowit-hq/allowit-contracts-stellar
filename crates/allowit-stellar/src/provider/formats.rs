//! Stellar address and asset formats: G… accounts, C… contracts and
//! Stellar Asset Contracts in place of a token code.
use crate::host::input::Formats;

fn account(s: &str) -> bool {
    s.starts_with('G') && allowit_stellar_wallet::account_key(s).is_ok()
}
fn contract(s: &str) -> bool {
    s.starts_with('C') && allowit_stellar_wallet::address(s).is_ok()
}
fn account_or_contract(s: &str) -> bool {
    account(s) || contract(s)
}
fn wallet_error(address: &str) -> Option<String> {
    if account_or_contract(address) {
        return None;
    }
    let mut clipped: String = address.chars().take(64).collect();
    if clipped.len() < address.len() {
        clipped.push('…');
    }
    Some(if address.starts_with('M') {
        format!("{clipped} is a muxed address. Use its G account address.")
    } else {
        format!("{clipped} is not a valid Stellar G or C address.")
    })
}
fn asset_code(code: &str) -> bool {
    !code.is_empty() && code.len() <= 12 && code.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Stellar Asset Contracts use the classic seven decimals.
fn asset_contract(s: &str) -> Option<u8> {
    contract(s).then_some(7)
}

fn address_candidate(token: &str) -> bool {
    token.len() == 56
        && matches!(token.as_bytes()[0], b'G' | b'C' | b'M')
        && token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}
fn resolve_asset(
    network: &str,
    symbol: &str,
    issuer: Option<&str>,
    known_default: bool,
) -> crate::host::error::Result<crate::host::input::asset::ResolvedAsset> {
    let issuer = issuer.or_else(|| {
        known_default
            .then(|| {
                super::tokens_for(network)
                    .iter()
                    .find(|t| t.code == symbol)
                    .and_then(|t| t.issuer)
            })
            .flatten()
    });
    let asset = allowit_stellar_wallet::asset_from_identity(symbol, issuer)
        .map_err(crate::host::error::Error::usage)?;
    let address = allowit_stellar_wallet::sac_address(network, &asset)
        .map_err(crate::host::error::Error::usage)?;
    Ok(crate::host::input::asset::ResolvedAsset {
        symbol: symbol.into(),
        address,
        decimals: 7,
    })
}

pub const FORMATS: Formats = Formats {
    account: (account, "a G… strkey"),
    wallet: (account_or_contract, "a G… account or C… contract strkey"),
    wallet_error,
    recipient: (account_or_contract, "a G… or C… strkey"),
    token: (account_or_contract, "a G… issuer or C… contract"),
    signing_digest: allowit_stellar_wallet::signing::signed_message_digest,
    account_key: |address| allowit_stellar_wallet::account_key(address).ok(),
    address_candidate,
    resolve_asset,
    same_wallet: |a, b| a == b,
    asset_code,
    asset_contract,
    // Classic Stellar assets have seven decimals.
    issuer_decimals: Some(7),
};

#[cfg(test)]
mod tests {
    use super::{asset_code, wallet_error};

    #[test]
    fn invalid_wallet_diagnostics_are_owned_by_the_native_adapter() {
        assert!(wallet_error("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF").is_none());
        assert!(wallet_error("Mfoo").unwrap().contains("muxed address"));
        assert!(
            wallet_error("bad")
                .unwrap()
                .contains("not a valid Stellar G or C address")
        );
    }

    #[test]
    fn classic_asset_codes_obey_native_limits() {
        for valid in ["A", "USDC", "a1", "ABCDEFGHIJKL"] {
            assert!(asset_code(valid), "{valid}");
        }
        for invalid in ["", "ABCDEFGHIJKLM", "USD-", "US D", "ÉUR", "USD\n"] {
            assert!(!asset_code(invalid), "{invalid:?}");
        }
    }
}
