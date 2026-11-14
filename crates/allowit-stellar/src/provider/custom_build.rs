//! The "build custom wallet" hook: build the `AllowitCustomPolicy` Wasm from the exact policy
//! source with the Stellar CLI and the Rust toolchain, hash wallet code, and sign and verify the
//! build statements as SEP-53 wallet messages.
//!
//! The build tree is the contract workspace of this release, embedded in the crate, with the
//! policy source in place of `contracts/allowit-custom-policy/policy/policy.rs`. It compiles the
//! same files as `scripts/build-custom-policy.sh` does from a checkout of this revision, so the
//! same source, toolchain and Stellar CLI give the same Wasm.
use crate::host::{
    Signer,
    error::{Error, Result},
};
use allowit_core::vendor::custom_build::{CustomWalletBuild, WalletCode, code, refusal};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

pub struct CustomBuild;
pub static CUSTOM_BUILD: CustomBuild = CustomBuild;

/// The Stellar CLI release that builds wallet code. Another release can emit other Wasm for the
/// same source, so the build refuses it.
pub const STELLAR_CLI_VERSION: &str = "28.1.0";
/// The environment variable that names the Stellar CLI binary. The default is `stellar` on `PATH`.
pub const STELLAR_BIN: &str = "STELLAR_BIN";
/// The policy source file of the Custom wallet contract in the build tree.
const POLICY_SOURCE: &str = "contracts/allowit-custom-policy/policy/policy.rs";
/// The largest policy source that the build compiles.
const MAX_SOURCE_BYTES: usize = 262_144;

macro_rules! tree {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_bytes!(concat!("../../../../", $path)).as_slice())),*]
    };
}
/// Every file of the contract workspace that the Custom wallet contract compiles from, at the
/// revision of this crate.
static TREE: &[(&str, &[u8])] = tree![
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "contracts/allowit-custom-policy/Cargo.toml",
    "contracts/allowit-custom-policy/build.rs",
    "contracts/allowit-custom-policy/src/branch_policy.rs",
    "contracts/allowit-custom-policy/src/catching_policy.rs",
    "contracts/allowit-custom-policy/src/lib.rs",
    "crates/policy/Cargo.toml",
    "crates/policy/build.rs",
    "crates/policy/src/lib.rs",
    "crates/policy-wallet/Cargo.toml",
    "crates/policy-wallet/src/lib.rs",
    "crates/policy-wallet/src/persistent.rs",
    "crates/protocol/Cargo.toml",
    "crates/protocol/src/lib.rs",
];
/// The other members of the contract workspace. Cargo reads their manifests to load the
/// workspace and its lock file; the build compiles none of them, so each gets an empty library.
static OTHER_MEMBERS: &[(&str, &[u8])] = tree![
    "contracts/allowit-common-policy-engine/Cargo.toml",
    "contracts/allowit-engine-parent/Cargo.toml",
    "contracts/allowit-simple-policy-engine/Cargo.toml",
    "contracts/allowit-wallet-engine/Cargo.toml",
    "crates/test-vault/Cargo.toml",
];

/// The smallest Wasm module that declares the current custody layout: the wallet code of the
/// shared test fixtures. It holds no code and installs no usable wallet.
pub fn fixture_wallet_code() -> Vec<u8> {
    let mut meta = 0u32.to_be_bytes().to_vec();
    for bytes in [
        b"allowit_custody_layout".as_slice(),
        crate::CONTRACT_VERSION.to_string().as_bytes(),
    ] {
        meta.extend((bytes.len() as u32).to_be_bytes());
        meta.extend(bytes);
        meta.resize(meta.len().div_ceil(4) * 4, 0);
    }
    let mut section = vec![b"contractmetav0".len() as u8];
    section.extend(b"contractmetav0");
    section.extend(meta);
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    bytes.extend([0, section.len() as u8]);
    bytes.extend(section);
    bytes
}

fn toolchain_missing(message: impl Into<String>) -> Error {
    refusal(code::TOOLCHAIN_MISSING, message)
}
fn build_failed(message: impl Into<String>) -> Error {
    refusal(code::BUILD_FAILED, message)
}

/// The first line of a tool's `--version` output.
fn version_line(tool: &Path, dir: &Path) -> Option<String> {
    let output = Command::new(tool)
        .arg("--version")
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .lines()
        .next()
        .map(|line| line.trim().to_owned())
}

/// Whether the complete output of a failed build names a compiler or a Wasm target that rustup
/// did not supply. That is a toolchain fault, not a fault of the policy source.
fn missing_toolchain(stderr: &str) -> bool {
    stderr.contains("wasm32v1-none") && stderr.contains("not be installed")
        || stderr.contains("wasm32v1-none") && stderr.contains("not installed")
        || stderr.contains("toolchain") && stderr.contains("is not installed")
        || stderr.contains("can't find crate for `core`")
}

/// The last lines of a failed tool run, for the owner. Tool output is local build output.
fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    lines[lines.len().saturating_sub(12)..].join("\n")
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let failed = || Error::config("Cannot write the custom wallet build tree");
    std::fs::create_dir_all(path.parent().ok_or_else(failed)?).map_err(|_| failed())?;
    std::fs::write(path, bytes).map_err(|_| failed())
}

/// Write the build tree of `source` under `tree`, which must not exist.
fn write_tree(tree: &Path, source: &str) -> Result<()> {
    for (path, bytes) in TREE {
        write(&tree.join(path), bytes)?;
    }
    for (manifest, bytes) in OTHER_MEMBERS {
        let manifest = tree.join(manifest);
        write(&manifest, bytes)?;
        write(&manifest.with_file_name("src").join("lib.rs"), b"")?;
    }
    write(&tree.join(POLICY_SOURCE), source.as_bytes())
}

/// Build the Custom wallet Wasm of `source` with the Stellar CLI binary `stellar`.
pub(crate) fn build_with(stellar: &Path, source: &str, work: &Path) -> Result<WalletCode> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Error::usage(
            "The policy source exceeds the custom wallet build limit",
        ));
    }
    // The contract compiles the source as a module. Only source that passes the portable policy
    // gate is compiled: it cannot include a local file or run code at compile time.
    crate::policy::tier_rules(crate::PolicyTier::Custom, source).map_err(|reason| {
        build_failed(format!(
            "The policy source does not pass the policy source gate: {reason}. Draft the policy again."
        ))
    })?;
    let unusable = || Error::config("Cannot prepare the custom wallet build folder");
    std::fs::create_dir_all(work).map_err(|_| unusable())?;
    let work = work.canonicalize().map_err(|_| unusable())?;
    let (tree, out) = (work.join("tree"), work.join("out"));
    for stale in [&tree, &out] {
        if stale.exists() {
            std::fs::remove_dir_all(stale).map_err(|_| unusable())?;
        }
    }
    write_tree(&tree, source)?;
    let cli = version_line(stellar, &tree).ok_or_else(|| {
        toolchain_missing(format!(
            "The Stellar CLI is missing. Install Stellar CLI {STELLAR_CLI_VERSION} (https://developers.stellar.org/docs/tools/cli/install-cli, or `cargo install --locked stellar-cli@{STELLAR_CLI_VERSION}`), or name its binary in {STELLAR_BIN}. Then run the build again."
        ))
    })?;
    if cli.split_whitespace().nth(1) != Some(STELLAR_CLI_VERSION) {
        return Err(toolchain_missing(format!(
            "The build needs Stellar CLI {STELLAR_CLI_VERSION}, and this one is {cli}. Install that release (`cargo install --locked stellar-cli@{STELLAR_CLI_VERSION}`), or name its binary in {STELLAR_BIN}. Then run the build again."
        )));
    }
    // `rust-toolchain.toml` of the tree selects the compiler and the Wasm target through rustup.
    let rustc = version_line(Path::new("rustc"), &tree).ok_or_else(|| {
        toolchain_missing(
            "The Rust toolchain is missing. Install rustup (https://rustup.rs); the build then installs the pinned compiler and its Wasm target. Then run the build again.",
        )
    })?;
    allowit_core::client::progress::report(
        "Building the wallet code with the Stellar CLI; a first build takes some minutes",
    );
    let output = Command::new(stellar)
        .args(["contract", "build", "--locked", "--package"])
        .arg("allowit-custom-policy")
        .arg("--out-dir")
        .arg(&out)
        .env("CARGO_TARGET_DIR", work.join("target"))
        .current_dir(&tree)
        .output()
        .map_err(|_| toolchain_missing("The Stellar CLI did not start. Install it again."))?;
    if !output.status.success() {
        let log = tail(&output.stderr);
        if missing_toolchain(&String::from_utf8_lossy(&output.stderr)) {
            return Err(toolchain_missing(format!(
                "The pinned Rust toolchain or its Wasm target is not installed. Run `rustup target add wasm32v1-none` in {} and build again.\n{log}",
                tree.display()
            )));
        }
        return Err(build_failed(format!(
            "The wallet code did not build. Check the network access to crates.io and GitHub, then build again.\n{log}"
        )));
    }
    let wasm = std::fs::read(out.join("allowit_custom_policy.wasm"))
        .map_err(|_| build_failed("The Stellar CLI wrote no wallet code. Build again."))?;
    let code_hash = crate::admin::check_wallet_code(&wasm)
        .map_err(|reason| build_failed(format!("The built wallet code is invalid: {reason}")))?;
    Ok(WalletCode {
        code: wasm,
        code_hash,
        toolchain: format!("{cli}; {rustc}"),
    })
}

impl CustomWalletBuild for CustomBuild {
    fn build(&self, network: &str, source: &str, work: &Path) -> Result<WalletCode> {
        crate::host::routing::normalize(network)?;
        let stellar = std::env::var_os(STELLAR_BIN)
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("stellar"), PathBuf::from);
        build_with(&stellar, source, work)
    }
    /// The SHA-256 of a wallet Wasm of the current custody layout, as the ledger records it.
    fn code_hash(&self, network: &str, code: &[u8]) -> Result<[u8; 32]> {
        crate::host::routing::normalize(network)?;
        crate::admin::check_wallet_code(code).map_err(Error::usage)
    }
    /// A SEP-53 message signature: the one that a browser wallet makes with `signMessage`.
    fn sign_message(&self, signer: &dyn Signer, message: &str) -> Result<Vec<u8>> {
        signer.sign_hash(&crate::signing::signed_message_digest(message))
    }
    fn verify_message(
        &self,
        network: &str,
        address: &str,
        message: &str,
        signature: &[u8],
    ) -> Result<()> {
        crate::host::routing::normalize(network)?;
        crate::signing::verify_digest(
            address,
            &crate::signing::signed_message_digest(message),
            signature,
        )
        .map_err(|_| Error::usage("The message signature is invalid"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowit_core::vendor::custom_build::{
        Admitted, attest, check_code_hash, presign, verify_attestation, verify_presignature,
    };

    const NETWORK: &str = "stellar:testnet";
    const SOURCE: &str =
        include_str!("../../../../contracts/allowit-custom-policy/policy/policy.rs");

    struct Key(crate::signing::LocalSigner);
    fn key(seed: u8) -> Key {
        Key(crate::signing::LocalSigner::from_entropy(&[seed; 32]).unwrap())
    }
    impl Signer for Key {
        fn network(&self) -> &str {
            NETWORK
        }
        fn address(&self) -> &str {
            self.0.account()
        }
        fn sign_hash(&self, digest: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_digest(digest).map_err(Error::config)
        }
    }
    fn refused(error: Error) -> String {
        error.api_code.unwrap_or_default()
    }

    #[test]
    fn the_statements_are_wallet_message_signatures() {
        let (server, owner) = (key(1), key(2));
        let presignature = presign(&CUSTOM_BUILD, &server, NETWORK, "policy-1", SOURCE).unwrap();
        let admitted = Admitted {
            network: NETWORK,
            policy_id: "policy-1",
            source: SOURCE,
            server: server.address(),
        };
        verify_presignature(&CUSTOM_BUILD, &presignature, &admitted).unwrap();
        // The signature is the SEP-53 signature of the message text, as a wallet makes it.
        let message = presignature.message().unwrap();
        let wallet = server
            .0
            .sign_digest(&crate::signing::signed_message_digest(&message))
            .unwrap();
        assert_eq!(crate::hex(&wallet), presignature.signature);
        let attestation = attest(&CUSTOM_BUILD, &owner, &presignature, &[9; 32]).unwrap();
        verify_attestation(&CUSTOM_BUILD, &attestation, &admitted, owner.address()).unwrap();
        check_code_hash(&attestation, &[9; 32]).unwrap();
        assert_eq!(
            refused(check_code_hash(&attestation, &[8; 32]).unwrap_err()),
            code::CODE_HASH_MISMATCH
        );
    }

    #[test]
    fn a_presignature_is_bound_to_its_network_policy_source_and_server_key() {
        let server = key(1);
        let presignature = presign(&CUSTOM_BUILD, &server, NETWORK, "policy-1", SOURCE).unwrap();
        let admitted = Admitted {
            network: NETWORK,
            policy_id: "policy-1",
            source: SOURCE,
            server: server.address(),
        };
        let altered = format!("{SOURCE}// altered\n");
        let untrusted = key(3);
        for other in [
            Admitted {
                network: "stellar:pubnet",
                ..admitted
            },
            Admitted {
                policy_id: "policy-2",
                ..admitted
            },
            Admitted {
                source: &altered,
                ..admitted
            },
            Admitted {
                server: untrusted.address(),
                ..admitted
            },
        ] {
            let error = verify_presignature(&CUSTOM_BUILD, &presignature, &other).unwrap_err();
            assert_eq!(refused(error), code::PRESIGNATURE_MISMATCH);
        }
        // A statement relabelled for Mainnet keeps a signature that covers Testnet.
        let mut replayed = presignature.clone();
        replayed.network = "stellar:pubnet".into();
        let mainnet = Admitted {
            network: "stellar:pubnet",
            ..admitted
        };
        let error = verify_presignature(&CUSTOM_BUILD, &replayed, &mainnet).unwrap_err();
        assert_eq!(refused(error), code::PRESIGNATURE_MISMATCH);
        // A presignature that an untrusted key signed under the trusted key's name.
        let mut forged = presign(&CUSTOM_BUILD, &untrusted, NETWORK, "policy-1", SOURCE).unwrap();
        forged.server = server.address().into();
        let error = verify_presignature(&CUSTOM_BUILD, &forged, &admitted).unwrap_err();
        assert_eq!(refused(error), code::PRESIGNATURE_MISMATCH);
    }

    #[test]
    fn an_attestation_needs_the_owner_signature_over_the_code_hash() {
        let (server, owner, stranger) = (key(1), key(2), key(3));
        let presignature = presign(&CUSTOM_BUILD, &server, NETWORK, "policy-1", SOURCE).unwrap();
        let admitted = Admitted {
            network: NETWORK,
            policy_id: "policy-1",
            source: SOURCE,
            server: server.address(),
        };
        let by_stranger = attest(&CUSTOM_BUILD, &stranger, &presignature, &[9; 32]).unwrap();
        let error = verify_attestation(&CUSTOM_BUILD, &by_stranger, &admitted, owner.address())
            .unwrap_err();
        assert_eq!(refused(error), code::ATTESTATION_INVALID);
        let mut changed = attest(&CUSTOM_BUILD, &owner, &presignature, &[9; 32]).unwrap();
        changed.code_hash = crate::hex(&[8; 32]);
        let error =
            verify_attestation(&CUSTOM_BUILD, &changed, &admitted, owner.address()).unwrap_err();
        assert_eq!(refused(error), code::ATTESTATION_INVALID);
    }

    #[test]
    fn a_sign_in_signature_is_not_a_build_statement() {
        // The same key signs a sign-in message. That signature covers another text.
        let server = key(1);
        let presignature = presign(&CUSTOM_BUILD, &server, NETWORK, "policy-1", SOURCE).unwrap();
        let sign_in = server
            .0
            .sign_digest(&crate::signing::signed_message_digest(
                "example.org wants you to sign in",
            ))
            .unwrap();
        assert!(
            CUSTOM_BUILD
                .verify_message(
                    NETWORK,
                    server.address(),
                    &presignature.message().unwrap(),
                    &sign_in
                )
                .is_err()
        );
        // A raw signature of the message bytes, without the SEP-53 prefix, is refused too.
        let raw = server
            .0
            .sign_digest(&crate::hash(presignature.message().unwrap().as_bytes()))
            .unwrap();
        assert!(
            CUSTOM_BUILD
                .verify_message(
                    NETWORK,
                    server.address(),
                    &presignature.message().unwrap(),
                    &raw
                )
                .is_err()
        );
    }

    #[test]
    fn a_missing_or_other_stellar_cli_is_a_typed_toolchain_refusal() {
        let work = tempfile::tempdir().unwrap();
        let error = build_with(Path::new("/nonexistent/stellar"), SOURCE, work.path()).unwrap_err();
        assert_eq!(refused(error.clone()), code::TOOLCHAIN_MISSING);
        assert!(
            error.message.contains("Install Stellar CLI 28.1.0"),
            "{error}"
        );
        // A tool that reports another release.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let other = work.path().join("stellar-other");
            std::fs::write(&other, "#!/bin/sh\necho 'stellar 1.0.0 (test)'\n").unwrap();
            std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
            let error = build_with(&other, SOURCE, &work.path().join("build")).unwrap_err();
            assert_eq!(refused(error.clone()), code::TOOLCHAIN_MISSING);
            assert!(
                error.message.contains("this one is stellar 1.0.0"),
                "{error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_wasm_target_is_a_typed_toolchain_refusal_however_long_the_build_log_is() {
        use std::os::unix::fs::PermissionsExt;
        let work = tempfile::tempdir().unwrap();
        // A Stellar CLI of the pinned release whose build fails as rustc does without the target.
        // The note that names the target is far above the last lines of the log.
        let stellar = work.path().join("stellar");
        let noise =
            "echo 'warning: build failed, waiting for other jobs to finish...' >&2\n".repeat(40);
        std::fs::write(
            &stellar,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'stellar {STELLAR_CLI_VERSION} (test)'; exit 0; fi\necho \"error[E0463]: can't find crate for \\`core\\`\" >&2\necho '  = note: the \\`wasm32v1-none\\` target may not be installed' >&2\n{noise}exit 101\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stellar, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = build_with(&stellar, SOURCE, &work.path().join("build")).unwrap_err();
        assert_eq!(refused(error.clone()), code::TOOLCHAIN_MISSING, "{error}");
        assert!(
            error.message.contains("rustup target add wasm32v1-none"),
            "{error}"
        );
        // A failed compile of another cause stays a build failure.
        std::fs::write(
            &stellar,
            format!(
                "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'stellar {STELLAR_CLI_VERSION} (test)'; exit 0; fi\necho 'error: could not download crate' >&2\nexit 101\n"
            ),
        )
        .unwrap();
        let error = build_with(&stellar, SOURCE, &work.path().join("build")).unwrap_err();
        assert_eq!(refused(error), code::BUILD_FAILED);
    }

    #[test]
    fn source_outside_the_policy_gate_is_not_compiled() {
        let work = tempfile::tempdir().unwrap();
        let source = "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    let _ = include_str!(\"/etc/hosts\");\n    Ok(())\n}\n";
        let error = build_with(Path::new("/nonexistent/stellar"), source, work.path()).unwrap_err();
        assert_eq!(refused(error), code::BUILD_FAILED);
        assert!(!work.path().join("tree").exists());
    }

    #[test]
    fn the_fixture_wallet_code_has_a_code_hash() {
        let code = fixture_wallet_code();
        assert_eq!(code, crate::test_support::owner::wasm());
        assert_eq!(
            CUSTOM_BUILD.code_hash(NETWORK, &code).unwrap(),
            crate::hash(&code)
        );
        assert!(CUSTOM_BUILD.code_hash(NETWORK, b"not wasm").is_err());
    }

    /// The embedded tree lists every file that the Custom wallet contract compiles from.
    #[test]
    fn the_build_tree_holds_the_contract_sources_of_this_revision() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut expected = vec![
            "Cargo.toml".to_owned(),
            "Cargo.lock".into(),
            "rust-toolchain.toml".into(),
        ];
        fn walk(root: &Path, dir: &str, found: &mut Vec<String>) {
            for entry in std::fs::read_dir(root.join(dir)).unwrap() {
                let entry = entry.unwrap();
                let name = entry.file_name().into_string().unwrap();
                let path = format!("{dir}/{name}");
                if entry.file_type().unwrap().is_dir() {
                    if !matches!(name.as_str(), "target" | "test_snapshots") {
                        walk(root, &path, found);
                    }
                } else if name == "Cargo.toml"
                    || name.ends_with(".rs") && !name.ends_with("tests.rs")
                {
                    found.push(path);
                }
            }
        }
        for member in [
            "contracts/allowit-custom-policy",
            "crates/policy",
            "crates/policy-wallet",
            "crates/protocol",
        ] {
            walk(&root, member, &mut expected);
        }
        expected.retain(|path| path != POLICY_SOURCE);
        expected.sort();
        let mut embedded: Vec<String> = TREE.iter().map(|(path, _)| (*path).to_owned()).collect();
        embedded.sort();
        assert_eq!(embedded, expected);
        // Every workspace member has its manifest in the tree.
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let members = manifest
            .lines()
            .find(|line| line.starts_with("members = "))
            .unwrap();
        let listed: Vec<&str> = TREE
            .iter()
            .chain(OTHER_MEMBERS)
            .filter_map(|(path, _)| path.strip_suffix("/Cargo.toml"))
            .collect();
        let count = members.matches('"').count() / 2;
        assert_eq!(listed.len(), count, "{members}");
        for member in listed {
            assert!(members.contains(&format!("\"{member}\"")), "{member}");
        }
    }
}
