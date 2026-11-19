//! The "build custom wallet" hook: build the `AllowitCustomPolicy` Wasm from the exact policy
//! source with the Stellar CLI and the Rust toolchain, and hash wallet code. The server builds
//! and uploads the code; an owner's client that builds the same source gets the same hash.
//!
//! The build tree is the contract workspace of this release, embedded in the crate. The on-chain
//! part of the policy source, which Core derives, takes the place of
//! `contracts/allowit-custom-policy/policy/policy.rs`. When that part differs from the source,
//! the source goes to `policy/source.rs`, and the contract embeds its hash. The build compiles
//! the same files as `scripts/build-custom-policy.sh` does from a checkout of this revision, so
//! the same source, toolchain and Stellar CLI give the same Wasm.
use crate::host::error::{Error, Result};
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
/// The folder of the build tree that holds the build inputs of the owner's policy source
/// ([`crate::policy::custom_build_inputs`]): the on-chain part that the contract compiles
/// (`policy.rs`), the keys of its figures (`policy.figures`), the state keys that the contract
/// keeps (`policy.state`) and, when the part differs from the source, the source (`source.rs`),
/// whose hash the contract embeds.
const POLICY_DIR: &str = "contracts/allowit-custom-policy/policy";
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
    "contracts/allowit-custom-policy/src/catching_policy.figures",
    "contracts/allowit-custom-policy/src/catching_policy.rs",
    "contracts/allowit-custom-policy/src/catching_policy.state",
    "contracts/allowit-custom-policy/src/daily_policy.figures",
    "contracts/allowit-custom-policy/src/daily_policy.rs",
    "contracts/allowit-custom-policy/src/daily_policy.state",
    "contracts/allowit-custom-policy/src/lib.rs",
    "contracts/allowit-custom-policy/state_keys.rs",
    "crates/policy/Cargo.toml",
    "crates/policy/build.rs",
    "crates/policy/src/lib.rs",
    "crates/policy-wallet/Cargo.toml",
    "crates/policy-wallet/src/lib.rs",
    "crates/policy-wallet/src/ops.rs",
    "crates/policy-wallet/src/pack.rs",
    "crates/protocol/Cargo.toml",
    "crates/protocol/src/lib.rs",
];
/// The other members of the contract workspace. Cargo reads their manifests to load the
/// workspace and its lock file; the build compiles none of them, so each gets an empty library.
static OTHER_MEMBERS: &[(&str, &[u8])] = tree![
    "contracts/allowit-common-policy-engine/Cargo.toml",
    "contracts/allowit-deployer/Cargo.toml",
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

/// Write the build tree under `tree`, which must not exist, with the build inputs of the owner's
/// source (`inputs`, from [`crate::policy::custom_build_inputs`]).
fn write_tree(tree: &Path, inputs: &[(&str, Vec<u8>)]) -> Result<()> {
    for (path, bytes) in TREE {
        write(&tree.join(path), bytes)?;
    }
    for (manifest, bytes) in OTHER_MEMBERS {
        let manifest = tree.join(manifest);
        write(&manifest, bytes)?;
        write(&manifest.with_file_name("src").join("lib.rs"), b"")?;
    }
    for (name, bytes) in inputs {
        write(&tree.join(POLICY_DIR).join(name), bytes)?;
    }
    Ok(())
}

/// The build inputs of `source` for a Custom wallet, or the refusal of a source that the wallet
/// cannot hold: one over the build's size limit, or one whose on-chain part does not pass the
/// portable gate, the build's text check or the wallet's storage of state keys (at most eight,
/// each with its own storage key). The build and [`CustomWalletBuild::check`] make these checks
/// alike; only the build compiles the part.
fn checked_inputs(source: &str) -> Result<Vec<crate::policy::BuildInput>> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Error::usage(
            "The policy source exceeds the custom wallet build limit",
        ));
    }
    // The contract compiles the on-chain part of the source as a module. Core derives that part,
    // so every client builds the same code from the same source. Only source that passes the
    // portable policy gate is compiled: it cannot include a local file or run code at compile
    // time.
    let (_, inputs) = crate::policy::custom_build_inputs(source).map_err(|reason| {
        build_failed(format!(
            "The policy source does not pass the policy source gate: {reason}. Draft the policy again."
        ))
    })?;
    Ok(inputs)
}

/// Build the Custom wallet Wasm of `source` with the Stellar CLI binary `stellar`.
pub(crate) fn build_with(stellar: &Path, source: &str, work: &Path) -> Result<WalletCode> {
    let inputs = checked_inputs(source)?;
    let unusable = || Error::config("Cannot prepare the custom wallet build folder");
    std::fs::create_dir_all(work).map_err(|_| unusable())?;
    let work = work.canonicalize().map_err(|_| unusable())?;
    let (tree, out) = (work.join("tree"), work.join("out"));
    for stale in [&tree, &out] {
        if stale.exists() {
            std::fs::remove_dir_all(stale).map_err(|_| unusable())?;
        }
    }
    write_tree(&tree, &inputs)?;
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
    /// The build's own checks of `source`, without the build: the size limit, the portable gate
    /// of the on-chain part, the build's text check of the compiled part and the wallet's storage
    /// of its state keys. It does not compile the part.
    fn check(&self, network: &str, source: &str) -> Result<()> {
        crate::host::routing::normalize(network)?;
        checked_inputs(source).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowit_core::vendor::custom_build::check_code_hash;

    const NETWORK: &str = "stellar:testnet";
    const SOURCE: &str =
        include_str!("../../../../contracts/allowit-custom-policy/policy/policy.rs");

    fn refused(error: Error) -> String {
        error.api_code.unwrap_or_default()
    }

    #[test]
    fn code_other_than_the_clients_build_is_refused() {
        let code = fixture_wallet_code();
        let built = CUSTOM_BUILD.code_hash(NETWORK, &code).unwrap();
        check_code_hash(&built, &crate::hash(&code)).unwrap();
        assert_eq!(
            refused(check_code_hash(&built, &[8; 32]).unwrap_err()),
            code::CODE_HASH_MISMATCH
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

    /// The hook's check refuses what the build refuses, without building: here nine state keys
    /// that the contract would keep, one more than its storage takes. Keys that the server keeps
    /// do not count. A source that the wallet can hold passes.
    #[test]
    fn the_check_refuses_what_the_build_refuses() {
        assert!(CUSTOM_BUILD.check(NETWORK, SOURCE).is_ok());
        let writes: String = (1..=9)
            .map(|i| format!("    allowit::set_state(ctx, \"k{i}\", ctx.request.amount)?;\n"))
            .collect();
        let nine = format!(
            "use allowit::prelude::*;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {{\n{writes}    allowit::new_decision_context(ctx, None)?;\n    Ok(())\n}}\n"
        );
        let error = CUSTOM_BUILD.check(NETWORK, &nine).unwrap_err();
        assert!(error.to_string().contains("at most 8"), "{error}");
        // The build's text check of the compiled part: a comment that names `unsafe` in it is
        // refused before the build, as the build refuses it.
        let unsafe_comment = SOURCE.replacen(
            "pub fn execute",
            "// Reject unsafe payments.\npub fn execute",
            1,
        );
        assert_ne!(unsafe_comment, SOURCE);
        let error = CUSTOM_BUILD.check(NETWORK, &unsafe_comment).unwrap_err();
        assert!(error.to_string().contains("`unsafe`"), "{error}");
        assert!(CUSTOM_BUILD.check("bitcoin:mainnet", SOURCE).is_err());
    }

    /// A source with a server part: the contract compiles its on-chain part, and the tree holds
    /// the owner's source beside it, whose hash the contract embeds, with the figures and the
    /// state keys that Core names for the part. A source without a server part is the one file.
    #[test]
    fn the_build_tree_holds_the_on_chain_part_and_the_owners_source() {
        const ONE: &str = "use allowit::prelude::*;\nuse allowit::AllowitDecision;\npub fn execute(ctx: &AllowitContext) -> allowit::Result {\n    allowit::payment_limit(ctx, &ctx.params[allowit::PAYMENT_LIMIT])?;\n    let visits: u64 = allowit::get_state(ctx, \"visits\")?.unwrap_or(0);\n    allowit::set_state(ctx, \"visits\", visits + 1)?;\n    let score = allowit::decision(ctx, &AllowitDecision { id: \"research\", query: \"Is this payment for research?\", deny_below: 3000, allow_above: 8000 })?;\n    allowit::set_state(ctx, \"last_score\", score)?;\n    Ok(())\n}\n";
        let work = tempfile::tempdir().unwrap();
        let read =
            |tree: &Path, name: &str| std::fs::read_to_string(tree.join(POLICY_DIR).join(name));
        let (parts, inputs) = crate::policy::custom_build_inputs(ONE).unwrap();
        assert!(parts.server_part);
        let tree = work.path().join("one");
        write_tree(&tree, &inputs).unwrap();
        let compiled = read(&tree, "policy.rs").unwrap();
        assert_eq!(compiled, parts.onchain);
        assert!(compiled.contains("\"visits\"") && !compiled.contains("decision"));
        assert!(!compiled.contains("last_score"));
        // Core names no figure for this on-chain part, and gives the chain the key "visits".
        assert_eq!(read(&tree, "policy.figures").unwrap(), "");
        assert_eq!(read(&tree, "policy.state").unwrap(), "visits lasting\n");
        assert_eq!(read(&tree, "source.rs").unwrap(), ONE);
        let plain = work.path().join("plain");
        let (parts, inputs) = crate::policy::custom_build_inputs(SOURCE).unwrap();
        write_tree(&plain, &inputs).unwrap();
        assert_eq!(read(&plain, "policy.rs").unwrap(), SOURCE);
        let figures: String = parts.figures.iter().map(|key| format!("{key}\n")).collect();
        assert_eq!(read(&plain, "policy.figures").unwrap(), figures);
        assert!(read(&plain, "source.rs").is_err());
    }

    /// The committed build inputs of the contract's own policy and of its fixtures are those that
    /// Core's derivation gives each source.
    #[test]
    fn the_committed_build_inputs_are_those_that_core_names() {
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/allowit-custom-policy");
        for stem in ["policy/policy", "src/catching_policy", "src/daily_policy"] {
            let source = std::fs::read_to_string(root.join(format!("{stem}.rs"))).unwrap();
            let (parts, inputs) = crate::policy::custom_build_inputs(&source).unwrap();
            assert!(!parts.server_part, "{stem}");
            for (name, bytes) in inputs {
                let ext = name.rsplit('.').next().unwrap();
                let committed = std::fs::read(root.join(format!("{stem}.{ext}"))).unwrap();
                assert_eq!(committed, bytes, "{stem}.{ext}");
            }
        }
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
                    || name.ends_with(".figures")
                    || name.ends_with(".state")
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
        // The committed tree's own build inputs: the build writes each of them again from the
        // owner's source.
        const POLICY_INPUTS: [&str; 3] = ["policy.rs", "policy.figures", "policy.state"];
        expected.retain(|path| {
            !POLICY_INPUTS
                .iter()
                .any(|name| *path == format!("{POLICY_DIR}/{name}"))
        });
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
