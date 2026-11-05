//! Supply the selected Core release's exact shared rule source to the native binding.
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo supplies OUT_DIR"));
    fs::write(out.join("core.rs"), allowit_common::SOURCE_CORE_RS)
        .expect("Write the common policy source to the Cargo output directory");
}
