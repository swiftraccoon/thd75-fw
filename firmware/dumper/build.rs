//! Build script — emits the linker-script path as a rustc link-arg.
//!
//! Cargo runs this before `cargo build` and lets us pass per-crate
//! linker arguments. The shared `linker.ld` lives one directory up at
//! `firmware/linker.ld`. The path must be absolute because the
//! linker's working directory is not the crate's manifest dir.

use std::path::PathBuf;

fn main() {
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is always set by cargo");
    let linker_script = PathBuf::from(manifest_dir)
        .parent()
        .expect("manifest dir always has a parent")
        .join("linker.ld");
    let path_display = linker_script.display();
    println!("cargo:rustc-link-arg=-T{path_display}");
    println!("cargo:rerun-if-changed={path_display}");
}
