use std::path::Path;

use lenso_contract_codegen::check_generated;

fn main() {
    println!("cargo:rerun-if-changed=capability.json");
    println!("cargo:rerun-if-changed=schemas");
    println!("cargo:rerun-if-changed=src/generated.rs");
    println!("cargo:rerun-if-changed=generated/bindings.ts");

    check_generated(
        Path::new("capability.json"),
        Path::new("src/generated.rs"),
        Path::new("generated/bindings.ts"),
    )
    .unwrap_or_else(|error| {
        panic!(
            "Secrets generated artifacts are stale: {error}. Run `cargo run -p lenso-contract-codegen -- generate capability.json src/generated.rs generated/bindings.ts`"
        )
    });
}
