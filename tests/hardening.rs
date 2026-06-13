//! Hardening regression guards.
//!
//! These tests enforce source-level invariants that should fail loudly if future
//! edits weaken Phase-1 side-channel hygiene.

use std::fs;
use std::path::{Path, PathBuf};

use subtle::Choice;
use veil7::l2_keygen::EphemeralKeys;
use veil7::l4_prove::Proof as L4Proof;
use veil7::l5_verify::{MlDsaVerifier, Verifier};
use veil7::pq_backends::slh_dsa::{PublicKey, SignatureBytes, SlhDsaSigner};
use veil7::relations::{
    hash_preimage::HashPreimage, merkle::MerkleInclusion, ml_dsa::MlDsaKnowledge, Relation,
};
use veil7::VeilError;

const SECRET_ARITHMETIC_PATHS: &[&str] = &[
    "src/layers/l1_entropy.rs",
    "src/layers/l2_keygen.rs",
    "src/layers/l4_prove.rs",
    "src/layers/l5_verify.rs",
    "src/pq_backends/slh_dsa.rs",
    "src/storage/oram.rs",
    "src/execution/vm.rs",
];

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn rust_sources_under(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![path.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).expect("source directory is readable") {
            let entry = entry.expect("source entry is readable");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    files.sort();
    files
}

fn read_source(path: &Path) -> String {
    fs::read_to_string(path).expect("source file is UTF-8")
}

fn display_path(path: &Path) -> String {
    path.strip_prefix(manifest_dir())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn code_before_line_comment(line: &str) -> &str {
    line.split("//").next().unwrap_or("")
}

#[test]
fn verification_public_boundaries_return_choice() {
    fn accepts_choice(_: Choice) {}

    let sig: SignatureBytes = [0u8; veil7::pq_backends::slh_dsa::SIGNATURE_LEN];
    let pk: PublicKey = [0u8; veil7::pq_backends::slh_dsa::PUBLIC_KEY_LEN];
    accepts_choice(SlhDsaSigner::verify(b"", &sig, &pk));

    fn assert_relation<R: Relation>() {
        let _: fn(&R::Statement, &R::Proof) -> Result<Choice, VeilError> = R::verify;
    }
    assert_relation::<HashPreimage>();
    assert_relation::<MerkleInclusion>();
    assert_relation::<MlDsaKnowledge>();

    fn assert_verifier<V: Verifier>() {
        let _: fn(&EphemeralKeys, &[u8], &L4Proof) -> Result<Choice, VeilError> = V::verify;
    }
    assert_verifier::<MlDsaVerifier>();
}

#[test]
fn source_has_no_direct_zeroize_or_bool_verify() {
    for path in rust_sources_under(&manifest_dir().join("src")) {
        let src = read_source(&path);
        let display = display_path(&path);

        assert!(
            !src.contains(".zeroize()"),
            "{display} uses direct zeroize(); use volatile zeroize helpers"
        );
        assert!(
            !src.contains("use zeroize::Zeroize"),
            "{display} imports Zeroize directly; route custom wipes through L0 helpers"
        );
        for line in src.lines() {
            assert!(
                !(line.contains("fn verify") && line.contains("-> bool")),
                "{display} has bool-returning verify API: {line}"
            );
        }
    }
}

#[test]
fn unsafe_code_is_confined_to_l0_memlock() {
    for path in rust_sources_under(&manifest_dir().join("src")) {
        let display = display_path(&path);
        let src = read_source(&path);
        if display == "src/layers/l0_memlock.rs" {
            continue;
        }

        for (idx, line) in src.lines().enumerate() {
            let code = code_before_line_comment(line);
            let has_unsafe_construct = code.contains("unsafe {")
                || code.contains("unsafe{")
                || code.contains("unsafe fn")
                || code.contains("unsafe impl")
                || code.contains("unsafe trait")
                || code.contains("unsafe extern")
                || code.contains("#![allow(unsafe_code)]");
            assert!(
                !has_unsafe_construct,
                "{display}:{} contains unsafe; only src/layers/l0_memlock.rs may use it",
                idx + 1
            );
        }
    }
}

#[test]
fn custom_drop_impls_are_inline_never() {
    for path in rust_sources_under(&manifest_dir().join("src")) {
        let src = read_source(&path);
        let display = display_path(&path);
        let mut previous = "";
        for line in src.lines() {
            if line.trim_start().starts_with("fn drop(&mut self)") {
                assert_eq!(
                    previous.trim(),
                    "#[inline(never)]",
                    "{display} has Drop impl without #[inline(never)]"
                );
            }
            previous = line;
        }
    }
}

#[test]
fn veil7_secret_paths_have_no_div_or_rem_operators() {
    for relative in SECRET_ARITHMETIC_PATHS {
        let path = manifest_dir().join(relative);
        let src = read_source(&path);

        for (idx, line) in src.lines().enumerate() {
            let code = code_before_line_comment(line);
            let compact: String = code.chars().filter(|c| !c.is_whitespace()).collect();
            assert!(
                !(compact.contains('/')
                    || compact.contains('%')
                    || compact.contains(".div_")
                    || compact.contains(".rem_")),
                "{relative}:{} contains division/remainder-like syntax in a secret path: {line}",
                idx + 1
            );
        }
    }
}
