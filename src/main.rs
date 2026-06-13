//! veil7 CLI — demo attestation interface.
//!
//! This is the only file in the crate that may print to stdout.
//! The engine library (all of `src/`) writes nothing; all output comes
//! from here — consistent with the `NO LOG` philosophy.
//!
//! Commands:
//!   sign <text>                Attest a string.
//!   sign-file <path>           Attest contents of a file (loads fully).
//!   sign-stream <path>         Attest contents of a file (chunked, no full load).
//!   chain <ev>...              Attest events as a tamper-evident chain.
//!   chain-root <ev>...         Compute the chain root only (no PQ, pure math).
//!   verify <hex> <ev>..        Verify events fold to a given root (no PQ).
//!   prove hash-preimage <hex>  Run the Lamport hash-preimage relation.
//!   prove merkle-root <hex>..  Compute Merkle root of a leaf set.
//!   prove merkle-include <hex_leaf> <hex_root> <index> <hex_sib>..
//!                             Verify a Merkle inclusion proof.
//!   prove ml-dsa <hex>         Run the ML-DSA-65 key-knowledge relation.
//!   help                       Show usage.

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "sign" => {
            let text = args.get(2).map(|s| s.as_str()).unwrap_or("");
            match veil7::interface::attest_text(text) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "sign-file" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("");
            match veil7::interface::attest_file(path) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "sign-stream" => {
            let path = args.get(2).map(|s| s.as_str()).unwrap_or("");
            match veil7::interface::attest_file_streaming(path) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "chain" => {
            // Each remaining argument is one event in the chain.
            let events: Vec<&[u8]> = args[2..].iter().map(|s| s.as_bytes()).collect();
            match veil7::interface::attest_chain(&events) {
                Ok(v) => match veil7::chain_root(&events) {
                    Ok(root) => println!(
                        "root={} valid={} transcript={}",
                        hex(&root),
                        v.is_valid_bool() as u8,
                        hex(v.transcript())
                    ),
                    Err(_) => println!("valid=0 transcript=-"),
                },
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "chain-root" => {
            // Pure math: compute chain root, no PQ, no entropy. Symmetric to
            // `chain` (attest) and `verify` (check). For auditors who want
            // the root without re-running the full pipeline.
            let events: Vec<&[u8]> = args[2..].iter().map(|s| s.as_bytes()).collect();
            match veil7::chain_root(&events) {
                Ok(root) => println!("root={}", hex(&root)),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "verify" => {
            // First arg = expected root as 64 hex chars; rest = events.
            // No PQ, no entropy — pure SHAKE256 chain framing check.
            // Universal verification: any holder of the events + the root
            // can audit without the engine, without keys, without side
            // effects. Here we use the engine for convenience.
            let hex_root = args.get(2).map(|s| s.as_str()).unwrap_or("");
            let events: Vec<&[u8]> = args[3..].iter().map(|s| s.as_bytes()).collect();
            let expected = match parse_hex_root(hex_root) {
                Some(r) => r,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let valid = veil7::chain_verify(&events, &expected);
            if valid.unwrap_u8() == 1 {
                println!("valid=1 transcript={}", hex_root);
            } else {
                // On mismatch, print the actual root so the auditor can see
                // what the events actually hash to. No secret material in
                // the output: the root is public.
                match veil7::chain_root(&events) {
                    Ok(actual) => println!("valid=0 transcript={}", hex(&actual)),
                    Err(_) => println!("valid=0 transcript=-"),
                }
            }
        }
        "prove" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("");
            run_prove(sub, &args[3..]);
        }
        "help" => print_help(),
        _ => print_help(),
    }
}

/// Dispatch the universal-verification subcommand.
fn run_prove(relation: &str, rest: &[String]) {
    match relation {
        "hash-preimage" => {
            // Argument: 64-char hex seed (32 bytes). Run the relation,
            // return the engine verdict bound to the derived Lamport pk.
            let hex_seed = rest.first().map(|s| s.as_str()).unwrap_or("");
            let seed = match parse_hex_root(hex_seed) {
                Some(s) => s,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let witness = veil7::relations::hash_preimage::Witness { seed };
            match veil7::prove_and_verify::<veil7::relations::hash_preimage::HashPreimage>(
                &witness, b"",
            ) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "merkle-root" => {
            // Arguments: each remaining arg is one leaf as hex bytes
            // (variable length). Compute the Merkle root of the leaf set.
            let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(rest.len());
            for arg in rest {
                match hex_decode(arg) {
                    Some(b) => leaves.push(b),
                    None => {
                        println!("valid=0 transcript=-");
                        return;
                    }
                }
            }
            if leaves.is_empty() {
                println!("valid=0 transcript=-");
                return;
            }
            let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
            match veil7::merkle_root(&refs) {
                Ok(root) => println!("root={}", hex(&root)),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "merkle-include" => {
            // Arguments: <hex_leaf> <hex_root> <index> <hex_sib1> [<hex_sib2>..]
            // Verifier side of the Merkle inclusion relation.
            if rest.len() < 3 {
                println!("valid=0 transcript=-");
                return;
            }
            let leaf = match parse_hex_root(&rest[0]) {
                Some(l) => l,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let root = match parse_hex_root(&rest[1]) {
                Some(r) => r,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let index: usize = match rest[2].parse() {
                Ok(i) => i,
                Err(_) => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let mut siblings: Vec<[u8; 32]> = Vec::with_capacity(rest.len() - 3);
            for sib_hex in &rest[3..] {
                match parse_hex_root(sib_hex) {
                    Some(s) => siblings.push(s),
                    None => {
                        println!("valid=0 transcript=-");
                        return;
                    }
                }
            }
            // We don't know leaf_count from the proof alone (it's part of
            // the public statement). Recover it from the sibling count:
            // a tree with n leaves has ceil(log2(n)) levels in its path,
            // and the number of siblings = number of consumed levels.
            // Reconstruct n_min = 2^siblings, then allow odd-tree bumping.
            let leaf_count = if siblings.is_empty() {
                1
            } else {
                1usize << siblings.len()
            };
            let ok = veil7::merkle_verify_path(&leaf, &root, index, &siblings, leaf_count);
            if ok.unwrap_u8() == 1 {
                println!("valid=1 transcript={}", hex(&root));
            } else {
                println!("valid=0 transcript={}", hex(&root));
            }
        }
        "ml-dsa" => {
            // Argument: 64-char hex seed (32 bytes). Run the ML-DSA-65
            // key-knowledge relation.
            let hex_seed = rest.first().map(|s| s.as_str()).unwrap_or("");
            let seed = match parse_hex_root(hex_seed) {
                Some(s) => s,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let witness = veil7::relations::ml_dsa::Witness { seed };
            match veil7::prove_and_verify::<veil7::relations::ml_dsa::MlDsaKnowledge>(&witness, b"")
            {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        _ => print_help(),
    }
}

fn print_verdict(v: &veil7::Verdict) {
    let valid = v.is_valid_bool() as u8;
    let tx = hex(v.transcript());
    println!("valid={} transcript={}", valid, tx);
}

fn hex(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in b.iter() {
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0x0f) as usize] as char);
    }
    s
}

/// Decode a hex string of any length into bytes.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..(s.len() / 2) {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

/// Parse a 64-char lowercase/uppercase hex string into a 32-byte root.
/// Returns `None` on length mismatch or non-hex characters — the caller
/// surfaces this as `valid=0` (no panic, no log).
fn parse_hex_root(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[2 * i])?;
        let lo = hex_nibble(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

#[inline]
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn print_help() {
    eprintln!("veil7 — stateless post-quantum attestation");
    eprintln!("Usage:");
    eprintln!("  sign <text>                       Attest a string");
    eprintln!("  sign-file <path>                  Attest a file (loads fully)");
    eprintln!("  sign-stream <path>                Attest a file (chunked, no full load)");
    eprintln!("  chain <ev> [<ev>..]               Attest events as a tamper-evident chain");
    eprintln!("  chain-root <ev> [<ev>..]          Compute chain root only (pure math)");
    eprintln!("  verify <hex> <ev>..               Verify events fold to a 32-byte hex root");
    eprintln!("  prove hash-preimage <hex>         Run Lamport hash-preimage relation");
    eprintln!("  prove merkle-root <hex>..         Compute Merkle root of a leaf set");
    eprintln!("  prove merkle-include <leaf> <root> <index> <sib>..");
    eprintln!("                                    Verify a Merkle inclusion proof");
    eprintln!("  prove ml-dsa <hex>                Run ML-DSA-65 key-knowledge relation");
    eprintln!("  help                              Show this help");
}
