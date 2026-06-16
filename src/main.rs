// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! veil7 CLI — the only file that may print.
//!
//! All library code is silent; output comes only from here.
//!
//! Subcommands: sign | sign-file | sign-stream | chain | chain-root | verify | prove | help

use std::env;

/// Maximum file size for sign-file / sign-stream (100 MB).
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Blocked path prefixes for sign-file / sign-stream.
const BLOCKED_PREFIXES: &[&str] = &["/proc/", "/dev/", "/proc", "/dev"];

fn main() {
    // Install custom panic hook: print only valid=0 then abort.
    // Prevents leaking source paths, line numbers, or internal state.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("valid=0 transcript=-");
    }));

    // Use args_os() to handle non-UTF8 arguments gracefully.
    let args_os: Vec<std::ffi::OsString> = env::args_os().collect();

    if args_os.len() < 2 {
        print_help();
        return;
    }

    let cmd = args_os[1].to_string_lossy().to_string();

    match cmd.as_str() {
        "sign" => {
            let text = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            match veil7::interface::attest_text(&text) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "sign-file" => {
            let path = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if is_blocked_path(&path) {
                println!("valid=0 transcript=-");
                return;
            }
            if is_file_too_large(&path) {
                println!("valid=0 transcript=-");
                return;
            }
            match veil7::interface::attest_file(&path) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "sign-stream" => {
            let path = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            if is_blocked_path(&path) {
                println!("valid=0 transcript=-");
                return;
            }
            if is_file_too_large(&path) {
                println!("valid=0 transcript=-");
                return;
            }
            match veil7::interface::attest_file_streaming(&path) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "chain" => {
            let owned_events: Vec<Vec<u8>> = args_os
                .get(2..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.to_string_lossy().as_bytes().to_vec())
                .collect();
            let event_refs: Vec<&[u8]> = owned_events.iter().map(|v| v.as_slice()).collect();
            match veil7::interface::attest_chain(&event_refs) {
                Ok(v) => match veil7::chain_root(&event_refs) {
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
            let owned_events: Vec<Vec<u8>> = args_os
                .get(2..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.to_string_lossy().as_bytes().to_vec())
                .collect();
            let event_refs: Vec<&[u8]> = owned_events.iter().map(|v| v.as_slice()).collect();
            match veil7::chain_root(&event_refs) {
                Ok(root) => println!("root={}", hex(&root)),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "verify" => {
            let hex_root = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let owned_events: Vec<Vec<u8>> = args_os
                .get(3..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.to_string_lossy().as_bytes().to_vec())
                .collect();
            let event_refs: Vec<&[u8]> = owned_events.iter().map(|v| v.as_slice()).collect();
            let expected = match parse_hex_root(&hex_root) {
                Some(r) => r,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let valid = veil7::chain_verify(&event_refs, &expected);
            if valid.unwrap_u8() == 1 {
                println!("valid=1 transcript={}", hex_root);
            } else {
                match veil7::chain_root(&event_refs) {
                    Ok(actual) => println!("valid=0 transcript={}", hex(&actual)),
                    Err(_) => println!("valid=0 transcript=-"),
                }
            }
        }
        "prove" => {
            let sub = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let rest: Vec<String> = args_os
                .get(3..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            run_prove(&sub, &rest);
        }
        "batch-sign" => {
            let owned_args: Vec<Vec<u8>> = args_os
                .get(2..)
                .unwrap_or(&[])
                .iter()
                .map(|s| s.to_string_lossy().as_bytes().to_vec())
                .collect();
            let claims: Vec<veil7::Claim<'_>> =
                owned_args.iter().map(|s| veil7::Claim::new(s)).collect();
            if claims.is_empty() {
                println!("valid=0 transcript=-");
                return;
            }
            match veil7::verify_batch(&claims) {
                Ok(v) => {
                    let valid = v.is_valid_bool() as u8;
                    let tx = hex(v.transcript());
                    println!("valid={} transcript={} count={}", valid, tx, claims.len());
                }
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "blind-sign" => {
            let text = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            match veil7::blind::blind_attest(text.as_bytes()) {
                Ok((v, unblinded)) => {
                    let valid = v.is_valid_bool() as u8;
                    println!(
                        "valid={} transcript={} unblinded={}",
                        valid,
                        hex(v.transcript()),
                        hex(&unblinded)
                    );
                }
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "threshold" => {
            let n: usize = args_os
                .get(2)
                .and_then(|s| s.to_string_lossy().parse().ok())
                .unwrap_or(0);
            let m: usize = args_os
                .get(3)
                .and_then(|s| s.to_string_lossy().parse().ok())
                .unwrap_or(0);
            let text = args_os
                .get(4)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let claim = veil7::Claim::new(text.as_bytes());
            match veil7::threshold::threshold_verify(&claim, n, m) {
                Ok(v) => {
                    let valid = v.is_valid_bool() as u8;
                    println!(
                        "valid={} transcript={} n={} m={}",
                        valid,
                        hex(v.transcript()),
                        n,
                        m
                    );
                }
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "hybrid-sign" => {
            let text = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let claim = veil7::Claim::new(text.as_bytes());
            match veil7::hybrid::hybrid_attest(&claim) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "vm-execute" => {
            let hex_code = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            match hex_decode(&hex_code) {
                Some(code) => {
                    let mut vm = veil7::execution::MicroVM::new();
                    let root = vm.execute(&code);
                    if root == [0u8; 64] {
                        println!("valid=0 transcript=-");
                    } else {
                        println!("valid=1 root={}", hex64(&root));
                    }
                }
                None => println!("valid=0 transcript=-"),
            }
        }
        "chain-entry" => {
            // chain-entry <event> [prev_transcript_hex]
            let event = args_os
                .get(2)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let prev_hex = args_os
                .get(3)
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let prev = if prev_hex.is_empty() {
                None
            } else {
                parse_hex_root(&prev_hex)
            };
            let prev_ref = prev.as_ref();
            match veil7::interface::attest_chain_entry(event.as_bytes(), prev_ref) {
                Ok(v) => {
                    let valid = v.is_valid_bool() as u8;
                    let tx = hex(v.transcript());
                    println!("valid={} transcript={}", valid, tx);
                }
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "help" => print_help(),
        _ => print_help(),
    }
}

/// Check if a file path is blocked (e.g. /proc, /dev).
fn is_blocked_path(path: &str) -> bool {
    for prefix in BLOCKED_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Check if a file exceeds the maximum file size limit.
fn is_file_too_large(path: &str) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.len() > MAX_FILE_SIZE,
        Err(_) => false, // Let the actual read fail with a proper error
    }
}

/// Dispatch the universal-verification subcommand.
fn run_prove(relation: &str, rest: &[String]) {
    match relation {
        "hash-preimage" => {
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
        "pedersen" => {
            let hex_value = rest.first().map(|s| s.as_str()).unwrap_or("");
            let hex_blinding = rest.get(1).map(|s| s.as_str()).unwrap_or("");
            let value = match parse_hex_root(hex_value) {
                Some(v) => v,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let blinding = match parse_hex_root(hex_blinding) {
                Some(b) => b,
                None => {
                    println!("valid=0 transcript=-");
                    return;
                }
            };
            let witness = veil7::relations::pedersen::Witness { value, blinding };
            match veil7::prove_and_verify::<veil7::relations::pedersen::PedersenCommitment>(
                &witness, b"",
            ) {
                Ok(v) => print_verdict(&v),
                Err(_) => println!("valid=0 transcript=-"),
            }
        }
        "range-proof" => {
            let value: u64 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let min: u64 = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let max: u64 = rest.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let witness = veil7::relations::range_proof::Witness { value, min, max };
            match veil7::prove_and_verify::<veil7::relations::range_proof::RangeProof>(
                &witness, b"",
            ) {
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

/// Encode a 64-byte array as 128 hex chars.
fn hex64(b: &[u8; 64]) -> String {
    let mut s = String::with_capacity(128);
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

/// Parse a 64-char hex string into a 32-byte array.
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
    eprintln!("veil7");
    eprintln!("sign <text> | sign-file <path> | sign-stream <path>");
    eprintln!("blind-sign <text> | hybrid-sign <text>");
    eprintln!("batch-sign <t1> <t2>.. | threshold <n> <m> <text>");
    eprintln!(
        "chain <ev>.. | chain-root <ev>.. | chain-entry <ev> [prev_hex] | verify <hex> <ev>.."
    );
    eprintln!("vm-execute <hex>");
    eprintln!(
        "prove hash-preimage | ml-dsa | pedersen | range-proof | merkle-root | merkle-include"
    );
    eprintln!("help");
}
