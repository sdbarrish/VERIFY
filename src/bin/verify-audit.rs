//! Standalone independent auditor (white paper §6.3, §6.5).
//!
//! Usage: verify-audit <chain-export-file> [--expect-chain-id <hex>]
//!
//! Holds no keys and trusts no node. It decodes the export strictly, then
//! replays every block from genesis: hash links, leader schedule, proposer
//! signatures, quorum certificates, Merkle roots and every state transition.
//! Pass the chain id published by the election authority through a separate
//! channel; otherwise the auditor can only say the file is self-consistent.
//! Exit status: 0 verified, 1 verification failed, 2 usage or I/O error.

use std::process::ExitCode;
use verify_chain::crypto::hex;
use verify_chain::node::{audit, import_chain};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (path, expect) = match args.as_slice() {
        [p] => (p, None),
        [p, flag, id] if flag == "--expect-chain-id" => (p, Some(id.to_lowercase())),
        _ => {
            eprintln!("usage: verify-audit <chain-export-file> [--expect-chain-id <hex>]");
            return ExitCode::from(2);
        }
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let (genesis, chain) = match import_chain(&bytes) {
        Ok(v) => v,
        Err(e) => {
            println!("FAILED  {e}");
            return ExitCode::from(1);
        }
    };
    let chain_id = hex(&genesis.chain_id());
    println!("export     {path} ({} bytes)", bytes.len());
    println!("network    {}", genesis.network);
    println!("chain id   {chain_id}");
    match &expect {
        Some(want) if want != &chain_id => {
            println!("FAILED  chain id does not match the published value {want}");
            return ExitCode::from(1);
        }
        Some(_) => println!("           matches the published chain id"),
        None => println!(
            "           WARNING: no --expect-chain-id given; only self-consistency is checked"
        ),
    }
    match audit(&genesis, &chain) {
        Ok(r) => {
            println!(
                "VERIFIED   {} blocks, {} transactions",
                r.blocks, r.transactions
            );
            println!("state root {}", hex(&r.final_state_root));
            if r.exceptions.is_empty() {
                println!("findings   none");
            }
            for (h, m) in &r.exceptions {
                println!("finding    height {h}: {m}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("FAILED     {e}");
            ExitCode::from(1)
        }
    }
}
