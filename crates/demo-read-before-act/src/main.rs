//! `demo-read-before-act up | record | vectors | explain`
//!
//! - `up [--port 7400] [--sim http://127.0.0.1:7878/mcp]`: the cells and the page on 127.0.0.1.
//! - `record`: rewrite `proof/transcript.json` and `proof/transcript.txt` (the scripted story).
//! - `vectors`: rewrite `proof/vectors.json` (the golden vectors).
//! - `explain`: print the chain of the scripted story as `ce-cal explain` reads it.

use std::path::PathBuf;

use demo_read_before_act::{explain_text, server, story, transcript_text, vectors};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn write(rel: &str, text: &str) -> Result<(), String> {
    let p = root().join(rel);
    std::fs::write(&p, text).map_err(|e| format!("{}: {e}", p.display()))?;
    println!("wrote {rel}");
    Ok(())
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("up") => {
            let port = arg(&args, "--port").map(|p| p.parse().map_err(|_| "--port takes a number".to_string())).transpose()?.unwrap_or(7400);
            let sim = arg(&args, "--sim").unwrap_or_else(|| "http://127.0.0.1:7878/mcp".into());
            server::up(port, &sim)
        }
        Some("record") => {
            let t = story()?;
            write("proof/transcript.json", &(serde_json::to_string_pretty(&t).unwrap() + "\n"))?;
            write("proof/transcript.txt", &transcript_text(&t))
        }
        Some("vectors") => write("proof/vectors.json", &(serde_json::to_string_pretty(&vectors()?).unwrap() + "\n")),
        Some("explain") => {
            let t = story()?;
            print!("{}", explain_text(t["token"].as_str().unwrap_or_default())?);
            Ok(())
        }
        _ => Err("usage: demo-read-before-act up [--port 7400] [--sim http://127.0.0.1:7878/mcp] | record | vectors | explain".into()),
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
