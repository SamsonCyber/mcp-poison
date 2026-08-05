use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use mcpdoctor::client::Framing;
use mcpdoctor::pin::{load_store, make_pins, save_store, upsert_pin};
use mcpdoctor::report::ScanReport;
use mcpdoctor::scan::{
    check_against_pins, scan_from_tools_list, scan_multi_lists, scan_stdio, ScanOptions,
};
use mcpdoctor::types::Severity;
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

const AFTER_HELP: &str = "\
Quick start:
  mcpdoctor tools.json                 scan one inventory (human summary)
  mcpdoctor a.json b.json              cross-server multi scan
  mcpdoctor scan -- python -m my_mcp   live stdio server after --
  mcpdoctor pin tools.json             save hashes after you reviewed them
  mcpdoctor check tools.json           fail if inventory drifted

Output:
  default     short human summary (CLEAN / FINDINGS)
  --json      full machine JSON on stdout
  -o file     write full JSON report to file
  --md file   write Markdown report to file

Aliases: doctor | audit  →  scan

Exit: 0 clean/ok · 2 findings ≥ --fail-on · 1 error
Hyphen args:  --arg=-m   or   scan -- python -m pkg
";

#[derive(Parser, Debug)]
#[command(
    name = "mcpdoctor",
    about = "MCPDoctor: lint MCP tool catalogs for poison + rugpulls",
    long_about = "Connect like an MCP client (or load a tools/list JSON), walk every \
schema string, emit findings. Non-mutating by default (no tools/call).",
    version,
    after_help = AFTER_HELP,
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log filter
    #[arg(long, global = true, default_value = "warn")]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a tools/list JSON or a live stdio MCP server
    #[command(visible_alias = "doctor", alias = "audit")]
    Scan {
        /// tools/list JSON path
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        /// Alias for LIST_JSON
        #[arg(long = "from-list", value_name = "PATH", hide = true)]
        from_list: Option<PathBuf>,

        /// Spawn stdio command (prefer: scan -- prog args)
        #[arg(long)]
        command: Option<String>,

        /// Args for --command (hyphen-safe: --arg=-m)
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,

        #[arg(long)]
        cwd: Option<String>,

        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        /// Write full JSON report to path
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        /// Write Markdown report to path
        #[arg(long)]
        md: Option<PathBuf>,

        /// Print full JSON to stdout (default is short human summary)
        #[arg(long)]
        json: bool,

        /// Print long Markdown to stdout
        #[arg(long)]
        markdown: bool,

        /// Treat server as trusted (skip D11 name-collision)
        #[arg(long)]
        trusted: bool,

        /// Exit 2 if severity >= this (info|low|medium|high|critical)
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Wire framing: ndjson (Python) or content-length (TS)
        #[arg(long, value_enum, default_value_t = FramingArg::Ndjson)]
        framing: FramingArg,

        /// Server argv after `--`
        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// Scan two+ tools/list files (cross-server shadow)
    Multi {
        #[arg(required = true, num_args = 2..)]
        lists: Vec<PathBuf>,

        #[arg(long)]
        trusted: bool,

        #[arg(long, default_value = "high")]
        fail_on: String,

        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        #[arg(long)]
        md: Option<PathBuf>,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        markdown: bool,
    },

    /// Pin inventory hashes after human review
    Pin {
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        #[arg(long = "from-list", value_name = "PATH", hide = true)]
        from_list: Option<PathBuf>,

        #[arg(long)]
        command: Option<String>,

        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,

        #[arg(long)]
        cwd: Option<String>,

        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        #[arg(long, default_value = ".mcpdoctor/pins.json")]
        store: PathBuf,

        /// Name for this server in the pin store
        #[arg(long, short = 'k', default_value = "default")]
        server_key: String,

        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// Fail if inventory drifted from pin store (CI gate)
    Check {
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        #[arg(long = "from-list", value_name = "PATH", hide = true)]
        from_list: Option<PathBuf>,

        #[arg(long)]
        command: Option<String>,

        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,

        #[arg(long)]
        cwd: Option<String>,

        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        #[arg(long, default_value = ".mcpdoctor/pins.json")]
        store: PathBuf,

        #[arg(long, short = 'k', default_value = "default")]
        server_key: String,

        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        #[arg(long, default_value = "high")]
        fail_on: String,

        #[arg(long)]
        trusted: bool,

        #[arg(long)]
        json: bool,

        #[arg(long)]
        markdown: bool,

        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// List detectors
    Detectors {
        #[arg(long, value_enum, default_value_t = OutFormat::Text)]
        format: OutFormat,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum OutFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum FramingArg {
    #[default]
    Ndjson,
    ContentLength,
}

impl From<FramingArg> for Framing {
    fn from(v: FramingArg) -> Self {
        match v {
            FramingArg::Ndjson => Framing::Ndjson,
            FramingArg::ContentLength => Framing::ContentLength,
        }
    }
}

fn looks_like_list_path(s: &str) -> bool {
    if s.starts_with('-') {
        return false;
    }
    s.ends_with(".json") || Path::new(s).is_file()
}

/// Rewrite argv into clap-friendly form:
///   tools.json              → scan tools.json
///   a.json b.json           → multi a.json b.json
///   doctor|audit …          → scan …
fn preprocess_argv(raw: Vec<String>) -> Vec<String> {
    if raw.len() < 2 {
        return raw;
    }
    let first = raw[1].as_str();
    const SUBS: &[&str] = &[
        "scan", "doctor", "audit", "multi", "pin", "check", "detectors", "help",
    ];

    // Alias doctor/audit already handled by clap once we pass them; leave them.
    if first.starts_with('-') || SUBS.contains(&first) {
        return raw;
    }

    // Collect leading list-like paths before first option/subcommand.
    let mut paths: Vec<String> = Vec::new();
    for arg in raw.iter().skip(1) {
        if arg.starts_with('-') {
            break;
        }
        if looks_like_list_path(arg) {
            paths.push(arg.clone());
        } else {
            break;
        }
    }
    if paths.is_empty() {
        return raw;
    }

    let rest: Vec<String> = raw.iter().skip(1 + paths.len()).cloned().collect();
    let mut out = vec![raw[0].clone()];
    if paths.len() >= 2 {
        out.push("multi".into());
        out.extend(paths);
    } else {
        out.push("scan".into());
        out.extend(paths);
    }
    out.extend(rest);
    out
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<ExitCode> {
    let argv = preprocess_argv(env::args().collect());
    let cli = Cli::parse_from(argv);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log))
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Scan {
            list,
            from_list,
            command,
            args,
            cwd,
            env,
            timeout_secs,
            out,
            md,
            json,
            markdown,
            trusted,
            fail_on,
            framing,
            server,
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                timeout: std::time::Duration::from_secs(timeout_secs),
                framing: framing.into(),
            };
            let (cmd, cmd_args) = resolve_target(command, args, server)?;
            let list_path = list.or(from_list);
            let report = run_scan(list_path, cmd, cmd_args, cwd, &parse_env(&env)?, &opts)?;
            emit_report(&report, out, md, json, markdown)?;
            Ok(exit_for_findings(&report, &fail_on)?)
        }
        Commands::Multi {
            lists,
            trusted,
            fail_on,
            out,
            md,
            json,
            markdown,
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                ..ScanOptions::default()
            };
            let pairs: Vec<(String, &Path)> = lists
                .iter()
                .enumerate()
                .map(|(i, p)| {
                    (
                        p.file_stem()
                            .and_then(|s| s.to_str())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("server{i}")),
                        p.as_path(),
                    )
                })
                .collect();
            let report = scan_multi_lists(&pairs, &opts)?;
            emit_report(&report, out, md, json, markdown)?;
            Ok(exit_for_findings(&report, &fail_on)?)
        }
        Commands::Pin {
            list,
            from_list,
            command,
            args,
            cwd,
            env,
            timeout_secs,
            store,
            server_key,
            server,
        } => {
            let opts = ScanOptions {
                untrusted: true,
                timeout: std::time::Duration::from_secs(timeout_secs),
                framing: Framing::Ndjson,
            };
            let (cmd, cmd_args) = resolve_target(command, args, server)?;
            let list_path = list.or(from_list);
            let report = run_scan(list_path, cmd, cmd_args, cwd, &parse_env(&env)?, &opts)?;
            let mut pin_store = load_store(&store)?;
            let pins = make_pins(
                &server_key,
                &report.tools,
                report.target.command.clone(),
                report.target.args.clone(),
                report.target.server_name.clone(),
            );
            upsert_pin(&mut pin_store, &server_key, pins);
            save_store(&store, &pin_store)?;
            eprintln!(
                "PINNED  key={server_key}  tools={}  hash={}  -> {}",
                report.summary.tools,
                report.summary.server_hash,
                store.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Check {
            list,
            from_list,
            command,
            args,
            cwd,
            env,
            timeout_secs,
            store,
            server_key,
            out,
            fail_on,
            trusted,
            json,
            markdown,
            server,
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                timeout: std::time::Duration::from_secs(timeout_secs),
                framing: Framing::Ndjson,
            };
            let envp = parse_env(&env)?;
            let (cmd, cmd_args) = resolve_target(command, args, server)?;
            let list_path = list.or(from_list);
            let base = run_scan(
                list_path,
                cmd.clone(),
                cmd_args.clone(),
                cwd,
                &envp,
                &opts,
            )?;
            let pin_store = load_store(&store)?;
            let Some(pins) = pin_store.servers.get(&server_key) else {
                bail!(
                    "no pin for server_key={server_key} in {}\n  tip: mcpdoctor pin <list.json> -k {server_key}",
                    store.display()
                );
            };
            let cmd_owned = cmd.or_else(|| base.target.command.clone());
            let arg_ref = if cmd_args.is_empty() {
                base.target.args.clone()
            } else {
                cmd_args
            };
            let tools = base.tools.clone();
            let report = check_against_pins(
                &tools,
                pins,
                cmd_owned.as_deref(),
                &arg_ref,
                base,
            );
            emit_report(&report, out, None, json, markdown)?;
            Ok(exit_for_findings(&report, &fail_on)?)
        }
        Commands::Detectors { format } => {
            let rows = detector_catalog();
            match format {
                OutFormat::Text => {
                    for (id, tech, title) in rows {
                        println!("{id}\t{tech}\t{title}");
                    }
                }
                OutFormat::Json => {
                    let v: Vec<_> = detector_catalog()
                        .into_iter()
                        .map(|(id, tech, title)| {
                            serde_json::json!({"detector": id, "technique": tech, "title": title})
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&v)?);
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn resolve_target(
    command: Option<String>,
    args: Vec<String>,
    server: Vec<String>,
) -> Result<(Option<String>, Vec<String>)> {
    if !server.is_empty() {
        if command.is_some() || !args.is_empty() {
            bail!("use either --command/--arg or trailing `-- prog args`, not both");
        }
        let mut it = server.into_iter();
        let cmd = it
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty server argv after --"))?;
        return Ok((Some(cmd), it.collect()));
    }
    Ok((command, args))
}

fn parse_env(pairs: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .with_context(|| format!("--env expects KEY=VALUE, got {p}"))?;
        if k.is_empty() {
            bail!("empty env key in {p}");
        }
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

fn run_scan(
    from_list: Option<PathBuf>,
    command: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
    env: &[(String, String)],
    opts: &ScanOptions,
) -> Result<ScanReport> {
    match (from_list, command) {
        (Some(path), None) => {
            let label = path.file_stem().and_then(|s| s.to_str());
            scan_from_tools_list(&path, opts, label)
        }
        (None, Some(cmd)) => scan_stdio(&cmd, &args, env, cwd.as_deref(), opts),
        (Some(_), Some(_)) => bail!("use either a tools-list JSON or a server command, not both"),
        (None, None) => bail!(
            "what should I scan?\n  \
             mcpdoctor tools.json\n  \
             mcpdoctor a.json b.json\n  \
             mcpdoctor scan -- python -m my_mcp"
        ),
    }
}

/// Human summary by default; --json / -o for full machine report.
fn emit_report(
    report: &ScanReport,
    out: Option<PathBuf>,
    md: Option<PathBuf>,
    json_stdout: bool,
    markdown_stdout: bool,
) -> Result<()> {
    if let Some(path) = &out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(path, &json).with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }
    if let Some(path) = &md {
        std::fs::write(path, report.to_markdown())
            .with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    if json_stdout {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else if markdown_stdout {
        print!("{}", report.to_markdown());
    } else {
        print!("{}", report.to_human());
    }
    Ok(())
}

fn exit_for_findings(report: &ScanReport, fail_on: &str) -> Result<ExitCode> {
    let threshold = Severity::parse_threshold(fail_on)
        .with_context(|| format!("invalid --fail-on {fail_on}"))?;
    if report.fails_threshold(threshold) {
        Ok(ExitCode::from(2))
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn detector_catalog() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("D01", "T1", "Instruction override language"),
        ("D02", "T1", "Exfil directive (secrets / network)"),
        ("D03", "T3", "Line-jump session mandates"),
        ("D04", "T4", "Cross-server shadow / conceal"),
        ("D05", "T4", "Whitespace hide"),
        ("D06", "T8", "ANSI concealment"),
        ("D07", "T8", "Unicode bidi / zero-width"),
        ("D08", "T6", "Param/tool name semantic exfil"),
        ("D09", "T12", "UI truncation bait"),
        ("D10", "T11", "Deferred sleeper trigger"),
        ("D11", "T1", "Trusted tool name collision"),
        ("D12", "T6", "Schema oddity"),
        ("D20", "T2", "Tool hash rugpull"),
        ("D21", "T2", "Server hash rugpull"),
        ("D22", "T2", "Command/args swap"),
        ("D23", "T2", "New tool appeared"),
        ("D24", "T2", "Pinned tool removed"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preprocess_inserts_scan_for_json_path() {
        let raw = vec![
            "mcpdoctor".into(),
            "fixtures/t3_line_jump.json".into(),
            "--trusted".into(),
        ];
        let out = preprocess_argv(raw);
        assert_eq!(out[1], "scan");
        assert_eq!(out[2], "fixtures/t3_line_jump.json");
        assert_eq!(out[3], "--trusted");
    }

    #[test]
    fn preprocess_multi_for_two_json_paths() {
        let raw = vec![
            "mcpdoctor".into(),
            "a.json".into(),
            "b.json".into(),
            "--trusted".into(),
        ];
        let out = preprocess_argv(raw);
        assert_eq!(out[1], "multi");
        assert_eq!(out[2], "a.json");
        assert_eq!(out[3], "b.json");
        assert_eq!(out[4], "--trusted");
    }

    #[test]
    fn preprocess_leaves_subcommands() {
        let raw = vec!["mcpdoctor".into(), "detectors".into()];
        let out = preprocess_argv(raw);
        assert_eq!(out[1], "detectors");
    }

    #[test]
    fn resolve_trailing_server_hyphen_args() {
        let (cmd, args) = resolve_target(
            None,
            vec![],
            vec![
                "python".into(),
                "-m".into(),
                "agent_tooling.sqlite_mcp".into(),
            ],
        )
        .unwrap();
        assert_eq!(cmd.as_deref(), Some("python"));
        assert_eq!(args, vec!["-m", "agent_tooling.sqlite_mcp"]);
    }

    #[test]
    fn parse_hyphen_arg_via_clap() {
        let argv = [
            "mcpdoctor",
            "scan",
            "--command",
            "python",
            "--arg=-m",
            "--arg",
            "agent_tooling.sqlite_mcp",
            "--timeout-secs",
            "5",
        ];
        let cli = Cli::parse_from(argv);
        match cli.command {
            Commands::Scan {
                command, args, ..
            } => {
                assert_eq!(command.as_deref(), Some("python"));
                assert_eq!(args, vec!["-m", "agent_tooling.sqlite_mcp"]);
            }
            _ => panic!("expected scan"),
        }
    }
}
