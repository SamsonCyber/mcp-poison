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
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

const AFTER_HELP: &str = "\
Examples:
  mcpdoctor fixtures/t3_line_jump.json
  mcpdoctor scan fixtures/clean_calculator.json --trusted
  mcpdoctor multi fixtures/t4_cross_server_a.json fixtures/t4_cross_server_b.json
  mcpdoctor scan -- python -m agent_tooling.sqlite_mcp
  mcpdoctor scan --command python --arg=-m --arg agent_tooling.sqlite_mcp
  mcpdoctor pin fixtures/clean_calculator.json --server-key calc
  mcpdoctor check fixtures/t1_description_poison.json --server-key calc
  mcpdoctor detectors

Exit codes: 0 clean/ok, 2 findings at or above --fail-on, 1 error.

Hyphen values: use --arg=-m or put the server after -- (scan -- python -m pkg).
Limits: tools list <= 8 MiB, <= 5000 tools, schema walk depth/leaf caps (DoS guard).
Static heuristics: not a model-level jailbreak judge; pair with live agent eval for ASR claims.
";

#[derive(Parser, Debug)]
#[command(
    name = "mcpdoctor",
    about = "Scan MCP tool surfaces for schema poison and rugpulls",
    long_about = "Protocol-native MCP tool-surface auditor.\n\
Connects like a client (or loads a tools/list JSON), walks every schema string, \
emits findings. Default path is non-mutating (no tools/call).",
    version,
    after_help = AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log filter (default: mcpdoctor=info)
    #[arg(long, global = true, default_value = "mcpdoctor=info,warn")]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a tools/list JSON or a live stdio MCP server
    Scan {
        /// tools/list JSON path (positional). Primary offline path.
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        /// Alias for positional LIST_JSON
        #[arg(long = "from-list", value_name = "PATH")]
        from_list: Option<PathBuf>,

        /// Spawn stdio MCP server command (use with --arg, or prefer trailing --)
        #[arg(long)]
        command: Option<String>,

        /// Args for --command. Hyphen-safe: --arg=-m
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,

        /// Working directory for stdio server
        #[arg(long)]
        cwd: Option<String>,

        /// Extra env KEY=VALUE for the child process
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Stdio handshake timeout seconds
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,

        /// Write JSON report to this path
        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        /// Also write Markdown report
        #[arg(long)]
        md: Option<PathBuf>,

        /// Treat server as trusted (disable D11 name-collision)
        #[arg(long)]
        trusted: bool,

        /// Fail exit code 2 if severity >= threshold
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Print Markdown to stdout
        #[arg(long)]
        markdown: bool,

        /// Wire framing for live stdio: ndjson (Python MCP) or content-length (TS)
        #[arg(long, value_enum, default_value_t = FramingArg::Ndjson)]
        framing: FramingArg,

        /// Server argv after `--`: mcpdoctor scan -- python -m pkg
        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// Scan two+ tools/list JSON files together (cross-server shadow)
    Multi {
        /// tools/list JSON paths (at least two)
        #[arg(required = true, num_args = 2..)]
        lists: Vec<PathBuf>,

        #[arg(long)]
        trusted: bool,

        #[arg(long, default_value = "high")]
        fail_on: String,

        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        #[arg(long)]
        markdown: bool,
    },

    /// Pin current inventory hashes after human review
    Pin {
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        #[arg(long = "from-list", value_name = "PATH")]
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

        #[arg(long, default_value = "default")]
        server_key: String,

        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// Diff current inventory against pin store (CI gate)
    Check {
        #[arg(value_name = "LIST_JSON")]
        list: Option<PathBuf>,

        #[arg(long = "from-list", value_name = "PATH")]
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

        #[arg(long, default_value = "default")]
        server_key: String,

        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        #[arg(long, default_value = "high")]
        fail_on: String,

        #[arg(long)]
        trusted: bool,

        #[arg(last = true, allow_hyphen_values = true)]
        server: Vec<String>,
    },

    /// List built-in detectors
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

/// Insert `scan` when the first arg looks like a tools-list path (not a subcommand).
fn preprocess_argv(raw: Vec<String>) -> Vec<String> {
    if raw.len() < 2 {
        return raw;
    }
    let first = raw[1].as_str();
    const SUBS: &[&str] = &["scan", "multi", "pin", "check", "detectors", "help"];
    if first.starts_with('-') || SUBS.contains(&first) {
        return raw;
    }
    // Bare path → scan <path>
    if first.ends_with(".json") || std::path::Path::new(first).exists() {
        let mut out = Vec::with_capacity(raw.len() + 1);
        out.push(raw[0].clone());
        out.push("scan".into());
        out.extend(raw.into_iter().skip(1));
        return out;
    }
    raw
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
            trusted,
            fail_on,
            markdown,
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
            emit_report(&report, out, md, markdown)?;
            Ok(exit_for_findings(&report, &fail_on)?)
        }
        Commands::Multi {
            lists,
            trusted,
            fail_on,
            out,
            markdown,
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                ..ScanOptions::default()
            };
            let pairs: Vec<(String, &std::path::Path)> = lists
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
            emit_report(&report, out, None, markdown)?;
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
                "pinned server_key={server_key} tools={} hash={} -> {}",
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
                    "no pin for server_key={server_key} in {}",
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
            emit_report(&report, out, None, false)?;
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

/// Merge --command/--arg with trailing `server` argv after `--`.
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
            "provide a tools-list JSON path or a server command\n\
             examples: mcpdoctor fixtures/t3_line_jump.json\n\
                       mcpdoctor scan -- python -m my_mcp"
        ),
    }
}

fn emit_report(
    report: &ScanReport,
    out: Option<PathBuf>,
    md: Option<PathBuf>,
    markdown_stdout: bool,
) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    if let Some(path) = &out {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &json).with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    } else if !markdown_stdout {
        println!("{json}");
    }

    if markdown_stdout {
        print!("{}", report.to_markdown());
    }
    if let Some(path) = md {
        std::fs::write(&path, report.to_markdown())
            .with_context(|| format!("write {}", path.display()))?;
        eprintln!("wrote {}", path.display());
    }

    eprintln!(
        "summary: tools={} findings={} max_severity={}",
        report.summary.tools,
        report.summary.findings,
        report
            .summary
            .max_severity
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into())
    );
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
