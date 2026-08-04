use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use mcp_poison::pin::{load_store, make_pins, save_store, upsert_pin};
use mcp_poison::report::ScanReport;
use mcp_poison::scan::{check_against_pins, scan_from_tools_list, scan_stdio, ScanOptions};
use mcp_poison::types::Severity;
use std::path::PathBuf;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(
    name = "mcp-poison",
    about = "Protocol-native MCP tool-surface auditor (full-schema poison + pin/rugpull)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Log filter (default: mcp_poison=info)
    #[arg(long, global = true, default_value = "mcp_poison=info,warn")]
    log: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a captured tools/list JSON (offline) or a live stdio MCP server
    Scan {
        /// Path to tools/list JSON fixture
        #[arg(long = "from-list", value_name = "PATH")]
        from_list: Option<PathBuf>,

        /// Spawn stdio MCP server command
        #[arg(long)]
        command: Option<String>,

        /// Args for stdio command (repeatable). Use --arg=-m for hyphen values.
        #[arg(long = "arg", allow_hyphen_values = true)]
        args: Vec<String>,

        /// Working directory for stdio server
        #[arg(long)]
        cwd: Option<String>,

        /// Extra env KEY=VALUE for the child process (repeatable)
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
    },

    /// Pin current inventory hashes after human review
    Pin {
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

        /// Pin store path
        #[arg(long, default_value = ".mcp-poison/pins.json")]
        store: PathBuf,

        /// Key in the pin store
        #[arg(long, default_value = "default")]
        server_key: String,
    },

    /// Diff current inventory against pin store (CI gate)
    Check {
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

        #[arg(long, default_value = ".mcp-poison/pins.json")]
        store: PathBuf,

        #[arg(long, default_value = "default")]
        server_key: String,

        #[arg(long, short = 'o')]
        out: Option<PathBuf>,

        #[arg(long, default_value = "high")]
        fail_on: String,

        #[arg(long)]
        trusted: bool,
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
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(&cli.log))
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Commands::Scan {
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
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                timeout: std::time::Duration::from_secs(timeout_secs),
            };
            let report = run_scan(from_list, command, args, cwd, &parse_env(&env)?, &opts)?;
            emit_report(&report, out, md, markdown)?;
            Ok(exit_for_findings(&report, &fail_on)?)
        }
        Commands::Pin {
            from_list,
            command,
            args,
            cwd,
            env,
            timeout_secs,
            store,
            server_key,
        } => {
            let opts = ScanOptions {
                untrusted: true,
                timeout: std::time::Duration::from_secs(timeout_secs),
            };
            let report = run_scan(from_list, command, args, cwd, &parse_env(&env)?, &opts)?;
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
        } => {
            let opts = ScanOptions {
                untrusted: !trusted,
                timeout: std::time::Duration::from_secs(timeout_secs),
            };
            let envp = parse_env(&env)?;
            let base = run_scan(from_list, command.clone(), args.clone(), cwd, &envp, &opts)?;
            let pin_store = load_store(&store)?;
            let Some(pins) = pin_store.servers.get(&server_key) else {
                bail!(
                    "no pin for server_key={server_key} in {}",
                    store.display()
                );
            };
            let cmd_owned = command
                .clone()
                .or_else(|| base.target.command.clone());
            let arg_ref = if args.is_empty() {
                base.target.args.clone()
            } else {
                args
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
        (Some(_), Some(_)) => bail!("use either --from-list or --command, not both"),
        (None, None) => bail!("provide --from-list PATH or --command CMD"),
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
