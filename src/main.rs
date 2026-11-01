use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openshell_annotate::config::Config;
use openshell_annotate::directive::Directive;
use openshell_annotate::drift;
use openshell_annotate::generate::{self, miette_str};
use openshell_annotate::lint::{self, Severity};
use openshell_annotate::providers::{self, Profile};
use openshell_annotate::scan::{self, Scan};
use openshell_annotate::validate;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Policy-as-code for OpenShell: `@openshell` source directives -> policy.yaml.
#[derive(Parser)]
#[command(name = "openshell-annotate", version, about)]
struct Cli {
    /// Repository root: paths in output are relative to it; `openshell-annotate.toml` is read from it.
    #[arg(long, global = true, default_value = ".")]
    root: PathBuf,
    /// Config file (default: <root>/openshell-annotate.toml if present).
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List directives with file:line.
    Scan {
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Generate policy.yaml (and a providers file) from directives.
    Generate {
        paths: Vec<PathBuf>,
        /// Write policy here (default: stdout).
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Write providers here: `.sh` = setup script, anything else = JSON.
        #[arg(long)]
        providers_out: Option<PathBuf>,
        /// Provider-profile directory (overrides [providers].profiles_dir).
        #[arg(long)]
        profiles_dir: Option<PathBuf>,
    },
    /// Validate directives, find un-annotated network/fs/secret call sites, optionally check a policy file.
    Lint {
        paths: Vec<PathBuf>,
        /// Also parse and semantically check this policy.yaml.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Exit 1 on warnings too.
        #[arg(long)]
        deny_warnings: bool,
        #[arg(long)]
        json: bool,
    },
    /// Compare the policy generated from directives with a committed policy.yaml (CI gate).
    Drift {
        paths: Vec<PathBuf>,
        #[arg(long)]
        policy: PathBuf,
        /// Also compare a committed providers JSON file.
        #[arg(long)]
        providers: Option<PathBuf>,
        #[arg(long)]
        profiles_dir: Option<PathBuf>,
        /// Flag committed sections directives cannot express (landlock, network_middlewares).
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        json: bool,
    },
}

fn expand(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(rest);
        }
    }
    PathBuf::from(p)
}

fn load_profiles(cfg: &Config, cli_dir: Option<&Path>, root: &Path) -> Result<Vec<Profile>> {
    let dir = cli_dir.map(Path::to_path_buf).or_else(|| {
        cfg.providers.profiles_dir.as_deref().map(expand).map(|p| {
            if p.is_relative() {
                root.join(p)
            } else {
                p
            }
        })
    });
    match dir {
        Some(d) => providers::load_profiles(&d),
        None => Ok(vec![]),
    }
}

fn do_scan(root: &Path, paths: &[PathBuf], cfg: &Config) -> Result<Scan> {
    scan::scan(root, paths, cfg)
}

fn report_parse_errors(s: &Scan) -> bool {
    for e in &s.errors {
        eprintln!("error: {e}");
    }
    !s.errors.is_empty()
}

fn run(cli: Cli) -> Result<ExitCode> {
    let root = cli
        .root
        .canonicalize()
        .with_context(|| format!("root {}", cli.root.display()))?;
    let cfg = Config::load_or_default(&root, cli.config.as_deref())?;
    match cli.cmd {
        Cmd::Scan { paths, json } => {
            let s = do_scan(&root, &paths, &cfg)?;
            if json {
                #[derive(serde::Serialize)]
                struct Out<'a> {
                    directives: &'a [Directive],
                    errors: &'a [openshell_annotate::directive::ParseError],
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&Out {
                        directives: &s.directives,
                        errors: &s.errors
                    })?
                );
            } else {
                for d in &s.directives {
                    let detail = match &d.kind {
                        openshell_annotate::directive::Kind::Egress { host, ports } => format!(
                            "{host}:{}",
                            ports
                                .iter()
                                .map(u16::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                        openshell_annotate::directive::Kind::Provider { env } => env.clone(),
                        openshell_annotate::directive::Kind::Fs { path, .. } => path.clone(),
                        openshell_annotate::directive::Kind::Bin { path } => path.clone(),
                        _ => String::new(),
                    };
                    let reason = d.reason().map(|r| format!("  # {r}")).unwrap_or_default();
                    println!("{}:{}  {} {detail}{reason}", d.file, d.line, d.kind.name());
                }
                eprintln!(
                    "{} directive(s) in {} file(s)",
                    s.directives.len(),
                    s.sources.len()
                );
            }
            let had = report_parse_errors(&s);
            Ok(if had {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Generate {
            paths,
            output,
            providers_out,
            profiles_dir,
        } => {
            let s = do_scan(&root, &paths, &cfg)?;
            if report_parse_errors(&s) {
                return Ok(ExitCode::from(1));
            }
            let profiles = load_profiles(&cfg, profiles_dir.as_deref(), &root)?;
            match generate::generate(&s.directives, &cfg, &profiles) {
                Ok(g) => {
                    for w in &g.warnings {
                        eprintln!("warning: {w}");
                    }
                    match &output {
                        Some(p) => {
                            if let Some(parent) = p.parent().filter(|x| !x.as_os_str().is_empty()) {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::write(p, &g.policy_yaml)?
                        }
                        None => print!("{}", g.policy_yaml),
                    }
                    if let Some(p) = &providers_out {
                        if let Some(parent) = p.parent().filter(|x| !x.as_os_str().is_empty()) {
                            std::fs::create_dir_all(parent)?;
                        }
                        let body = if p.extension().and_then(|e| e.to_str()) == Some("sh") {
                            g.providers.to_script(
                                &output
                                    .as_ref()
                                    .map(|o| o.display().to_string())
                                    .unwrap_or_else(|| "policy.yaml".into()),
                            )
                        } else {
                            g.providers.to_json()
                        };
                        std::fs::write(p, body)?;
                    }
                    eprintln!(
                        "generated: {} directive(s) -> {} network rule(s), {} endpoint(s), {} binary path(s), fs read {} / write {}, {} provider(s) ({} unmapped)",
                        g.stats.directives, g.stats.network_rules, g.stats.endpoints, g.stats.binaries, g.stats.fs_read, g.stats.fs_write, g.stats.providers, g.stats.unmapped_providers
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(errs) => {
                    for e in errs {
                        eprintln!("error: {e}");
                    }
                    Ok(ExitCode::from(1))
                }
            }
        }
        Cmd::Lint {
            paths,
            policy,
            deny_warnings,
            json,
        } => {
            let s = do_scan(&root, &paths, &cfg)?;
            let mut findings = lint::lint(&s, &cfg);
            if let Some(p) = &policy {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                match openshell_policy_schema::parse_policy(&text) {
                    Ok(doc) => {
                        let (errs, warns) = validate::check_document(&doc);
                        for (v, sev) in errs
                            .into_iter()
                            .map(|e| (e, Severity::Error))
                            .chain(warns.into_iter().map(|w| (w, Severity::Warning)))
                        {
                            findings.push(lint::Finding {
                                file: p.display().to_string(),
                                line: 0,
                                severity: sev,
                                category: "policy",
                                message: v,
                            });
                        }
                    }
                    Err(e) => findings.push(lint::Finding {
                        file: p.display().to_string(),
                        line: 0,
                        severity: Severity::Error,
                        category: "policy",
                        message: miette_str(&e),
                    }),
                }
            }
            let (ne, nw, ni) = (
                findings
                    .iter()
                    .filter(|f| f.severity == Severity::Error)
                    .count(),
                findings
                    .iter()
                    .filter(|f| f.severity == Severity::Warning)
                    .count(),
                findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count(),
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&findings)?);
            } else {
                for f in &findings {
                    let sev = format!("{:?}", f.severity).to_lowercase();
                    println!(
                        "{}:{}: {sev}[{}]: {}",
                        f.file, f.line, f.category, f.message
                    );
                }
            }
            eprintln!(
                "lint: {} directive(s); {ne} error(s), {nw} warning(s), {ni} info",
                s.directives.len()
            );
            Ok(if ne > 0 || (deny_warnings && nw > 0) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Drift {
            paths,
            policy,
            providers: prov_file,
            profiles_dir,
            strict,
            json,
        } => {
            let s = do_scan(&root, &paths, &cfg)?;
            if report_parse_errors(&s) {
                return Ok(ExitCode::from(1));
            }
            let profiles = load_profiles(&cfg, profiles_dir.as_deref(), &root)?;
            let g = match generate::generate(&s.directives, &cfg, &profiles) {
                Ok(g) => g,
                Err(errs) => {
                    for e in errs {
                        eprintln!("error: {e}");
                    }
                    return Ok(ExitCode::from(1));
                }
            };
            let text = std::fs::read_to_string(&policy)
                .with_context(|| format!("reading {}", policy.display()))?;
            let committed = openshell_policy_schema::parse_policy(&text)
                .map_err(|e| anyhow::anyhow!("{}: {}", policy.display(), miette_str(&e)))?;
            let mut rep = drift::compare(&g.doc, &committed, strict);
            if let Some(pf) = prov_file {
                let v: serde_json::Value = serde_json::from_str(
                    &std::fs::read_to_string(&pf)
                        .with_context(|| format!("reading {}", pf.display()))?,
                )?;
                rep.findings
                    .extend(drift::compare_providers(&g.providers, &v));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&rep)?);
            } else if rep.findings.is_empty() {
                print!("{}", rep.render());
                println!(
                    "no drift: {} matches {} directive(s)",
                    policy.display(),
                    g.stats.directives
                );
            } else {
                print!("{}", rep.render());
                eprintln!(
                    "drift: {} finding(s); regenerate with `openshell-annotate generate -o {}`",
                    rep.findings.len(),
                    policy.display()
                );
            }
            Ok(if rep.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
