//! Linter: directive validity + heuristic detection of un-annotated network, filesystem-write,
//! secret and subprocess call sites.
//!
//! Call-site detection is regex based on the lexer's code mask (comments and string contents
//! blanked), so matches inside strings/comments are ignored. It is a heuristic: dynamic URLs and
//! SDK-hidden HTTP calls need a directive or `@openshell ignore`. A tree-sitter backend is the planned
//! upgrade (see docs/design.md).

use crate::config::Config;
use crate::directive::{Directive, Kind};
use crate::lexer::Language;
use crate::scan::Scan;
use crate::validate;
use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub severity: Severity,
    pub category: &'static str,
    pub message: String,
}

const DEFAULT_EXCLUDES: &[&str] = &[
    "/test/",
    "/tests/",
    "/__tests__/",
    ".test.",
    ".spec.",
    "_test.go",
    "/fixtures/",
    "/__mocks__/",
    ".d.ts",
    "/e2e/",
];

struct Pat {
    cat: &'static str,
    code: Regex,
    /// Applied to the raw line from the code match start; must match for a hit.
    raw: Option<Regex>,
    /// Applied to the raw line from the code match start; a match suppresses the hit.
    not_raw: Option<Regex>,
    what: &'static str,
}

fn p(cat: &'static str, what: &'static str, code: &str) -> Pat {
    Pat {
        cat,
        code: Regex::new(code).unwrap(),
        raw: None,
        not_raw: None,
        what,
    }
}

fn patterns(lang: Language) -> &'static Vec<Pat> {
    static JS: OnceLock<Vec<Pat>> = OnceLock::new();
    static PY: OnceLock<Vec<Pat>> = OnceLock::new();
    static GO: OnceLock<Vec<Pat>> = OnceLock::new();
    static SH: OnceLock<Vec<Pat>> = OnceLock::new();
    match lang {
        Language::JavaScript => JS.get_or_init(|| {
            vec![
                p("net", "fetch()", r"(?:^|[^.\w])fetch\s*\(|globalThis\.fetch\s*\("),
                p("net", "axios", r"\baxios\s*[.(]"),
                p("net", "node http(s) request", r"\b(?:https?\.(?:request|get)|httpsRequest|httpRequest)\s*\("),
                p("net", "WebSocket client", r"new\s+WebSocket\s*\("),
                p("net", "EventSource", r"new\s+EventSource\s*\("),
                p("net", "raw socket", r"\b(?:net\.(?:connect|createConnection)|tls\.connect)\s*\("),
                p("fs", "filesystem write", r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|mkdir|mkdirSync|mkdtemp|mkdtempSync|unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync|rmSync|truncate|truncateSync|symlink|symlinkSync)\s*\(|\bfs\w*\.(?:rm|cp|cpSync)\s*\("),
                p("env", "environment read", r"\bprocess\.env\b"),
                p("exec", "subprocess", r"(?:^|[^.\w])(?:spawn|spawnSync|execFile|execFileSync|execSync|fork)\s*\(|\bchild_process\.\w+\s*\("),
            ]
        }),
        Language::Python => PY.get_or_init(|| {
            let mut open = p("fs", "open() for writing", r"\bopen\s*\(");
            open.raw = Some(Regex::new(r#"^open\s*\([^)]*,\s*(?:mode\s*=\s*)?['"][rbt]*[wax+][^'"]*['"]"#).unwrap());
            vec![
                p("net", "requests", r"\brequests\.(?:get|post|put|patch|delete|head|request|Session)\b"),
                p("net", "httpx", r"\bhttpx\.\w+"),
                p("net", "urllib", r"\burllib\.request\.|\burlopen\s*\("),
                p("net", "aiohttp", r"\baiohttp\.ClientSession\b"),
                p("net", "raw socket", r"\bsocket\.create_connection\s*\(|\bwebsockets\.connect\s*\("),
                open,
                p("fs", "filesystem write", r"\.write_text\s*\(|\.write_bytes\s*\(|\bshutil\.(?:copy\w*|move|rmtree)\s*\(|\bos\.(?:remove|rename|makedirs|mkdir|unlink|rmdir)\s*\("),
                p("env", "environment read", r"\bos\.(?:environ|getenv)\b"),
                p("exec", "subprocess", r"\bsubprocess\.\w+\s*\(|\bos\.(?:system|popen)\s*\("),
            ]
        }),
        Language::Go => GO.get_or_init(|| {
            vec![
                p("net", "net/http client", r"\bhttp\.(?:Get|Post|PostForm|Head|NewRequest|NewRequestWithContext|DefaultClient)\b"),
                p("net", "raw socket", r"\b(?:net\.(?:Dial|DialTimeout)|tls\.Dial|websocket\.Dial)\s*\("),
                p("fs", "filesystem write", r"\bos\.(?:WriteFile|Create|OpenFile|MkdirAll|Mkdir|MkdirTemp|CreateTemp|Remove|RemoveAll|Rename)\s*\(|\bioutil\.WriteFile\s*\("),
                p("env", "environment read", r"\bos\.Getenv\s*\("),
                p("exec", "subprocess", r"\bexec\.Command(?:Context)?\s*\("),
            ]
        }),
        Language::Shell => SH.get_or_init(|| {
            let mut redir = p("fs", "output redirection", r"(?:^|[^>&0-9<\-=])>>?\s*[^&\s>]");
            redir.not_raw = Some(Regex::new(r"^>>?\s*(?:/dev/(?:null|stderr|stdout|tty)|&)").unwrap());
            vec![
                p("net", "curl/wget", r"\b(?:curl|wget)\b"),
                p("net", "git remote operation", r"\bgit\s+(?:clone|fetch|pull|push|ls-remote)\b"),
                p("net", "package manager", r"\b(?:npm|pnpm|yarn)\s+(?:install|i|add|ci|publish|view)\b|\bpip3?\s+install\b|\bapt(?:-get)?\s+(?:install|update)\b"),
                p("net", "container registry", r"\bdocker\s+(?:pull|push)\b"),
                redir,
                p("fs", "filesystem write", r"(?:^|[;&|(]\s*|\s)(?:mkdir|rm|cp|mv|touch|tee|chmod|chown|ln)\s+"),
                p("env", "environment read", r"\$\{?[A-Z]"),
            ]
        }),
    }
}

fn env_name_re(lang: Language) -> Regex {
    Regex::new(match lang {
        Language::JavaScript => r#"process\.env(?:\.|\[\s*["'])([A-Z][A-Z0-9_]*)"#,
        Language::Python => {
            r#"os\.(?:environ(?:\.get)?\s*[\(\[]|getenv\s*\()\s*["']([A-Z][A-Z0-9_]*)["']"#
        }
        Language::Go => r#"os\.Getenv\(\s*"([A-Z][A-Z0-9_]*)""#,
        Language::Shell => r"\$\{?([A-Z][A-Z0-9_]*)",
    })
    .unwrap()
}

pub fn secret_like(name: &str) -> bool {
    let parts: Vec<&str> = name.split('_').collect();
    let last = *parts.last().unwrap_or(&"");
    if matches!(
        last,
        "FILE"
            | "PATH"
            | "DIR"
            | "URL"
            | "URI"
            | "ENV"
            | "HOST"
            | "HOSTS"
            | "PORT"
            | "ID"
            | "NAME"
            | "MS"
            | "SECONDS"
            | "LIMIT"
            | "WINDOW"
            | "TTL"
            | "TIMEOUT"
            | "ENABLED"
            | "DISABLED"
    ) {
        return false;
    }
    parts.iter().any(|t| {
        matches!(
            *t,
            "KEY"
                | "TOKEN"
                | "SECRET"
                | "PASSWORD"
                | "PASSWD"
                | "CREDENTIAL"
                | "CREDENTIALS"
                | "PAT"
                | "APIKEY"
        )
    })
}

fn url_hosts(raw: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?:https?|wss?)://([A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9])(?::(\d+))?").unwrap()
    });
    let mut v = Vec::new();
    for c in re.captures_iter(raw) {
        let whole = c.get(0).unwrap().as_str();
        let default = if whole.starts_with("https") || whole.starts_with("wss") {
            "443"
        } else {
            "80"
        };
        let host = &c[1];
        if host.contains('.') && !host.starts_with("127.") && host != "localhost" {
            v.push(format!(
                "{host}:{}",
                c.get(2).map_or(default, |m| m.as_str())
            ));
        }
    }
    v.dedup();
    v
}

fn excluded(rel: &str, cfg: &Config) -> bool {
    let path = format!("/{rel}");
    DEFAULT_EXCLUDES.iter().any(|x| path.contains(x))
        || cfg.lint.exclude.iter().any(|x| crate::config::path_matches(rel, x))
}

pub fn lint(scan: &Scan, cfg: &Config) -> Vec<Finding> {
    let mut out = Vec::new();
    for e in &scan.errors {
        out.push(Finding {
            file: e.file.clone(),
            line: e.line,
            severity: Severity::Error,
            category: "directive",
            message: e.message.clone(),
        });
    }
    for d in &scan.directives {
        for m in validate::check_directive(d) {
            out.push(Finding {
                file: d.file.clone(),
                line: d.line,
                severity: Severity::Error,
                category: "directive",
                message: m,
            });
        }
    }
    let provider_envs: BTreeSet<&str> = scan
        .directives
        .iter()
        .filter_map(|d| {
            if let Kind::Provider { env } = &d.kind {
                Some(env.as_str())
            } else {
                None
            }
        })
        .collect();
    for src in &scan.sources {
        if excluded(&src.rel, cfg) {
            continue;
        }
        let here: Vec<&Directive> = scan
            .directives
            .iter()
            .filter(|d| d.file == src.rel)
            .collect();
        let covered = |line: usize, cat: &str| -> bool {
            here.iter().any(|d| {
                d.covers().contains(&cat)
                    && (d.file_scoped() || (d.line <= line && line - d.line <= cfg.lint.window))
            })
        };
        let env_re = env_name_re(src.lang);
        for (i, code) in src.lexed.code.iter().enumerate() {
            let line = i + 1;
            let raw = src.lexed.raw.get(i).map(String::as_str).unwrap_or("");
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for pat in patterns(src.lang) {
                if !cfg.lint.categories.is_empty()
                    && !cfg.lint.categories.iter().any(|c| c == pat.cat)
                {
                    continue;
                }
                if pat.cat != "env" && seen.contains(pat.cat) {
                    continue;
                }
                let Some(m) = pat.code.find(code) else {
                    continue;
                };
                let raw_full: String = {
                    let off = code[..m.start()].chars().count();
                    raw.chars().skip(off).collect()
                };
                let raw_from = raw_full.trim_start_matches(|c: char| {
                    !(c.is_alphanumeric() || c == '>' || c == '$' || c == '_')
                });
                if let Some(r) = &pat.raw {
                    if !r.is_match(raw_from) {
                        continue;
                    }
                }
                if let Some(r) = &pat.not_raw {
                    // For redirections the regex consumed the char before `>`; re-anchor at `>`.
                    let at = raw_from
                        .find('>')
                        .map(|k| &raw_from[k..])
                        .unwrap_or(raw_from);
                    if r.is_match(at) {
                        continue;
                    }
                }
                match pat.cat {
                    "env" => {
                        let names: Vec<String> = env_re
                            .captures_iter(&raw_full)
                            .map(|c| c[1].to_string())
                            .filter(|n| secret_like(n))
                            .collect();
                        for n in names {
                            if provider_envs.contains(n.as_str()) || covered(line, "env") {
                                continue;
                            }
                            out.push(Finding {
                                file: src.rel.clone(),
                                line,
                                severity: Severity::Warning,
                                category: "env",
                                message: format!("reads secret-like variable {n} with no `@openshell provider {n}`; if a provider supplies it, declare it; otherwise `@openshell ignore kind=env reason=\"...\"`"),
                            });
                        }
                    }
                    "exec" => {
                        if !covered(line, "exec") {
                            out.push(Finding { file: src.rel.clone(), line, severity: Severity::Info, category: "exec", message: format!("{}: the spawned program is the binary that opens its own connections; if it talks to the network add `bin=` on its egress, else `@openshell ignore kind=exec reason=\"...\"`", pat.what) });
                        }
                    }
                    cat => {
                        if covered(line, cat) {
                            continue;
                        }
                        let hint = if cat == "net" {
                            let hosts = url_hosts(raw);
                            if hosts.is_empty() {
                                " (no literal URL on this line: declare the host with @openshell egress, or @openshell ignore kind=net)".to_string()
                            } else {
                                format!(
                                    " (suggest: @openshell egress {} reason=\"...\")",
                                    hosts.join(", ")
                                )
                            }
                        } else {
                            " (add `@openshell fs write <absolute in-sandbox path> reason=\"...\"`, or `@openshell ignore kind=fs`)".to_string()
                        };
                        out.push(Finding {
                            file: src.rel.clone(),
                            line,
                            severity: Severity::Warning,
                            category: if cat == "net" { "net" } else { "fs" },
                            message: format!("{} without an @openshell directive{hint}", pat.what),
                        });
                    }
                }
                seen.insert(pat.cat);
            }
        }
    }
    out.sort_by(|a, b| (a.severity, &a.file, a.line).cmp(&(b.severity, &b.file, b.line)));
    out
}

#[cfg(test)]
mod secret_name_tests {
    use super::secret_like;

    #[test]
    fn secret_names() {
        for n in ["OPENAI_API_KEY", "GITHUB_TOKEN", "BETTER_AUTH_SECRET", "DB_PASSWORD"] {
            assert!(secret_like(n), "{n}");
        }
        for n in [
            "PAPERCLIP_MCP_GATEWAY_TOKEN_REQUEST_LIMIT",
            "PAPERCLIP_TOKEN_BROKER_ALLOWED_HOSTS",
            "TOKEN_FILE",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "PATH",
        ] {
            assert!(!secret_like(n), "{n}");
        }
    }
}
