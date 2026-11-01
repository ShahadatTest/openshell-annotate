//! `openshell-annotate.toml` (strict: unknown keys are errors).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const CONFIG_FILE: &str = "openshell-annotate.toml";

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Default executable per language family (`javascript`, `python`, `go`, `shell`).
    /// Must be the *real path* of the binary inside the sandbox image (OpenShell does not follow symlinks).
    #[serde(default)]
    pub languages: BTreeMap<String, String>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub providers: ProvidersConfig,
    #[serde(default)]
    pub lint: LintConfig,
    #[serde(default)]
    pub scan: ScanConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Emitted when any `fs` directive exists. A present `filesystem_policy` otherwise defaults it to false.
    #[serde(default = "yes")]
    pub include_workdir: bool,
    /// Default `enforcement` for inspected endpoints (OpenShell's own default is `audit`).
    #[serde(default = "enforce")]
    pub enforcement: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        PolicyConfig {
            include_workdir: true,
            enforcement: "enforce".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProvidersConfig {
    /// Directory of provider-profile YAML files (e.g. `<OpenShell>/providers`).
    pub profiles_dir: Option<String>,
    /// Env var -> profile id overrides.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LintConfig {
    /// A directive covers call sites within this many lines below it.
    #[serde(default = "window")]
    pub window: usize,
    /// Extra path substrings excluded from lint call-site heuristics (tests are excluded by default).
    #[serde(default)]
    pub exclude: Vec<String>,
}

impl Default for LintConfig {
    fn default() -> Self {
        LintConfig {
            window: 8,
            exclude: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ScanConfig {
    /// Path substrings never scanned (in addition to .gitignore, node_modules, dist, build, target).
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn yes() -> bool {
    true
}
fn enforce() -> String {
    "enforce".into()
}
fn window() -> usize {
    8
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let s =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: Config =
            toml::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        if !matches!(c.policy.enforcement.as_str(), "enforce" | "audit") {
            anyhow::bail!(
                "{}: policy.enforcement must be `enforce` or `audit`",
                path.display()
            );
        }
        Ok(c)
    }

    pub fn load_or_default(root: &Path, explicit: Option<&Path>) -> Result<Config> {
        match explicit {
            Some(p) => Config::load(p),
            None => {
                let p = root.join(CONFIG_FILE);
                if p.is_file() {
                    Config::load(&p)
                } else {
                    Ok(Config::default())
                }
            }
        }
    }
}
