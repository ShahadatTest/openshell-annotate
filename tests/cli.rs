//! End-to-end tests: drive the real binary against the fixture repo in a temp dir.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_openshell-annotate"))
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), to).unwrap();
        }
    }
}

fn fixture() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sample"),
        t.path(),
    );
    t
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn scan_lists_directives_with_locations_and_ignores_strings() {
    let t = fixture();
    let o = run(t.path(), &["scan"]);
    assert!(o.status.success(), "{}", err(&o));
    let s = out(&o);
    assert!(s.contains("src/llm.ts:1  egress api.openai.com:443"), "{s}");
    assert!(s.contains("src/llm.ts:2  provider OPENAI_API_KEY"), "{s}");
    assert!(
        s.contains("src/cache.py:2  fs write /workspace/data"),
        "{s}"
    );
    assert!(
        s.contains("cmd/main.go:3  egress api.github.com:443"),
        "{s}"
    );
    assert!(
        s.contains("scripts/run.sh:3  fs read /etc/ssl/certs"),
        "{s}"
    );
    assert!(
        !s.contains("not-a-directive.test"),
        "directive inside a string literal must be ignored: {s}"
    );
    assert_eq!(s.lines().count(), 8);
}

#[test]
fn scan_json() {
    let t = fixture();
    let o = run(t.path(), &["scan", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out(&o)).unwrap();
    assert_eq!(v["directives"].as_array().unwrap().len(), 8);
    assert_eq!(v["directives"][0]["file"], "cmd/main.go");
    assert_eq!(v["directives"][0]["kind"], "egress");
}

#[test]
fn generate_matches_golden_and_validates_with_schema_crate() {
    let t = fixture();
    let o = run(
        t.path(),
        &[
            "generate",
            "-o",
            "policy.yaml",
            "--providers-out",
            "providers.json",
        ],
    );
    assert!(o.status.success(), "{}", err(&o));
    let got = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    let want = std::fs::read_to_string(t.path().join("policy.expected.yaml")).unwrap();
    assert_eq!(got, want);
    let doc =
        openshell_policy_schema::parse_policy(&got).expect("schema crate accepts generated policy");
    assert_eq!(doc.version, 1);
    assert_eq!(doc.network_policies.len(), 4);
    let gh = &doc.network_policies["api_github_com"];
    assert_eq!(gh.endpoints[0].host, "api.github.com");
    assert_eq!(gh.endpoints[0].access, "read-only");
    assert_eq!(gh.endpoints[0].enforcement, "enforce");
    assert_eq!(gh.binaries[0].path, "/opt/app/server");
    let fs = doc.filesystem_policy.unwrap();
    assert!(fs.include_workdir);
    assert_eq!(fs.read_write, vec!["/workspace/data"]);
    // Each endpoint carries a provenance comment with file:line.
    assert!(got.contains("# LLM calls (src/llm.ts:1)"));
    assert!(got.contains("# release lookup (second call site) (cmd/main.go:4)"));
    let prov = std::fs::read_to_string(t.path().join("providers.json")).unwrap();
    assert_eq!(
        prov,
        std::fs::read_to_string(t.path().join("providers.expected.json")).unwrap()
    );
}

#[test]
fn providers_script_has_no_secrets_and_uses_bare_credential_form() {
    let t = fixture();
    let o = run(
        t.path(),
        &[
            "generate",
            "-o",
            "p.yaml",
            "--providers-out",
            "providers.sh",
        ],
    );
    assert!(o.status.success(), "{}", err(&o));
    let s = std::fs::read_to_string(t.path().join("providers.sh")).unwrap();
    assert!(
        s.contains(
            "openshell provider create --name openai --type openai --credential OPENAI_API_KEY\n"
        ),
        "{s}"
    );
    assert!(!s.contains("OPENAI_API_KEY="), "{s}");
    assert!(
        s.contains("openshell sandbox create --provider openai --policy p.yaml"),
        "{s}"
    );
}

#[test]
fn drift_clean_then_detects_missing_extra_and_changed() {
    let t = fixture();
    assert!(run(t.path(), &["generate", "-o", "policy.yaml"])
        .status
        .success());
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert!(o.status.success(), "{}{}", out(&o), err(&o));
    assert!(out(&o).contains("no drift"));

    // Comment/format-only edits are not drift.
    let y = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    std::fs::write(
        t.path().join("policy.yaml"),
        format!(
            "# hand-added comment\n{}",
            y.replace("\"api.github.com\"", "api.github.com")
        ),
    )
    .unwrap();
    assert!(run(t.path(), &["drift", "--policy", "policy.yaml"])
        .status
        .success());

    // A new directive that the committed policy lacks -> missing (live).
    std::fs::write(
        t.path().join("src/new.ts"),
        "// @openshell egress api.example.com:443 reason=\"new\"\n",
    )
    .unwrap();
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        out(&o).contains("missing  [live] network_policies api_example_com"),
        "{}",
        out(&o)
    );
    std::fs::remove_file(t.path().join("src/new.ts")).unwrap();

    // A grant with no directive -> extra.
    let y = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    std::fs::write(t.path().join("policy.yaml"), format!("{y}  sneaky:\n    endpoints:\n      - host: evil.test\n        port: 443\n    binaries:\n      - path: /usr/bin/curl\n")).unwrap();
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        out(&o).contains("extra    [live] network_policies sneaky"),
        "{}",
        out(&o)
    );

    // Changed binary -> changed.
    assert!(run(t.path(), &["generate", "-o", "policy.yaml"])
        .status
        .success());
    let y = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    std::fs::write(
        t.path().join("policy.yaml"),
        y.replace("/opt/app/server", "/opt/app/other"),
    )
    .unwrap();
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert_eq!(o.status.code(), Some(1));
    let s = out(&o);
    assert!(
        s.contains("changed")
            && s.contains("binaries")
            && s.contains("/opt/app/server")
            && s.contains("/opt/app/other"),
        "{s}"
    );
}

#[test]
fn drift_labels_startup_sections() {
    let t = fixture();
    assert!(run(t.path(), &["generate", "-o", "policy.yaml"])
        .status
        .success());
    let y = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    std::fs::write(
        t.path().join("policy.yaml"),
        y.replace(
            "    - \"/workspace/data\"\n",
            "    - \"/workspace/data\"\n    - \"/var/extra\"\n",
        ),
    )
    .unwrap();
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        out(&o).contains("[startup] filesystem_policy.read_write /var/extra"),
        "{}",
        out(&o)
    );
}

#[test]
fn drift_unmanaged_sections_noted_and_strict_flags_them() {
    let t = fixture();
    assert!(run(t.path(), &["generate", "-o", "policy.yaml"])
        .status
        .success());
    let y = std::fs::read_to_string(t.path().join("policy.yaml")).unwrap();
    std::fs::write(
        t.path().join("policy.yaml"),
        y.replace(
            "version: 1\n",
            "version: 1\nlandlock:\n  compatibility: hard_requirement\n",
        ),
    )
    .unwrap();
    let o = run(t.path(), &["drift", "--policy", "policy.yaml"]);
    assert!(o.status.success());
    assert!(out(&o).contains("landlock"));
    let o = run(t.path(), &["drift", "--policy", "policy.yaml", "--strict"]);
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn generate_rejects_invalid_directives_with_locations() {
    let t = fixture();
    std::fs::write(
        t.path().join("src/bad.ts"),
        "// @openshell egress api.bad.test:443\n// @openshell egress localhost:8080 reason=x\n// @openshell fs write relative/path reason=x\n// @openshell egress *.com:443 reason=x\n// @openshell egress ok.test:443 reason=x access=full allow=\"GET:/x\"\n",
    )
    .unwrap();
    let o = run(t.path(), &["generate"]);
    assert_eq!(o.status.code(), Some(1));
    let e = err(&o);
    assert!(e.contains("src/bad.ts:1: egress requires reason"), "{e}");
    assert!(e.contains("src/bad.ts:2:") && e.contains("loopback"), "{e}");
    assert!(e.contains("src/bad.ts:3:") && e.contains("absolute"), "{e}");
    assert!(
        e.contains("src/bad.ts:4:") && e.contains("three DNS labels"),
        "{e}"
    );
    assert!(
        e.contains("src/bad.ts:5:") && e.contains("mutually exclusive"),
        "{e}"
    );
}

#[test]
fn generate_requires_a_binary_when_unknown() {
    let t = fixture();
    std::fs::remove_file(t.path().join("openshell-annotate.toml")).unwrap();
    let o = run(t.path(), &["generate"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("[languages].javascript"), "{}", err(&o));
}

#[test]
fn conflicting_settings_and_slug_collisions_are_errors() {
    let t = fixture();
    std::fs::write(t.path().join("src/c1.ts"), "// @openshell egress dup.test:443 reason=a access=read-only\n// @openshell egress dup.test:443 reason=b access=full\n").unwrap();
    let o = run(t.path(), &["generate"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        err(&o).contains("conflicting settings for dup.test:443"),
        "{}",
        err(&o)
    );
    std::fs::remove_file(t.path().join("src/c1.ts")).unwrap();
    std::fs::write(
        t.path().join("src/c2.ts"),
        "// @openshell egress a-b.test:443 reason=a\n// @openshell egress a.b.test:443 reason=b\n",
    )
    .unwrap();
    let o = run(t.path(), &["generate"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("rule=<name>"), "{}", err(&o));
}

#[test]
fn rule_attribute_groups_endpoints_and_unions_binaries() {
    let t = fixture();
    std::fs::write(
        t.path().join("src/g.ts"),
        "// @openshell egress a.example.com:443 reason=a rule=pair\n// @openshell egress b.example.com:443,8443 reason=b rule=pair bin=/usr/bin/curl\n",
    )
    .unwrap();
    let o = run(t.path(), &["generate", "-o", "p.yaml"]);
    assert!(o.status.success(), "{}", err(&o));
    let doc = openshell_policy_schema::parse_policy(
        &std::fs::read_to_string(t.path().join("p.yaml")).unwrap(),
    )
    .unwrap();
    let r = &doc.network_policies["pair"];
    assert_eq!(r.endpoints.len(), 2);
    assert_eq!(r.endpoints[1].ports, vec![443, 8443]);
    let bins: Vec<_> = r.binaries.iter().map(|b| b.path.as_str()).collect();
    assert_eq!(bins, vec!["/usr/bin/curl", "/usr/local/bin/node"]);
}

#[test]
fn lint_flags_unannotated_calls_and_honours_ignore() {
    let t = fixture();
    std::fs::write(
        t.path().join("src/raw.ts"),
        "import { writeFileSync } from \"node:fs\";\nexport async function f() {\n  const r = await fetch(\"https://api.stripe.com/v1/charges\");\n  writeFileSync(\"/tmp/x\", \"a\");\n  const k = process.env.STRIPE_API_KEY;\n  const m = \"fetch(not code)\"; // fetch(also not code)\n}\n",
    )
    .unwrap();
    let o = run(t.path(), &["lint"]);
    assert!(o.status.success());
    let s = out(&o);
    assert!(s.contains("src/raw.ts:3: warning[net]: fetch() without an @openshell directive (suggest: @openshell egress api.stripe.com:443"), "{s}");
    assert!(
        s.contains("src/raw.ts:4: warning[fs]: filesystem write"),
        "{s}"
    );
    assert!(
        s.contains("src/raw.ts:5: warning[env]: reads secret-like variable STRIPE_API_KEY"),
        "{s}"
    );
    assert!(
        !s.contains("src/raw.ts:6"),
        "strings/comments must not match: {s}"
    );
    assert_eq!(
        run(t.path(), &["lint", "--deny-warnings"]).status.code(),
        Some(1)
    );

    // Annotate -> clean.
    std::fs::write(
        t.path().join("src/raw.ts"),
        "// @openshell ignore kind=fs reason=\"tmp scratch\" scope=file\n// @openshell egress api.stripe.com:443 reason=\"charges\"\n// @openshell provider STRIPE_API_KEY\nimport { writeFileSync } from \"node:fs\";\nexport async function f() {\n  const r = await fetch(\"https://api.stripe.com/v1/charges\");\n  writeFileSync(\"/tmp/x\", \"a\");\n  const k = process.env.STRIPE_API_KEY;\n}\n",
    )
    .unwrap();
    let o = run(t.path(), &["lint", "--deny-warnings"]);
    assert!(o.status.success(), "{}{}", out(&o), err(&o));
}

#[test]
fn lint_python_go_shell_call_sites_and_test_files_excluded() {
    let t = fixture();
    std::fs::write(t.path().join("src/x.py"), "import requests, subprocess\nrequests.get(\"https://example.org/a\")\nopen(\"out.txt\", \"w\").write(\"x\")\nopen(\"in.txt\").read()\nsubprocess.run([\"git\", \"pull\"])\n").unwrap();
    std::fs::write(t.path().join("cmd/x.go"), "package main\nfunc f() { http.Get(\"https://example.net/\"); os.WriteFile(\"a\", nil, 0o644); _ = os.Getenv(\"DB_PASSWORD\") }\n").unwrap();
    std::fs::write(
        t.path().join("scripts/x.sh"),
        "curl -fsSL https://example.com/i.sh > /opt/i.sh\necho hi > /dev/null\nmkdir -p /opt/a\n",
    )
    .unwrap();
    std::fs::create_dir_all(t.path().join("src/__tests__")).unwrap();
    std::fs::write(
        t.path().join("src/__tests__/t.ts"),
        "fetch(\"https://ignored.test\")\n",
    )
    .unwrap();
    let s = out(&run(t.path(), &["lint"]));
    assert!(s.contains("src/x.py:2: warning[net]: requests"), "{s}");
    assert!(
        s.contains("src/x.py:3: warning[fs]: open() for writing"),
        "{s}"
    );
    assert!(
        !s.contains("src/x.py:4"),
        "read-mode open must not be flagged: {s}"
    );
    assert!(s.contains("src/x.py:5: info[exec]"), "{s}");
    assert!(
        s.contains("cmd/x.go:2: warning[net]")
            && s.contains("cmd/x.go:2: warning[fs]")
            && s.contains("DB_PASSWORD"),
        "{s}"
    );
    assert!(
        s.contains("scripts/x.sh:1: warning[net]: curl/wget")
            && s.contains("scripts/x.sh:1: warning[fs]"),
        "{s}"
    );
    assert!(
        !s.contains("scripts/x.sh:2"),
        "> /dev/null is not a write: {s}"
    );
    assert!(s.contains("scripts/x.sh:3: warning[fs]"), "{s}");
    assert!(!s.contains("__tests__"), "{s}");
}

#[test]
fn lint_checks_a_policy_file() {
    let t = fixture();
    std::fs::write(t.path().join("bad.yaml"), "version: 1\nprocess:\n  run_as_user: \"0\"\nnetwork_policies:\n  x:\n    endpoints:\n      - host: \"*.com\"\n        port: 443\n    binaries: []\nbogus: 1\n").unwrap();
    let o = run(t.path(), &["lint", "--policy", "bad.yaml"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(out(&o).contains("unknown field 'bogus'"), "{}", out(&o));
    std::fs::write(t.path().join("bad.yaml"), "version: 1\nprocess:\n  run_as_user: \"0\"\nnetwork_policies:\n  x:\n    endpoints:\n      - host: \"*.com\"\n        port: 443\n    binaries: []\n").unwrap();
    let s = out(&run(t.path(), &["lint", "--policy", "bad.yaml"]));
    assert!(
        s.contains("run_as_user") && s.contains("root is rejected"),
        "{s}"
    );
    assert!(s.contains("three DNS labels"), "{s}");
    assert!(s.contains("allows nothing"), "{s}");
}

#[test]
fn schema_crate_rejects_what_we_never_emit() {
    // Guard rails: the pinned OpenShell schema really is strict about these.
    assert!(
        openshell_policy_schema::parse_policy("version: 1\nproviders: {}\n").is_err(),
        "policy.yaml has no providers section"
    );
    assert!(openshell_policy_schema::parse_policy("version: 2\n").is_err());
    assert!(openshell_policy_schema::parse_policy("version: 1\nnetwork_policies:\n  a:\n    endpoints:\n      - host: x.test\n        port: 443\n        nope: 1\n").is_err());
}
