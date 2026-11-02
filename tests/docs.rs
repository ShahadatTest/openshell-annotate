//! The committed reference docs must match what the code generates.
use std::process::Command;

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_openshell-annotate"));
    c.current_dir(env!("CARGO_MANIFEST_DIR"));
    c
}

#[test]
fn committed_docs_are_current() {
    let o = bin()
        .args(["docs", "--check", "--out", "docs"])
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "docs/CLI.md or docs/DIRECTIVES.md is stale: run scripts/gen-docs.sh\n{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn check_fails_on_stale_docs() {
    let d = tempfile::tempdir().unwrap();
    let ok = bin()
        .args(["docs", "--out"])
        .arg(d.path())
        .status()
        .unwrap();
    assert!(ok.success());
    std::fs::write(d.path().join("DIRECTIVES.md"), "stale\n").unwrap();
    let o = bin()
        .args(["docs", "--check", "--out"])
        .arg(d.path())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("DIRECTIVES.md"));
}

#[test]
fn directives_doc_covers_every_verb_and_attribute() {
    let md = openshell_annotate::spec::directives_md();
    for v in openshell_annotate::spec::VERBS {
        assert!(md.contains(&format!("## {}\n", v.verb)));
        for a in v.attrs {
            assert!(
                md.contains(&format!("| `{}` |", a.name)),
                "{} {}",
                v.verb,
                a.name
            );
        }
    }
}
