//! openshell-annotate: policy-as-code for OpenShell via `@openshell` source directives.
pub mod config;
pub mod ast;
pub mod diff_logs;
pub mod docs;
pub mod directive;
pub mod drift;
pub mod generate;
pub mod lexer;
pub mod lint;
pub mod providers;
pub mod scan;
pub mod spec;
pub mod validate;
