//! `sesearch` — a dependency-free parser and query engine for SELinux binary
//! kernel policies (Android `sepolicy` / `precompiled_sepolicy`, or a live
//! `/sys/fs/selinux/policy`).
//!
//! The [`parser::parse`] entry point turns a policy blob into a structured,
//! queryable [`policy::Policy`]; [`policy::Query`] filters its rules.

pub mod json;
pub mod parser;
pub mod policy;
pub mod reader;
pub mod testgen;
