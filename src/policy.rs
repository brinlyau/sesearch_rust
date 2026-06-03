//! Structured, queryable representation of a parsed SELinux policy.
//!
//! Unlike a diff-oriented model that stores rules as pre-formatted strings,
//! every rule here keeps its source / target / class / permission components
//! separate so the query engine can filter on each independently and expand
//! attributes semantically.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The kind of access-vector rule an `AvRule` represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvKind {
    Allow,
    AuditAllow,
    DontAudit,
}

impl AvKind {
    pub fn keyword(self) -> &'static str {
        match self {
            AvKind::Allow => "allow",
            AvKind::AuditAllow => "auditallow",
            AvKind::DontAudit => "dontaudit",
        }
    }
}

/// An access-vector rule: `<kind> source target:class { perms };`
#[derive(Debug, Clone)]
pub struct AvRule {
    pub kind: AvKind,
    pub source: String,
    pub target: String,
    pub class: String,
    pub perms: Vec<String>,
    /// True when the rule lives inside a conditional (`if`) block.
    pub conditional: bool,
}

impl fmt::Display for AvRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}:{} {{ {} }};",
            self.kind.keyword(),
            self.source,
            self.target,
            self.class,
            self.perms.join(" ")
        )?;
        if self.conditional {
            write!(f, "  # conditional")?;
        }
        Ok(())
    }
}

/// The kind of extended-permission rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpermKind {
    AllowXperm,
    AuditAllowXperm,
    DontAuditXperm,
}

impl XpermKind {
    pub fn keyword(self) -> &'static str {
        match self {
            XpermKind::AllowXperm => "allowxperm",
            XpermKind::AuditAllowXperm => "auditallowxperm",
            XpermKind::DontAuditXperm => "dontauditxperm",
        }
    }
}

/// An extended-permission rule, e.g. `allowxperm s t:class ioctl { 0x8910-0x8927 };`
#[derive(Debug, Clone)]
pub struct XpermRule {
    pub kind: XpermKind,
    pub source: String,
    pub target: String,
    pub class: String,
    /// The xperm operation, currently always `ioctl`.
    pub op: String,
    /// Inclusive command ranges (already coalesced).
    pub ranges: Vec<(u32, u32)>,
}

impl fmt::Display for XpermRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let body: Vec<String> = self
            .ranges
            .iter()
            .map(|(lo, hi)| {
                if lo == hi {
                    format!("{:#06x}", lo)
                } else {
                    format!("{:#06x}-{:#06x}", lo, hi)
                }
            })
            .collect();
        write!(
            f,
            "{} {} {}:{} {} {{ {} }};",
            self.kind.keyword(),
            self.source,
            self.target,
            self.class,
            self.op,
            body.join(" ")
        )
    }
}

/// A type rule that produces a new type: transition / member / change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeKind {
    Transition,
    Member,
    Change,
}

impl TeKind {
    pub fn keyword(self) -> &'static str {
        match self {
            TeKind::Transition => "type_transition",
            TeKind::Member => "type_member",
            TeKind::Change => "type_change",
        }
    }
}

/// A type-rule: `type_transition source target:class default ["name"];`
#[derive(Debug, Clone)]
pub struct TeRule {
    pub kind: TeKind,
    pub source: String,
    pub target: String,
    pub class: String,
    pub default: String,
    /// Object name, for filename transitions.
    pub object_name: Option<String>,
}

impl fmt::Display for TeRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}:{} {}",
            self.kind.keyword(),
            self.source,
            self.target,
            self.class,
            self.default
        )?;
        if let Some(name) = &self.object_name {
            write!(f, " \"{}\"", name)?;
        }
        write!(f, ";")
    }
}

/// A `genfscon` filesystem-context binding.
#[derive(Debug, Clone)]
pub struct Genfs {
    pub fstype: String,
    pub path: String,
    pub context_type: String,
}

impl fmt::Display for Genfs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "genfscon {} {} {}", self.fstype, self.path, self.context_type)
    }
}

/// A `constrain` / `mlsconstrain` statement: a boolean expression that must
/// hold for the listed permissions on a class to be granted.
#[derive(Debug, Clone)]
pub struct Constraint {
    pub class: String,
    pub perms: Vec<String>,
    /// The rendered boolean expression, e.g. `u1 == u2 or t1 == { foo }`.
    pub expr: String,
    /// True for `mlsconstrain` (the expression references MLS levels).
    pub mls: bool,
    /// True for `validatetrans` / `mlsvalidatetrans` statements.
    pub validatetrans: bool,
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let keyword = match (self.validatetrans, self.mls) {
            (true, true) => "mlsvalidatetrans",
            (true, false) => "validatetrans",
            (false, true) => "mlsconstrain",
            (false, false) => "constrain",
        };
        if self.validatetrans {
            write!(f, "{} {} ({});", keyword, self.class, self.expr)
        } else {
            write!(
                f,
                "{} {} {{ {} }} ({});",
                keyword,
                self.class,
                self.perms.join(" "),
                self.expr
            )
        }
    }
}

/// A fully parsed policy, ready to query.
#[derive(Debug, Default)]
pub struct Policy {
    pub version: u32,
    pub mls: bool,
    pub policy_kind: String,
    /// Concrete (non-attribute) types.
    pub types: BTreeSet<String>,
    /// Attribute name -> the set of types that belong to it.
    pub attributes: BTreeMap<String, BTreeSet<String>>,
    /// Object class -> ordered permission names.
    pub classes: BTreeMap<String, Vec<String>>,
    pub booleans: BTreeMap<String, bool>,
    pub av_rules: Vec<AvRule>,
    pub xperm_rules: Vec<XpermRule>,
    pub te_rules: Vec<TeRule>,
    pub constraints: Vec<Constraint>,
    pub genfs: Vec<Genfs>,
    pub policycaps: BTreeSet<String>,
    pub role_count: usize,
    pub user_count: usize,
}

/// How a `--source` / `--target` filter should match a rule's operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Match only the literal name written in the rule.
    Direct,
    /// Match the literal name, plus the attribute/member relationship in
    /// either direction (the default, matching `sesearch` semantics).
    Semantic,
}

/// A compiled set of query filters.
#[derive(Debug, Default, Clone)]
pub struct Query {
    pub source: Option<String>,
    pub target: Option<String>,
    pub class: Option<String>,
    /// Requested permissions; a rule matches if it grants any of them.
    pub perms: Vec<String>,
    pub mode_direct: bool,
}

impl Query {
    fn mode(&self) -> MatchMode {
        if self.mode_direct {
            MatchMode::Direct
        } else {
            MatchMode::Semantic
        }
    }

    /// Does `operand` (a name written in a rule) satisfy `filter` under the
    /// configured matching mode, given the policy's attribute membership?
    fn operand_matches(&self, policy: &Policy, filter: &str, operand: &str) -> bool {
        if filter == operand {
            return true;
        }
        if self.mode() == MatchMode::Direct {
            return false;
        }
        // Semantic: the rule's operand is an attribute containing the queried
        // type, or the queried name is an attribute containing the rule's type.
        if let Some(members) = policy.attributes.get(operand) {
            if members.contains(filter) {
                return true;
            }
        }
        if let Some(members) = policy.attributes.get(filter) {
            if members.contains(operand) {
                return true;
            }
        }
        false
    }

    fn matches_st(&self, policy: &Policy, source: &str, target: &str, class: &str) -> bool {
        if let Some(s) = &self.source {
            if !self.operand_matches(policy, s, source) {
                return false;
            }
        }
        if let Some(t) = &self.target {
            if !self.operand_matches(policy, t, target) {
                return false;
            }
        }
        if let Some(c) = &self.class {
            if c != class {
                return false;
            }
        }
        true
    }

    pub fn matches_av(&self, policy: &Policy, rule: &AvRule) -> bool {
        if !self.matches_st(policy, &rule.source, &rule.target, &rule.class) {
            return false;
        }
        if !self.perms.is_empty() {
            let granted = self.perms.iter().any(|p| rule.perms.iter().any(|rp| rp == p));
            if !granted {
                return false;
            }
        }
        true
    }

    pub fn matches_xperm(&self, policy: &Policy, rule: &XpermRule) -> bool {
        // xperm rules have no named perms to filter on.
        self.perms.is_empty() && self.matches_st(policy, &rule.source, &rule.target, &rule.class)
    }

    pub fn matches_te(&self, policy: &Policy, rule: &TeRule) -> bool {
        self.perms.is_empty() && self.matches_st(policy, &rule.source, &rule.target, &rule.class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> Policy {
        let mut p = Policy::default();
        p.types.insert("untrusted_app".into());
        p.types.insert("shell_data_file".into());
        p.types.insert("app_data_file".into());
        let mut members = BTreeSet::new();
        members.insert("untrusted_app".into());
        members.insert("priv_app".into());
        p.attributes.insert("appdomain".into(), members);
        p.types.insert("priv_app".into());
        p
    }

    fn allow(s: &str, t: &str, c: &str, perms: &[&str]) -> AvRule {
        AvRule {
            kind: AvKind::Allow,
            source: s.into(),
            target: t.into(),
            class: c.into(),
            perms: perms.iter().map(|x| x.to_string()).collect(),
            conditional: false,
        }
    }

    #[test]
    fn direct_match() {
        let p = sample_policy();
        let q = Query {
            source: Some("untrusted_app".into()),
            ..Default::default()
        };
        assert!(q.matches_av(&p, &allow("untrusted_app", "shell_data_file", "file", &["read"])));
        assert!(!q.matches_av(&p, &allow("priv_app", "shell_data_file", "file", &["read"])));
    }

    #[test]
    fn semantic_expands_attribute_in_rule() {
        let p = sample_policy();
        // Rule is written on the attribute; querying a member should match.
        let q = Query {
            source: Some("untrusted_app".into()),
            ..Default::default()
        };
        let rule = allow("appdomain", "app_data_file", "file", &["read"]);
        assert!(q.matches_av(&p, &rule));
        // Direct mode should not match across the attribute boundary.
        let q_direct = Query {
            source: Some("untrusted_app".into()),
            mode_direct: true,
            ..Default::default()
        };
        assert!(!q_direct.matches_av(&p, &rule));
    }

    #[test]
    fn semantic_expands_queried_attribute() {
        let p = sample_policy();
        // Query an attribute; a rule on a member type should match.
        let q = Query {
            source: Some("appdomain".into()),
            ..Default::default()
        };
        assert!(q.matches_av(&p, &allow("priv_app", "app_data_file", "file", &["read"])));
    }

    #[test]
    fn perm_filter_any() {
        let p = sample_policy();
        let q = Query {
            perms: vec!["execute".into()],
            ..Default::default()
        };
        assert!(q.matches_av(&p, &allow("a", "b", "file", &["read", "execute"])));
        assert!(!q.matches_av(&p, &allow("a", "b", "file", &["read", "write"])));
    }

    #[test]
    fn class_filter() {
        let p = sample_policy();
        let q = Query {
            class: Some("dir".into()),
            ..Default::default()
        };
        assert!(q.matches_av(&p, &allow("a", "b", "dir", &["search"])));
        assert!(!q.matches_av(&p, &allow("a", "b", "file", &["read"])));
    }
}
