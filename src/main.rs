//! `sesearch_rust` — query SELinux binary kernel policies.
//!
//! A self-contained, dependency-free reimplementation of the parts of SETools'
//! `sesearch`/`seinfo` that work against a compiled kernel policy blob
//! (Android `sepolicy` / `precompiled_sepolicy`, or `/sys/fs/selinux/policy`).

use sesearch_rust::{json, parser, policy};

use policy::{Policy, Query};
use std::process::ExitCode;

const USAGE: &str = "\
sesearch_rust — query SELinux binary kernel policies

USAGE:
    sesearch_rust [RULE TYPES] [FILTERS] [OPTIONS] <policy>

    <policy> is a compiled kernel policy: an Android `sepolicy` /
    `precompiled_sepolicy`, or `/sys/fs/selinux/policy` on a live system.

RULE TYPES (choose one or more; the matching rules are printed):
    -A, --allow            allow rules
        --auditallow       auditallow rules
        --dontaudit        dontaudit rules
    -T, --type_trans       type_transition / type_member / type_change rules
    -X, --xperm            extended-permission (ioctl) rules
        --all-rules        all of the above

FILTERS (apply to rules and, where meaningful, to --constrain):
    -s, --source <NAME>    match rules whose source is NAME
    -t, --target <NAME>    match rules whose target is NAME
    -c, --class <NAME>     match rules whose object class is NAME
    -p, --perm <P[,P..]>   match rules granting any of these permissions
    -d, --direct           literal matching only (do not expand attributes)

INFO (seinfo-style; printed instead of rules):
        --stats            summary counts and policy metadata
        --types            list all concrete types
        --attributes       list all type attributes
        --classes          list object classes and their permissions
        --booleans         list booleans and their default state
        --policycaps       list enabled policy capabilities
        --constrain        list constrain / mlsconstrain statements (filter with -c)
        --sensitivities    list MLS sensitivities
        --categories       list MLS categories
        --genfs            list genfscon entries
        --initialsids      list initial SID contexts
        --portcon          list portcon entries
        --netifcon         list netifcon entries
        --nodecon          list nodecon entries
        --fs_use           list fs_use_xattr / _task / _trans entries
        --permissive       list domains marked permissive
        --expand <ATTR>    list the member types of an attribute

OPTIONS:
        --json             emit results as JSON
    -n, --limit <N>        print at most N rules
    -h, --help             show this help
    -V, --version          show version

EXAMPLES:
    sesearch_rust -A -s untrusted_app -t shell_data_file -c file sepolicy
    sesearch_rust -A -p execute_no_trans sepolicy
    sesearch_rust -T -s init sepolicy
    sesearch_rust --classes sepolicy
    sesearch_rust --expand domain sepolicy
";

#[derive(Default)]
struct Config {
    policy_path: Option<String>,
    // rule types
    allow: bool,
    auditallow: bool,
    dontaudit: bool,
    type_trans: bool,
    xperm: bool,
    // filters
    query: Query,
    // rule types (cont.)
    constrain: bool,
    // info
    stats: bool,
    list_types: bool,
    list_attributes: bool,
    list_classes: bool,
    list_booleans: bool,
    list_policycaps: bool,
    list_genfs: bool,
    list_sensitivities: bool,
    list_categories: bool,
    list_initialsids: bool,
    list_portcon: bool,
    list_netifcon: bool,
    list_nodecon: bool,
    list_fsuse: bool,
    list_permissive: bool,
    expand_attr: Option<String>,
    // output
    json: bool,
    limit: Option<usize>,
}

impl Config {
    fn any_rule_type(&self) -> bool {
        self.allow || self.auditallow || self.dontaudit || self.type_trans || self.xperm
    }
    fn any_info(&self) -> bool {
        self.stats
            || self.list_types
            || self.list_attributes
            || self.list_classes
            || self.list_booleans
            || self.list_policycaps
            || self.list_genfs
            || self.list_sensitivities
            || self.list_categories
            || self.list_initialsids
            || self.list_portcon
            || self.list_netifcon
            || self.list_nodecon
            || self.list_fsuse
            || self.list_permissive
            || self.constrain
            || self.expand_attr.is_some()
    }
}

/// Restore the default `SIGPIPE` disposition. Rust installs `SIG_IGN`, which
/// turns a closed downstream pipe (e.g. `sesearch_rust ... | head`) into an `EPIPE`
/// that panics on the next write. Resetting to `SIG_DFL` makes the process exit
/// quietly, the way every other Unix filter does.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: a single libc call with constant arguments, before any threads.
    unsafe {
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        const SIGPIPE: i32 = 13;
        const SIG_DFL: usize = 0;
        signal(SIGPIPE, SIG_DFL);
    }
}
#[cfg(not(unix))]
fn reset_sigpipe() {}

fn main() -> ExitCode {
    reset_sigpipe();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sesearch_rust: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let cfg = match parse_args(args)? {
        Some(cfg) => cfg,
        None => return Ok(ExitCode::SUCCESS), // --help / --version already printed
    };

    let path = cfg
        .policy_path
        .as_deref()
        .ok_or("no policy file given (try --help)")?;
    let data = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let policy = parser::parse(&data)?;

    validate_query(&cfg, &policy)?;

    if !cfg.any_rule_type() && !cfg.any_info() {
        return Err("nothing to do: specify a rule type (e.g. -A) or an info flag (e.g. --stats). See --help".into());
    }

    if cfg.any_info() {
        print_info(&cfg, &policy)?;
    }
    if cfg.any_rule_type() {
        print_rules(&cfg, &policy);
    }
    Ok(ExitCode::SUCCESS)
}

fn validate_query(cfg: &Config, p: &Policy) -> Result<(), String> {
    let mut names: Vec<String> = p.types.iter().cloned().collect();
    names.extend(p.attributes.keys().cloned());
    for (label, value) in [("source", cfg.query.source.as_deref()), ("target", cfg.query.target.as_deref())] {
        if let Some(v) = value { if !names.iter().any(|n| n == v) { return Err(unknown_filter(label, v, &names)); } }
    }
    if let Some(v) = cfg.query.class.as_deref() {
        let classes: Vec<String> = p.classes.keys().cloned().collect();
        if !classes.iter().any(|n| n == v) { return Err(unknown_filter("class", v, &classes)); }
    }
    let perms: Vec<String> = p.classes.values().flatten().cloned().collect();
    for v in &cfg.query.perms { if !perms.iter().any(|n| n == v) { return Err(unknown_filter("permission", v, &perms)); } }
    if let Some(v) = cfg.expand_attr.as_deref() {
        if !p.attributes.contains_key(v) { return Err(unknown_filter("attribute", v, &p.attributes.keys().cloned().collect::<Vec<_>>())); }
    }
    Ok(())
}

fn unknown_filter(kind: &str, value: &str, candidates: &[String]) -> String {
    let mut ranked: Vec<(usize, &str)> = candidates.iter().map(|c| (edit_distance(value, c), c.as_str())).collect();
    ranked.sort_by_key(|x| x.0);
    let suggestion = ranked.first().filter(|x| x.0 <= value.len().max(x.1.len()) / 2).map(|x| format!(" did you mean: {}?", x.1)).unwrap_or_default();
    format!("unknown {kind} {value}.{suggestion}")
}

fn edit_distance(a: &str, b: &str) -> usize {
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.bytes().enumerate() {
        let mut prev = row[0]; row[0] = i + 1;
        for (j, cb) in b.bytes().enumerate() {
            let old = row[j + 1];
            row[j + 1] = (row[j + 1] + 1).min(row[j] + 1).min(prev + usize::from(ca != cb));
            prev = old;
        }
    }
    row[b.len()]
}

fn parse_args(args: Vec<String>) -> Result<Option<Config>, String> {
    let mut cfg = Config::default();
    let mut it = args.into_iter().peekable();

    // Pull the value for an option, supporting both `--opt val` and `--opt=val`.
    fn take_value(
        flag: &str,
        inline: Option<String>,
        it: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
    ) -> Result<String, String> {
        if let Some(v) = inline {
            return Ok(v);
        }
        it.next().ok_or_else(|| format!("option {flag} requires a value"))
    }

    while let Some(arg) = it.next() {
        // Split `--opt=value` into (`--opt`, Some(value)).
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if arg.starts_with('-') => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };

        match flag.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("sesearch_rust {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "-A" | "--allow" => cfg.allow = true,
            "--auditallow" => cfg.auditallow = true,
            "--dontaudit" => cfg.dontaudit = true,
            "-T" | "--type_trans" | "--type-trans" => cfg.type_trans = true,
            "-X" | "--xperm" => cfg.xperm = true,
            "--all-rules" => {
                cfg.allow = true;
                cfg.auditallow = true;
                cfg.dontaudit = true;
                cfg.type_trans = true;
                cfg.xperm = true;
            }
            "-s" | "--source" => cfg.query.source = Some(take_value(&flag, inline, &mut it)?),
            "-t" | "--target" => cfg.query.target = Some(take_value(&flag, inline, &mut it)?),
            "-c" | "--class" => cfg.query.class = Some(take_value(&flag, inline, &mut it)?),
            "-p" | "--perm" | "--perms" => {
                let raw = take_value(&flag, inline, &mut it)?;
                cfg.query.perms = raw
                    .split([',', ' '])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
            }
            "-d" | "--direct" => cfg.query.mode_direct = true,
            "--stats" => cfg.stats = true,
            "--types" => cfg.list_types = true,
            "--attributes" => cfg.list_attributes = true,
            "--classes" => cfg.list_classes = true,
            "--booleans" => cfg.list_booleans = true,
            "--policycaps" => cfg.list_policycaps = true,
            "--genfs" => cfg.list_genfs = true,
            "--sensitivities" | "--sens" => cfg.list_sensitivities = true,
            "--categories" | "--cats" => cfg.list_categories = true,
            "--initialsids" | "--isids" => cfg.list_initialsids = true,
            "--portcon" | "--ports" => cfg.list_portcon = true,
            "--netifcon" => cfg.list_netifcon = true,
            "--nodecon" => cfg.list_nodecon = true,
            "--fs_use" | "--fsuse" => cfg.list_fsuse = true,
            "--permissive" => cfg.list_permissive = true,
            "--constrain" => cfg.constrain = true,
            "--expand" | "--expand-attr" => {
                cfg.expand_attr = Some(take_value(&flag, inline, &mut it)?)
            }
            "--json" => cfg.json = true,
            "-n" | "--limit" => {
                let v = take_value(&flag, inline, &mut it)?;
                cfg.limit = Some(v.parse().map_err(|_| format!("invalid --limit value: {v}"))?);
            }
            other if other.starts_with('-') && other != "-" => {
                return Err(format!("unknown option: {other} (try --help)"));
            }
            _ => {
                if cfg.policy_path.is_some() {
                    return Err(format!("unexpected extra argument: {arg}"));
                }
                cfg.policy_path = Some(arg);
            }
        }
    }

    Ok(Some(cfg))
}

// ---------------------------------------------------------------------------
// Rule printing
// ---------------------------------------------------------------------------

fn print_rules(cfg: &Config, policy: &Policy) {
    let q = &cfg.query;
    let limit = cfg.limit.unwrap_or(usize::MAX);

    // Collect matching rules as display strings (and structured json values).
    let mut lines: Vec<String> = Vec::new();
    let mut json_items: Vec<json::Value> = Vec::new();

    for rule in &policy.av_rules {
        let want = match rule.kind {
            policy::AvKind::Allow => cfg.allow,
            policy::AvKind::AuditAllow => cfg.auditallow,
            policy::AvKind::DontAudit => cfg.dontaudit,
        };
        if want && q.matches_av(policy, rule) {
            lines.push(rule.to_string());
            if cfg.json {
                json_items.push(av_json(rule));
            }
        }
    }
    if cfg.xperm {
        for rule in &policy.xperm_rules {
            if q.matches_xperm(policy, rule) {
                lines.push(rule.to_string());
                if cfg.json {
                    json_items.push(xperm_json(rule));
                }
            }
        }
    }
    if cfg.type_trans {
        for rule in &policy.te_rules {
            if q.matches_te(policy, rule) {
                lines.push(rule.to_string());
                if cfg.json {
                    json_items.push(te_json(rule));
                }
            }
        }
    }

    lines.sort();
    lines.dedup();

    if cfg.json {
        // Sorting json_items to match would require re-deriving keys; instead
        // re-sort by rendered rule for determinism.
        json_items.sort_by_key(json::Value::sort_key);
        json_items.dedup_by_key(|v| v.sort_key());
        let arr = json::Value::Array(json_items.into_iter().take(limit).collect());
        println!("{}", arr.render());
    } else {
        for line in lines.into_iter().take(limit) {
            println!("{line}");
        }
    }
}

fn av_json(r: &policy::AvRule) -> json::Value {
    use json::Value::*;
    Object(vec![
        ("rule_type".into(), Str(r.kind.keyword().into())),
        ("source".into(), Str(r.source.clone())),
        ("target".into(), Str(r.target.clone())),
        ("class".into(), Str(r.class.clone())),
        (
            "perms".into(),
            Array(r.perms.iter().cloned().map(Str).collect()),
        ),
        ("conditional".into(), Bool(r.conditional)),
        ("conditional_branch".into(), Str(match r.conditional_branch {
            Some(true) => "true".into(),
            Some(false) => "false".into(),
            None => "unconditional".into(),
        })),
        ("conditional_expr".into(), Str(r.conditional_expr.clone().unwrap_or_default())),
    ])
}

fn xperm_json(r: &policy::XpermRule) -> json::Value {
    use json::Value::*;
    Object(vec![
        ("rule_type".into(), Str(r.kind.keyword().into())),
        ("source".into(), Str(r.source.clone())),
        ("target".into(), Str(r.target.clone())),
        ("class".into(), Str(r.class.clone())),
        ("op".into(), Str(r.op.clone())),
        (
            "ranges".into(),
            Array(
                r.ranges
                    .iter()
                    .map(|(lo, hi)| {
                        Array(vec![Num(*lo as i64), Num(*hi as i64)])
                    })
                    .collect(),
            ),
        ),
    ])
}

fn te_json(r: &policy::TeRule) -> json::Value {
    use json::Value::*;
    let mut fields = vec![
        ("rule_type".into(), Str(r.kind.keyword().into())),
        ("source".into(), Str(r.source.clone())),
        ("target".into(), Str(r.target.clone())),
        ("class".into(), Str(r.class.clone())),
        ("default".into(), Str(r.default.clone())),
    ];
    if let Some(name) = &r.object_name {
        fields.push(("object_name".into(), Str(name.clone())));
    }
    Object(fields)
}

// ---------------------------------------------------------------------------
// Info / listing
// ---------------------------------------------------------------------------

fn print_info(cfg: &Config, policy: &Policy) -> Result<(), String> {
    if cfg.stats {
        if cfg.json {
            println!("{}", stats_json(policy).render());
        } else {
            print_stats(policy);
        }
    }
    if cfg.list_types {
        print_list("Types", policy.types.iter().cloned().collect(), cfg.json);
    }
    if cfg.list_attributes {
        print_list(
            "Attributes",
            policy.attributes.keys().cloned().collect(),
            cfg.json,
        );
    }
    if cfg.list_classes {
        if cfg.json {
            let obj = json::Value::Object(
                policy
                    .classes
                    .iter()
                    .map(|(c, perms)| {
                        (
                            c.clone(),
                            json::Value::Array(
                                perms.iter().cloned().map(json::Value::Str).collect(),
                            ),
                        )
                    })
                    .collect(),
            );
            println!("{}", obj.render());
        } else {
            for (class, perms) in &policy.classes {
                println!("class {class} {{ {} }}", perms.join(" "));
            }
        }
    }
    if cfg.list_booleans {
        if cfg.json {
            let obj = json::Value::Object(
                policy
                    .booleans
                    .iter()
                    .map(|(b, v)| (b.clone(), json::Value::Bool(*v)))
                    .collect(),
            );
            println!("{}", obj.render());
        } else {
            for (b, v) in &policy.booleans {
                println!("bool {b} {}", if *v { "true" } else { "false" });
            }
        }
    }
    if cfg.list_policycaps {
        print_list(
            "Policy capabilities",
            policy.policycaps.iter().cloned().collect(),
            cfg.json,
        );
    }
    if cfg.list_genfs {
        if cfg.json {
            let arr = json::Value::Array(
                policy
                    .genfs
                    .iter()
                    .map(|g| {
                        json::Value::Object(vec![
                            ("fstype".into(), json::Value::Str(g.fstype.clone())),
                            ("path".into(), json::Value::Str(g.path.clone())),
                            ("type".into(), json::Value::Str(g.context_type.clone())),
                        ])
                    })
                    .collect(),
            );
            println!("{}", arr.render());
        } else {
            for g in &policy.genfs {
                println!("{g}");
            }
        }
    }
    if cfg.list_sensitivities {
        print_rendered(policy.sensitivities.clone(), cfg.json);
    }
    if cfg.list_categories {
        print_rendered(policy.categories.clone(), cfg.json);
    }
    if cfg.constrain {
        let class = cfg.query.class.as_deref();
        let lines: Vec<String> = policy
            .constraints
            .iter()
            .filter(|c| class.is_none_or(|want| c.class == want))
            .map(|c| c.to_string())
            .collect();
        print_rendered(lines, cfg.json);
    }
    if cfg.list_initialsids {
        print_rendered(policy.initial_sids.iter().map(|x| x.to_string()).collect(), cfg.json);
    }
    if cfg.list_portcon {
        print_rendered(policy.portcons.iter().map(|x| x.to_string()).collect(), cfg.json);
    }
    if cfg.list_netifcon {
        print_rendered(policy.netifcons.iter().map(|x| x.to_string()).collect(), cfg.json);
    }
    if cfg.list_nodecon {
        print_rendered(policy.nodecons.iter().map(|x| x.to_string()).collect(), cfg.json);
    }
    if cfg.list_fsuse {
        print_rendered(policy.fs_uses.iter().map(|x| x.to_string()).collect(), cfg.json);
    }
    if cfg.list_permissive {
        print_list("Permissive types", policy.permissive_types.iter().cloned().collect(), cfg.json);
    }
    if let Some(attr) = &cfg.expand_attr {
        let members = policy
            .attributes
            .get(attr)
            .ok_or_else(|| format!("no such attribute: {attr}"))?;
        print_list(
            &format!("Members of {attr}"),
            members.iter().cloned().collect(),
            cfg.json,
        );
    }
    Ok(())
}

/// Print a set of names with a count header (text) or a JSON string array.
fn print_list(title: &str, mut items: Vec<String>, json_out: bool) {
    items.sort();
    if json_out {
        let arr = json::Value::Array(items.into_iter().map(json::Value::Str).collect());
        println!("{}", arr.render());
    } else {
        println!("{title} ({}):", items.len());
        for item in items {
            println!("  {item}");
        }
    }
}

/// Print already-rendered statement lines verbatim (text) or as a JSON string
/// array. Order is preserved — used for listings where order carries meaning
/// (sensitivities) or matches the policy file (contexts, constraints).
fn print_rendered(lines: Vec<String>, json_out: bool) {
    if json_out {
        let arr = json::Value::Array(lines.into_iter().map(json::Value::Str).collect());
        println!("{}", arr.render());
    } else {
        for line in lines {
            println!("{line}");
        }
    }
}

fn print_stats(p: &Policy) {
    println!("Policy kind:       {}", p.policy_kind);
    println!("Policy version:    {}", p.version);
    println!("MLS enabled:       {}", p.mls);
    println!("Types:             {}", p.types.len());
    println!("Attributes:        {}", p.attributes.len());
    println!("Classes:           {}", p.classes.len());
    println!("Roles:             {}", p.role_count);
    println!("Users:             {}", p.user_count);
    println!("Booleans:          {}", p.booleans.len());
    let (mut allow, mut auditallow, mut dontaudit) = (0, 0, 0);
    for r in &p.av_rules {
        match r.kind {
            policy::AvKind::Allow => allow += 1,
            policy::AvKind::AuditAllow => auditallow += 1,
            policy::AvKind::DontAudit => dontaudit += 1,
        }
    }
    println!("allow rules:       {allow}");
    println!("auditallow rules:  {auditallow}");
    println!("dontaudit rules:   {dontaudit}");
    println!("xperm rules:       {}", p.xperm_rules.len());
    println!("type rules:        {}", p.te_rules.len());
    println!("constraints:       {}", p.constraints.len());
    println!("sensitivities:     {}", p.sensitivities.len());
    println!("categories:        {}", p.categories.len());
    println!("genfscon entries:  {}", p.genfs.len());
    println!("initial SIDs:      {}", p.initial_sids.len());
    println!("portcon entries:   {}", p.portcons.len());
    println!("netifcon entries:  {}", p.netifcons.len());
    println!("nodecon entries:   {}", p.nodecons.len());
    println!("fs_use entries:    {}", p.fs_uses.len());
    println!("policy caps:       {}", p.policycaps.len());
}

fn stats_json(p: &Policy) -> json::Value {
    use json::Value::*;
    let (mut allow, mut auditallow, mut dontaudit) = (0i64, 0i64, 0i64);
    for r in &p.av_rules {
        match r.kind {
            policy::AvKind::Allow => allow += 1,
            policy::AvKind::AuditAllow => auditallow += 1,
            policy::AvKind::DontAudit => dontaudit += 1,
        }
    }
    Object(vec![
        ("policy_kind".into(), Str(p.policy_kind.clone())),
        ("version".into(), Num(p.version as i64)),
        ("mls".into(), Bool(p.mls)),
        ("types".into(), Num(p.types.len() as i64)),
        ("attributes".into(), Num(p.attributes.len() as i64)),
        ("classes".into(), Num(p.classes.len() as i64)),
        ("roles".into(), Num(p.role_count as i64)),
        ("users".into(), Num(p.user_count as i64)),
        ("booleans".into(), Num(p.booleans.len() as i64)),
        ("allow_rules".into(), Num(allow)),
        ("auditallow_rules".into(), Num(auditallow)),
        ("dontaudit_rules".into(), Num(dontaudit)),
        ("xperm_rules".into(), Num(p.xperm_rules.len() as i64)),
        ("type_rules".into(), Num(p.te_rules.len() as i64)),
        ("constraints".into(), Num(p.constraints.len() as i64)),
        ("sensitivities".into(), Num(p.sensitivities.len() as i64)),
        ("categories".into(), Num(p.categories.len() as i64)),
        ("genfs".into(), Num(p.genfs.len() as i64)),
        ("initial_sids".into(), Num(p.initial_sids.len() as i64)),
        ("portcons".into(), Num(p.portcons.len() as i64)),
        ("netifcons".into(), Num(p.netifcons.len() as i64)),
        ("nodecons".into(), Num(p.nodecons.len() as i64)),
        ("fs_uses".into(), Num(p.fs_uses.len() as i64)),
        ("policycaps".into(), Num(p.policycaps.len() as i64)),
    ])
}
