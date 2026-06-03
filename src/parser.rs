//! Parser for the SELinux kernel binary policy (`policydb`) format.
//!
//! Targets the format used by Android's `sepolicy` / `precompiled_sepolicy`
//! blobs and by `/sys/fs/selinux/policy` on a live system. The layout follows
//! the kernel's `policydb_read` exactly: header, leading policy-capability /
//! permissive / never-audit ebitmaps, the symbol tables (each preceded by its
//! own `(nprim, nel)` counts), the access-vector table, conditional rules,
//! role and filename transitions, object and genfs contexts, MLS range
//! transitions, and finally the type-attribute map.

use crate::policy::*;
use crate::reader::Reader;
use std::collections::{BTreeSet, HashMap};

const SELINUX_MAGIC: u32 = 0xF97C_FF8C;

// policydb version gates (kernel policy).
const V_VALIDATETRANS: u32 = 19;
const V_AVTAB: u32 = 20;
const V_POLCAP: u32 = 22;
const V_PERMISSIVE: u32 = 23;
const V_BOUNDARY: u32 = 24;
const V_FILENAME_TRANS: u32 = 25;
const V_ROLETRANS: u32 = 26;
const V_NEW_OBJECT_DEFAULTS: u32 = 27;
const V_DEFAULT_TYPE: u32 = 28;
const V_CONSTRAINT_NAMES: u32 = 29;
const V_COMP_FTRANS: u32 = 33;
const V_NEVERAUDIT: u32 = 34;

// Symbol-table indices, in file order.
const SYM_COMMONS: usize = 0;
const SYM_CLASSES: usize = 1;
const SYM_ROLES: usize = 2;
const SYM_TYPES: usize = 3;
const SYM_USERS: usize = 4;
const SYM_BOOLS: usize = 5;
const SYM_LEVELS: usize = 6;
const SYM_CATS: usize = 7;

// avtab "specified" flags.
const AVTAB_ALLOWED: u16 = 0x0001;
const AVTAB_AUDITALLOW: u16 = 0x0002;
const AVTAB_AUDITDENY: u16 = 0x0004;
const AVTAB_TRANSITION: u16 = 0x0010;
const AVTAB_MEMBER: u16 = 0x0020;
const AVTAB_CHANGE: u16 = 0x0040;
const AVTAB_XPERMS_ALLOWED: u16 = 0x0100;
const AVTAB_XPERMS_AUDITALLOW: u16 = 0x0200;
const AVTAB_XPERMS_DONTAUDIT: u16 = 0x0400;
const AVTAB_XPERMS: u16 = AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT;

const AVTAB_XPERMS_IOCTLFUNCTION: u8 = 1;
const AVTAB_XPERMS_IOCTLDRIVER: u8 = 2;

// Constraint expression node types.
const CEXPR_NOT: u32 = 1;
const CEXPR_AND: u32 = 2;
const CEXPR_OR: u32 = 3;
const CEXPR_ATTR: u32 = 4;
const CEXPR_NAMES: u32 = 5;

// Constraint expression attribute flags.
const CEXPR_USER: u32 = 1;
const CEXPR_ROLE: u32 = 2;
const CEXPR_TYPE: u32 = 4;
const CEXPR_TARGET: u32 = 8;
const CEXPR_XTARGET: u32 = 16;
const CEXPR_L1L2: u32 = 32;
const CEXPR_L1H2: u32 = 64;
const CEXPR_H1L2: u32 = 128;
const CEXPR_H1H2: u32 = 256;
const CEXPR_L1H1: u32 = 512;
const CEXPR_L2H2: u32 = 1024;
const CEXPR_MLS_MASK: u32 =
    CEXPR_L1L2 | CEXPR_L1H2 | CEXPR_H1L2 | CEXPR_H1H2 | CEXPR_L1H1 | CEXPR_L2H2;

// Constraint expression operators.
const CEXPR_EQ: u32 = 1;
const CEXPR_NEQ: u32 = 2;
const CEXPR_DOM: u32 = 3;
const CEXPR_DOMBY: u32 = 4;
const CEXPR_INCOMP: u32 = 5;

// type_datum property flags (version >= BOUNDARY).
const TYPE_PROP_ATTRIBUTE: u32 = 0x0002;

// ---------------------------------------------------------------------------
// Intermediate symbol-table structures
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Perm {
    name: String,
    value: u32, // 1-based
}

struct ClassDatum {
    name: String,
    value: u32,
    common_name: Option<String>,
    perms: Vec<Perm>,
}

/// A single constraint-expression node, captured raw and rendered later (once
/// the type/role/user name maps are populated).
struct RawExpr {
    expr_type: u32,
    attr: u32,
    op: u32,
    names: Vec<u32>, // 1-based symbol values, for CEXPR_NAMES nodes
}

/// A constraint captured during class parsing, pending rendering.
struct RawConstraint {
    class_value: u32,
    perm_mask: u32,
    exprs: Vec<RawExpr>,
    validatetrans: bool,
}

/// A class with its full permission set (common-inherited + class-specific),
/// indexed by 0-based bit position for fast access-vector decoding.
struct ResolvedClass {
    name: String,
    perms: HashMap<u32, String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Parse a kernel binary policy blob into a queryable [`Policy`].
pub fn parse(data: &[u8]) -> Result<Policy, String> {
    let mut r = Reader::new(data);
    let mut policy = Policy::default();

    // ---- Header ----
    let magic = r.read_u32()?;
    if magic != SELINUX_MAGIC {
        return Err(format!(
            "not a SELinux kernel policy (magic {:#010x}, expected {:#010x})",
            magic, SELINUX_MAGIC
        ));
    }
    let str_len = r.read_u32()? as usize;
    policy.policy_kind = String::from_utf8_lossy(r.read_bytes(str_len)?).into_owned();

    let version = r.read_u32()?;
    if !(15..=35).contains(&version) {
        return Err(format!("unsupported policy version {}", version));
    }
    policy.version = version;

    let config = r.read_u32()?;
    let mls = config & 1 != 0;
    policy.mls = mls;

    let sym_num = r.read_u32()? as usize;
    let oclass_num = r.read_u32()? as usize;

    // ---- Leading ebitmaps (read here, not at the end) ----
    if version >= V_POLCAP {
        for bit in r.read_ebitmap()? {
            policy.policycaps.insert(policycap_name(bit));
        }
    }
    if version >= V_PERMISSIVE {
        r.skip_ebitmap()?; // permissive map (per-type permissive flags)
    }
    if version >= V_NEVERAUDIT {
        r.skip_ebitmap()?; // never-audit map
    }

    // ---- Symbol tables (each preceded by its own nprim/nel) ----
    let mut commons: HashMap<String, Vec<Perm>> = HashMap::new();
    let mut classes: Vec<ClassDatum> = Vec::new();
    let mut raw_constraints: Vec<RawConstraint> = Vec::new();
    let mut type_val_to_name: HashMap<u32, String> = HashMap::new();
    let mut role_val_to_name: HashMap<u32, String> = HashMap::new();
    let mut user_val_to_name: HashMap<u32, String> = HashMap::new();
    let mut attr_names: BTreeSet<String> = BTreeSet::new();
    let mut types_nprim: usize = 0;

    for sym_idx in 0..sym_num {
        let nprim = r.read_u32()? as usize;
        let nel = r.read_u32()?;
        match sym_idx {
            SYM_COMMONS => {
                for _ in 0..nel {
                    let (name, perms) = read_common(&mut r)?;
                    commons.insert(name, perms);
                }
            }
            SYM_CLASSES => {
                for _ in 0..nel {
                    let (cd, cons) = read_class(&mut r, version)?;
                    raw_constraints.extend(cons);
                    classes.push(cd);
                }
            }
            SYM_ROLES => {
                policy.role_count = nel as usize;
                for _ in 0..nel {
                    let (name, value) = read_role(&mut r, version)?;
                    role_val_to_name.insert(value, name);
                }
            }
            SYM_TYPES => {
                types_nprim = nprim;
                for _ in 0..nel {
                    let (name, value, is_attrib) = read_type(&mut r, version)?;
                    type_val_to_name.insert(value, name.clone());
                    if is_attrib {
                        attr_names.insert(name.clone());
                        policy.attributes.entry(name).or_default();
                    } else {
                        policy.types.insert(name);
                    }
                }
            }
            SYM_USERS => {
                policy.user_count = nel as usize;
                for _ in 0..nel {
                    let (name, value) = read_user(&mut r, version, mls)?;
                    user_val_to_name.insert(value, name);
                }
            }
            SYM_BOOLS => {
                for _ in 0..nel {
                    let (name, state) = read_bool(&mut r)?;
                    policy.booleans.insert(name, state);
                }
            }
            SYM_LEVELS => {
                for _ in 0..nel {
                    if let Some(name) = read_sens(&mut r)? {
                        policy.sensitivities.push(name);
                    }
                }
            }
            SYM_CATS => {
                for _ in 0..nel {
                    if let Some(name) = read_cat(&mut r)? {
                        policy.categories.push(name);
                    }
                }
            }
            _ => {}
        }
    }

    // ---- Resolve classes (merge common + class-specific perms) ----
    let mut class_map: HashMap<u32, ResolvedClass> = HashMap::new();
    for cd in &classes {
        let mut perms: HashMap<u32, String> = HashMap::new();
        if let Some(cn) = &cd.common_name {
            if let Some(common_perms) = commons.get(cn) {
                for p in common_perms {
                    perms.insert(p.value - 1, p.name.clone());
                }
            }
        }
        for p in &cd.perms {
            perms.insert(p.value - 1, p.name.clone());
        }
        let mut ordered: Vec<(u32, String)> = perms.iter().map(|(k, v)| (*k, v.clone())).collect();
        ordered.sort_by_key(|(k, _)| *k);
        policy
            .classes
            .insert(cd.name.clone(), ordered.into_iter().map(|(_, v)| v).collect());
        class_map.insert(
            cd.value,
            ResolvedClass {
                name: cd.name.clone(),
                perms,
            },
        );
    }

    // ---- Render constraints (now that name maps exist) ----
    let names = NameMaps {
        types: &type_val_to_name,
        roles: &role_val_to_name,
        users: &user_val_to_name,
    };
    for rc in &raw_constraints {
        let Some(class) = class_map.get(&rc.class_value) else {
            continue;
        };
        let (expr, mls) = render_constraint_expr(&rc.exprs, &names);
        if expr.is_empty() {
            continue;
        }
        let perms = if rc.validatetrans {
            Vec::new()
        } else {
            decode_perms(rc.perm_mask, class)
        };
        policy.constraints.push(Constraint {
            class: class.name.clone(),
            perms,
            expr,
            mls,
            validatetrans: rc.validatetrans,
        });
    }

    let ctx = Ctx {
        type_map: &type_val_to_name,
        class_map: &class_map,
    };

    // ---- Access-vector table ----
    let nel = r.read_u32()?;
    for _ in 0..nel {
        read_avtab_entry(&mut r, &ctx, &mut policy, false)?;
    }

    // ---- Conditional rules ----
    read_cond_list(&mut r, &ctx, &mut policy)?;

    // ---- Role transitions ----
    let role_tr_nel = r.read_u32()?;
    for _ in 0..role_tr_nel {
        r.skip(12)?; // role + type + new_role
        if version >= V_ROLETRANS {
            r.skip(4)?; // tclass
        }
    }

    // ---- Role allows ----
    let role_allow_nel = r.read_u32()?;
    r.skip(role_allow_nel as usize * 8)?;

    // ---- Filename transitions ----
    if version >= V_FILENAME_TRANS {
        read_filename_trans(&mut r, version, &ctx, &mut policy)?;
    }

    // ---- Object contexts ----
    for ocon_idx in 0..oclass_num {
        let nel = r.read_u32()?;
        for _ in 0..nel {
            skip_ocon_entry(&mut r, ocon_idx, mls)?;
        }
    }

    // ---- genfs contexts ----
    let genfs_nel = r.read_u32()?;
    for _ in 0..genfs_nel {
        let fstype = r.read_string()?;
        let ncon = r.read_u32()?;
        for _ in 0..ncon {
            let path = r.read_string()?;
            let _sclass = r.read_u32()?;
            let ctx_type = r.read_context_type(mls)?;
            policy.genfs.push(Genfs {
                fstype: fstype.clone(),
                path,
                context_type: ctx.type_name(ctx_type),
            });
        }
    }

    // ---- MLS range transitions ----
    if mls {
        let range_tr_nel = r.read_u32()?;
        for _ in 0..range_tr_nel {
            r.skip(8)?; // source_type + target_type
            if version >= 21 {
                r.skip(4)?; // target_class
            }
            r.skip_mls_range()?;
        }
    }

    // ---- Type-attribute map: type value -> set of its attributes ----
    if version >= V_AVTAB {
        for i in 0..types_nprim {
            let bits = r.read_ebitmap()?;
            let type_val = (i as u32) + 1;
            let Some(type_name) = type_val_to_name.get(&type_val) else {
                continue;
            };
            // A real type's map lists the attributes it belongs to; invert it
            // into attribute -> member-types.
            if attr_names.contains(type_name) {
                continue;
            }
            for bit in bits {
                let attr_val = bit + 1;
                if let Some(attr_name) = type_val_to_name.get(&attr_val) {
                    if let Some(members) = policy.attributes.get_mut(attr_name) {
                        members.insert(type_name.clone());
                    }
                }
            }
        }
    }

    Ok(policy)
}

fn policycap_name(bit: u32) -> String {
    const CAP_NAMES: &[&str] = &[
        "network_peer_controls",
        "open_perms",
        "extended_socket_class",
        "always_check_network",
        "cgroup_seclabel",
        "nnp_nosuid_transition",
        "genfs_seclabel_symlinks",
        "ioctl_skip_cloexec",
        "userspace_initial_context",
        "netlink_xperm",
        "netif_wildcard",
        "genfs_seclabel_wildcard",
    ];
    CAP_NAMES
        .get(bit as usize)
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("policycap_{}", bit))
}

/// Lookup tables shared by the rule readers.
struct Ctx<'a> {
    type_map: &'a HashMap<u32, String>,
    class_map: &'a HashMap<u32, ResolvedClass>,
}

impl Ctx<'_> {
    fn type_name(&self, val: u32) -> String {
        self.type_map
            .get(&val)
            .cloned()
            .unwrap_or_else(|| format!("type#{}", val))
    }

    fn class_name(&self, val: u32) -> String {
        self.class_map
            .get(&val)
            .map(|c| c.name.clone())
            .unwrap_or_else(|| format!("class#{}", val))
    }
}

// ---------------------------------------------------------------------------
// Symbol-table readers (keys are read AFTER the fixed-size fields)
// ---------------------------------------------------------------------------

fn read_perm(r: &mut Reader) -> Result<Perm, String> {
    let len = r.read_u32()? as usize;
    let value = r.read_u32()?;
    let name = r.read_key(len)?;
    Ok(Perm { name, value })
}

fn read_common(r: &mut Reader) -> Result<(String, Vec<Perm>), String> {
    let len = r.read_u32()? as usize;
    let _value = r.read_u32()?;
    let _nprim = r.read_u32()?;
    let nel = r.read_u32()?;
    let name = r.read_key(len)?;
    let mut perms = Vec::with_capacity(nel as usize);
    for _ in 0..nel {
        perms.push(read_perm(r)?);
    }
    Ok((name, perms))
}

fn read_class(r: &mut Reader, version: u32) -> Result<(ClassDatum, Vec<RawConstraint>), String> {
    let len = r.read_u32()? as usize;
    let common_len = r.read_u32()? as usize;
    let value = r.read_u32()?;
    let _nprim = r.read_u32()?;
    let nel = r.read_u32()?;
    let ncons = r.read_u32()?;

    let name = r.read_key(len)?;
    let common_name = if common_len > 0 {
        Some(r.read_key(common_len)?)
    } else {
        None
    };

    let mut perms = Vec::with_capacity(nel as usize);
    for _ in 0..nel {
        perms.push(read_perm(r)?);
    }

    let mut constraints = Vec::new();
    for _ in 0..ncons {
        constraints.push(read_constraint(r, version, value, false)?);
    }
    if version >= V_VALIDATETRANS {
        let nvtrans = r.read_u32()?;
        for _ in 0..nvtrans {
            constraints.push(read_constraint(r, version, value, true)?);
        }
    }
    if version >= V_NEW_OBJECT_DEFAULTS {
        r.skip(12)?; // default_user, default_role, default_range
    }
    if version >= V_DEFAULT_TYPE {
        r.skip(4)?; // default_type
    }

    Ok((
        ClassDatum {
            name,
            value,
            common_name,
            perms,
        },
        constraints,
    ))
}

/// A constraint: a permission mask, then a list of expression nodes (in
/// reverse-Polish order). Only `CEXPR_NAMES` nodes carry a names ebitmap (and,
/// on newer policies, a type name set) — reading one for any other node type
/// would desync the stream.
fn read_constraint(
    r: &mut Reader,
    version: u32,
    class_value: u32,
    validatetrans: bool,
) -> Result<RawConstraint, String> {
    let perm_mask = r.read_u32()?;
    let nexpr = r.read_u32()?;
    let mut exprs = Vec::with_capacity(nexpr as usize);
    for _ in 0..nexpr {
        let expr_type = r.read_u32()?;
        let attr = r.read_u32()?;
        let op = r.read_u32()?;
        let mut names = Vec::new();
        if expr_type == CEXPR_NAMES {
            names = r.read_ebitmap()?.into_iter().map(|b| b + 1).collect();
            if version >= V_CONSTRAINT_NAMES {
                r.skip_ebitmap()?; // type_names.types
                r.skip_ebitmap()?; // type_names.negset
                let _flags = r.read_u32()?;
            }
        }
        exprs.push(RawExpr {
            expr_type,
            attr,
            op,
            names,
        });
    }
    Ok(RawConstraint {
        class_value,
        perm_mask,
        exprs,
        validatetrans,
    })
}

fn read_role(r: &mut Reader, version: u32) -> Result<(String, u32), String> {
    let len = r.read_u32()? as usize;
    let value = r.read_u32()?;
    if version >= V_BOUNDARY {
        let _bounds = r.read_u32()?;
    }
    let name = r.read_key(len)?;
    r.skip_ebitmap()?; // dominates
    r.skip_ebitmap()?; // types
    Ok((name, value))
}

fn read_type(r: &mut Reader, version: u32) -> Result<(String, u32, bool), String> {
    let len = r.read_u32()? as usize;
    let value = r.read_u32()?;
    let is_attrib = if version >= V_BOUNDARY {
        let prop = r.read_u32()?;
        let _bounds = r.read_u32()?;
        prop & TYPE_PROP_ATTRIBUTE != 0
    } else {
        let primary = r.read_u32()?;
        primary == 0
    };
    let name = r.read_key(len)?;
    Ok((name, value, is_attrib))
}

fn read_user(r: &mut Reader, version: u32, mls: bool) -> Result<(String, u32), String> {
    let len = r.read_u32()? as usize;
    let value = r.read_u32()?;
    if version >= V_BOUNDARY {
        let _bounds = r.read_u32()?;
    }
    let name = r.read_key(len)?;
    r.skip_ebitmap()?; // roles
    if mls {
        r.skip_mls_range()?; // range
        r.skip_mls_level()?; // default level
    }
    Ok((name, value))
}

fn read_bool(r: &mut Reader) -> Result<(String, bool), String> {
    let len = r.read_u32()? as usize;
    let _value = r.read_u32()?;
    let state = r.read_u32()? != 0;
    let name = r.read_key(len)?;
    Ok((name, state))
}

/// A sensitivity datum; returns its name unless it's an alias.
fn read_sens(r: &mut Reader) -> Result<Option<String>, String> {
    let len = r.read_u32()? as usize;
    let isalias = r.read_u32()?;
    let name = r.read_key(len)?;
    r.skip_mls_level()?;
    Ok((isalias == 0).then_some(name))
}

/// A category datum; returns its name unless it's an alias.
fn read_cat(r: &mut Reader) -> Result<Option<String>, String> {
    let len = r.read_u32()? as usize;
    let _value = r.read_u32()?;
    let isalias = r.read_u32()?;
    let name = r.read_key(len)?;
    Ok((isalias == 0).then_some(name))
}

// ---------------------------------------------------------------------------
// Constraint expression rendering
// ---------------------------------------------------------------------------

/// Value -> name maps for resolving constraint name sets.
struct NameMaps<'a> {
    types: &'a HashMap<u32, String>,
    roles: &'a HashMap<u32, String>,
    users: &'a HashMap<u32, String>,
}

/// Render a constraint's reverse-Polish expression list into an infix string,
/// returning the string and whether it references MLS levels. Returns an empty
/// string if the expression can't be rendered (leaving an unbalanced stack).
fn render_constraint_expr(exprs: &[RawExpr], names: &NameMaps) -> (String, bool) {
    let mut stack: Vec<String> = Vec::new();
    let mut mls = false;

    for e in exprs {
        match e.expr_type {
            CEXPR_NOT => {
                let Some(a) = stack.pop() else {
                    return (String::new(), mls);
                };
                stack.push(format!("not ({})", a));
            }
            CEXPR_AND | CEXPR_OR => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    return (String::new(), mls);
                };
                let kw = if e.expr_type == CEXPR_AND { "and" } else { "or" };
                stack.push(format!("{} {} {}", a, kw, b));
            }
            CEXPR_ATTR => {
                if e.attr & CEXPR_MLS_MASK != 0 {
                    mls = true;
                }
                let (lhs, rhs) = attr_operands(e.attr);
                stack.push(format!("{} {} {}", lhs, op_symbol(e.op), rhs));
            }
            CEXPR_NAMES => {
                let lhs = names_lhs(e.attr);
                let map = if e.attr & CEXPR_USER != 0 {
                    names.users
                } else if e.attr & CEXPR_ROLE != 0 {
                    names.roles
                } else {
                    names.types
                };
                let mut resolved: Vec<String> = e
                    .names
                    .iter()
                    .map(|v| map.get(v).cloned().unwrap_or_else(|| format!("#{}", v)))
                    .collect();
                resolved.sort();
                let set = match resolved.len() {
                    1 => resolved.into_iter().next().unwrap(),
                    _ => format!("{{ {} }}", resolved.join(" ")),
                };
                stack.push(format!("{} {} {}", lhs, op_symbol(e.op), set));
            }
            _ => return (String::new(), mls),
        }
    }

    match stack.len() {
        1 => (stack.pop().unwrap(), mls),
        _ => (String::new(), mls),
    }
}

/// The left/right operands for a `CEXPR_ATTR` comparison.
fn attr_operands(attr: u32) -> (&'static str, &'static str) {
    if attr & CEXPR_L1L2 != 0 {
        ("l1", "l2")
    } else if attr & CEXPR_L1H2 != 0 {
        ("l1", "h2")
    } else if attr & CEXPR_H1L2 != 0 {
        ("h1", "l2")
    } else if attr & CEXPR_H1H2 != 0 {
        ("h1", "h2")
    } else if attr & CEXPR_L1H1 != 0 {
        ("l1", "h1")
    } else if attr & CEXPR_L2H2 != 0 {
        ("l2", "h2")
    } else if attr & CEXPR_USER != 0 {
        ("u1", "u2")
    } else if attr & CEXPR_ROLE != 0 {
        ("r1", "r2")
    } else if attr & CEXPR_TYPE != 0 {
        ("t1", "t2")
    } else {
        ("?", "?")
    }
}

/// The left-hand operand for a `CEXPR_NAMES` comparison (against a name set).
fn names_lhs(attr: u32) -> &'static str {
    let target = attr & (CEXPR_TARGET | CEXPR_XTARGET) != 0;
    if attr & CEXPR_USER != 0 {
        if target {
            "u2"
        } else {
            "u1"
        }
    } else if attr & CEXPR_ROLE != 0 {
        if target {
            "r2"
        } else {
            "r1"
        }
    } else if target {
        "t2"
    } else {
        "t1"
    }
}

fn op_symbol(op: u32) -> &'static str {
    match op {
        CEXPR_EQ => "==",
        CEXPR_NEQ => "!=",
        CEXPR_DOM => "dom",
        CEXPR_DOMBY => "domby",
        CEXPR_INCOMP => "incomp",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// Access-vector / extended-permission decoding
// ---------------------------------------------------------------------------

fn decode_perms(mask: u32, class: &ResolvedClass) -> Vec<String> {
    let mut perms: Vec<String> = (0..32u32)
        .filter(|bit| mask & (1 << bit) != 0)
        .filter_map(|bit| class.perms.get(&bit).cloned())
        .collect();
    perms.sort();
    perms
}

/// Coalesce a sorted list of command numbers into inclusive ranges.
fn coalesce(mut cmds: Vec<u32>) -> Vec<(u32, u32)> {
    cmds.sort_unstable();
    cmds.dedup();
    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for c in cmds {
        match ranges.last_mut() {
            Some(last) if c == last.1 + 1 => last.1 = c,
            _ => ranges.push((c, c)),
        }
    }
    ranges
}

fn read_avtab_entry(
    r: &mut Reader,
    ctx: &Ctx,
    policy: &mut Policy,
    conditional: bool,
) -> Result<(), String> {
    let source = r.read_u16()? as u32;
    let target = r.read_u16()? as u32;
    let tclass = r.read_u16()? as u32;
    let specified = r.read_u16()?;

    // Extended permissions (ioctl / nlmsg whitelists).
    if specified & AVTAB_XPERMS != 0 {
        let xspec = r.read_u8()?;
        let driver = r.read_u8()? as u32;
        let map_bytes = r.read_bytes(32)?;
        let (Some(src), Some(tgt), Some(class)) = (
            ctx.type_map.get(&source),
            ctx.type_map.get(&target),
            ctx.class_map.get(&tclass),
        ) else {
            return Ok(());
        };

        let mut set_bits = Vec::new();
        for (i, chunk) in map_bytes.chunks_exact(4).enumerate() {
            let word = u32::from_le_bytes(chunk.try_into().unwrap());
            for bit in 0..32u32 {
                if word & (1 << bit) != 0 {
                    set_bits.push(i as u32 * 32 + bit);
                }
            }
        }
        let cmds: Vec<u32> = match xspec {
            AVTAB_XPERMS_IOCTLFUNCTION => set_bits.iter().map(|b| (driver << 8) | b).collect(),
            AVTAB_XPERMS_IOCTLDRIVER => set_bits
                .iter()
                .flat_map(|b| (0..256u32).map(move |f| (b << 8) | f))
                .collect(),
            _ => set_bits,
        };
        if cmds.is_empty() {
            return Ok(());
        }
        let kind = if specified & AVTAB_XPERMS_ALLOWED != 0 {
            XpermKind::AllowXperm
        } else if specified & AVTAB_XPERMS_AUDITALLOW != 0 {
            XpermKind::AuditAllowXperm
        } else {
            XpermKind::DontAuditXperm
        };
        policy.xperm_rules.push(XpermRule {
            kind,
            source: src.clone(),
            target: tgt.clone(),
            class: class.name.clone(),
            op: "ioctl".to_string(),
            ranges: coalesce(cmds),
        });
        return Ok(());
    }

    let datum = r.read_u32()?;
    let (Some(src), Some(tgt), Some(class)) = (
        ctx.type_map.get(&source),
        ctx.type_map.get(&target),
        ctx.class_map.get(&tclass),
    ) else {
        return Ok(());
    };

    // type_transition / type_member / type_change: datum is a type value.
    if specified & (AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE) != 0 {
        let kind = if specified & AVTAB_TRANSITION != 0 {
            TeKind::Transition
        } else if specified & AVTAB_MEMBER != 0 {
            TeKind::Member
        } else {
            TeKind::Change
        };
        policy.te_rules.push(TeRule {
            kind,
            source: src.clone(),
            target: tgt.clone(),
            class: class.name.clone(),
            default: ctx.type_name(datum),
            object_name: None,
        });
        return Ok(());
    }

    if specified & AVTAB_ALLOWED != 0 {
        push_av(policy, AvKind::Allow, src, tgt, class, datum, conditional);
    }
    if specified & AVTAB_AUDITALLOW != 0 {
        push_av(policy, AvKind::AuditAllow, src, tgt, class, datum, conditional);
    }
    if specified & AVTAB_AUDITDENY != 0 {
        // auditdeny stores the perms that ARE audited on denial; dontaudit is
        // the complement against the class's full permission set.
        let max_bit = class.perms.keys().max().copied().unwrap_or(0);
        let full_mask = if max_bit < 31 {
            (1u32 << (max_bit + 1)) - 1
        } else {
            u32::MAX
        };
        let dontaudit_mask = !datum & full_mask;
        push_av(policy, AvKind::DontAudit, src, tgt, class, dontaudit_mask, conditional);
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_av(
    policy: &mut Policy,
    kind: AvKind,
    src: &str,
    tgt: &str,
    class: &ResolvedClass,
    mask: u32,
    conditional: bool,
) {
    let perms = decode_perms(mask, class);
    if perms.is_empty() {
        return;
    }
    policy.av_rules.push(AvRule {
        kind,
        source: src.to_string(),
        target: tgt.to_string(),
        class: class.name.clone(),
        perms,
        conditional,
    });
}

fn read_cond_list(r: &mut Reader, ctx: &Ctx, policy: &mut Policy) -> Result<(), String> {
    let nel = r.read_u32()?;
    for _ in 0..nel {
        let _cur_state = r.read_u32()?;
        let expr_len = r.read_u32()?;
        r.skip(expr_len as usize * 8)?; // expr_type + bool_val per node

        let true_nel = r.read_u32()?;
        for _ in 0..true_nel {
            read_avtab_entry(r, ctx, policy, true)?;
        }
        let false_nel = r.read_u32()?;
        for _ in 0..false_nel {
            read_avtab_entry(r, ctx, policy, true)?;
        }
    }
    Ok(())
}

fn read_filename_trans(
    r: &mut Reader,
    version: u32,
    ctx: &Ctx,
    policy: &mut Policy,
) -> Result<(), String> {
    let nel = r.read_u32()?;
    if version >= V_COMP_FTRANS {
        // Compressed: one record per (ttype, tclass, name), with a list of
        // (source-type set, otype) data.
        for _ in 0..nel {
            let name = r.read_string()?;
            let ttype = r.read_u32()?;
            let tclass = r.read_u32()?;
            let ndatum = r.read_u32()?;
            for _ in 0..ndatum {
                let stypes = r.read_ebitmap()?;
                let otype = r.read_u32()?;
                for sbit in stypes {
                    policy.te_rules.push(TeRule {
                        kind: TeKind::Transition,
                        source: ctx.type_name(sbit + 1),
                        target: ctx.type_name(ttype),
                        class: ctx.class_name(tclass),
                        default: ctx.type_name(otype),
                        object_name: Some(name.clone()),
                    });
                }
            }
        }
    } else {
        // Legacy: one record per (stype, ttype, tclass, name).
        for _ in 0..nel {
            let name = r.read_string()?;
            let stype = r.read_u32()?;
            let ttype = r.read_u32()?;
            let tclass = r.read_u32()?;
            let otype = r.read_u32()?;
            policy.te_rules.push(TeRule {
                kind: TeKind::Transition,
                source: ctx.type_name(stype),
                target: ctx.type_name(ttype),
                class: ctx.class_name(tclass),
                default: ctx.type_name(otype),
                object_name: Some(name),
            });
        }
    }
    Ok(())
}

fn skip_ocon_entry(r: &mut Reader, idx: usize, mls: bool) -> Result<(), String> {
    match idx {
        0 => {
            // ISID: sid(u32) + context
            r.skip(4)?;
            r.skip_context(mls)?;
        }
        1 | 3 => {
            // FS / NETIF: name + context + context
            let _name = r.read_string()?;
            r.skip_context(mls)?;
            r.skip_context(mls)?;
        }
        2 => {
            // PORT: protocol + low + high + context
            r.skip(12)?;
            r.skip_context(mls)?;
        }
        4 => {
            // NODE: addr + mask + context
            r.skip(8)?;
            r.skip_context(mls)?;
        }
        5 => {
            // FSUSE: behavior + name + context
            let _behavior = r.read_u32()?;
            let _name = r.read_string()?;
            r.skip_context(mls)?;
        }
        6 => {
            // NODE6: addr(4*u32) + mask(4*u32) + context
            r.skip(32)?;
            r.skip_context(mls)?;
        }
        7 => {
            // IBPKEY: subnet_prefix(u64) + low(u32) + high(u32) + context
            r.skip(16)?;
            r.skip_context(mls)?;
        }
        8 => {
            // IBENDPORT: name + port + context
            let _name = r.read_string()?;
            let _port = r.read_u32()?;
            r.skip_context(mls)?;
        }
        _ => return Err(format!("unknown object-context index {}", idx)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        assert!(parse(&[0u8; 32]).is_err());
        assert!(parse(b"not a policy at all").unwrap_err().contains("not a SELinux"));
    }

    #[test]
    fn rejects_truncated() {
        let mut data = vec![0x8C, 0xFF, 0x7C, 0xF9];
        data.extend_from_slice(&[0; 20]);
        let err = parse(&data).unwrap_err();
        assert!(err.contains("EOF") || err.contains("unsupported"), "got: {err}");
    }

    #[test]
    fn decode_perms_orders_alphabetically() {
        let mut perms = HashMap::new();
        perms.insert(0, "read".to_string());
        perms.insert(1, "write".to_string());
        perms.insert(2, "execute".to_string());
        let class = ResolvedClass {
            name: "file".into(),
            perms,
        };
        assert_eq!(decode_perms(0b101, &class), vec!["execute", "read"]);
        assert_eq!(decode_perms(0b010, &class), vec!["write"]);
    }

    #[test]
    fn coalesces_ranges() {
        assert_eq!(coalesce(vec![3, 1, 2, 5]), vec![(1, 3), (5, 5)]);
        assert_eq!(coalesce(vec![]), Vec::<(u32, u32)>::new());
        assert_eq!(coalesce(vec![7, 7, 8]), vec![(7, 8)]);
    }

    #[test]
    fn parses_synthetic_policy() {
        let blob = crate::testgen::minimal_policy();
        let p = parse(&blob).expect("synthetic policy should parse");
        assert_eq!(p.version, 30);
        assert!(p.types.contains("source_t"));
        assert!(p.types.contains("target_t"));
        assert!(p.classes.contains_key("file"));
        let allow = p
            .av_rules
            .iter()
            .find(|r| r.kind == AvKind::Allow)
            .expect("should have an allow rule");
        assert_eq!(allow.source, "source_t");
        assert_eq!(allow.target, "target_t");
        assert_eq!(allow.class, "file");
        assert!(allow.perms.contains(&"read".to_string()));
        assert!(allow.perms.contains(&"write".to_string()));
    }
}
