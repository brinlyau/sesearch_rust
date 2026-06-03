//! Synthetic policy generator used by the test suite and as a CLI fixture.
//!
//! Hand-assembling a minimal but structurally complete `policydb` lets the
//! parser be exercised end to end — header, the leading policy-capability and
//! permissive ebitmaps, every symbol table, the access-vector table, and all
//! the trailing sections — without committing a real (large, license-
//! encumbered) `sepolicy` blob to the repository. The byte layout matches the
//! kernel's `policydb_read`, so any drift between parser and format shows up as
//! a failing test.

/// A tiny little-endian writer mirroring `Reader`'s read order.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    /// Raw key bytes (length is written separately as a preceding field).
    fn key(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }
    /// A length-prefixed string (used by genfs/filename-trans/ocontext).
    fn string(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.key(s);
    }
    /// An ebitmap (mapsize, highbit, count) followed by `(startbit, map)` nodes.
    fn ebitmap(&mut self, highbit: u32, nodes: &[(u32, u64)]) {
        self.u32(64); // mapsize (ignored by reader)
        self.u32(highbit);
        self.u32(nodes.len() as u32);
        for (startbit, map) in nodes {
            self.u32(*startbit);
            self.buf.extend_from_slice(&map.to_le_bytes());
        }
    }
    fn ebitmap_empty(&mut self) {
        self.ebitmap(0, &[]);
    }
    /// A perm datum: len, value, key.
    fn perm(&mut self, name: &str, value: u32) {
        self.u32(name.len() as u32);
        self.u32(value);
        self.key(name);
    }
}

/// Build a minimal version-30, non-MLS policy:
/// types `source_t` (val 1) and `target_t` (val 2), class `file` with perms
/// read/write/execute, one policy capability, and a single
/// `allow source_t target_t:file { read write };` rule.
pub fn minimal_policy() -> Vec<u8> {
    let mut w = Writer::new();

    // ---- Header ----
    w.u32(0xF97C_FF8C); // magic
    w.string("SE Linux"); // policydb kind
    w.u32(30); // version
    w.u32(0); // config: MLS off
    w.u32(8); // sym_num
    w.u32(0); // oclass_num (no object contexts)

    // ---- Leading ebitmaps (v30 >= POLCAP(22) and PERMISSIVE(23)) ----
    w.ebitmap(64, &[(0, 0b11)]); // policycaps: bits 0,1
    w.ebitmap_empty(); // permissive map

    // ---- SYM_COMMONS: none ----
    w.u32(0); // nprim
    w.u32(0); // nel

    // ---- SYM_CLASSES: class "file" ----
    w.u32(1); // nprim
    w.u32(1); // nel
    // class_read header: len, common_len, value, nprim, nel, ncons
    w.u32("file".len() as u32);
    w.u32(0); // no common
    w.u32(1); // value
    w.u32(3); // nprim
    w.u32(3); // nel (perms)
    w.u32(1); // ncons
    w.key("file");
    w.perm("read", 1);
    w.perm("write", 2);
    w.perm("execute", 3);
    // one constraint: constrain file { write } (u1 == u2)
    w.u32(0b010); // permission mask: write
    w.u32(1); // nexpr
    w.u32(4); // expr_type = CEXPR_ATTR
    w.u32(1); // attr = CEXPR_USER
    w.u32(1); // op = CEXPR_EQ
    w.u32(0); // nvalidatetrans (v>=19)
    w.u32(0); // default_user
    w.u32(0); // default_role
    w.u32(0); // default_range
    w.u32(0); // default_type (v>=28)

    // ---- SYM_ROLES: "object_r" ----
    w.u32(1); // nprim
    w.u32(1); // nel
    w.u32("object_r".len() as u32); // len
    w.u32(1); // value
    w.u32(0); // bounds (v>=24)
    w.key("object_r");
    w.ebitmap_empty(); // dominates
    w.ebitmap_empty(); // types

    // ---- SYM_TYPES: source_t (val 1), target_t (val 2) ----
    w.u32(2); // nprim
    w.u32(2); // nel
    for (name, val) in [("source_t", 1u32), ("target_t", 2u32)] {
        w.u32(name.len() as u32); // len
        w.u32(val); // value
        w.u32(0); // properties: not an attribute (v>=24)
        w.u32(0); // bounds
        w.key(name);
    }

    // ---- SYM_USERS: "system_u" ----
    w.u32(1); // nprim
    w.u32(1); // nel
    w.u32("system_u".len() as u32); // len
    w.u32(1); // value
    w.u32(0); // bounds (v>=24)
    w.key("system_u");
    w.ebitmap_empty(); // roles

    // ---- SYM_BOOLS / LEVELS / CATS: none ----
    for _ in 0..3 {
        w.u32(0); // nprim
        w.u32(0); // nel
    }

    // ---- Access vector table: allow source_t target_t:file { read write } ----
    w.u32(1); // nel
    w.u16(1); // source = source_t
    w.u16(2); // target = target_t
    w.u16(1); // tclass = file
    w.u16(0x0001); // specified = AVTAB_ALLOWED
    w.u32(0b011); // perm mask: read(bit0) + write(bit1)

    // ---- Conditional list / role trans / role allow / filename trans ----
    w.u32(0); // cond list nel
    w.u32(0); // role transition nel
    w.u32(0); // role allow nel
    w.u32(0); // filename transition nel (v>=25, < COMP_FTRANS)

    // No object contexts (oclass_num == 0).
    w.u32(0); // genfs nel

    // No MLS range transitions (MLS off).

    // ---- Type-attribute map (v>=AVTAB): one ebitmap per type (nprim = 2) ----
    w.ebitmap_empty();
    w.ebitmap_empty();

    w.buf
}
