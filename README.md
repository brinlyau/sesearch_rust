# sesearch_rust

A self-contained, dependency-free Rust tool for parsing and querying **SELinux
binary kernel policies** — Android's `sepolicy` / `precompiled_sepolicy`, or
`/sys/fs/selinux/policy` on a live Linux/Android system.

It's a focused reimplementation of the parts of [SETools'](https://github.com/SELinuxProject/setools)
`sesearch` and `seinfo` that work against a *compiled* policy blob, with no
need for `libsepol`, `setools`, Python, or any system SELinux libraries. That
makes it usable on **macOS** and anywhere else those tools won't build — point
it at a policy file pulled off a device and query away.

```console
$ sesearch_rust -A -s untrusted_app -c file precompiled_sepolicy
allow appdomain apk_data_file:file { execute execute_no_trans getattr ioctl lock map open read };
allow appdomain app_fuse_file:file { append getattr map read write };
...
```

## Why

`sesearch` proper depends on `libsepol`, which is awkward or impossible to build
on macOS. When you've extracted a `precompiled_sepolicy` from a firmware image
or device and just want to ask "what can this domain do?", you shouldn't need a
Linux VM. This tool parses the binary format directly in safe Rust and answers
the common queries.

## Build & install

Requires a recent Rust toolchain (2021 edition).

```console
$ cargo build --release
$ ./target/release/sesearch_rust --help
```

The binary has **no runtime dependencies** and no crates beyond the standard
library.

## Usage

```
sesearch_rust [RULE TYPES] [FILTERS] [OPTIONS] <policy>
```

`<policy>` is a compiled kernel policy blob.

### Rule types

Pick one or more; matching rules are printed.

| Flag | Rules |
|------|-------|
| `-A`, `--allow` | `allow` rules |
| `--auditallow` | `auditallow` rules |
| `--dontaudit` | `dontaudit` rules |
| `-T`, `--type_trans` | `type_transition` / `type_member` / `type_change` (incl. filename transitions) |
| `-X`, `--xperm` | extended-permission (ioctl) rules |
| `--all-rules` | all of the above |

### Filters

| Flag | Effect |
|------|--------|
| `-s`, `--source <NAME>` | source type/attribute |
| `-t`, `--target <NAME>` | target type/attribute |
| `-c`, `--class <NAME>` | object class |
| `-p`, `--perm <P[,P..]>` | match rules granting **any** of these permissions |
| `-d`, `--direct` | literal matching only (don't expand attributes) |

By default, type filters match **semantically**: querying `-s untrusted_app`
also returns rules written on any attribute `untrusted_app` belongs to (e.g.
`appdomain`), and querying an attribute returns rules on its member types.
`--direct` disables that and matches the literal name only.

### Info (seinfo-style)

Printed instead of rules:

| Flag | Output |
|------|--------|
| `--stats` | summary counts and policy metadata |
| `--types` | all concrete types |
| `--attributes` | all type attributes |
| `--classes` | object classes and their permissions |
| `--booleans` | booleans and default state |
| `--policycaps` | enabled policy capabilities |
| `--genfs` | `genfscon` entries |
| `--expand <ATTR>` | the member types of an attribute |

### Options

| Flag | Effect |
|------|--------|
| `--json` | emit results as JSON |
| `-n`, `--limit <N>` | print at most N rules |
| `-h`, `--help` | help |
| `-V`, `--version` | version |

## Examples

```console
# Everything untrusted_app can do to files (semantically, via its attributes)
$ sesearch_rust -A -s untrusted_app -c file precompiled_sepolicy

# Who can execute_no_trans anything?
$ sesearch_rust -A -p execute_no_trans precompiled_sepolicy

# Domain transitions out of init
$ sesearch_rust -T -s init precompiled_sepolicy
type_transition init adbd_exec:process adbd;
...

# ioctl whitelists for adbd
$ sesearch_rust -X -s adbd precompiled_sepolicy
allowxperm adbd functionfs:file ioctl { 0x6703 0x6782 };
...

# Policy overview
$ sesearch_rust --stats precompiled_sepolicy
Policy kind:       SE Linux
Policy version:    30
MLS enabled:       true
Types:             2707
Attributes:        205
Classes:           107
allow rules:       54324
...

# What types make up the `domain` attribute?
$ sesearch_rust --expand domain precompiled_sepolicy

# Machine-readable output (--direct so the source is literally `shell`)
$ sesearch_rust -A -s shell -d --json precompiled_sepolicy | jq '.[0]'
{
  "rule_type": "allow",
  "source": "shell",
  "target": "shell_data_file",
  "class": "file",
  "perms": ["append", "create", ...],
  "conditional": false
}
```

## What it parses

From the compiled `policydb`:

- **Header**: magic, policy kind string, version (15–35), MLS flag.
- **Symbol tables**: commons, classes (with full permission sets, common
  permissions inherited), roles, types, **attributes** (with membership),
  users, booleans, sensitivities, categories.
- **Access vectors**: `allow`, `auditallow`, and `dontaudit` (reconstructed
  from the `auditdeny` mask), including rules inside conditional (`if`) blocks.
- **Extended permissions**: `allowxperm` / `auditallowxperm` / `dontauditxperm`
  ioctl rules, with command bitmaps decoded into coalesced hex ranges.
- **Type rules**: `type_transition` / `type_member` / `type_change`, plus
  name-based filename transitions (both the legacy and compressed on-disk
  layouts).
- **Contexts**: `genfscon` entries; policy capabilities.

### Known limitations

- **`neverallow`** rules are *not* present in a compiled kernel policy — they're
  compile-time assertions checked by `checkpolicy`/`secilc` and discarded. This
  tool can't show them. (A future CIL/`.te` front end could.)
- MLS levels/categories and constraint expressions are parsed for correct
  stream alignment but not surfaced as queryable output.
- Object contexts other than `genfscon` (ports, nodes, fs_use, …) are skipped
  (parsed only enough to stay aligned).

## How it works

The kernel `policydb` is a flat, little-endian binary blob with no internal
offsets, so it must be read strictly sequentially. The layout follows the
kernel's `policydb_read`:

```
header
  └ magic, policy-kind string, version, config (MLS), sym_num, ocon_num
policycaps ebitmap        (version ≥ 22)
permissive ebitmap        (version ≥ 23)
neveraudit ebitmap        (version ≥ 34)
for each symbol table:    (commons, classes, roles, types, users, bools, levels, cats)
  └ nprim, nel, then nel datums      ← sizes are INTERLEAVED, not front-loaded
access-vector table
conditional rule lists
role transitions / role allows
filename transitions       (version ≥ 25; compressed form ≥ 33)
object contexts
genfs contexts
MLS range transitions      (MLS policies)
type-attribute map         (version ≥ 20)
```

A few format details that commonly trip up naive parsers, and which this tool
gets right:

- The per-symbol-table `(nprim, nel)` counts are **interleaved** with each
  table's data, not all written up front.
- The policy-capability and permissive ebitmaps live at the **front**, right
  after the header — not at the end.
- Symbol-table datums (common, class, type, perm, …) store their fixed-size
  fields **first** and the variable-length name key **after** them.
- A class header is six `u32`s: `name_len, common_key_len, value, nprim, nel,
  ncons` — the common-class reference length is the second field.
- A constraint expression node carries a names ebitmap **only** when its
  `expr_type` is `CEXPR_NAMES`; reading one unconditionally desyncs the stream.
- An MLS range is `items`-prefixed: when `items == 1` only a single
  sensitivity and category set are stored (the high bound mirrors the low).
- Attribute membership comes from inverting the on-disk type→attributes map
  into attribute→member-types.

### Crate layout

| Module | Responsibility |
|--------|----------------|
| `reader.rs` | bounds-checked little-endian cursor (primitives, strings, ebitmaps, MLS, contexts) |
| `parser.rs` | the sequential `policydb` walk → structured `Policy` |
| `policy.rs` | the queryable data model and the `Query` filter engine |
| `json.rs` | minimal JSON serializer |
| `main.rs` | CLI argument parsing and output |
| `testgen.rs` | synthetic policy generator for tests |

## Tests

```console
$ cargo test
```

The suite includes unit tests for the byte reader, permission decoding, ioctl
range coalescing, and the query/attribute-expansion logic, plus an end-to-end
test that assembles a complete synthetic v30 policy in memory, parses it, and
drives the compiled binary against it.

## Credit

The binary-format walk was informed by the kernel's
[`security/selinux/ss/policydb.c`](https://github.com/torvalds/linux/blob/master/security/selinux/ss/policydb.c)
and the SETools project.

## License

MIT
