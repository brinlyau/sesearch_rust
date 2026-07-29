/*
 * sepolicy.js — SELinux kernel binary policy (`policydb`) parser in plain
 * JavaScript. A direct port of sesearch_rust's reader.rs / parser.rs /
 * policy.rs: parses Android `sepolicy` / `precompiled_sepolicy` blobs (or
 * `/sys/fs/selinux/policy`) entirely client-side, with no dependencies.
 *
 * Works in the browser (window.SePolicy) and in Node (module.exports), the
 * latter so the parser can be diffed against the Rust implementation.
 */
(function (global) {
  'use strict';

  var SELINUX_MAGIC = 0xf97cff8c;

  // policydb version gates (kernel policy).
  var V_VALIDATETRANS = 19;
  var V_AVTAB = 20;
  var V_POLCAP = 22;
  var V_PERMISSIVE = 23;
  var V_BOUNDARY = 24;
  var V_FILENAME_TRANS = 25;
  var V_ROLETRANS = 26;
  var V_NEW_OBJECT_DEFAULTS = 27;
  var V_DEFAULT_TYPE = 28;
  var V_CONSTRAINT_NAMES = 29;
  var V_COMP_FTRANS = 33;
  var V_NEVERAUDIT = 34;

  // Symbol-table indices, in file order.
  var SYM_COMMONS = 0;
  var SYM_CLASSES = 1;
  var SYM_ROLES = 2;
  var SYM_TYPES = 3;
  var SYM_USERS = 4;
  var SYM_BOOLS = 5;
  var SYM_LEVELS = 6;
  var SYM_CATS = 7;

  // avtab "specified" flags.
  var AVTAB_ALLOWED = 0x0001;
  var AVTAB_AUDITALLOW = 0x0002;
  var AVTAB_AUDITDENY = 0x0004;
  var AVTAB_TRANSITION = 0x0010;
  var AVTAB_MEMBER = 0x0020;
  var AVTAB_CHANGE = 0x0040;
  var AVTAB_XPERMS_ALLOWED = 0x0100;
  var AVTAB_XPERMS_AUDITALLOW = 0x0200;
  var AVTAB_XPERMS_DONTAUDIT = 0x0400;
  var AVTAB_XPERMS = AVTAB_XPERMS_ALLOWED | AVTAB_XPERMS_AUDITALLOW | AVTAB_XPERMS_DONTAUDIT;

  var AVTAB_XPERMS_IOCTLFUNCTION = 1;
  var AVTAB_XPERMS_IOCTLDRIVER = 2;

  // Constraint expression node types.
  var CEXPR_NOT = 1;
  var CEXPR_AND = 2;
  var CEXPR_OR = 3;
  var CEXPR_ATTR = 4;
  var CEXPR_NAMES = 5;

  // Constraint expression attribute flags.
  var CEXPR_USER = 1;
  var CEXPR_ROLE = 2;
  var CEXPR_TYPE = 4;
  var CEXPR_TARGET = 8;
  var CEXPR_XTARGET = 16;
  var CEXPR_L1L2 = 32;
  var CEXPR_L1H2 = 64;
  var CEXPR_H1L2 = 128;
  var CEXPR_H1H2 = 256;
  var CEXPR_L1H1 = 512;
  var CEXPR_L2H2 = 1024;
  var CEXPR_MLS_MASK = CEXPR_L1L2 | CEXPR_L1H2 | CEXPR_H1L2 | CEXPR_H1H2 | CEXPR_L1H1 | CEXPR_L2H2;

  // Constraint expression operators.
  var CEXPR_EQ = 1;
  var CEXPR_NEQ = 2;
  var CEXPR_DOM = 3;
  var CEXPR_DOMBY = 4;
  var CEXPR_INCOMP = 5;

  // type_datum property flags (version >= BOUNDARY).
  var TYPE_PROP_ATTRIBUTE = 0x0002;

  var FS_USE_NAMES = ['fs_use_none', 'fs_use_xattr', 'fs_use_trans', 'fs_use_task'];

  // The standard initial-SID names, indexed by 1-based SID value.
  var INITIAL_SID_NAMES = [
    'kernel', 'security', 'unlabeled', 'fs', 'file', 'file_labels', 'init',
    'any_socket', 'port', 'netif', 'netmsg', 'node', 'igmp_packet',
    'icmp_socket', 'tcp_socket', 'sysctl_modprobe', 'sysctl', 'sysctl_fs',
    'sysctl_kernel', 'sysctl_net', 'sysctl_net_unix', 'sysctl_vm',
    'sysctl_dev', 'kmod', 'policy', 'scmp_packet', 'devnull',
  ];

  var POLICYCAP_NAMES = [
    'network_peer_controls', 'open_perms', 'extended_socket_class',
    'always_check_network', 'cgroup_seclabel', 'nnp_nosuid_transition',
    'genfs_seclabel_symlinks', 'ioctl_skip_cloexec',
    'userspace_initial_context', 'netlink_xperm', 'netif_wildcard',
    'genfs_seclabel_wildcard',
  ];

  function policycapName(bit) {
    return POLICYCAP_NAMES[bit] || 'policycap_' + bit;
  }

  function protocolName(proto) {
    switch (proto) {
      case 6: return 'tcp';
      case 17: return 'udp';
      case 33: return 'dccp';
      case 132: return 'sctp';
      default: return 'proto/' + proto;
    }
  }

  var utf8 = new TextDecoder('utf-8');

  // -------------------------------------------------------------------------
  // Reader: sequential, bounds-checked little-endian cursor over the blob.
  // -------------------------------------------------------------------------

  function Reader(bytes) {
    this.b = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }

  Reader.prototype.ensure = function (n) {
    if (this.pos + n > this.b.length) {
      throw new Error(
        'unexpected EOF at offset 0x' + this.pos.toString(16) +
        ': need ' + n + ' more byte(s), have ' + (this.b.length - this.pos)
      );
    }
  };

  Reader.prototype.u8 = function () {
    this.ensure(1);
    return this.b[this.pos++];
  };

  Reader.prototype.u16 = function () {
    this.ensure(2);
    var v = this.dv.getUint16(this.pos, true);
    this.pos += 2;
    return v;
  };

  Reader.prototype.u32 = function () {
    this.ensure(4);
    var v = this.dv.getUint32(this.pos, true);
    this.pos += 4;
    return v;
  };

  Reader.prototype.bytes = function (n) {
    this.ensure(n);
    var s = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return s;
  };

  Reader.prototype.skip = function (n) {
    this.ensure(n);
    this.pos += n;
  };

  // A key of already-known length; a trailing NUL is tolerated and stripped.
  Reader.prototype.key = function (len) {
    if (len === 0) return '';
    var bytes = this.bytes(len);
    var end = bytes.indexOf(0);
    if (end < 0) end = len;
    return utf8.decode(bytes.subarray(0, end));
  };

  // A length-prefixed string: u32 byte length followed by the raw bytes.
  Reader.prototype.string = function () {
    var len = this.u32();
    return this.key(len);
  };

  // Read an ebitmap and return the indices of every set bit.
  // Layout: mapsize(u32), highbit(u32), count(u32), then `count` nodes of
  // startbit(u32) + map(u64). The u64 is read as two little-endian u32 halves.
  Reader.prototype.ebitmap = function () {
    this.u32(); // mapsize
    var highbit = this.u32();
    var count = this.u32();
    var bits = [];
    if (highbit === 0) return bits;
    for (var i = 0; i < count; i++) {
      var startbit = this.u32();
      var lo = this.u32();
      var hi = this.u32();
      for (var bit = 0; bit < 32; bit++) {
        if (lo & (1 << bit)) bits.push(startbit + bit);
      }
      for (bit = 0; bit < 32; bit++) {
        if (hi & (1 << bit)) bits.push(startbit + 32 + bit);
      }
    }
    return bits;
  };

  Reader.prototype.skipEbitmap = function () {
    this.u32(); // mapsize
    this.u32(); // highbit
    var count = this.u32();
    this.skip(count * 12); // startbit(u32) + map(u64)
  };

  // MLS level: sensitivity(u32) + category ebitmap.
  Reader.prototype.skipMlsLevel = function () {
    this.u32();
    this.skipEbitmap();
  };

  // MLS range: items count, 1-2 sensitivities, 1-2 category ebitmaps.
  Reader.prototype.skipMlsRange = function () {
    var items = this.u32();
    this.u32(); // sens_low
    if (items > 1) this.u32(); // sens_high
    this.skipEbitmap(); // low categories
    if (items > 1) this.skipEbitmap(); // high categories
  };

  // Context struct: user(u32), role(u32), type(u32), [+MLS range]. Returns the
  // type value, the only field surfaced.
  Reader.prototype.contextType = function (mls) {
    this.u32(); // user
    this.u32(); // role
    var typ = this.u32();
    if (mls) this.skipMlsRange();
    return typ;
  };

  // -------------------------------------------------------------------------
  // Parser
  // -------------------------------------------------------------------------

  function parse(input) {
    var data = input instanceof Uint8Array ? input : new Uint8Array(input);
    var r = new Reader(data);

    var policy = {
      version: 0,
      mls: false,
      policyKind: '',
      types: new Set(),
      attributes: new Map(), // name -> Set of member type names
      classes: new Map(), // name -> ordered perm names
      booleans: new Map(), // name -> bool
      sensitivities: [],
      categories: [],
      avRules: [],
      xpermRules: [],
      teRules: [],
      constraints: [],
      genfs: [],
      initialSids: [],
      portcons: [],
      netifcons: [],
      nodecons: [],
      fsUses: [],
      policycaps: new Set(),
      roleCount: 0,
      userCount: 0,
    };

    // ---- Header ----
    var magic = r.u32();
    if (magic !== SELINUX_MAGIC) {
      throw new Error(
        'not a SELinux kernel policy (magic 0x' + magic.toString(16).padStart(8, '0') +
        ', expected 0x' + SELINUX_MAGIC.toString(16) + ')'
      );
    }
    var strLen = r.u32();
    policy.policyKind = utf8.decode(r.bytes(strLen));

    var version = r.u32();
    if (version < 15 || version > 35) {
      throw new Error('unsupported policy version ' + version);
    }
    policy.version = version;

    var config = r.u32();
    var mls = (config & 1) !== 0;
    policy.mls = mls;

    var symNum = r.u32();
    var oclassNum = r.u32();

    // ---- Leading ebitmaps (read here, not at the end) ----
    if (version >= V_POLCAP) {
      r.ebitmap().forEach(function (bit) {
        policy.policycaps.add(policycapName(bit));
      });
    }
    if (version >= V_PERMISSIVE) r.skipEbitmap(); // permissive map
    if (version >= V_NEVERAUDIT) r.skipEbitmap(); // never-audit map

    // ---- Symbol tables (each preceded by its own nprim/nel) ----
    var commons = new Map(); // name -> [{name, value}]
    var classes = []; // ClassDatum
    var rawConstraints = [];
    var typeValToName = new Map();
    var roleValToName = new Map();
    var userValToName = new Map();
    var attrNames = new Set();
    var typesNprim = 0;

    for (var symIdx = 0; symIdx < symNum; symIdx++) {
      var nprim = r.u32();
      var nel = r.u32();
      var i;
      switch (symIdx) {
        case SYM_COMMONS:
          for (i = 0; i < nel; i++) {
            var common = readCommon(r);
            commons.set(common.name, common.perms);
          }
          break;
        case SYM_CLASSES:
          for (i = 0; i < nel; i++) {
            var cls = readClass(r, version);
            rawConstraints.push.apply(rawConstraints, cls.constraints);
            classes.push(cls.datum);
          }
          break;
        case SYM_ROLES:
          policy.roleCount = nel;
          for (i = 0; i < nel; i++) {
            var role = readRole(r, version);
            roleValToName.set(role.value, role.name);
          }
          break;
        case SYM_TYPES:
          typesNprim = nprim;
          for (i = 0; i < nel; i++) {
            var ty = readType(r, version);
            typeValToName.set(ty.value, ty.name);
            if (ty.isAttrib) {
              attrNames.add(ty.name);
              if (!policy.attributes.has(ty.name)) policy.attributes.set(ty.name, new Set());
            } else {
              policy.types.add(ty.name);
            }
          }
          break;
        case SYM_USERS:
          policy.userCount = nel;
          for (i = 0; i < nel; i++) {
            var user = readUser(r, version, mls);
            userValToName.set(user.value, user.name);
          }
          break;
        case SYM_BOOLS:
          for (i = 0; i < nel; i++) {
            var b = readBool(r);
            policy.booleans.set(b.name, b.state);
          }
          break;
        case SYM_LEVELS:
          for (i = 0; i < nel; i++) {
            var sens = readSens(r);
            if (sens !== null) policy.sensitivities.push(sens);
          }
          break;
        case SYM_CATS:
          for (i = 0; i < nel; i++) {
            var cat = readCat(r);
            if (cat !== null) policy.categories.push(cat);
          }
          break;
      }
    }

    // ---- Resolve classes (merge common + class-specific perms) ----
    var classMap = new Map(); // value -> {name, perms: Map bit -> name}
    classes.forEach(function (cd) {
      var perms = new Map();
      if (cd.commonName !== null) {
        var commonPerms = commons.get(cd.commonName);
        if (commonPerms) {
          commonPerms.forEach(function (p) {
            perms.set(p.value - 1, p.name);
          });
        }
      }
      cd.perms.forEach(function (p) {
        perms.set(p.value - 1, p.name);
      });
      var ordered = Array.from(perms.entries()).sort(function (a, b) { return a[0] - b[0]; });
      policy.classes.set(cd.name, ordered.map(function (e) { return e[1]; }));
      classMap.set(cd.value, { name: cd.name, perms: perms });
    });

    // ---- Render constraints (now that name maps exist) ----
    var names = { types: typeValToName, roles: roleValToName, users: userValToName };
    rawConstraints.forEach(function (rc) {
      var cls = classMap.get(rc.classValue);
      if (!cls) return;
      var rendered = renderConstraintExpr(rc.exprs, names);
      if (rendered.expr === '') return;
      var perms = rc.validatetrans ? [] : decodePerms(rc.permMask, cls);
      policy.constraints.push({
        class: cls.name,
        perms: perms,
        expr: rendered.expr,
        mls: rendered.mls,
        validatetrans: rc.validatetrans,
      });
    });

    var ctx = {
      typeMap: typeValToName,
      classMap: classMap,
      typeName: function (val) {
        return typeValToName.get(val) !== undefined ? typeValToName.get(val) : 'type#' + val;
      },
      className: function (val) {
        var c = classMap.get(val);
        return c ? c.name : 'class#' + val;
      },
    };

    // ---- Access-vector table ----
    var avNel = r.u32();
    for (i = 0; i < avNel; i++) {
      readAvtabEntry(r, ctx, policy, false);
    }

    // ---- Conditional rules ----
    readCondList(r, ctx, policy);

    // ---- Role transitions ----
    var roleTrNel = r.u32();
    for (i = 0; i < roleTrNel; i++) {
      r.skip(12); // role + type + new_role
      if (version >= V_ROLETRANS) r.skip(4); // tclass
    }

    // ---- Role allows ----
    var roleAllowNel = r.u32();
    r.skip(roleAllowNel * 8);

    // ---- Filename transitions ----
    if (version >= V_FILENAME_TRANS) {
      readFilenameTrans(r, version, ctx, policy);
    }

    // ---- Object contexts ----
    for (var oconIdx = 0; oconIdx < oclassNum; oconIdx++) {
      var oconNel = r.u32();
      for (i = 0; i < oconNel; i++) {
        readOconEntry(r, oconIdx, mls, ctx, policy);
      }
    }

    // ---- genfs contexts ----
    var genfsNel = r.u32();
    for (i = 0; i < genfsNel; i++) {
      var fstype = r.string();
      var ncon = r.u32();
      for (var j = 0; j < ncon; j++) {
        var path = r.string();
        r.u32(); // sclass
        var ctxType = r.contextType(mls);
        policy.genfs.push({ fstype: fstype, path: path, contextType: ctx.typeName(ctxType) });
      }
    }

    // ---- MLS range transitions ----
    if (mls) {
      var rangeTrNel = r.u32();
      for (i = 0; i < rangeTrNel; i++) {
        r.skip(8); // source_type + target_type
        if (version >= 21) r.skip(4); // target_class
        r.skipMlsRange();
      }
    }

    // ---- Type-attribute map: type value -> set of its attributes ----
    if (version >= V_AVTAB) {
      for (i = 0; i < typesNprim; i++) {
        var bits = r.ebitmap();
        var typeVal = i + 1;
        var typeName = typeValToName.get(typeVal);
        if (typeName === undefined) continue;
        // A real type's map lists the attributes it belongs to; invert it
        // into attribute -> member-types.
        if (attrNames.has(typeName)) continue;
        for (j = 0; j < bits.length; j++) {
          var attrName = typeValToName.get(bits[j] + 1);
          if (attrName === undefined) continue;
          var members = policy.attributes.get(attrName);
          if (members) members.add(typeName);
        }
      }
    }

    return policy;
  }

  // -------------------------------------------------------------------------
  // Symbol-table readers (keys are read AFTER the fixed-size fields)
  // -------------------------------------------------------------------------

  function readPerm(r) {
    var len = r.u32();
    var value = r.u32();
    var name = r.key(len);
    return { name: name, value: value };
  }

  function readCommon(r) {
    var len = r.u32();
    r.u32(); // value
    r.u32(); // nprim
    var nel = r.u32();
    var name = r.key(len);
    var perms = [];
    for (var i = 0; i < nel; i++) perms.push(readPerm(r));
    return { name: name, perms: perms };
  }

  function readClass(r, version) {
    var len = r.u32();
    var commonLen = r.u32();
    var value = r.u32();
    r.u32(); // nprim
    var nel = r.u32();
    var ncons = r.u32();

    var name = r.key(len);
    var commonName = commonLen > 0 ? r.key(commonLen) : null;

    var perms = [];
    var i;
    for (i = 0; i < nel; i++) perms.push(readPerm(r));

    var constraints = [];
    for (i = 0; i < ncons; i++) {
      constraints.push(readConstraint(r, version, value, false));
    }
    if (version >= V_VALIDATETRANS) {
      var nvtrans = r.u32();
      for (i = 0; i < nvtrans; i++) {
        constraints.push(readConstraint(r, version, value, true));
      }
    }
    if (version >= V_NEW_OBJECT_DEFAULTS) r.skip(12); // default_user/role/range
    if (version >= V_DEFAULT_TYPE) r.skip(4); // default_type

    return {
      datum: { name: name, value: value, commonName: commonName, perms: perms },
      constraints: constraints,
    };
  }

  // A constraint: perm mask + expression nodes in reverse-Polish order. Only
  // CEXPR_NAMES nodes carry a names ebitmap (plus, on newer policies, a type
  // name set) — reading one for any other node type would desync the stream.
  function readConstraint(r, version, classValue, validatetrans) {
    var permMask = r.u32();
    var nexpr = r.u32();
    var exprs = [];
    for (var i = 0; i < nexpr; i++) {
      var exprType = r.u32();
      var attr = r.u32();
      var op = r.u32();
      var names = [];
      if (exprType === CEXPR_NAMES) {
        names = r.ebitmap().map(function (b) { return b + 1; });
        if (version >= V_CONSTRAINT_NAMES) {
          r.skipEbitmap(); // type_names.types
          r.skipEbitmap(); // type_names.negset
          r.u32(); // flags
        }
      }
      exprs.push({ exprType: exprType, attr: attr, op: op, names: names });
    }
    return { classValue: classValue, permMask: permMask, exprs: exprs, validatetrans: validatetrans };
  }

  function readRole(r, version) {
    var len = r.u32();
    var value = r.u32();
    if (version >= V_BOUNDARY) r.u32(); // bounds
    var name = r.key(len);
    r.skipEbitmap(); // dominates
    r.skipEbitmap(); // types
    return { name: name, value: value };
  }

  function readType(r, version) {
    var len = r.u32();
    var value = r.u32();
    var isAttrib;
    if (version >= V_BOUNDARY) {
      var prop = r.u32();
      r.u32(); // bounds
      isAttrib = (prop & TYPE_PROP_ATTRIBUTE) !== 0;
    } else {
      var primary = r.u32();
      isAttrib = primary === 0;
    }
    var name = r.key(len);
    return { name: name, value: value, isAttrib: isAttrib };
  }

  function readUser(r, version, mls) {
    var len = r.u32();
    var value = r.u32();
    if (version >= V_BOUNDARY) r.u32(); // bounds
    var name = r.key(len);
    r.skipEbitmap(); // roles
    if (mls) {
      r.skipMlsRange(); // range
      r.skipMlsLevel(); // default level
    }
    return { name: name, value: value };
  }

  function readBool(r) {
    var len = r.u32();
    r.u32(); // value
    var state = r.u32() !== 0;
    var name = r.key(len);
    return { name: name, state: state };
  }

  // A sensitivity datum; returns its name unless it's an alias.
  function readSens(r) {
    var len = r.u32();
    var isalias = r.u32();
    var name = r.key(len);
    r.skipMlsLevel();
    return isalias === 0 ? name : null;
  }

  // A category datum; returns its name unless it's an alias.
  function readCat(r) {
    var len = r.u32();
    r.u32(); // value
    var isalias = r.u32();
    var name = r.key(len);
    return isalias === 0 ? name : null;
  }

  // -------------------------------------------------------------------------
  // Constraint expression rendering
  // -------------------------------------------------------------------------

  // Render a constraint's reverse-Polish expression list into an infix string;
  // returns {expr, mls}. `expr` is '' if the stack doesn't balance.
  function renderConstraintExpr(exprs, names) {
    var stack = [];
    var mls = false;

    for (var i = 0; i < exprs.length; i++) {
      var e = exprs[i];
      switch (e.exprType) {
        case CEXPR_NOT: {
          if (stack.length < 1) return { expr: '', mls: mls };
          var a = stack.pop();
          stack.push('not (' + a + ')');
          break;
        }
        case CEXPR_AND:
        case CEXPR_OR: {
          if (stack.length < 2) return { expr: '', mls: mls };
          var b2 = stack.pop();
          var a2 = stack.pop();
          var kw = e.exprType === CEXPR_AND ? 'and' : 'or';
          stack.push(a2 + ' ' + kw + ' ' + b2);
          break;
        }
        case CEXPR_ATTR: {
          if (e.attr & CEXPR_MLS_MASK) mls = true;
          var ops = attrOperands(e.attr);
          stack.push(ops[0] + ' ' + opSymbol(e.op) + ' ' + ops[1]);
          break;
        }
        case CEXPR_NAMES: {
          var lhs = namesLhs(e.attr);
          var map;
          if (e.attr & CEXPR_USER) map = names.users;
          else if (e.attr & CEXPR_ROLE) map = names.roles;
          else map = names.types;
          var resolved = e.names.map(function (v) {
            var n = map.get(v);
            return n !== undefined ? n : '#' + v;
          });
          resolved.sort();
          var set = resolved.length === 1 ? resolved[0] : '{ ' + resolved.join(' ') + ' }';
          stack.push(lhs + ' ' + opSymbol(e.op) + ' ' + set);
          break;
        }
        default:
          return { expr: '', mls: mls };
      }
    }

    return stack.length === 1 ? { expr: stack.pop(), mls: mls } : { expr: '', mls: mls };
  }

  function attrOperands(attr) {
    if (attr & CEXPR_L1L2) return ['l1', 'l2'];
    if (attr & CEXPR_L1H2) return ['l1', 'h2'];
    if (attr & CEXPR_H1L2) return ['h1', 'l2'];
    if (attr & CEXPR_H1H2) return ['h1', 'h2'];
    if (attr & CEXPR_L1H1) return ['l1', 'h1'];
    if (attr & CEXPR_L2H2) return ['l2', 'h2'];
    if (attr & CEXPR_USER) return ['u1', 'u2'];
    if (attr & CEXPR_ROLE) return ['r1', 'r2'];
    if (attr & CEXPR_TYPE) return ['t1', 't2'];
    return ['?', '?'];
  }

  function namesLhs(attr) {
    var target = (attr & (CEXPR_TARGET | CEXPR_XTARGET)) !== 0;
    if (attr & CEXPR_USER) return target ? 'u2' : 'u1';
    if (attr & CEXPR_ROLE) return target ? 'r2' : 'r1';
    return target ? 't2' : 't1';
  }

  function opSymbol(op) {
    switch (op) {
      case CEXPR_EQ: return '==';
      case CEXPR_NEQ: return '!=';
      case CEXPR_DOM: return 'dom';
      case CEXPR_DOMBY: return 'domby';
      case CEXPR_INCOMP: return 'incomp';
      default: return '?';
    }
  }

  // -------------------------------------------------------------------------
  // Access-vector / extended-permission decoding
  // -------------------------------------------------------------------------

  function decodePerms(mask, cls) {
    var perms = [];
    for (var bit = 0; bit < 32; bit++) {
      if ((mask >>> bit) & 1) {
        var name = cls.perms.get(bit);
        if (name !== undefined) perms.push(name);
      }
    }
    perms.sort();
    return perms;
  }

  // Coalesce a sorted list of command numbers into inclusive [lo, hi] ranges.
  function coalesce(cmds) {
    cmds.sort(function (a, b) { return a - b; });
    var ranges = [];
    var prev = -2;
    for (var i = 0; i < cmds.length; i++) {
      var c = cmds[i];
      if (c === prev) continue; // dedup
      if (ranges.length > 0 && c === ranges[ranges.length - 1][1] + 1) {
        ranges[ranges.length - 1][1] = c;
      } else {
        ranges.push([c, c]);
      }
      prev = c;
    }
    return ranges;
  }

  function readAvtabEntry(r, ctx, policy, conditional) {
    var source = r.u16();
    var target = r.u16();
    var tclass = r.u16();
    var specified = r.u16();

    // Extended permissions (ioctl whitelists).
    if (specified & AVTAB_XPERMS) {
      var xspec = r.u8();
      var driver = r.u8();
      var mapBytes = r.bytes(32);
      var src = ctx.typeMap.get(source);
      var tgt = ctx.typeMap.get(target);
      var cls = ctx.classMap.get(tclass);
      if (src === undefined || tgt === undefined || cls === undefined) return;

      var setBits = [];
      for (var i = 0; i < 8; i++) {
        var word =
          mapBytes[i * 4] |
          (mapBytes[i * 4 + 1] << 8) |
          (mapBytes[i * 4 + 2] << 16) |
          (mapBytes[i * 4 + 3] << 24);
        for (var bit = 0; bit < 32; bit++) {
          if ((word >>> bit) & 1) setBits.push(i * 32 + bit);
        }
      }
      var cmds;
      if (xspec === AVTAB_XPERMS_IOCTLFUNCTION) {
        cmds = setBits.map(function (b) { return (driver << 8) | b; });
      } else if (xspec === AVTAB_XPERMS_IOCTLDRIVER) {
        cmds = [];
        setBits.forEach(function (b) {
          for (var f = 0; f < 256; f++) cmds.push((b << 8) | f);
        });
      } else {
        cmds = setBits;
      }
      if (cmds.length === 0) return;
      var kind;
      if (specified & AVTAB_XPERMS_ALLOWED) kind = 'allowxperm';
      else if (specified & AVTAB_XPERMS_AUDITALLOW) kind = 'auditallowxperm';
      else kind = 'dontauditxperm';
      policy.xpermRules.push({
        kind: kind,
        source: src,
        target: tgt,
        class: cls.name,
        op: 'ioctl',
        ranges: coalesce(cmds),
      });
      return;
    }

    var datum = r.u32();
    var src2 = ctx.typeMap.get(source);
    var tgt2 = ctx.typeMap.get(target);
    var cls2 = ctx.classMap.get(tclass);
    if (src2 === undefined || tgt2 === undefined || cls2 === undefined) return;

    // type_transition / type_member / type_change: datum is a type value.
    if (specified & (AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE)) {
      var teKind;
      if (specified & AVTAB_TRANSITION) teKind = 'type_transition';
      else if (specified & AVTAB_MEMBER) teKind = 'type_member';
      else teKind = 'type_change';
      policy.teRules.push({
        kind: teKind,
        source: src2,
        target: tgt2,
        class: cls2.name,
        default: ctx.typeName(datum),
        objectName: null,
      });
      return;
    }

    if (specified & AVTAB_ALLOWED) {
      pushAv(policy, 'allow', src2, tgt2, cls2, datum, conditional);
    }
    if (specified & AVTAB_AUDITALLOW) {
      pushAv(policy, 'auditallow', src2, tgt2, cls2, datum, conditional);
    }
    if (specified & AVTAB_AUDITDENY) {
      // auditdeny stores the perms that ARE audited on denial; dontaudit is
      // the complement against the class's full permission set.
      var maxBit = 0;
      cls2.perms.forEach(function (_name, bit) {
        if (bit > maxBit) maxBit = bit;
      });
      var fullMask = maxBit < 31 ? ((1 << (maxBit + 1)) >>> 0) - 1 : 0xffffffff;
      var dontauditMask = (~datum & fullMask) >>> 0;
      pushAv(policy, 'dontaudit', src2, tgt2, cls2, dontauditMask, conditional);
    }
  }

  function pushAv(policy, kind, src, tgt, cls, mask, conditional) {
    var perms = decodePerms(mask, cls);
    if (perms.length === 0) return;
    policy.avRules.push({
      kind: kind,
      source: src,
      target: tgt,
      class: cls.name,
      perms: perms,
      conditional: conditional,
    });
  }

  function readCondList(r, ctx, policy) {
    var nel = r.u32();
    for (var i = 0; i < nel; i++) {
      r.u32(); // cur_state
      var exprLen = r.u32();
      r.skip(exprLen * 8); // expr_type + bool_val per node

      var trueNel = r.u32();
      for (var j = 0; j < trueNel; j++) readAvtabEntry(r, ctx, policy, true);
      var falseNel = r.u32();
      for (j = 0; j < falseNel; j++) readAvtabEntry(r, ctx, policy, true);
    }
  }

  function readFilenameTrans(r, version, ctx, policy) {
    var nel = r.u32();
    var i, j;
    if (version >= V_COMP_FTRANS) {
      // Compressed: one record per (ttype, tclass, name), with a list of
      // (source-type set, otype) data.
      for (i = 0; i < nel; i++) {
        var name = r.string();
        var ttype = r.u32();
        var tclass = r.u32();
        var ndatum = r.u32();
        for (j = 0; j < ndatum; j++) {
          var stypes = r.ebitmap();
          var otype = r.u32();
          for (var k = 0; k < stypes.length; k++) {
            policy.teRules.push({
              kind: 'type_transition',
              source: ctx.typeName(stypes[k] + 1),
              target: ctx.typeName(ttype),
              class: ctx.className(tclass),
              default: ctx.typeName(otype),
              objectName: name,
            });
          }
        }
      }
    } else {
      // Legacy: one record per (stype, ttype, tclass, name).
      for (i = 0; i < nel; i++) {
        var lname = r.string();
        var stype = r.u32();
        var lttype = r.u32();
        var ltclass = r.u32();
        var lotype = r.u32();
        policy.teRules.push({
          kind: 'type_transition',
          source: ctx.typeName(stype),
          target: ctx.typeName(lttype),
          class: ctx.className(ltclass),
          default: ctx.typeName(lotype),
          objectName: lname,
        });
      }
    }
  }

  function readOconEntry(r, idx, mls, ctx, policy) {
    switch (idx) {
      case 0: { // ISID: sid(u32) + context
        var sid = r.u32();
        var ty = r.contextType(mls);
        var name = INITIAL_SID_NAMES[sid - 1] || 'sid#' + sid;
        policy.initialSids.push({ name: name, contextType: ctx.typeName(ty) });
        break;
      }
      case 1: { // FS (fscon, legacy): name + context + context
        r.string();
        r.contextType(mls);
        r.contextType(mls);
        break;
      }
      case 2: { // PORT: protocol + low + high + context
        var protocol = r.u32();
        var low = r.u32();
        var high = r.u32();
        var pty = r.contextType(mls);
        policy.portcons.push({
          protocol: protocolName(protocol),
          low: low,
          high: high,
          contextType: ctx.typeName(pty),
        });
        break;
      }
      case 3: { // NETIF: name + interface context + packet context
        var nname = r.string();
        var ifTy = r.contextType(mls);
        var pktTy = r.contextType(mls);
        policy.netifcons.push({
          name: nname,
          ifType: ctx.typeName(ifTy),
          packetType: ctx.typeName(pktTy),
        });
        break;
      }
      case 4: { // NODE: addr(u32) + mask(u32) + context (IPv4, network order)
        var addr = r.u32();
        var mask = r.u32();
        var nty = r.contextType(mls);
        policy.nodecons.push({
          addr: ipv4(addr),
          mask: ipv4(mask),
          contextType: ctx.typeName(nty),
        });
        break;
      }
      case 5: { // FSUSE: behavior + fstype name + context
        var behavior = r.u32();
        var fstype = r.string();
        var fty = r.contextType(mls);
        policy.fsUses.push({
          behavior: FS_USE_NAMES[behavior] || 'fs_use_' + behavior,
          fstype: fstype,
          contextType: ctx.typeName(fty),
        });
        break;
      }
      case 6: { // NODE6: addr(4*u32) + mask(4*u32) + context (IPv6)
        var addr6 = [r.u32(), r.u32(), r.u32(), r.u32()];
        var mask6 = [r.u32(), r.u32(), r.u32(), r.u32()];
        var n6ty = r.contextType(mls);
        policy.nodecons.push({
          addr: ipv6(addr6),
          mask: ipv6(mask6),
          contextType: ctx.typeName(n6ty),
        });
        break;
      }
      case 7: { // IBPKEY: subnet_prefix(u64) + low(u32) + high(u32) + context
        r.skip(16);
        r.contextType(mls);
        break;
      }
      case 8: { // IBENDPORT: name + port + context
        r.string();
        r.u32();
        r.contextType(mls);
        break;
      }
      default:
        throw new Error('unknown object-context index ' + idx);
    }
  }

  // Format an IPv4 address (matching Rust: the u32 is read little-endian and
  // rendered via to_be_bytes, i.e. most-significant byte first).
  function ipv4(addr) {
    var b0 = (addr >>> 24) & 0xff;
    var b1 = (addr >>> 16) & 0xff;
    var b2 = (addr >>> 8) & 0xff;
    var b3 = addr & 0xff;
    return b0 + '.' + b1 + '.' + b2 + '.' + b3;
  }

  // Format an IPv6 address from four words (matching Rust's rendering: each
  // u32 read little-endian, then split big-endian into two groups).
  function ipv6(words) {
    var groups = [];
    words.forEach(function (w) {
      groups.push(((w >>> 24) & 0xff) << 8 | ((w >>> 16) & 0xff));
      groups.push(((w >>> 8) & 0xff) << 8 | (w & 0xff));
    });
    return groups.map(function (g) { return g.toString(16); }).join(':');
  }

  // -------------------------------------------------------------------------
  // Rendering (mirrors the Rust Display impls)
  // -------------------------------------------------------------------------

  function hex4(v) {
    var s = v.toString(16);
    while (s.length < 4) s = '0' + s;
    return '0x' + s;
  }

  function formatAvRule(r) {
    var s = r.kind + ' ' + r.source + ' ' + r.target + ':' + r.class +
      ' { ' + r.perms.join(' ') + ' };';
    if (r.conditional) s += '  # conditional';
    return s;
  }

  function formatXpermRule(r) {
    var body = r.ranges.map(function (range) {
      return range[0] === range[1] ? hex4(range[0]) : hex4(range[0]) + '-' + hex4(range[1]);
    });
    return r.kind + ' ' + r.source + ' ' + r.target + ':' + r.class + ' ' +
      r.op + ' { ' + body.join(' ') + ' };';
  }

  function formatTeRule(r) {
    var s = r.kind + ' ' + r.source + ' ' + r.target + ':' + r.class + ' ' + r.default;
    if (r.objectName !== null) s += ' "' + r.objectName + '"';
    return s + ';';
  }

  function formatConstraint(c) {
    var keyword = c.validatetrans
      ? (c.mls ? 'mlsvalidatetrans' : 'validatetrans')
      : (c.mls ? 'mlsconstrain' : 'constrain');
    if (c.validatetrans) {
      return keyword + ' ' + c.class + ' (' + c.expr + ');';
    }
    return keyword + ' ' + c.class + ' { ' + c.perms.join(' ') + ' } (' + c.expr + ');';
  }

  function formatGenfs(g) {
    return 'genfscon ' + g.fstype + ' ' + g.path + ' ' + g.contextType;
  }

  function formatInitialSid(s) {
    return 'sid ' + s.name + ' ' + s.contextType;
  }

  function formatPortcon(p) {
    return p.low === p.high
      ? 'portcon ' + p.protocol + ' ' + p.low + ' ' + p.contextType
      : 'portcon ' + p.protocol + ' ' + p.low + '-' + p.high + ' ' + p.contextType;
  }

  function formatNetifcon(n) {
    return 'netifcon ' + n.name + ' ' + n.ifType + ' ' + n.packetType;
  }

  function formatNodecon(n) {
    return 'nodecon ' + n.addr + ' ' + n.mask + ' ' + n.contextType;
  }

  function formatFsUse(f) {
    return f.behavior + ' ' + f.fstype + ' ' + f.contextType;
  }

  // -------------------------------------------------------------------------
  // Query engine (mirrors policy.rs)
  // -------------------------------------------------------------------------

  // Does `operand` (a name written in a rule) satisfy `filter` under the
  // configured matching mode, given the policy's attribute membership?
  function operandMatches(policy, filter, operand, direct) {
    if (filter === operand) return true;
    if (direct) return false;
    // Semantic: the rule's operand is an attribute containing the queried
    // type, or the queried name is an attribute containing the rule's type.
    var m = policy.attributes.get(operand);
    if (m && m.has(filter)) return true;
    m = policy.attributes.get(filter);
    if (m && m.has(operand)) return true;
    return false;
  }

  // query: {source, target, class, perms: [], direct: bool} — empty-string /
  // empty-array fields are treated as unset.
  function matchesSt(policy, query, source, target, cls) {
    if (query.source && !operandMatches(policy, query.source, source, query.direct)) return false;
    if (query.target && !operandMatches(policy, query.target, target, query.direct)) return false;
    if (query.class && query.class !== cls) return false;
    return true;
  }

  function matchesAv(policy, query, rule) {
    if (!matchesSt(policy, query, rule.source, rule.target, rule.class)) return false;
    if (query.perms && query.perms.length > 0) {
      var granted = query.perms.some(function (p) { return rule.perms.indexOf(p) !== -1; });
      if (!granted) return false;
    }
    return true;
  }

  function matchesXperm(policy, query, rule) {
    // xperm rules have no named perms to filter on.
    if (query.perms && query.perms.length > 0) return false;
    return matchesSt(policy, query, rule.source, rule.target, rule.class);
  }

  function matchesTe(policy, query, rule) {
    if (query.perms && query.perms.length > 0) return false;
    return matchesSt(policy, query, rule.source, rule.target, rule.class);
  }

  function stats(p) {
    var allow = 0, auditallow = 0, dontaudit = 0;
    p.avRules.forEach(function (r) {
      if (r.kind === 'allow') allow++;
      else if (r.kind === 'auditallow') auditallow++;
      else dontaudit++;
    });
    return {
      policy_kind: p.policyKind,
      version: p.version,
      mls: p.mls,
      types: p.types.size,
      attributes: p.attributes.size,
      classes: p.classes.size,
      roles: p.roleCount,
      users: p.userCount,
      booleans: p.booleans.size,
      allow_rules: allow,
      auditallow_rules: auditallow,
      dontaudit_rules: dontaudit,
      xperm_rules: p.xpermRules.length,
      type_rules: p.teRules.length,
      constraints: p.constraints.length,
      sensitivities: p.sensitivities.length,
      categories: p.categories.length,
      genfs: p.genfs.length,
      initial_sids: p.initialSids.length,
      portcons: p.portcons.length,
      netifcons: p.netifcons.length,
      nodecons: p.nodecons.length,
      fs_uses: p.fsUses.length,
      policycaps: p.policycaps.size,
    };
  }

  var SePolicy = {
    parse: parse,
    stats: stats,
    matchesAv: matchesAv,
    matchesXperm: matchesXperm,
    matchesTe: matchesTe,
    format: {
      avRule: formatAvRule,
      xpermRule: formatXpermRule,
      teRule: formatTeRule,
      constraint: formatConstraint,
      genfs: formatGenfs,
      initialSid: formatInitialSid,
      portcon: formatPortcon,
      netifcon: formatNetifcon,
      nodecon: formatNodecon,
      fsUse: formatFsUse,
    },
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = SePolicy;
  } else {
    global.SePolicy = SePolicy;
  }
})(typeof window !== 'undefined' ? window : globalThis);
