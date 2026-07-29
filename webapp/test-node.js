#!/usr/bin/env node
// Diff harness: emulates sesearch_rust's text output paths using sepolicy.js
// so the JS parser can be compared byte-for-byte against the Rust binary.
//
//   node test-node.js <mode> <policy>
//
// modes: stats, all-rules, constrain, contexts, classes, booleans, types,
//        attributes, policycaps, expand:<attr>
'use strict';

const fs = require('fs');
const SePolicy = require('./sepolicy.js');

const mode = process.argv[2];
const path = process.argv[3];
if (!mode || !path) {
  console.error('usage: node test-node.js <mode> <policy>');
  process.exit(2);
}

const data = new Uint8Array(fs.readFileSync(path));
const p = SePolicy.parse(data);
const out = [];

function sorted(arr) {
  return Array.from(arr).sort();
}

switch (true) {
  case mode === 'stats': {
    const s = SePolicy.stats(p);
    out.push('Policy kind:       ' + s.policy_kind);
    out.push('Policy version:    ' + s.version);
    out.push('MLS enabled:       ' + s.mls);
    out.push('Types:             ' + s.types);
    out.push('Attributes:        ' + s.attributes);
    out.push('Classes:           ' + s.classes);
    out.push('Roles:             ' + s.roles);
    out.push('Users:             ' + s.users);
    out.push('Booleans:          ' + s.booleans);
    out.push('allow rules:       ' + s.allow_rules);
    out.push('auditallow rules:  ' + s.auditallow_rules);
    out.push('dontaudit rules:   ' + s.dontaudit_rules);
    out.push('xperm rules:       ' + s.xperm_rules);
    out.push('type rules:        ' + s.type_rules);
    out.push('constraints:       ' + s.constraints);
    out.push('sensitivities:     ' + s.sensitivities);
    out.push('categories:        ' + s.categories);
    out.push('genfscon entries:  ' + s.genfs);
    out.push('initial SIDs:      ' + s.initial_sids);
    out.push('portcon entries:   ' + s.portcons);
    out.push('netifcon entries:  ' + s.netifcons);
    out.push('nodecon entries:   ' + s.nodecons);
    out.push('fs_use entries:    ' + s.fs_uses);
    out.push('policy caps:       ' + s.policycaps);
    break;
  }
  case mode === 'all-rules': {
    const lines = [];
    p.avRules.forEach((r) => lines.push(SePolicy.format.avRule(r)));
    p.xpermRules.forEach((r) => lines.push(SePolicy.format.xpermRule(r)));
    p.teRules.forEach((r) => lines.push(SePolicy.format.teRule(r)));
    lines.sort();
    let prev = null;
    for (const l of lines) {
      if (l !== prev) out.push(l);
      prev = l;
    }
    break;
  }
  case mode === 'constrain':
    p.constraints.forEach((c) => out.push(SePolicy.format.constraint(c)));
    break;
  case mode === 'contexts':
    p.genfs.forEach((g) => out.push(SePolicy.format.genfs(g)));
    p.initialSids.forEach((s) => out.push(SePolicy.format.initialSid(s)));
    p.portcons.forEach((s) => out.push(SePolicy.format.portcon(s)));
    p.netifcons.forEach((s) => out.push(SePolicy.format.netifcon(s)));
    p.nodecons.forEach((s) => out.push(SePolicy.format.nodecon(s)));
    p.fsUses.forEach((s) => out.push(SePolicy.format.fsUse(s)));
    p.sensitivities.forEach((s) => out.push(s));
    p.categories.forEach((s) => out.push(s));
    break;
  case mode === 'classes':
    Array.from(p.classes.keys()).sort().forEach((c) => {
      out.push('class ' + c + ' { ' + p.classes.get(c).join(' ') + ' }');
    });
    break;
  case mode === 'booleans':
    sorted(p.booleans.keys()).forEach((b) => {
      out.push('bool ' + b + ' ' + (p.booleans.get(b) ? 'true' : 'false'));
    });
    break;
  case mode === 'types': {
    const items = sorted(p.types);
    out.push('Types (' + items.length + '):');
    items.forEach((t) => out.push('  ' + t));
    break;
  }
  case mode === 'attributes': {
    const items = sorted(p.attributes.keys());
    out.push('Attributes (' + items.length + '):');
    items.forEach((t) => out.push('  ' + t));
    break;
  }
  case mode === 'policycaps': {
    const items = sorted(p.policycaps);
    out.push('Policy capabilities (' + items.length + '):');
    items.forEach((t) => out.push('  ' + t));
    break;
  }
  case mode.startsWith('expand:'): {
    const attr = mode.slice('expand:'.length);
    const members = p.attributes.get(attr);
    if (!members) {
      console.error('no such attribute: ' + attr);
      process.exit(1);
    }
    const items = sorted(members);
    out.push('Members of ' + attr + ' (' + items.length + '):');
    items.forEach((t) => out.push('  ' + t));
    break;
  }
  default:
    console.error('unknown mode: ' + mode);
    process.exit(2);
}

process.stdout.write(out.join('\n') + (out.length ? '\n' : ''));
