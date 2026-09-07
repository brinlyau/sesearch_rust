/* app.js — UI for the sepolicy workbench. All state lives in this tab; the
 * policy blob is parsed by sepolicy.js and never leaves the machine. */
(function () {
  'use strict';

  var policy = null;
  var fileName = 'policy';
  var currentView = 'rules'; // 'rules' or an info-view key
  var lastJson = null; // JSON-able value for the current view

  var $ = function (id) { return document.getElementById(id); };
  var output = $('output');
  var cmdtext = $('cmdtext');
  var resultmeta = $('resultmeta');

  function esc(s) {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // ------------------------------------------------------------------
  // File loading
  // ------------------------------------------------------------------

  var dropzone = $('dropzone');

  function loadFile(file) {
    hideError();
    var reader = new FileReader();
    reader.onload = function () {
      var t0 = performance.now();
      try {
        policy = SePolicy.parse(new Uint8Array(reader.result));
      } catch (e) {
        showError('Could not parse ' + file.name + ': ' + e.message +
          '. Expected a compiled kernel policy (sepolicy / precompiled_sepolicy).');
        return;
      }
      var ms = Math.round(performance.now() - t0);
      fileName = file.name;
      $('filemeta').innerHTML = '<b>' + esc(file.name) + '</b> · ' +
        (file.size / 1024 / 1024).toFixed(2) + ' MB · parsed in ' + ms + ' ms';
      onPolicyLoaded();
    };
    reader.onerror = function () {
      showError('Could not read ' + file.name + '.');
    };
    reader.readAsArrayBuffer(file);
  }

  function showError(msg) {
    var el = $('error');
    el.textContent = msg;
    el.style.display = 'block';
  }
  function hideError() { $('error').style.display = 'none'; }

  $('openbtn').addEventListener('click', function () { $('fileinput').click(); });
  dropzone.addEventListener('click', function () { $('fileinput').click(); });
  dropzone.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); $('fileinput').click(); }
  });
  $('fileinput').addEventListener('change', function (e) {
    if (e.target.files.length) loadFile(e.target.files[0]);
  });
  ['dragover', 'dragenter'].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      e.preventDefault();
      dropzone.classList.add('drag');
    });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    document.addEventListener(ev, function (e) {
      e.preventDefault();
      dropzone.classList.remove('drag');
    });
  });
  document.addEventListener('drop', function (e) {
    if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]);
  });

  // ------------------------------------------------------------------
  // Post-load setup
  // ------------------------------------------------------------------

  function onPolicyLoaded() {
    dropzone.style.display = 'none';
    $('app').classList.add('loaded');

    var s = SePolicy.stats(policy);
    var strip = $('statstrip');
    strip.style.display = 'flex';
    strip.innerHTML =
      '<span>' + esc(s.policy_kind) + ' <b>v' + s.version + '</b>' +
      (s.mls ? ' <span class="mlsflag">MLS</span>' : '') + '</span>' +
      '<span><b>' + s.types.toLocaleString() + '</b> types</span>' +
      '<span><b>' + s.attributes.toLocaleString() + '</b> attributes</span>' +
      '<span><b>' + s.classes.toLocaleString() + '</b> classes</span>' +
      '<span><b>' + s.allow_rules.toLocaleString() + '</b> allow</span>' +
      '<span><b>' + s.dontaudit_rules.toLocaleString() + '</b> dontaudit</span>' +
      '<span><b>' + s.xperm_rules.toLocaleString() + '</b> xperm</span>' +
      '<span><b>' + s.type_rules.toLocaleString() + '</b> type rules</span>' +
      '<span><b>' + s.constraints.toLocaleString() + '</b> constraints</span>';

    // Autocomplete datalists.
    var typeOpts = [];
    policy.attributes.forEach(function (_m, name) { typeOpts.push(name); });
    policy.types.forEach(function (name) { typeOpts.push(name); });
    typeOpts.sort();
    $('dl-types').innerHTML = typeOpts.map(function (t) {
      return '<option value="' + esc(t) + '">';
    }).join('');
    var classOpts = Array.from(policy.classes.keys()).sort();
    $('dl-classes').innerHTML = classOpts.map(function (c) {
      return '<option value="' + esc(c) + '">';
    }).join('');
    var permSet = new Set();
    policy.classes.forEach(function (perms) {
      perms.forEach(function (p) { permSet.add(p); });
    });
    $('dl-perms').innerHTML = Array.from(permSet).sort().map(function (p) {
      return '<option value="' + esc(p) + '">';
    }).join('');

    render();
  }

  // ------------------------------------------------------------------
  // Info-view navigation
  // ------------------------------------------------------------------

  var INFO_VIEWS = [
    ['rules', 'rule query'],
    ['stats', '--stats'],
    ['types', '--types'],
    ['attributes', '--attributes'],
    ['classes', '--classes'],
    ['booleans', '--booleans'],
    ['policycaps', '--policycaps'],
    ['constrain', '--constrain'],
    ['sensitivities', '--sensitivities'],
    ['categories', '--categories'],
    ['genfs', '--genfs'],
    ['initialsids', '--initialsids'],
    ['portcon', '--portcon'],
    ['netifcon', '--netifcon'],
    ['nodecon', '--nodecon'],
    ['fs_use', '--fs_use'],
  ];

  var infonav = $('infonav');
  INFO_VIEWS.forEach(function (v) {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = v[1];
    btn.dataset.view = v[0];
    btn.addEventListener('click', function () {
      currentView = v[0];
      render();
    });
    infonav.appendChild(btn);
  });

  function markActiveNav() {
    Array.prototype.forEach.call(infonav.children, function (btn) {
      btn.classList.toggle('active', btn.dataset.view === currentView);
    });
  }

  // Any change to the query controls switches back to the rules view.
  var queryInputs = ['k-allow', 'k-auditallow', 'k-dontaudit', 'k-te', 'k-xperm',
    'f-source', 'f-target', 'f-class', 'f-perm', 'f-direct', 'f-limit'];
  var debounceTimer = null;
  queryInputs.forEach(function (id) {
    $(id).addEventListener('input', function () {
      // The class filter also narrows --constrain; keep that view if active.
      if (currentView !== 'constrain' || id !== 'f-class') currentView = 'rules';
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(render, 150);
    });
  });

  $('copycmd').addEventListener('click', function () {
    navigator.clipboard && navigator.clipboard.writeText('sesearch_rust ' + cmdtext.textContent);
  });

  // ------------------------------------------------------------------
  // Query + render
  // ------------------------------------------------------------------

  function readQuery() {
    var perms = $('f-perm').value.split(/[,\s]+/).filter(function (p) { return p.length > 0; });
    return {
      allow: $('k-allow').checked,
      auditallow: $('k-auditallow').checked,
      dontaudit: $('k-dontaudit').checked,
      te: $('k-te').checked,
      xperm: $('k-xperm').checked,
      source: $('f-source').value.trim(),
      target: $('f-target').value.trim(),
      class: $('f-class').value.trim(),
      perms: perms,
      direct: $('f-direct').checked,
      limit: Math.max(1, parseInt($('f-limit').value, 10) || 2000),
    };
  }

  function cmdForRules(q) {
    var parts = [];
    if (q.allow && q.auditallow && q.dontaudit && q.te && q.xperm) {
      parts.push('--all-rules');
    } else {
      if (q.allow) parts.push('-A');
      if (q.auditallow) parts.push('--auditallow');
      if (q.dontaudit) parts.push('--dontaudit');
      if (q.te) parts.push('-T');
      if (q.xperm) parts.push('-X');
    }
    if (q.source) parts.push('-s ' + q.source);
    if (q.target) parts.push('-t ' + q.target);
    if (q.class) parts.push('-c ' + q.class);
    if (q.perms.length) parts.push('-p ' + q.perms.join(','));
    if (q.direct) parts.push('-d');
    parts.push('-n ' + q.limit);
    parts.push(fileName);
    return parts.join(' ');
  }

  // ---- syntax-highlighted rule renderers ----

  function avHtml(r) {
    return '<span class="k-' + r.kind + '">' + r.kind + '</span> ' +
      esc(r.source) + ' ' + esc(r.target) +
      '<span class="dim">:</span><span class="cls">' + esc(r.class) + '</span>' +
      ' <span class="dim">{</span> ' + esc(r.perms.join(' ')) +
      ' <span class="dim">};</span>' +
      (r.conditional ? '  <span class="dim"># conditional (' + (r.conditionalBranch ? 'true' : 'false') + ')</span>' : '');
  }

  function xpermHtml(r) {
    var body = r.ranges.map(function (range) {
      return range[0] === range[1] ? hex4(range[0]) : hex4(range[0]) + '-' + hex4(range[1]);
    }).join(' ');
    return '<span class="k-xperm">' + r.kind + '</span> ' +
      esc(r.source) + ' ' + esc(r.target) +
      '<span class="dim">:</span><span class="cls">' + esc(r.class) + '</span> ' +
      r.op + ' <span class="dim">{</span> <span class="num">' + body +
      '</span> <span class="dim">};</span>';
  }

  function hex4(v) {
    var s = v.toString(16);
    while (s.length < 4) s = '0' + s;
    return '0x' + s;
  }

  function teHtml(r) {
    return '<span class="k-te">' + r.kind + '</span> ' +
      esc(r.source) + ' ' + esc(r.target) +
      '<span class="dim">:</span><span class="cls">' + esc(r.class) + '</span> ' +
      esc(r.default) +
      (r.objectName !== null ? ' <span class="str">"' + esc(r.objectName) + '"</span>' : '') +
      '<span class="dim">;</span>';
  }

  function constraintHtml(c) {
    var keyword = c.validatetrans
      ? (c.mls ? 'mlsvalidatetrans' : 'validatetrans')
      : (c.mls ? 'mlsconstrain' : 'constrain');
    var head = '<span class="k-constrain">' + keyword + '</span> <span class="cls">' +
      esc(c.class) + '</span> ';
    if (!c.validatetrans) {
      head += '<span class="dim">{</span> ' + esc(c.perms.join(' ')) + ' <span class="dim">}</span> ';
    }
    return head + '<span class="dim">(</span>' + esc(c.expr) + '<span class="dim">);</span>';
  }

  // ---- JSON shapes matching the CLI's --json output ----

  function avJson(r) {
    return { rule_type: r.kind, source: r.source, target: r.target, class: r.class, perms: r.perms, conditional: r.conditional, conditional_branch: r.conditionalBranch };
  }

  function reasonHtml(query, r) {
    var reasons = [];
    var s = SePolicy.matchReason(policy, query.source, r.source, query.direct);
    var t = SePolicy.matchReason(policy, query.target, r.target, query.direct);
    if (s) reasons.push('source: ' + s);
    if (t) reasons.push('target: ' + t);
    return reasons.length ? '<span class="dim">  # matched via ' + esc(reasons.join('; ')) + '</span>' : '';
  }
  function xpermJson(r) {
    return { rule_type: r.kind, source: r.source, target: r.target, class: r.class, op: r.op, ranges: r.ranges };
  }
  function teJson(r) {
    var o = { rule_type: r.kind, source: r.source, target: r.target, class: r.class, default: r.default };
    if (r.objectName !== null) o.object_name = r.objectName;
    return o;
  }

  // ---- rules view ----

  function renderRules() {
    var q = readQuery();
    var query = { source: q.source, target: q.target, class: q.class, perms: q.perms, direct: q.direct };

    // Collect [sortKey, html, json] triples; sort + dedup by key like the CLI.
    var items = [];
    policy.avRules.forEach(function (r) {
      var want = r.kind === 'allow' ? q.allow : r.kind === 'auditallow' ? q.auditallow : q.dontaudit;
      if (want && SePolicy.matchesAv(policy, query, r)) {
        var j = avJson(r); var why = reasonHtml(query, r); if (why) j.match_reason = why.replace(/<[^>]+>/g, '').replace(/^\s*# matched via /, '');
        items.push([SePolicy.format.avRule(r), avHtml(r) + why, j]);
      }
    });
    if (q.xperm) {
      policy.xpermRules.forEach(function (r) {
        if (SePolicy.matchesXperm(policy, query, r)) {
          items.push([SePolicy.format.xpermRule(r), xpermHtml(r), xpermJson(r)]);
        }
      });
    }
    if (q.te) {
      policy.teRules.forEach(function (r) {
        if (SePolicy.matchesTe(policy, query, r)) {
          items.push([SePolicy.format.teRule(r), teHtml(r), teJson(r)]);
        }
      });
    }
    items.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0; });

    var htmls = [];
    var jsons = [];
    var prev = null;
    var total = 0;
    for (var i = 0; i < items.length; i++) {
      if (items[i][0] === prev) continue;
      prev = items[i][0];
      total++;
      if (htmls.length < q.limit) {
        htmls.push(items[i][1]);
        jsons.push(items[i][2]);
      }
    }

    cmdtext.textContent = cmdForRules(q);
    var meta = '<span><b>' + total.toLocaleString() + '</b> matching rule' + (total === 1 ? '' : 's') + '</span>';
    if (total > htmls.length) {
      meta += '<span class="trunc">showing first ' + htmls.length.toLocaleString() +
        ' — raise the limit to see more</span>';
    }
    resultmeta.innerHTML = meta + jsonButton();
    output.innerHTML = htmls.length
      ? htmls.join('\n')
      : '<span class="hdr">no rules match this query' +
        (q.allow || q.auditallow || q.dontaudit || q.te || q.xperm
          ? ' — loosen a filter, or check more rule kinds'
          : ' — pick at least one rule kind on the left') + '</span>';
    lastJson = jsons;
    wireJsonButton();
  }

  // ---- info views ----

  function padKey(k) {
    return (k + ':').padEnd(19, ' ');
  }

  function renderInfo(view) {
    var lines = [];
    var cmd = '--' + view;
    lastJson = null;

    switch (view) {
      case 'stats': {
        var s = SePolicy.stats(policy);
        cmd = '--stats';
        var rows = [
          ['Policy kind', s.policy_kind], ['Policy version', s.version],
          ['MLS enabled', s.mls], ['Types', s.types], ['Attributes', s.attributes],
          ['Classes', s.classes], ['Roles', s.roles], ['Users', s.users],
          ['Booleans', s.booleans], ['allow rules', s.allow_rules],
          ['auditallow rules', s.auditallow_rules], ['dontaudit rules', s.dontaudit_rules],
          ['xperm rules', s.xperm_rules], ['type rules', s.type_rules],
          ['constraints', s.constraints], ['sensitivities', s.sensitivities],
          ['categories', s.categories], ['genfscon entries', s.genfs],
          ['initial SIDs', s.initial_sids], ['portcon entries', s.portcons],
          ['netifcon entries', s.netifcons], ['nodecon entries', s.nodecons],
          ['fs_use entries', s.fs_uses], ['policy caps', s.policycaps],
        ];
        rows.forEach(function (row) {
          lines.push('<span class="hdr">' + padKey(row[0]) + '</span><b>' + esc(String(row[1])) + '</b>');
        });
        lastJson = s;
        break;
      }
      case 'types': {
        var types = Array.from(policy.types).sort();
        lines.push('<span class="hdr">Types (' + types.length + '):</span>');
        types.forEach(function (t) { lines.push('  ' + esc(t)); });
        lastJson = types;
        break;
      }
      case 'attributes': {
        var attrs = Array.from(policy.attributes.keys()).sort();
        lines.push('<span class="hdr">Attributes (' + attrs.length + ') — click one to expand its member types:</span>');
        var parts = [lines[0], ''];
        attrs.forEach(function (a) {
          var members = Array.from(policy.attributes.get(a)).sort();
          parts.push(
            '<details><summary>' + esc(a) +
            ' <span class="count">(' + members.length + ')</span></summary><div>' +
            members.map(esc).join('\n') + '</div></details>'
          );
        });
        cmdtext.textContent = '--attributes ' + fileName + '   # click an attribute ≙ --expand <attr>';
        resultmeta.innerHTML = '<span><b>' + attrs.length + '</b> attributes</span>' + jsonButton();
        output.innerHTML = parts.join('');
        var attrsJson = {};
        attrs.forEach(function (a) { attrsJson[a] = Array.from(policy.attributes.get(a)).sort(); });
        lastJson = attrsJson;
        wireJsonButton();
        markActiveNav();
        return; // handled its own output (uses <details>, not plain lines)
      }
      case 'classes': {
        var classes = Array.from(policy.classes.keys()).sort();
        classes.forEach(function (c) {
          lines.push('<span class="hdr">class</span> <span class="cls">' + esc(c) +
            '</span> <span class="dim">{</span> ' + esc(policy.classes.get(c).join(' ')) +
            ' <span class="dim">}</span>');
        });
        var classJson = {};
        classes.forEach(function (c) { classJson[c] = policy.classes.get(c); });
        lastJson = classJson;
        break;
      }
      case 'booleans': {
        var bools = Array.from(policy.booleans.keys()).sort();
        bools.forEach(function (b) {
          lines.push('<span class="hdr">bool</span> ' + esc(b) + ' <b>' +
            (policy.booleans.get(b) ? 'true' : 'false') + '</b>');
        });
        var boolJson = {};
        bools.forEach(function (b) { boolJson[b] = policy.booleans.get(b); });
        lastJson = boolJson;
        break;
      }
      case 'policycaps': {
        var caps = Array.from(policy.policycaps).sort();
        lines.push('<span class="hdr">Policy capabilities (' + caps.length + '):</span>');
        caps.forEach(function (c) { lines.push('  ' + esc(c)); });
        lastJson = caps;
        break;
      }
      case 'constrain': {
        var clsFilter = $('f-class').value.trim();
        cmd = '--constrain' + (clsFilter ? ' -c ' + clsFilter : '');
        var shown = policy.constraints.filter(function (c) {
          return !clsFilter || c.class === clsFilter;
        });
        shown.forEach(function (c) { lines.push(constraintHtml(c)); });
        lastJson = shown.map(SePolicy.format.constraint);
        break;
      }
      case 'sensitivities':
        policy.sensitivities.forEach(function (s2) { lines.push(esc(s2)); });
        lastJson = policy.sensitivities;
        break;
      case 'categories':
        policy.categories.forEach(function (c) { lines.push(esc(c)); });
        lastJson = policy.categories;
        break;
      case 'genfs':
        policy.genfs.forEach(function (g) {
          lines.push('<span class="hdr">genfscon</span> <span class="cls">' + esc(g.fstype) +
            '</span> ' + esc(g.path) + ' ' + esc(g.contextType));
        });
        lastJson = policy.genfs.map(SePolicy.format.genfs);
        break;
      case 'initialsids':
        policy.initialSids.forEach(function (s3) {
          lines.push('<span class="hdr">sid</span> <span class="cls">' + esc(s3.name) + '</span> ' +
            esc(s3.contextType));
        });
        lastJson = policy.initialSids.map(SePolicy.format.initialSid);
        break;
      case 'portcon':
        policy.portcons.forEach(function (p) {
          lines.push('<span class="hdr">portcon</span> <span class="cls">' + esc(p.protocol) +
            '</span> <span class="num">' + (p.low === p.high ? p.low : p.low + '-' + p.high) +
            '</span> ' + esc(p.contextType));
        });
        lastJson = policy.portcons.map(SePolicy.format.portcon);
        break;
      case 'netifcon':
        policy.netifcons.forEach(function (n) {
          lines.push('<span class="hdr">netifcon</span> <span class="cls">' + esc(n.name) +
            '</span> ' + esc(n.ifType) + ' ' + esc(n.packetType));
        });
        lastJson = policy.netifcons.map(SePolicy.format.netifcon);
        break;
      case 'nodecon':
        policy.nodecons.forEach(function (n) {
          lines.push('<span class="hdr">nodecon</span> <span class="num">' + esc(n.addr) + '</span> <span class="num">' +
            esc(n.mask) + '</span> ' + esc(n.contextType));
        });
        lastJson = policy.nodecons.map(SePolicy.format.nodecon);
        break;
      case 'fs_use':
        cmd = '--fs_use';
        policy.fsUses.forEach(function (f) {
          lines.push('<span class="hdr">' + esc(f.behavior) + '</span> <span class="cls">' +
            esc(f.fstype) + '</span> ' + esc(f.contextType));
        });
        lastJson = policy.fsUses.map(SePolicy.format.fsUse);
        break;
    }

    cmdtext.textContent = cmd + ' ' + fileName;
    var count = lines.length;
    resultmeta.innerHTML = '<span><b>' + count.toLocaleString() + '</b> line' +
      (count === 1 ? '' : 's') + '</span>' + jsonButton();
    output.innerHTML = count ? lines.join('\n')
      : '<span class="hdr">nothing to show — this policy has no entries of this kind</span>';
    wireJsonButton();
  }

  function jsonButton() {
    return '<button id="dljson" type="button">Download JSON</button>';
  }

  function wireJsonButton() {
    var btn = $('dljson');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var blob = new Blob([JSON.stringify(lastJson, null, 2)], { type: 'application/json' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fileName.replace(/[^\w.-]/g, '_') + '.' +
        (currentView === 'rules' ? 'rules' : currentView) + '.json';
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }

  function render() {
    if (!policy) return;
    if (currentView === 'rules') renderRules();
    else renderInfo(currentView);
    markActiveNav();
  }
})();
