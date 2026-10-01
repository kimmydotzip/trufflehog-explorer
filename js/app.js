'use strict';

(function () {
  const C = window.THCore;
  const $ = (id) => document.getElementById(id);
  const REVIEW_KEY = 'thReview.v2';
  const RULES_KEY = 'thRules.v1';
  const MANUAL = 'Pruned manually';

  const el = {
    trufflehogFile: $('trufflehogFile'),
    sessionFile: $('sessionFile'),
    fieldFilters: $('fieldFilters'),
    filterVerified: $('filterVerified'),
    filterDateRange: $('filterDateRange'),
    sortBy: $('sortBy'),
    clearFiltersBtn: $('clearFiltersBtn'),
    pruneFilteredBtn: $('pruneFilteredBtn'),
    restoreFilteredBtn: $('restoreFilteredBtn'),
    confirmAllBtn: $('verifyAllBtn'),
    saveRuleBtn: $('saveRuleBtn'),
    applyAllRulesBtn: $('applyAllRulesBtn'),
    rulesList: $('rulesList'),
    exportRulesBtn: $('exportRulesBtn'),
    rulesFile: $('rulesFile'),
    togglePrunedBtn: $('togglePrunedBtn'),
    expandAllBtn: $('expandAllBtn'),
    exportVerifiedBtn: $('exportVerifiedBtn'),
    exportFilteredBtn: $('exportFilteredBtn'),
    saveSessionBtn: $('saveSessionBtn'),
    totalFindings: $('totalFindings'),
    uniqueRepositories: $('uniqueRepositories'),
    uniqueDetectors: $('uniqueDetectors'),
    uniqueFiles: $('uniqueFiles'),
    uniqueAuthors: $('uniqueAuthors'),
    firstSeen: $('firstSeen'),
    lastSeen: $('lastSeen'),
    prunedCount: $('prunedCount'),
    verifiedCount: $('verifiedCount'),
    unverifiedCount: $('unverifiedCount'),
    verificationBar: $('verificationBar'),
    filteredCountDisplay: $('filteredCountDisplay'),
    results: $('results-container'),
    viewFindingsBtn: $('viewFindingsBtn'),
    viewGroupsBtn: $('viewGroupsBtn'),
    errorLog: $('errorLog'),
  };

  const state = {
    records: [],
    filtered: [],
    page: 0,
    pageSize: 50,
    hidePruned: true,
    collapsed: false,
    dateRange: [null, null],
    rules: [],
    view: 'findings', // or 'groups'
    groups: [],
    expandedGroups: new Set(),
  };

  const items = () => (state.view === 'groups' ? state.groups : state.filtered);

  /* ---------------- DOM helpers ---------------- */

  function h(tag, props, ...children) {
    const node = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v === undefined || v === null || v === false) continue;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = v;
        else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const c of children.flat()) {
      if (c === undefined || c === null || c === false) continue;
      node.append(c instanceof Node ? c : String(c));
    }
    return node;
  }

  const icon = (name) => h('i', { class: `bi bi-${name}` });

  function logError(message) {
    el.errorLog.append(h('div', { class: 'error-message', text: message }));
  }

  function download(content, filename, type = 'application/json') {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = h('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  /* ---------------- Review state ---------------- */

  function loadReviewStore() {
    try {
      return JSON.parse(localStorage.getItem(REVIEW_KEY) || '{}');
    } catch {
      return {};
    }
  }

  // review = { confirmed: bool, pruned: reason string | null }. Older stores used { rejected: bool }.
  const toReview = (saved = {}) => ({
    confirmed: !!saved.confirmed,
    pruned: saved.pruned ? String(saved.pruned) : saved.rejected ? MANUAL : null,
  });

  function saveReviewStore() {
    const store = loadReviewStore();
    for (const r of state.records) {
      if (r.review.confirmed || r.review.pruned) store[r.id] = { ...r.review };
      else delete store[r.id];
    }
    try {
      localStorage.setItem(REVIEW_KEY, JSON.stringify(store));
    } catch (e) {
      console.warn('Unable to persist review state:', e);
    }
  }

  function setReview(records, patch) {
    for (const r of records) Object.assign(r.review, patch);
    saveReviewStore();
    refresh();
  }

  /* ---------------- Loading ---------------- */

  function setRecords(records) {
    C.assignIds(records);
    const store = loadReviewStore();
    for (const r of records) {
      r.review = r.review ? toReview(r.review) : toReview(store[r.id]);
    }
    state.records = records;
    rebuildOptions();
    refresh();
  }

  async function parseFiles(fileList) {
    const records = [];
    for (const file of fileList) {
      try {
        const { records: recs, errors } = C.parseFindings(await file.text(), file.name);
        errors.forEach((e) => logError(`${file.name}${e.line ? ` line ${e.line}` : ''}: ${e.message}`));
        records.push(...recs);
      } catch (e) {
        logError(`Error reading ${file.name}: ${e.message}`);
      }
    }
    return records;
  }

  el.trufflehogFile.addEventListener('change', async (event) => {
    const files = [...event.target.files];
    if (!files.length) return;
    el.errorLog.replaceChildren();
    setRecords(await parseFiles(files));
    event.target.value = '';
  });

  // Session format: JSON array of findings annotated with Pruned/Confirmed (also reads legacy Rejected).
  el.sessionFile.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    el.errorLog.replaceChildren();
    try {
      const data = JSON.parse(await file.text());
      if (!Array.isArray(data)) throw new Error('Session file is not an array of findings.');
      const records = data.map((item) => {
        const rec = C.normalizeFinding(C.stripInternal(item), item._uploadedFile || file.name);
        rec.review = toReview({ confirmed: item.Confirmed, pruned: item.Pruned, rejected: item.Rejected });
        return rec;
      });
      setRecords(records);
      saveReviewStore();
    } catch (e) {
      logError(`Error loading session file: ${e.message}`);
    }
    event.target.value = '';
  });

  function rebuildOptions() {
    for (const field of C.FIELDS.filter((f) => f.suggest)) {
      const values = new Set(state.records.flatMap((r) => field.get(r)).filter(Boolean));
      fieldInputs[field.key].list.replaceChildren(...[...values].sort().map((v) => h('option', { value: v })));
    }
  }

  /* ---------------- Stats ---------------- */

  function updateStats() {
    const recs = state.records;
    const uniq = (fn) => new Set(recs.map(fn).filter(Boolean)).size;
    el.totalFindings.textContent = recs.length;
    el.uniqueRepositories.textContent = uniq((r) => r.repository);
    el.uniqueDetectors.textContent = uniq((r) => r.detector);
    el.uniqueFiles.textContent = new Set(recs.flatMap((r) => r.sourceFiles)).size;
    el.uniqueAuthors.textContent = uniq((r) => r.email);

    const times = recs.map((r) => r.timestamp).filter((t) => t !== null);
    el.firstSeen.textContent = times.length ? new Date(Math.min(...times)).toLocaleDateString() : 'N/A';
    el.lastSeen.textContent = times.length ? new Date(Math.max(...times)).toLocaleDateString() : 'N/A';

    const verified = recs.filter((r) => r.verified).length;
    el.verifiedCount.textContent = verified;
    el.unverifiedCount.textContent = recs.length - verified;
    el.prunedCount.textContent = recs.filter((r) => r.review.pruned).length;
    el.verificationBar.style.width = recs.length ? ((verified / recs.length) * 100).toFixed(1) + '%' : '0%';
  }

  /* ---------------- Filtering ---------------- */

  const fieldInputs = {};
  for (const field of C.FIELDS) {
    const id = `filter-${field.key}`;
    const input = h('input', { type: 'text', id, placeholder: field.placeholder, autocomplete: 'off', spellcheck: 'false' });
    const list = field.suggest ? h('datalist', { id: `${id}-list` }) : null;
    if (list) input.setAttribute('list', list.id);
    const error = h('div', { class: 'filter-error' });
    fieldInputs[field.key] = { input, list, error };
    el.fieldFilters.append(h('div', { class: 'field-filter' },
      h('label', { for: id, text: field.label }), input, list, error));
  }

  function currentSpec() {
    const fields = {};
    for (const [key, { input }] of Object.entries(fieldInputs)) {
      if (input.value.trim()) fields[key] = input.value.trim();
    }
    const [start, end] = state.dateRange;
    return {
      fields,
      verified: el.filterVerified.value,
      from: start ? start.getTime() : null,
      to: end ? end.getTime() + 86400000 - 1 : null, // inclusive end date
    };
  }

  function applyFilters() {
    const spec = currentSpec();
    const predicate = C.buildPredicate(spec);
    for (const [key, { input, error }] of Object.entries(fieldInputs)) {
      const msg = predicate.errors[key] || '';
      input.classList.toggle('active-filter', !!spec.fields[key] && !msg);
      input.classList.toggle('invalid-filter', !!msg);
      error.textContent = msg;
    }

    const out = state.records.filter((r) => !(state.hidePruned && r.review.pruned) && predicate.test(r));

    const sorters = {
      dateAsc: (a, b) => (a.timestamp || 0) - (b.timestamp || 0),
      dateDesc: (a, b) => (b.timestamp || 0) - (a.timestamp || 0),
      repoAsc: (a, b) => a.repository.localeCompare(b.repository),
      repoDesc: (a, b) => b.repository.localeCompare(a.repository),
      detectorAsc: (a, b) => a.detector.localeCompare(b.detector),
      pathAsc: (a, b) => a.file.localeCompare(b.file),
      verifiedAsc: (a, b) => Number(b.verified) - Number(a.verified),
      verifiedDesc: (a, b) => Number(a.verified) - Number(b.verified),
    };
    if (sorters[el.sortBy.value]) out.sort(sorters[el.sortBy.value]);

    state.filtered = out;
    state.groups = state.view === 'groups' ? C.groupBySecret(out) : [];
    state.page = 0;
    render();
  }

  function refresh() {
    updateStats();
    renderRules();
    const page = state.page;
    applyFilters();
    // Keep the reviewer on the same page after an action when possible.
    const maxPage = Math.max(0, Math.ceil(items().length / state.pageSize) - 1);
    if (page !== state.page) {
      state.page = Math.min(page, maxPage);
      render();
    }
  }

  /* ---------------- Rendering ---------------- */

  function render() {
    const list = items();
    const total = list.length;
    const startIdx = state.page * state.pageSize;
    const endIdx = Math.min(startIdx + state.pageSize, total);
    const groupNote = state.view === 'groups' ? ` unique secrets from ${state.filtered.length} findings` : ' filtered';
    el.filteredCountDisplay.textContent = total
      ? `Showing ${startIdx + 1}-${endIdx} / ${total}${groupNote} (${state.records.length} total)`
      : `Showing 0 / 0${groupNote} (${state.records.length} total)`;

    if (!total) {
      el.results.replaceChildren(h('p', {
        text: state.records.length ? 'No results match the current filters.' : 'Load one or more TruffleHog JSON files to begin.',
      }));
      return;
    }
    const renderItem = state.view === 'groups' ? renderGroupCard : renderCard;
    const cards = list.slice(startIdx, endIdx).map(renderItem);
    el.results.replaceChildren(...cards, renderPager());
  }

  function renderPager() {
    const pages = Math.ceil(items().length / state.pageSize);
    if (pages <= 1) return '';
    const go = (p) => () => {
      state.page = p;
      render();
      window.scrollTo(0, 0);
    };
    return h('div', { class: 'pager' },
      h('button', { class: 'btn btn-info', disabled: state.page === 0, onclick: go(state.page - 1) }, icon('chevron-left'), ' Previous'),
      h('span', { class: 'pager-info', text: `Page ${state.page + 1} of ${pages}` }),
      h('button', { class: 'btn btn-info', disabled: state.page >= pages - 1, onclick: go(state.page + 1) }, 'Next ', icon('chevron-right')));
  }

  function detail(label, value) {
    return h('div', { class: 'result-detail' }, h('strong', { text: label }), value === '' ? 'N/A' : value);
  }

  function tag(text, cls) {
    return h('span', { class: `tag ${cls}`, text });
  }

  function renderCard(r) {
    const card = h('div', { class: 'result-container' + (state.collapsed ? ' collapsed' : '') });

    const actions = h('div', { class: 'card-actions' },
      h('button', {
        class: r.review.pruned ? 'btn btn-info' : 'btn btn-danger',
        title: r.review.pruned ? 'Restore this finding to the working set' : 'Prune this finding as a false positive',
        onclick: (e) => { e.stopPropagation(); setReview([r], { pruned: r.review.pruned ? null : MANUAL }); },
      }, icon(r.review.pruned ? 'arrow-counterclockwise' : 'scissors'), r.review.pruned ? ' Restore' : ' Prune'),
      h('button', {
        class: 'btn btn-secondary', title: 'Mark as a confirmed true positive',
        onclick: (e) => { e.stopPropagation(); setReview([r], { confirmed: !r.review.confirmed }); },
      }, icon('check-circle'), r.review.confirmed ? ' Unconfirm' : ' Confirm'));

    const header = h('div', { class: 'result-header', onclick: () => card.classList.toggle('collapsed') },
      h('div', { class: 'title' }, r.detector || 'Unknown detector',
        r.verified ? tag('Verified', 'tag-verified') : tag('Unverified', 'tag-unverified'),
        r.review.confirmed ? tag('Confirmed', 'tag-confirmed') : '',
        r.review.pruned ? h('span', { class: 'tag tag-rejected', title: r.review.pruned, text: 'Pruned' }) : ''),
      actions);

    const where = r.file ? `${r.file}${r.line ? ':' + r.line : ''}` : r.link;
    const snippet = r.secret.length > 50 ? r.secret.slice(0, 50) + '…' : r.secret;
    const summary = h('div', { class: 'summary-line' },
      h('strong', { text: 'Path: ' }), where || 'N/A', ' — ', h('strong', { text: 'Snippet: ' }), snippet);

    const url = C.safeUrl(r.link);
    const pathValue = url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: where || url }) : (where || '');

    const body = h('div', { class: 'result-body' },
      detail('Path:', pathValue),
      detail('Source File:', r.sourceFiles.join(', ')),
      detail('Repository:', r.repository),
      detail('Commit:', r.commit),
      detail('Date:', r.timestampText),
      detail('Author:', r.email),
      detail('Detector:', r.detector),
      detail('Decoder:', r.decoder),
      detail('Description:', r.description),
      detail('Verification:', r.verificationError ? `Error: ${r.verificationError}` : (r.verified ? 'Verified by TruffleHog' : 'Not verified')),
      r.review.pruned ? detail('Pruned:', r.review.pruned) : '',
      h('div', { class: 'leaked-container' }, h('strong', { text: 'Leaked Information:' }), '\n', r.secret || 'N/A'));

    card.append(header, summary, body);
    return card;
  }

  const GROUP_PREVIEW = 25;

  function renderGroupCard(g) {
    const s = C.summarizeGroup(g);
    const card = h('div', { class: 'result-container group-card' + (state.collapsed ? ' collapsed' : '') });
    const unprunedCount = s.count - s.pruned;
    const allConfirmed = s.confirmed === s.count;

    const actions = h('div', { class: 'card-actions' },
      unprunedCount ? h('button', {
        class: 'btn btn-danger', title: 'Prune every occurrence of this secret (verified/confirmed are skipped)',
        onclick: (e) => { e.stopPropagation(); pruneWithPreview(g.records, null, `${MANUAL} (all occurrences of secret)`, `Prune ${g.detector} secret`); },
      }, icon('scissors'), ` Prune ${unprunedCount}`) : '',
      s.pruned ? h('button', {
        class: 'btn btn-info', title: 'Restore every pruned occurrence of this secret',
        onclick: (e) => { e.stopPropagation(); setReview(g.records.filter((r) => r.review.pruned), { pruned: null }); },
      }, icon('arrow-counterclockwise'), ` Restore ${s.pruned}`) : '',
      h('button', {
        class: 'btn btn-secondary', title: 'Mark every occurrence as a confirmed true positive',
        onclick: (e) => { e.stopPropagation(); setReview(g.records, { confirmed: !allConfirmed }); },
      }, icon('check-circle'), allConfirmed ? ' Unconfirm All' : ' Confirm All'));

    const header = h('div', { class: 'result-header', onclick: () => card.classList.toggle('collapsed') },
      h('div', { class: 'title' }, g.detector || 'Unknown detector',
        s.verified ? tag(`Verified ×${s.verified}`, 'tag-verified') : tag('Unverified', 'tag-unverified'),
        s.confirmed ? tag(`Confirmed ×${s.confirmed}`, 'tag-confirmed') : '',
        s.pruned ? tag(`Pruned ×${s.pruned}`, 'tag-rejected') : ''),
      actions);

    const snippet = g.secret.length > 50 ? g.secret.slice(0, 50) + '…' : g.secret;
    const summary = h('div', { class: 'summary-line' },
      h('strong', { text: `${s.count} occurrence${s.count === 1 ? '' : 's'}` }),
      ` in ${s.files} file${s.files === 1 ? '' : 's'} across ${s.repos} repo${s.repos === 1 ? '' : 's'} — `,
      h('strong', { text: 'Snippet: ' }), snippet);

    const expanded = state.expandedGroups.has(g.key);
    const shown = expanded ? g.records : g.records.slice(0, GROUP_PREVIEW);
    const rows = shown.map((r) => {
      const where = r.file ? `${r.file}${r.line ? ':' + r.line : ''}` : r.link || 'N/A';
      const url = C.safeUrl(r.link);
      return h('tr', { class: r.review.pruned ? 'row-pruned' : '' },
        h('td', {}, url ? h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: where }) : where),
        h('td', { text: r.repository || 'N/A' }),
        h('td', { text: r.commit ? r.commit.slice(0, 10) : '' }),
        h('td', { text: r.timestampText }),
        h('td', {},
          r.verified ? tag('Verified', 'tag-verified') : '',
          r.review.confirmed ? tag('Confirmed', 'tag-confirmed') : '',
          r.review.pruned ? h('span', { class: 'tag tag-rejected', title: r.review.pruned, text: 'Pruned' }) : ''));
    });
    const more = g.records.length - shown.length;

    const body = h('div', { class: 'result-body group-body' },
      h('table', { class: 'occurrences' },
        h('thead', {}, h('tr', {}, ['Path', 'Repository', 'Commit', 'Date', 'Status'].map((t) => h('th', { text: t })))),
        h('tbody', {}, rows)),
      more > 0 || expanded && g.records.length > GROUP_PREVIEW ? h('button', {
        class: 'btn btn-info btn-small',
        onclick: () => {
          if (expanded) state.expandedGroups.delete(g.key); else state.expandedGroups.add(g.key);
          card.replaceWith(renderGroupCard(g));
        },
      }, expanded ? 'Show fewer' : `Show all ${g.records.length} occurrences`) : '',
      h('div', { class: 'leaked-container' }, h('strong', { text: 'Leaked Information:' }), '\n', g.secret || 'N/A'));

    card.append(header, summary, body);
    return card;
  }

  /* ---------------- Pruning & rules ---------------- */

  // Shows a preview of what will happen and prunes on confirmation. Returns the number pruned.
  function pruneWithPreview(candidates, predicate, reason, label) {
    const plan = C.planPrune(candidates, predicate);
    const lines = [`${label}`, '', `Prune ${plan.prune.length} finding(s).`];
    if (plan.protectedCount) lines.push(`Skip ${plan.protectedCount} TruffleHog-verified or confirmed finding(s).`);
    if (plan.alreadyPruned) lines.push(`${plan.alreadyPruned} already pruned.`);
    if (!plan.prune.length) {
      alert(lines.concat('', 'Nothing to prune.').join('\n'));
      return 0;
    }
    if (!confirm(lines.concat('', `Reason: ${reason}`).join('\n'))) return 0;
    setReview(plan.prune, { pruned: reason });
    return plan.prune.length;
  }

  function loadRules() {
    try {
      return C.parseRules(localStorage.getItem(RULES_KEY) || '[]').rules;
    } catch {
      return [];
    }
  }

  function saveRules() {
    try {
      localStorage.setItem(RULES_KEY, JSON.stringify(state.rules));
    } catch (e) {
      console.warn('Unable to persist rules:', e);
    }
    renderRules();
  }

  const rulePredicate = (rule) => C.buildPredicate(rule).test;

  function setFiltersFromRule(rule) {
    for (const [key, { input }] of Object.entries(fieldInputs)) input.value = rule.fields[key] || '';
    el.filterVerified.value = rule.verified || '';
    applyFilters();
  }

  function renderRules() {
    if (!state.rules.length) {
      el.rulesList.replaceChildren(h('li', { class: 'rule-empty', text: 'No rules yet.' }));
      return;
    }
    el.rulesList.replaceChildren(...state.rules.map((rule) => {
      const pending = C.planPrune(state.records, rulePredicate(rule)).prune.length;
      return h('li', { class: 'rule-item' },
        h('div', { class: 'rule-head' },
          h('span', { class: 'rule-name', text: rule.name }),
          h('span', { class: 'rule-count', title: 'Findings this rule would prune now', text: String(pending) })),
        h('div', { class: 'rule-pattern' }, h('code', { text: C.describeRule(rule) })),
        h('div', { class: 'rule-actions' },
          h('button', { class: 'btn btn-info btn-small', title: 'Load this rule into the filters', onclick: () => setFiltersFromRule(rule) }, icon('funnel')),
          h('button', {
            class: 'btn btn-danger btn-small', title: 'Prune findings matching this rule', disabled: !pending,
            onclick: () => pruneWithPreview(state.records, rulePredicate(rule), `Rule: ${rule.name}`, `Apply rule "${rule.name}"`),
          }, icon('scissors')),
          h('button', {
            class: 'btn btn-secondary btn-small', title: 'Delete this rule',
            onclick: () => {
              if (!confirm(`Delete rule "${rule.name}"? Findings it already pruned stay pruned.`)) return;
              state.rules = state.rules.filter((r) => r.id !== rule.id);
              saveRules();
            },
          }, icon('trash'))));
    }));
  }

  el.pruneFilteredBtn.addEventListener('click', () => {
    const spec = currentSpec();
    const predicate = C.buildPredicate(spec);
    if (Object.keys(predicate.errors).length) return alert('Fix the invalid filter patterns first.');
    if (!predicate.active && !confirm('No filters are active. This will prune every unprotected finding. Continue?')) return;
    const desc = C.describeRule(C.ruleFromSpec('', spec)) + (spec.from !== null ? ' · date range' : '');
    pruneWithPreview(state.filtered, null, `Filter: ${desc}`, 'Prune filtered findings');
  });

  el.restoreFilteredBtn.addEventListener('click', () => {
    const pruned = state.filtered.filter((r) => r.review.pruned);
    if (!pruned.length) {
      return alert(state.hidePruned
        ? 'No pruned findings are visible. Use "Show Pruned" to include them in the results first.'
        : 'No pruned findings match the current filters.');
    }
    if (confirm(`Restore ${pruned.length} pruned finding(s) to the working set?`)) setReview(pruned, { pruned: null });
  });

  el.saveRuleBtn.addEventListener('click', () => {
    const spec = currentSpec();
    if (Object.keys(C.buildPredicate(spec).errors).length) return alert('Fix the invalid filter patterns first.');
    const draft = C.ruleFromSpec('', spec);
    if (!Object.keys(draft.fields).length && !draft.verified) return alert('Set at least one pattern filter before saving a rule.');
    const name = prompt(`Name for this rule:\n${C.describeRule(draft)}`, '');
    if (name === null) return;
    const rule = C.ruleFromSpec(name, spec);
    state.rules = state.rules.filter((r) => r.id !== rule.id).concat(rule);
    saveRules();
  });

  el.applyAllRulesBtn.addEventListener('click', () => {
    if (!state.rules.length) return alert('No rules to apply.');
    // Prune per rule so each finding records the first rule that matched.
    const plans = state.rules.map((rule) => ({ rule, predicate: rulePredicate(rule) }));
    const reasonFor = (r) => plans.find((p) => p.predicate(r));
    const plan = C.planPrune(state.records, (r) => !!reasonFor(r));
    if (!plan.prune.length) return alert('No unprotected findings match any rule.');
    const msg = [`Apply ${state.rules.length} rule(s)`, '', `Prune ${plan.prune.length} finding(s).`];
    if (plan.protectedCount) msg.push(`Skip ${plan.protectedCount} TruffleHog-verified or confirmed finding(s).`);
    if (!confirm(msg.join('\n'))) return;
    for (const r of plan.prune) r.review.pruned = `Rule: ${reasonFor(r).rule.name}`;
    saveReviewStore();
    refresh();
  });

  el.exportRulesBtn.addEventListener('click', () => {
    if (!state.rules.length) return alert('No rules to export.');
    const rules = state.rules.map(({ name, fields, verified }) => ({ name, fields, verified }));
    download(JSON.stringify({ type: 'trufflehog-explorer-rules', version: 1, rules }, null, 2), 'prune_rules.json');
  });

  el.rulesFile.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const { rules, errors } = C.parseRules(await file.text());
      errors.forEach((e) => logError(`${file.name}: ${e}`));
      const ids = new Set(rules.map((r) => r.id));
      state.rules = state.rules.filter((r) => !ids.has(r.id)).concat(rules);
      saveRules();
      alert(`Imported ${rules.length} rule(s)${errors.length ? `, skipped ${errors.length} (see error log)` : ''}.`);
    } catch (e) {
      logError(`Error importing rules: ${e.message}`);
    }
    event.target.value = '';
  });

  /* ---------------- Actions ---------------- */

  [el.filterVerified, el.sortBy].forEach((s) => s.addEventListener('change', applyFilters));

  let filterTimer;
  el.fieldFilters.addEventListener('input', () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(applyFilters, 250);
  });

  const datePicker = flatpickr(el.filterDateRange, {
    mode: 'range',
    dateFormat: 'Y-m-d',
    onClose: (dates) => {
      state.dateRange = dates.length === 2 ? dates : [null, null];
      applyFilters();
    },
  });

  el.clearFiltersBtn.addEventListener('click', () => {
    for (const { input } of Object.values(fieldInputs)) input.value = '';
    el.filterVerified.value = '';
    el.sortBy.value = '';
    state.dateRange = [null, null];
    datePicker.clear();
    applyFilters();
  });

  el.confirmAllBtn.addEventListener('click', () => {
    if (!state.filtered.length) return;
    if (confirm(`Mark ${state.filtered.length} filtered finding(s) as confirmed true positives?`)) setReview(state.filtered, { confirmed: true });
  });

  el.togglePrunedBtn.addEventListener('click', () => {
    state.hidePruned = !state.hidePruned;
    el.togglePrunedBtn.replaceChildren(icon(state.hidePruned ? 'eye' : 'eye-slash'),
      state.hidePruned ? ' Show Pruned' : ' Hide Pruned');
    applyFilters();
  });

  function setView(view) {
    state.view = view;
    for (const [btn, v] of [[el.viewFindingsBtn, 'findings'], [el.viewGroupsBtn, 'groups']]) {
      btn.classList.toggle('active', v === view);
      btn.setAttribute('aria-pressed', String(v === view));
    }
    applyFilters();
  }
  el.viewFindingsBtn.addEventListener('click', () => setView('findings'));
  el.viewGroupsBtn.addEventListener('click', () => setView('groups'));

  el.expandAllBtn.addEventListener('click', () => {
    state.collapsed = !state.collapsed;
    el.expandAllBtn.replaceChildren(icon(state.collapsed ? 'arrows-expand' : 'arrows-collapse'),
      state.collapsed ? ' Expand All' : ' Collapse All');
    render();
  });

  const toJsonArray = (records) => JSON.stringify(records.map((r) => r.raw), null, 2);

  el.exportVerifiedBtn.addEventListener('click', () => {
    const verified = state.records.filter((r) => r.verified || r.review.confirmed);
    if (!verified.length) return alert('No verified or confirmed results to export.');
    download(toJsonArray(verified), 'verified_findings.json');
  });

  el.exportFilteredBtn.addEventListener('click', () => {
    if (!state.filtered.length) return alert('No filtered results to export.');
    download(toJsonArray(state.filtered), 'filtered_findings.json');
  });

  el.saveSessionBtn.addEventListener('click', () => {
    if (!state.records.length) return alert('No data loaded to save.');
    const session = state.records.map((r) => ({
      ...r.raw, _uploadedFile: r.sourceFiles[0], Pruned: r.review.pruned || undefined, Confirmed: r.review.confirmed,
    }));
    download(JSON.stringify(session, null, 2), 'session_backup.json');
  });

  state.rules = loadRules();
  renderRules();
  render();
})();
