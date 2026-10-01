'use strict';

(function () {
  const C = window.THCore;
  const $ = (id) => document.getElementById(id);
  const REVIEW_KEY = 'thReview.v2';
  const RULES_KEY = 'thRules.v1';
  const VERSIONS_KEY = 'thVersions.v1';
  const MANUAL = 'Pruned manually';

  const el = {
    trufflehogFile: $('trufflehogFile'),
    appendLoad: $('appendLoad'),
    loadStatus: $('loadStatus'),
    clearDataBtn: $('clearDataBtn'),
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
    revealSecretsBtn: $('revealSecretsBtn'),
    exportFormat: $('exportFormat'),
    exportKeptBtn: $('exportKeptBtn'),
    exportPrunedBtn: $('exportPrunedBtn'),
    exportVerifiedBtn: $('exportVerifiedBtn'),
    exportFilteredBtn: $('exportFilteredBtn'),
    saveSessionBtn: $('saveSessionBtn'),
    saveVersionBtn: $('saveVersionBtn'),
    resetReviewBtn: $('resetReviewBtn'),
    versionList: $('versionList'),
    versionDialog: $('versionDialog'),
    versionForm: $('versionForm'),
    versionSummary: $('versionSummary'),
    versionLabel: $('versionLabel'),
    versionNotes: $('versionNotes'),
    versionKept: $('versionKept'),
    versionPruned: $('versionPruned'),
    versionReview: $('versionReview'),
    totalFindings: $('totalFindings'),
    uniqueRepositories: $('uniqueRepositories'),
    uniqueDetectors: $('uniqueDetectors'),
    uniqueFiles: $('uniqueFiles'),
    uniqueAuthors: $('uniqueAuthors'),
    firstSeen: $('firstSeen'),
    lastSeen: $('lastSeen'),
    prunedCount: $('prunedCount'),
    keptCount: $('keptCount'),
    confirmedCount: $('confirmedCount'),
    uniqueSecrets: $('uniqueSecrets'),
    verificationErrors: $('verificationErrors'),
    hotspotsPanel: $('hotspotsPanel'),
    hotspotsList: $('hotspotsList'),
    filterChips: $('filterChips'),
    pageSize: $('pageSize'),
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
    predicate: null,
    revealAll: false,
    revealed: new Set(), // secretKeys revealed individually
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

  // Files are merged one by one so overlapping scans (e.g. full + verified-only) cross-reference.
  async function parseFiles(fileList, base = []) {
    let records = base;
    const totals = { added: 0, merged: 0, upgraded: 0 };
    for (const file of fileList) {
      try {
        const { records: recs, errors } = C.parseFindings(await file.text(), file.name);
        errors.forEach((e) => logError(`${file.name}${e.line ? ` line ${e.line}` : ''}: ${e.message}`));
        const result = C.mergeRecords(records, recs);
        records = result.records;
        for (const k of Object.keys(totals)) totals[k] += result.stats[k];
      } catch (e) {
        logError(`Error reading ${file.name}: ${e.message}`);
      }
    }
    return { records, totals };
  }

  el.trufflehogFile.addEventListener('change', async (event) => {
    const files = [...event.target.files];
    if (!files.length) return;
    el.errorLog.replaceChildren();
    const append = el.appendLoad.checked && state.records.length > 0;
    const { records, totals } = await parseFiles(files, append ? state.records : []);
    setRecords(records);
    const parts = [`${append ? 'Added' : 'Loaded'} ${totals.added} finding(s) from ${files.length} file(s).`];
    if (totals.merged) parts.push(`${totals.merged} matched existing locations`);
    if (totals.upgraded) parts.push(`${totals.upgraded} marked verified by cross-reference`);
    const reviewed = append ? 0 : records.filter((r) => r.review.confirmed || r.review.pruned).length;
    if (reviewed) parts.push(`restored saved review for ${reviewed} finding(s) from this browser`);
    const prunedVerified = records.filter((r) => r.verified && r.review.pruned).length;
    if (prunedVerified) parts.push(`⚠ ${prunedVerified} verified finding(s) are pruned — use Show Pruned with Verified filter to review`);
    el.loadStatus.textContent = parts.join(' · ');
    event.target.value = '';
  });

  el.clearDataBtn.addEventListener('click', () => {
    if (!state.records.length) return;
    if (!confirm('Unload all findings? Review state stays saved in this browser and is reapplied if you load the same data again.')) return;
    el.loadStatus.textContent = '';
    setRecords([]);
  });

  // Accepts a review file (decisions + rules for the loaded scan) or a legacy session backup
  // (array of findings annotated with Pruned/Rejected/Confirmed).
  el.sessionFile.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    el.errorLog.replaceChildren();
    try {
      const data = JSON.parse(await file.text());
      if (C.isReviewFile(data)) {
        if (!state.records.length) throw new Error('Load the scan file(s) first, then load the review file.');
        const { applied, unmatched } = C.applyReviewFile(state.records, data);
        const { rules, errors } = C.parseRules(data.rules || []);
        errors.forEach((e) => logError(`${file.name}: ${e}`));
        const ids = new Set(rules.map((r) => r.id));
        state.rules = state.rules.filter((r) => !ids.has(r.id)).concat(rules);
        saveRules();
        saveReviewStore();
        refresh();
        el.loadStatus.textContent = `Review "${data.label || file.name}": applied ${applied} decision(s), ${rules.length} rule(s)` +
          (unmatched ? ` · ${unmatched} decision(s) did not match a loaded finding` : '');
        event.target.value = '';
        return;
      }
      if (!Array.isArray(data)) throw new Error('Not a review file or a session backup (array of findings).');
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
    el.uniqueFiles.textContent = new Set(recs.filter((r) => r.file).map((r) => `${r.repository || ''}\u0000${r.file}`)).size;
    el.uniqueAuthors.textContent = uniq((r) => r.email);

    const times = recs.map((r) => r.timestamp).filter((t) => t !== null);
    el.firstSeen.textContent = times.length ? new Date(Math.min(...times)).toLocaleDateString() : 'N/A';
    el.lastSeen.textContent = times.length ? new Date(Math.max(...times)).toLocaleDateString() : 'N/A';

    const verified = recs.filter((r) => r.verified).length;
    el.verifiedCount.textContent = verified;
    el.unverifiedCount.textContent = recs.length - verified;
    el.prunedCount.textContent = recs.filter((r) => r.review.pruned).length;
    const keptRecs = recs.filter((r) => !r.review.pruned);
    el.keptCount.textContent = keptRecs.length;
    el.confirmedCount.textContent = recs.filter((r) => r.review.confirmed).length;
    el.uniqueSecrets.textContent = new Set(keptRecs.map((r) => r.secretKey)).size;
    el.verificationErrors.textContent = recs.filter((r) => r.verificationError).length;
    renderHotspots(keptRecs);
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
    state.predicate = predicate;
    renderChips(spec);

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
      el.results.replaceChildren(renderEmptyState());
      return;
    }
    const renderItem = state.view === 'groups' ? renderGroupCard : renderCard;
    const cards = list.slice(startIdx, endIdx).map(renderItem);
    el.results.replaceChildren(...cards, renderPager());
  }

  function renderEmptyState() {
    if (!state.records.length) {
      return h('div', { class: 'empty-state' },
        h('h3', {}, icon('cloud-upload'), ' No findings loaded'),
        h('p', { text: 'Load one or more TruffleHog JSON / NDJSON files (trufflehog ... --json) from the sidebar.' }),
        h('ul', {},
          h('li', { text: 'Tip: load a full scan and a verified-only scan together to mark verified findings.' }),
          h('li', { text: 'Tip: load a review file afterwards to resume earlier pruning decisions.' })));
    }
    const prunedMatches = state.hidePruned && state.predicate
      ? state.records.filter((r) => r.review.pruned && state.predicate.test(r)).length : 0;
    return h('div', { class: 'empty-state' },
      h('h3', {}, icon('funnel'), ' Nothing matches'),
      h('p', { text: prunedMatches ? `${prunedMatches} pruned finding(s) match these filters but are hidden.` : 'No findings match the current filters.' }),
      h('div', { class: 'buttons-group' },
        prunedMatches ? h('button', { class: 'btn btn-info', onclick: () => el.togglePrunedBtn.click() }, icon('eye'), ' Show Pruned') : '',
        state.predicate && state.predicate.active
          ? h('button', { class: 'btn btn-danger', onclick: () => el.clearFiltersBtn.click() }, icon('backspace'), ' Clear Filters') : ''));
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

  /* ---------------- Secret masking ---------------- */

  const isRevealed = (key) => state.revealAll || state.revealed.has(key);
  const snippetOf = (secret, key) =>
    isRevealed(key) ? (secret.length > 50 ? secret.slice(0, 50) + '…' : secret) : C.maskSecret(secret);

  // Re-renders one card in place, keeping its collapsed/expanded state.
  function rerenderCard(card, renderFn, item) {
    const fresh = renderFn(item);
    fresh.classList.toggle('collapsed', card.classList.contains('collapsed'));
    card.replaceWith(fresh);
  }

  function secretBlock(secret, key, rerender) {
    const revealed = isRevealed(key);
    const copyBtn = h('button', {
      class: 'btn btn-info btn-small', title: 'Copy the full secret to the clipboard',
      onclick: async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(secret);
          copyBtn.lastChild.textContent = ' Copied';
        } catch {
          copyBtn.lastChild.textContent = ' Copy failed';
        }
        setTimeout(() => { copyBtn.lastChild.textContent = ' Copy'; }, 1500);
      },
    }, icon('clipboard'), h('span', { text: ' Copy' }));
    return h('div', { class: 'leaked-container' },
      h('div', { class: 'leaked-head' },
        h('strong', { text: 'Leaked Information:' }),
        secret ? h('span', { class: 'leaked-tools' },
          state.revealAll ? '' : h('button', {
            class: 'btn btn-info btn-small reveal-btn', 'aria-pressed': String(revealed),
            title: revealed ? 'Mask this secret' : 'Show this secret',
            onclick: (e) => {
              e.stopPropagation();
              if (revealed) state.revealed.delete(key); else state.revealed.add(key);
              rerender();
            },
          }, icon(revealed ? 'eye-slash' : 'eye'), revealed ? ' Hide' : ' Reveal'),
          copyBtn) : ''),
      h('div', { class: 'leaked-value' + (revealed ? '' : ' masked'), text: secret ? (revealed ? secret : C.maskSecret(secret)) : 'N/A' }));
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
    const snippet = snippetOf(r.secret, r.secretKey);
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
      secretBlock(r.secret, r.secretKey, () => rerenderCard(card, renderCard, r)));

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

    const snippet = snippetOf(g.secret, g.key);
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
          rerenderCard(card, renderGroupCard, g);
        },
      }, expanded ? 'Show fewer' : `Show all ${g.records.length} occurrences`) : '',
      secretBlock(g.secret, g.key, () => rerenderCard(card, renderGroupCard, g)));

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
    setFilterFields(rule.fields, rule.verified);
  }

  function setFilterFields(fields, verified = '') {
    for (const [key, { input }] of Object.entries(fieldInputs)) input.value = fields[key] || '';
    el.filterVerified.value = verified;
    applyFilters();
  }

  /* ---------------- Hotspots ---------------- */

  function renderHotspots(keptRecs) {
    el.hotspotsPanel.hidden = !state.records.length;
    const spots = C.hotspots(keptRecs, 8);
    if (!spots.length) {
      el.hotspotsList.replaceChildren(h('p', { class: 'hint', text: 'No kept findings.' }));
      return;
    }
    const max = spots[0].count;
    el.hotspotsList.replaceChildren(h('table', { class: 'hotspot-table' },
      h('thead', {}, h('tr', {}, ['Detector', 'File name', 'Findings', 'Secrets', 'Repos', ''].map((t) => h('th', { text: t })))),
      h('tbody', {}, spots.map((s) => {
        const fields = C.hotspotFields(s);
        return h('tr', {},
          h('td', { text: s.detector }),
          h('td', { text: s.fileName }),
          h('td', {}, h('div', { class: 'hotspot-bar' },
            h('span', { style: `width:${Math.max(4, (s.count / max) * 100).toFixed(0)}%` }), h('em', { text: String(s.count) }))),
          h('td', { text: String(s.secrets) }),
          h('td', { text: String(s.repos) }),
          h('td', { class: 'hotspot-actions' },
            h('button', { class: 'btn btn-info btn-small', title: 'Show these findings', onclick: () => setFilterFields(fields) }, icon('funnel'), ' Filter'),
            h('button', {
              class: 'btn btn-danger btn-small', title: 'Prune these findings (verified/confirmed are skipped)',
              onclick: () => pruneWithPreview(state.records, C.buildPredicate({ fields }).test,
                `Hotspot: ${s.detector} in ${s.fileName}`, `Prune ${s.detector} findings in ${s.fileName}`),
            }, icon('scissors'), ' Prune')));
      }))));
  }

  /* ---------------- Filter chips ---------------- */

  function renderChips(spec) {
    const chips = [];
    const chip = (label, clear) => chips.push(h('span', { class: 'chip' },
      h('span', { text: label }),
      h('button', { class: 'chip-x', title: `Remove filter ${label}`, 'aria-label': `Remove filter ${label}`, onclick: clear }, '×')));
    for (const [key, value] of Object.entries(spec.fields)) {
      chip(`${C.FIELD_BY_KEY[key].label}: ${value}`, () => { fieldInputs[key].input.value = ''; applyFilters(); });
    }
    if (spec.verified) chip(spec.verified === 'true' ? 'Verified only' : 'Unverified only', () => { el.filterVerified.value = ''; applyFilters(); });
    if (spec.from !== null) {
      chip(`Date: ${state.dateRange.map((d) => d.toLocaleDateString()).join(' – ')}`, () => {
        state.dateRange = [null, null];
        datePicker.clear();
        applyFilters();
      });
    }
    if (chips.length > 1) {
      chips.push(h('button', { class: 'chip chip-clear', onclick: () => el.clearFiltersBtn.click() }, 'Clear all'));
    }
    el.filterChips.replaceChildren(...chips);
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

  el.pageSize.addEventListener('change', () => {
    state.pageSize = Number(el.pageSize.value) || 50;
    state.page = 0;
    render();
  });

  // "/" focuses the first filter (like many search UIs); Escape leaves a filter field.
  document.addEventListener('keydown', (e) => {
    const t = e.target;
    const typing = t instanceof HTMLElement && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
    if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      fieldInputs[C.FIELDS[0].key].input.focus();
    } else if (e.key === 'Escape' && typing && el.fieldFilters.contains(t)) {
      t.blur();
    }
  });

  el.revealSecretsBtn.addEventListener('click', () => {
    state.revealAll = !state.revealAll;
    if (!state.revealAll) state.revealed.clear();
    el.revealSecretsBtn.setAttribute('aria-pressed', String(state.revealAll));
    el.revealSecretsBtn.replaceChildren(icon(state.revealAll ? 'eye-slash' : 'eye'),
      state.revealAll ? ' Mask Secrets' : ' Reveal Secrets');
    render();
  });

  el.expandAllBtn.addEventListener('click', () => {
    state.collapsed = !state.collapsed;
    el.expandAllBtn.replaceChildren(icon(state.collapsed ? 'arrows-expand' : 'arrows-collapse'),
      state.collapsed ? ' Expand All' : ' Collapse All');
    render();
  });

  /* ---------------- Export & versions ---------------- */

  const stamp = () => new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const kept = () => state.records.filter((r) => !r.review.pruned);
  const prunedRecords = () => state.records.filter((r) => r.review.pruned);

  function exportRecords(records, name) {
    if (!records.length) return alert('Nothing to export.');
    const format = el.exportFormat.value;
    if (format === 'csv') download(C.toCsv(records), `${name}_${stamp()}.csv`, 'text/csv');
    else if (format === 'json') download(C.toJsonArray(records), `${name}_${stamp()}.json`);
    else download(C.toNdjson(records), `${name}_${stamp()}.ndjson`, 'application/x-ndjson');
  }

  el.exportKeptBtn.addEventListener('click', () => exportRecords(kept(), 'kept_findings'));
  el.exportPrunedBtn.addEventListener('click', () => exportRecords(prunedRecords(), 'pruned_findings'));
  el.exportFilteredBtn.addEventListener('click', () => exportRecords(state.filtered, 'filtered_findings'));
  el.exportVerifiedBtn.addEventListener('click', () =>
    exportRecords(state.records.filter((r) => r.verified || r.review.confirmed), 'verified_findings'));

  const sourceNames = () => [...new Set(state.records.flatMap((r) => r.sourceFiles))];

  function reviewFile(meta) {
    return JSON.stringify(C.buildReviewFile(state.records, state.rules, {
      createdAt: new Date().toISOString(), sources: sourceNames(), ...meta,
    }), null, 2);
  }

  el.saveSessionBtn.addEventListener('click', () => {
    if (!state.records.length) return alert('No data loaded to save.');
    download(reviewFile({ label: 'review' }), `review_${stamp()}.json`);
  });

  el.resetReviewBtn.addEventListener('click', () => {
    const reviewed = state.records.filter((r) => r.review.pruned || r.review.confirmed);
    if (!reviewed.length) return alert('No review decisions to reset.');
    if (!confirm(`Clear prune and confirm decisions for ${reviewed.length} loaded finding(s)? Rules are kept.`)) return;
    setReview(reviewed, { pruned: null, confirmed: false });
  });

  function loadVersions() {
    try {
      const list = JSON.parse(localStorage.getItem(VERSIONS_KEY) || '[]');
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  function renderVersions() {
    const versions = loadVersions();
    if (!versions.length) {
      el.versionList.replaceChildren(h('li', { class: 'rule-empty', text: 'No versions saved yet.' }));
      return;
    }
    el.versionList.replaceChildren(...versions.slice().reverse().map((v) => h('li', { class: 'rule-item' },
      h('div', { class: 'rule-head' },
        h('span', { class: 'rule-name', text: v.label }),
        h('span', { class: 'rule-count', title: 'Kept / pruned', text: `${v.counts.kept} / ${v.counts.pruned}` })),
      h('div', { class: 'version-meta', text: `${new Date(v.createdAt).toLocaleString()} · ${v.sources.join(', ')}` }),
      v.notes ? h('div', { class: 'version-meta', text: v.notes }) : '',
      h('div', { class: 'version-meta', text: v.files.join(', ') }))));
  }

  el.saveVersionBtn.addEventListener('click', () => {
    if (!state.records.length) return alert('No data loaded to save.');
    const n = loadVersions().length + 1;
    el.versionSummary.textContent = `${kept().length} kept · ${prunedRecords().length} pruned · ` +
      `${state.records.filter((r) => r.review.confirmed).length} confirmed · ${state.rules.length} rule(s)`;
    el.versionLabel.value = `v${n}`;
    el.versionNotes.value = '';
    el.versionDialog.showModal();
    el.versionLabel.select();
  });

  el.versionDialog.addEventListener('close', () => {
    if (el.versionDialog.returnValue !== 'save') return;
    const label = el.versionLabel.value.trim() || 'version';
    const notes = el.versionNotes.value.trim();
    const base = `${C.slugify(label)}_${stamp()}`;
    const files = [];
    const keptRecs = kept();
    const prunedRecs = prunedRecords();
    if (el.versionKept.checked) {
      download(C.toNdjson(keptRecs), `${base}_kept.ndjson`, 'application/x-ndjson');
      files.push(`${base}_kept.ndjson`);
    }
    if (el.versionPruned.checked) {
      download(C.toNdjson(prunedRecs), `${base}_pruned.ndjson`, 'application/x-ndjson');
      files.push(`${base}_pruned.ndjson`);
    }
    if (el.versionReview.checked) {
      download(reviewFile({ label, notes }), `${base}_review.json`);
      files.push(`${base}_review.json`);
    }
    const versions = loadVersions();
    versions.push({
      label, notes, createdAt: new Date().toISOString(), sources: sourceNames(), files,
      counts: {
        total: state.records.length, kept: keptRecs.length, pruned: prunedRecs.length,
        confirmed: state.records.filter((r) => r.review.confirmed).length, verified: state.records.filter((r) => r.verified).length,
      },
      rules: state.rules.map((r) => r.name),
    });
    try {
      localStorage.setItem(VERSIONS_KEY, JSON.stringify(versions.slice(-50)));
    } catch (e) {
      console.warn('Unable to persist version history:', e);
    }
    renderVersions();
  });

  state.rules = loadRules();
  renderRules();
  renderVersions();
  render();
})();
