'use strict';

(function () {
  const C = window.THCore;
  const $ = (id) => document.getElementById(id);
  const REVIEW_KEY = 'thReview.v2';

  const el = {
    trufflehogFile: $('trufflehogFile'),
    sessionFile: $('sessionFile'),
    filterRepository: $('filterRepository'),
    filterDetector: $('filterDetector'),
    filterFileName: $('filterFileName'),
    filterVerified: $('filterVerified'),
    filterDateRange: $('filterDateRange'),
    filterRegex: $('filterRegex'),
    sortBy: $('sortBy'),
    clearFiltersBtn: $('clearFiltersBtn'),
    rejectAllBtn: $('rejectAllBtn'),
    confirmAllBtn: $('verifyAllBtn'),
    toggleRejectedBtn: $('toggleRejectedBtn'),
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
    rejectedCount: $('rejectedCount'),
    verifiedCount: $('verifiedCount'),
    unverifiedCount: $('unverifiedCount'),
    verificationBar: $('verificationBar'),
    filteredCountDisplay: $('filteredCountDisplay'),
    results: $('results-container'),
    errorLog: $('errorLog'),
  };

  const state = {
    records: [],
    filtered: [],
    page: 0,
    pageSize: 50,
    hideRejected: true,
    collapsed: false,
    dateRange: [null, null],
  };

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

  function saveReviewStore() {
    const store = loadReviewStore();
    for (const r of state.records) {
      if (r.review.confirmed || r.review.rejected) store[r.id] = { ...r.review };
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
      const saved = store[r.id] || {};
      r.review = { confirmed: !!saved.confirmed, rejected: !!saved.rejected, ...(r.review || {}) };
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

  // Session format: JSON array of findings annotated with Rejected/Confirmed (legacy compatible).
  el.sessionFile.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    el.errorLog.replaceChildren();
    try {
      const data = JSON.parse(await file.text());
      if (!Array.isArray(data)) throw new Error('Session file is not an array of findings.');
      const records = data.map((item) => {
        const rec = C.normalizeFinding(C.stripInternal(item), item._uploadedFile || file.name);
        rec.review = { confirmed: !!item.Confirmed, rejected: !!item.Rejected };
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
    const fill = (select, values) => {
      const current = select.value;
      select.replaceChildren(h('option', { value: '', text: 'All' }),
        ...[...values].filter(Boolean).sort().map((v) => h('option', { value: v, text: v })));
      select.value = values.has(current) ? current : '';
    };
    fill(el.filterRepository, new Set(state.records.map((r) => r.repository)));
    fill(el.filterDetector, new Set(state.records.map((r) => r.detector)));
    fill(el.filterFileName, new Set(state.records.flatMap((r) => r.sourceFiles)));
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
    el.rejectedCount.textContent = recs.filter((r) => r.review.rejected).length;
    el.verificationBar.style.width = recs.length ? ((verified / recs.length) * 100).toFixed(1) + '%' : '0%';
  }

  /* ---------------- Filtering ---------------- */

  function compileRegex() {
    const value = el.filterRegex.value.trim();
    el.filterRegex.classList.toggle('active-filter', !!value);
    el.filterRegex.classList.remove('invalid-filter');
    if (!value) return null;
    try {
      return new RegExp(value, 'i');
    } catch {
      el.filterRegex.classList.add('invalid-filter');
      return null;
    }
  }

  function applyFilters() {
    const repo = el.filterRepository.value;
    const det = el.filterDetector.value;
    const src = el.filterFileName.value;
    const ver = el.filterVerified.value;
    const regex = compileRegex();

    let [start, end] = state.dateRange;
    start = start ? start.getTime() : null;
    end = end ? end.getTime() + 86400000 - 1 : null; // inclusive end date

    const out = state.records.filter((r) => {
      if (state.hideRejected && r.review.rejected) return false;
      if (ver === 'true' && !r.verified) return false;
      if (ver === 'false' && r.verified) return false;
      if (repo && r.repository !== repo) return false;
      if (det && r.detector !== det) return false;
      if (src && !r.sourceFiles.includes(src)) return false;
      if (start !== null && (r.timestamp === null || r.timestamp < start)) return false;
      if (end !== null && (r.timestamp === null || r.timestamp > end)) return false;
      if (regex && !regex.test(r.secret)) return false;
      return true;
    });

    const sorters = {
      dateAsc: (a, b) => (a.timestamp || 0) - (b.timestamp || 0),
      dateDesc: (a, b) => (b.timestamp || 0) - (a.timestamp || 0),
      repoAsc: (a, b) => a.repository.localeCompare(b.repository),
      repoDesc: (a, b) => b.repository.localeCompare(a.repository),
      verifiedAsc: (a, b) => Number(b.verified) - Number(a.verified),
      verifiedDesc: (a, b) => Number(a.verified) - Number(b.verified),
    };
    if (sorters[el.sortBy.value]) out.sort(sorters[el.sortBy.value]);

    state.filtered = out;
    state.page = 0;
    render();
  }

  function refresh() {
    updateStats();
    const page = state.page;
    applyFilters();
    // Keep the reviewer on the same page after an action when possible.
    const maxPage = Math.max(0, Math.ceil(state.filtered.length / state.pageSize) - 1);
    if (page !== state.page) {
      state.page = Math.min(page, maxPage);
      render();
    }
  }

  /* ---------------- Rendering ---------------- */

  function render() {
    const total = state.filtered.length;
    const startIdx = state.page * state.pageSize;
    const endIdx = Math.min(startIdx + state.pageSize, total);
    el.filteredCountDisplay.textContent = total
      ? `Showing ${startIdx + 1}-${endIdx} / ${total} filtered (${state.records.length} total)`
      : `Showing 0 / 0 filtered (${state.records.length} total)`;

    if (!total) {
      el.results.replaceChildren(h('p', {
        text: state.records.length ? 'No results match the current filters.' : 'Load one or more TruffleHog JSON files to begin.',
      }));
      return;
    }
    const cards = state.filtered.slice(startIdx, endIdx).map(renderCard);
    el.results.replaceChildren(...cards, renderPager());
  }

  function renderPager() {
    const pages = Math.ceil(state.filtered.length / state.pageSize);
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
        class: 'btn btn-danger', title: r.review.rejected ? 'Restore this finding' : 'Reject this finding as a false positive',
        onclick: (e) => { e.stopPropagation(); setReview([r], { rejected: !r.review.rejected }); },
      }, icon(r.review.rejected ? 'arrow-counterclockwise' : 'x-circle'), r.review.rejected ? ' Restore' : ' Reject'),
      h('button', {
        class: 'btn btn-secondary', title: 'Mark as a confirmed true positive',
        onclick: (e) => { e.stopPropagation(); setReview([r], { confirmed: !r.review.confirmed }); },
      }, icon('check-circle'), r.review.confirmed ? ' Unconfirm' : ' Confirm'));

    const header = h('div', { class: 'result-header', onclick: () => card.classList.toggle('collapsed') },
      h('div', { class: 'title' }, r.detector || 'Unknown detector',
        r.verified ? tag('Verified', 'tag-verified') : tag('Unverified', 'tag-unverified'),
        r.review.confirmed ? tag('Confirmed', 'tag-confirmed') : '',
        r.review.rejected ? tag('Rejected', 'tag-rejected') : ''),
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
      h('div', { class: 'leaked-container' }, h('strong', { text: 'Leaked Information:' }), '\n', r.secret || 'N/A'));

    card.append(header, summary, body);
    return card;
  }

  /* ---------------- Actions ---------------- */

  [el.filterRepository, el.filterDetector, el.filterFileName, el.filterVerified, el.sortBy]
    .forEach((s) => s.addEventListener('change', applyFilters));

  let regexTimer;
  el.filterRegex.addEventListener('input', () => {
    clearTimeout(regexTimer);
    regexTimer = setTimeout(applyFilters, 300);
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
    for (const s of [el.filterRepository, el.filterDetector, el.filterFileName, el.filterVerified, el.sortBy]) s.value = '';
    el.filterRegex.value = '';
    state.dateRange = [null, null];
    datePicker.clear();
    applyFilters();
  });

  el.rejectAllBtn.addEventListener('click', () => setReview(state.filtered, { rejected: true }));
  el.confirmAllBtn.addEventListener('click', () => setReview(state.filtered, { confirmed: true }));

  el.toggleRejectedBtn.addEventListener('click', () => {
    state.hideRejected = !state.hideRejected;
    el.toggleRejectedBtn.replaceChildren(icon(state.hideRejected ? 'eye' : 'eye-slash'),
      state.hideRejected ? ' Show Rejected' : ' Hide Rejected');
    applyFilters();
  });

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
      ...r.raw, _uploadedFile: r.sourceFiles[0], Rejected: r.review.rejected, Confirmed: r.review.confirmed,
    }));
    download(JSON.stringify(session, null, 2), 'session_backup.json');
  });

  render();
})();
