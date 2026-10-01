/*
 * Pure helpers for parsing and matching TruffleHog findings.
 * Loaded as a classic script in the browser (window.THCore) and as a CommonJS module in tests.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.THCore = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // cyrb53: fast, stable, non-cryptographic 53-bit string hash.
  function hash(input, seed = 0) {
    const s = String(input);
    let h1 = 0xdeadbeef ^ seed;
    let h2 = 0x41c6ce57 ^ seed;
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507);
    h1 ^= Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507);
    h2 ^= Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36).padStart(11, '0');
  }

  function str(value) {
    return value === undefined || value === null ? '' : String(value);
  }

  // TruffleHog emits "2015-08-27 05:43:03 +0000", which Date.parse rejects in some browsers.
  function parseTimestamp(value) {
    if (value === undefined || value === null || value === '') return null;
    const s = String(value).trim();
    const m = s.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)\s*(Z|[+-]\d{2}:?\d{2})?$/i);
    let ms;
    if (m) {
      let tz = (m[3] || 'Z').toUpperCase();
      if (/^[+-]\d{4}$/.test(tz)) tz = tz.slice(0, 3) + ':' + tz.slice(3);
      ms = Date.parse(`${m[1]}T${m[2]}${tz}`);
    } else {
      ms = Date.parse(s);
    }
    return Number.isNaN(ms) ? null : ms;
  }

  // SourceMetadata.Data has a single key naming the source (Github, Git, Filesystem, ...).
  function sourceMeta(obj) {
    const data = obj && obj.SourceMetadata && obj.SourceMetadata.Data;
    if (!data || typeof data !== 'object') return { kind: '', meta: {} };
    const kind = Object.keys(data)[0] || '';
    const meta = data[kind];
    return { kind, meta: meta && typeof meta === 'object' ? meta : {} };
  }

  function normalizeFinding(obj, sourceFile) {
    const { kind, meta } = sourceMeta(obj);
    const rec = {
      id: '',
      raw: obj,
      sourceFiles: [str(sourceFile)],
      sourceKind: kind,
      sourceName: str(obj.SourceName),
      detector: str(obj.DetectorName),
      description: str(obj.DetectorDescription),
      decoder: str(obj.DecoderName),
      secret: str(obj.Raw),
      secretV2: str(obj.RawV2),
      redacted: str(obj.Redacted),
      verified: obj.Verified === true,
      verificationError: str(obj.VerificationError),
      repository: str(meta.repository || meta.repo),
      file: str(meta.file || meta.path),
      line: meta.line === undefined || meta.line === null ? '' : String(meta.line),
      commit: str(meta.commit),
      email: str(meta.email),
      link: str(meta.link),
      timestampText: str(meta.timestamp),
      timestamp: parseTimestamp(meta.timestamp),
      extra: obj.ExtraData && typeof obj.ExtraData === 'object' ? obj.ExtraData : null,
    };
    rec.secretKey = hash(rec.detector + '\u0000' + rec.secret);
    rec.locationKey = hash([
      rec.detector, rec.secret, rec.sourceKind, rec.repository, rec.commit, rec.file, rec.line, rec.link,
    ].join('\u0000'));
    return rec;
  }

  // Legacy explorer sessions stored annotated copies of the findings; strip those fields.
  const INTERNAL_FIELDS = ['_id', '_uploadedFile', 'Rejected', 'Confirmed', 'Pruned'];
  function stripInternal(obj) {
    const copy = { ...obj };
    for (const k of INTERNAL_FIELDS) delete copy[k];
    return copy;
  }

  // Accepts TruffleHog NDJSON (one finding per line) or a JSON array of findings.
  function parseFindings(text, sourceFile) {
    const records = [];
    const errors = [];
    let skipped = 0;
    const body = String(text || '').replace(/^\uFEFF/, '');
    const trimmed = body.trim();

    const push = (obj) => {
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) { skipped++; return; }
      records.push(normalizeFinding(stripInternal(obj), sourceFile));
    };

    if (trimmed.startsWith('[')) {
      try {
        JSON.parse(trimmed).forEach(push);
        return { records, errors, skipped };
      } catch (e) {
        errors.push({ line: 0, message: 'Invalid JSON array: ' + e.message });
        return { records, errors, skipped };
      }
    }

    body.split(/\r?\n/).forEach((line, idx) => {
      const s = line.trim();
      if (!s) return;
      if (!s.startsWith('{')) { skipped++; return; }
      try {
        push(JSON.parse(s));
      } catch (e) {
        errors.push({ line: idx + 1, message: e.message });
      }
    });
    return { records, errors, skipped };
  }

  // Stable IDs: identical findings get the same ID across reloads; exact repeats get a suffix.
  function assignIds(records) {
    const seen = new Map();
    for (const rec of records) {
      const n = (seen.get(rec.locationKey) || 0) + 1;
      seen.set(rec.locationKey, n);
      rec.id = n === 1 ? rec.locationKey : `${rec.locationKey}-${n}`;
    }
    return records;
  }

  const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  function escapeHtml(value) {
    return str(value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
  }

  function safeUrl(value) {
    const s = str(value).trim();
    return /^https?:\/\//i.test(s) ? s : '';
  }

  /* ---------------- Pattern filters ---------------- */

  function escapeRegex(value) {
    return str(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // Split on commas, except inside a /regex/ token.
  function splitPatterns(text) {
    const s = str(text);
    const out = [];
    let cur = '';
    let inRegex = false;
    let inClass = false; // '/' inside [...] does not end a regex, as in JS regex literals
    for (let i = 0; i < s.length; i++) {
      const ch = s[i];
      if (inRegex) {
        cur += ch;
        if (ch === '\\' && i + 1 < s.length) cur += s[++i];
        else if (ch === '[') inClass = true;
        else if (ch === ']') inClass = false;
        else if (ch === '/' && !inClass) inRegex = false;
        continue;
      }
      if (ch === ',') {
        out.push(cur);
        cur = '';
        continue;
      }
      cur += ch;
      if (ch === '/' && /^\s*!?\s*\/$/.test(cur)) inRegex = true;
    }
    out.push(cur);
    if (inRegex) return s.split(',').map((t) => t.trim()).filter(Boolean);
    return out.map((t) => t.trim()).filter(Boolean);
  }

  // "!x" excludes; "/re/" is a regex; "*" and "?" are wildcards (whole value); otherwise substring.
  // All matching is case-insensitive.
  function compilePattern(token) {
    let s = str(token).trim();
    let negate = false;
    if (s.startsWith('!')) {
      negate = true;
      s = s.slice(1).trim();
    }
    if (!s) return null;
    const rx = s.match(/^\/(.+)\/$/);
    if (rx) {
      const re = new RegExp(rx[1], 'i');
      return { negate, kind: 'regex', source: s, test: (v) => re.test(v) };
    }
    if (/[*?]/.test(s)) {
      const re = new RegExp('^' + escapeRegex(s).replace(/\\\*/g, '.*').replace(/\\\?/g, '.') + '$', 'is');
      return { negate, kind: 'glob', source: s, test: (v) => re.test(v) };
    }
    const needle = s.toLowerCase();
    return { negate, kind: 'text', source: s, test: (v) => v.toLowerCase().includes(needle) };
  }

  function compileFilter(text) {
    const f = { text: str(text), includes: [], excludes: [], error: '' };
    for (const token of splitPatterns(text)) {
      try {
        const p = compilePattern(token);
        if (p) (p.negate ? f.excludes : f.includes).push(p);
      } catch (e) {
        f.error = `Invalid regex ${token}: ${e.message}`;
      }
    }
    f.active = f.includes.length + f.excludes.length > 0;
    return f;
  }

  // A field may expose several values (e.g. Raw and RawV2); empty values are ignored.
  function matchFilter(f, values) {
    const vals = values.filter((v) => v !== '' && v !== undefined && v !== null).map(String);
    if (!vals.length) vals.push('');
    if (f.includes.length && !f.includes.some((p) => vals.some((v) => p.test(v)))) return false;
    if (f.excludes.some((p) => vals.some((v) => p.test(v)))) return false;
    return true;
  }

  function extraValues(rec) {
    if (!rec.extra) return [];
    return Object.entries(rec.extra).map(([k, v]) => `${k}=${v !== null && typeof v === 'object' ? JSON.stringify(v) : str(v)}`);
  }

  const FIELDS = [
    { key: 'detector', label: 'Detector', suggest: true, placeholder: 'AWS, Azure*, !URI', get: (r) => [r.detector] },
    { key: 'file', label: 'File path', placeholder: '!*.lock, !*package.json', get: (r) => [r.file] },
    { key: 'repository', label: 'Repository', suggest: true, placeholder: '*terraform*', get: (r) => [r.repository] },
    { key: 'secret', label: 'Secret value', placeholder: '/^AKIA/, !*example*', get: (r) => [r.secret, r.secretV2] },
    { key: 'email', label: 'Author', placeholder: '*@example.com', get: (r) => [r.email] },
    { key: 'commit', label: 'Commit', placeholder: 'a1b2c3*', get: (r) => [r.commit] },
    { key: 'decoder', label: 'Decoder', suggest: true, placeholder: 'PLAIN, BASE64', get: (r) => [r.decoder] },
    { key: 'extra', label: 'Extra data', placeholder: 'token_type=*, !rotation_guide=*', get: extraValues },
    { key: 'source', label: 'Source file', suggest: true, placeholder: 'scan*.json', get: (r) => r.sourceFiles },
  ];
  const FIELD_BY_KEY = Object.fromEntries(FIELDS.map((f) => [f.key, f]));

  /*
   * spec: { fields: { [key]: patternText }, verified: '' | 'true' | 'false', from: ms|null, to: ms|null }
   * Returns { test(rec) -> bool, errors: { [key]: message }, active: bool }.
   */
  function buildPredicate(spec) {
    const s = spec || {};
    const errors = {};
    const compiled = [];
    for (const [key, text] of Object.entries(s.fields || {})) {
      const field = FIELD_BY_KEY[key];
      if (!field) continue;
      const f = compileFilter(text);
      if (f.error) errors[key] = f.error;
      if (f.active) compiled.push([field, f]);
    }
    const verified = s.verified || '';
    const from = typeof s.from === 'number' ? s.from : null;
    const to = typeof s.to === 'number' ? s.to : null;
    const test = (r) => {
      if (verified === 'true' && !r.verified) return false;
      if (verified === 'false' && r.verified) return false;
      if (from !== null && (r.timestamp === null || r.timestamp < from)) return false;
      if (to !== null && (r.timestamp === null || r.timestamp > to)) return false;
      for (const [field, f] of compiled) if (!matchFilter(f, field.get(r))) return false;
      return true;
    };
    return { test, errors, active: compiled.length > 0 || !!verified || from !== null || to !== null };
  }

  /* ---------------- Pruning & rules ---------------- */

  // TruffleHog-verified and reviewer-confirmed findings are never pruned by bulk actions unless forced.
  const isProtected = (r) => !!(r.verified || (r.review && r.review.confirmed));

  // Splits candidates into those that would be pruned and those skipped (protected or already pruned).
  function planPrune(records, predicate, { includeProtected = false } = {}) {
    const prune = [];
    let protectedCount = 0;
    let alreadyPruned = 0;
    for (const r of records) {
      if (predicate && !predicate(r)) continue;
      if (r.review && r.review.pruned) { alreadyPruned++; continue; }
      if (!includeProtected && isProtected(r)) { protectedCount++; continue; }
      prune.push(r);
    }
    return { prune, protectedCount, alreadyPruned };
  }

  // Rules are portable: only field patterns and the verified selector (no dates, no record ids).
  function ruleFromSpec(name, spec) {
    const fields = {};
    for (const [k, v] of Object.entries((spec && spec.fields) || {})) {
      if (FIELD_BY_KEY[k] && str(v).trim()) fields[k] = str(v).trim();
    }
    const verified = spec && (spec.verified === 'true' || spec.verified === 'false') ? spec.verified : '';
    const ruleName = str(name).trim() || 'Unnamed rule';
    return { id: 'r' + hash(JSON.stringify([ruleName, fields, verified])), name: ruleName, fields, verified };
  }

  function describeRule(rule) {
    const parts = Object.entries(rule.fields || {}).map(([k, v]) => `${(FIELD_BY_KEY[k] || { label: k }).label}: ${v}`);
    if (rule.verified) parts.push(rule.verified === 'true' ? 'Verified only' : 'Unverified only');
    return parts.join(' · ') || 'Matches everything';
  }

  // Accepts an exported rules file ({rules:[...]} or a bare array); returns valid rules and errors.
  function parseRules(json) {
    const data = typeof json === 'string' ? JSON.parse(json) : json;
    const list = Array.isArray(data) ? data : data && Array.isArray(data.rules) ? data.rules : null;
    if (!list) throw new Error('Expected an array of rules or an object with a "rules" array.');
    const rules = [];
    const errors = [];
    list.forEach((item, i) => {
      if (!item || typeof item !== 'object') return errors.push(`Rule ${i + 1}: not an object`);
      const rule = ruleFromSpec(item.name, item);
      if (!Object.keys(rule.fields).length && !rule.verified) return errors.push(`Rule ${i + 1} (${rule.name}): no patterns`);
      const bad = Object.entries(rule.fields).map(([k, v]) => compileFilter(v).error && `${k}: ${compileFilter(v).error}`).filter(Boolean);
      if (bad.length) return errors.push(`Rule ${i + 1} (${rule.name}): ${bad.join('; ')}`);
      rules.push(rule);
    });
    return { rules, errors };
  }

  // Merges incoming findings into base by location. The k-th incoming copy of a location matches the
  // k-th existing copy, so exact repeats stay distinct and re-loading the same file is idempotent.
  // A TruffleHog-verified copy upgrades an unverified one (its original object becomes the export source).
  function mergeRecords(base, incoming) {
    const byKey = new Map();
    for (const r of base) {
      if (!byKey.has(r.locationKey)) byKey.set(r.locationKey, []);
      byKey.get(r.locationKey).push(r);
    }
    const consumed = new Map();
    const records = base.slice();
    const stats = { added: 0, merged: 0, upgraded: 0 };
    for (const r of incoming) {
      const k = consumed.get(r.locationKey) || 0;
      consumed.set(r.locationKey, k + 1);
      const target = (byKey.get(r.locationKey) || [])[k];
      if (!target) {
        records.push(r);
        stats.added++;
        continue;
      }
      stats.merged++;
      for (const f of r.sourceFiles) if (!target.sourceFiles.includes(f)) target.sourceFiles.push(f);
      if (r.verified && !target.verified) {
        target.verified = true;
        target.raw = r.raw;
        target.verificationError = r.verificationError;
        target.extra = r.extra || target.extra;
        stats.upgraded++;
      }
    }
    return { records, stats };
  }

  // Groups records sharing the same detector + secret, largest groups first (stable for ties).
  function groupBySecret(records) {
    const groups = new Map();
    for (const r of records) {
      let g = groups.get(r.secretKey);
      if (!g) groups.set(r.secretKey, (g = { key: r.secretKey, detector: r.detector, secret: r.secret, records: [] }));
      g.records.push(r);
    }
    return [...groups.values()].sort((a, b) => b.records.length - a.records.length);
  }

  function summarizeGroup(group) {
    const recs = group.records;
    const uniq = (fn) => new Set(recs.map(fn).filter(Boolean)).size;
    return {
      count: recs.length,
      repos: uniq((r) => r.repository),
      files: uniq((r) => r.file),
      verified: recs.filter((r) => r.verified).length,
      confirmed: recs.filter((r) => r.review && r.review.confirmed).length,
      pruned: recs.filter((r) => r.review && r.review.pruned).length,
    };
  }

  /* ---------------- Export & review files ---------------- */

  // Original TruffleHog objects, one per line, so exports can be re-loaded or diffed against the scan.
  const toNdjson = (records) => records.map((r) => JSON.stringify(r.raw)).join('\n') + (records.length ? '\n' : '');
  const toJsonArray = (records) => JSON.stringify(records.map((r) => r.raw), null, 2);

  function maskSecret(value) {
    const s = str(value);
    if (!s) return '';
    if (s.length <= 8) return s.slice(0, 1) + '•'.repeat(Math.max(3, s.length - 1));
    const keep = Math.min(4, Math.floor(s.length / 6));
    return s.slice(0, keep) + '•'.repeat(8) + s.slice(-keep) + ` (${s.length} chars)`;
  }

  // Quotes every cell and neutralises spreadsheet formulas (=, +, -, @, tab, CR).
  function csvCell(value) {
    let s = str(value);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  const CSV_COLUMNS = [
    ['detector', (r) => r.detector],
    ['trufflehog_verified', (r) => (r.verified ? 'true' : 'false')],
    ['confirmed', (r) => (r.review && r.review.confirmed ? 'true' : 'false')],
    ['pruned_reason', (r) => (r.review && r.review.pruned) || ''],
    ['repository', (r) => r.repository],
    ['file', (r) => r.file],
    ['line', (r) => r.line],
    ['commit', (r) => r.commit],
    ['author', (r) => r.email],
    ['timestamp', (r) => r.timestampText],
    ['link', (r) => r.link],
    ['source_files', (r) => r.sourceFiles.join('; ')],
    ['secret_masked', (r) => maskSecret(r.secret)],
    ['secret_id', (r) => r.secretKey],
  ];

  function toCsv(records, { includeSecret = false } = {}) {
    const cols = includeSecret ? CSV_COLUMNS.concat([['secret', (r) => r.secret]]) : CSV_COLUMNS;
    const rows = [cols.map(([name]) => csvCell(name)).join(',')];
    for (const r of records) rows.push(cols.map(([, get]) => csvCell(get(r))).join(','));
    return rows.join('\r\n') + '\r\n';
  }

  const REVIEW_TYPE = 'trufflehog-explorer-review';

  // Review files hold decisions keyed by finding id plus rules; they never contain secret values.
  function buildReviewFile(records, rules, meta = {}) {
    const review = {};
    for (const r of records) {
      if (r.review && (r.review.confirmed || r.review.pruned)) {
        review[r.id] = { confirmed: !!r.review.confirmed, pruned: r.review.pruned || null };
      }
    }
    return {
      type: REVIEW_TYPE,
      version: 1,
      ...meta,
      rules: (rules || []).map(({ name, fields, verified }) => ({ name, fields, verified })),
      review,
    };
  }

  const isReviewFile = (data) => !!data && typeof data === 'object' && !Array.isArray(data) && data.type === REVIEW_TYPE;

  function applyReviewFile(records, data) {
    const review = (data && data.review) || {};
    let applied = 0;
    for (const r of records) {
      const saved = review[r.id];
      if (!saved) continue;
      r.review = { confirmed: !!saved.confirmed, pruned: saved.pruned ? String(saved.pruned) : null };
      applied++;
    }
    return { applied, unmatched: Object.keys(review).length - applied };
  }

  function slugify(text, fallback = 'version') {
    const s = str(text).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
    return s || fallback;
  }

  return {
    hash, str, parseTimestamp, sourceMeta, normalizeFinding, stripInternal,
    parseFindings, assignIds, escapeHtml, safeUrl,
    escapeRegex, splitPatterns, compilePattern, compileFilter, matchFilter, extraValues,
    FIELDS, FIELD_BY_KEY, buildPredicate,
    isProtected, planPrune, ruleFromSpec, describeRule, parseRules,
    groupBySecret, summarizeGroup, mergeRecords,
    toNdjson, toJsonArray, maskSecret, csvCell, toCsv, buildReviewFile, isReviewFile, applyReviewFile, slugify,
  };
});
