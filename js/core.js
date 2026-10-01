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
  const INTERNAL_FIELDS = ['_id', '_uploadedFile', 'Rejected', 'Confirmed'];
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

  return {
    hash, str, parseTimestamp, sourceMeta, normalizeFinding, stripInternal,
    parseFindings, assignIds, escapeHtml, safeUrl,
  };
});
