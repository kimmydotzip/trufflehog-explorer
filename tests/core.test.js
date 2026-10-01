const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const finding = (over = {}, meta = {}) => ({
  SourceMetadata: { Data: { Github: {
    link: 'https://github.com/o/r/blob/abc/src/a.py#L3', repository: 'https://github.com/o/r.git',
    commit: 'abc', email: 'dev <dev@example.com>', file: 'src/a.py',
    timestamp: '2015-08-27 05:43:03 +0000', line: 3, ...meta,
  } } },
  SourceName: 'trufflehog - github', DetectorName: 'AWS', DecoderName: 'PLAIN',
  Verified: false, Raw: 'AKIAEXAMPLEEXAMPLE', RawV2: '', Redacted: '', ExtraData: null,
  ...over,
});

test('parseTimestamp handles TruffleHog and ISO formats', () => {
  assert.equal(C.parseTimestamp('2015-08-27 05:43:03 +0000'), Date.UTC(2015, 7, 27, 5, 43, 3));
  assert.equal(C.parseTimestamp('2015-08-27 07:43:03 +0200'), Date.UTC(2015, 7, 27, 5, 43, 3));
  assert.equal(C.parseTimestamp('2015-08-27T05:43:03Z'), Date.UTC(2015, 7, 27, 5, 43, 3));
  assert.equal(C.parseTimestamp(''), null);
  assert.equal(C.parseTimestamp('not a date'), null);
});

test('normalizeFinding preserves Verified and tolerates missing metadata', () => {
  const v = C.normalizeFinding(finding({ Verified: true }), 'scan.json');
  assert.equal(v.verified, true);
  assert.equal(v.file, 'src/a.py');
  assert.equal(v.line, '3');
  const bare = C.normalizeFinding({ DetectorName: 'X', Raw: 'y' }, 'f');
  assert.equal(bare.file, '');
  assert.equal(bare.timestamp, null);
  const fs = C.normalizeFinding({ DetectorName: 'X', Raw: 'y', SourceMetadata: { Data: { Filesystem: { file: '/tmp/a', line: 1 } } } }, 'f');
  assert.equal(fs.sourceKind, 'Filesystem');
  assert.equal(fs.file, '/tmp/a');
});

test('parseFindings reads NDJSON, skips log lines, reports bad JSON', () => {
  const text = [JSON.stringify(finding()), 'INFO some log line', '{bad json', '', JSON.stringify(finding({ Raw: 'other' }))].join('\r\n');
  const out = C.parseFindings(text, 'scan.json');
  assert.equal(out.records.length, 2);
  assert.equal(out.skipped, 1);
  assert.equal(out.errors.length, 1);
  assert.equal(out.errors[0].line, 3);
});

test('parseFindings reads legacy JSON arrays and strips internal fields', () => {
  const legacy = [{ ...finding(), _id: 'idabc', _uploadedFile: 'x.json', Rejected: true }];
  const out = C.parseFindings(JSON.stringify(legacy, null, 2), 'session.json');
  assert.equal(out.records.length, 1);
  assert.equal('_id' in out.records[0].raw, false);
  assert.equal('Rejected' in out.records[0].raw, false);
});

test('assignIds is stable across loads and unique for exact repeats', () => {
  const text = [finding(), finding(), finding({ Raw: 'other' })].map((f) => JSON.stringify(f)).join('\n');
  const a = C.assignIds(C.parseFindings(text, 'a').records).map((r) => r.id);
  const b = C.assignIds(C.parseFindings(text, 'a').records).map((r) => r.id);
  assert.deepEqual(a, b);
  assert.equal(new Set(a).size, 3);
  assert.equal(a[1], a[0] + '-2');
});

test('secretKey groups identical secrets across locations', () => {
  const a = C.normalizeFinding(finding(), 'f');
  const b = C.normalizeFinding(finding({}, { file: 'other.py', line: 9 }), 'f');
  assert.equal(a.secretKey, b.secretKey);
  assert.notEqual(a.locationKey, b.locationKey);
});

test('escapeHtml and safeUrl neutralize markup and scripts', () => {
  assert.equal(C.escapeHtml('<img src=x onerror="a">&\''), '&lt;img src=x onerror=&quot;a&quot;&gt;&amp;&#39;');
  assert.equal(C.safeUrl('javascript:alert(1)'), '');
  assert.equal(C.safeUrl('https://github.com/x'), 'https://github.com/x');
});
