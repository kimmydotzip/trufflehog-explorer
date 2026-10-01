const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const line = (raw, file, verified = false, extra = {}) => JSON.stringify({
  DetectorName: 'Github', Raw: raw, Verified: verified,
  SourceMetadata: { Data: { Git: { repository: 'r', file, commit: 'c', line: 1 } } }, ...extra,
});
const parse = (lines, name) => C.parseFindings(lines.join('\n'), name).records;

test('mergeRecords cross-references a verified-only scan into a full scan', () => {
  const full = parse([line('a', 'x'), line('b', 'y'), line('b', 'y'), line('c', 'z')], 'full.json');
  const verified = parse([line('b', 'y', true, { ExtraData: { name: 'bot' } }), line('d', 'w', true)], 'verified.json');
  const { records, stats } = C.mergeRecords(full, verified);

  assert.deepEqual(stats, { added: 1, merged: 1, upgraded: 1 });
  assert.equal(records.length, 5);
  const b = records[1];
  assert.equal(b.verified, true);
  assert.equal(b.raw.Verified, true);
  assert.deepEqual(b.extra, { name: 'bot' });
  assert.deepEqual(b.sourceFiles, ['full.json', 'verified.json']);
  assert.equal(records[2].verified, false, 'second exact repeat is a separate finding');
  assert.equal(records[4].secret, 'd');
});

test('mergeRecords is idempotent and never downgrades verification', () => {
  const v = parse([line('a', 'x', true), line('a', 'x', true)], 'v.json');
  const once = C.mergeRecords([], v).records;
  const twice = C.mergeRecords(once, parse([line('a', 'x', true), line('a', 'x', true)], 'v.json'));
  assert.equal(twice.records.length, 2);
  assert.deepEqual(twice.stats, { added: 0, merged: 2, upgraded: 0 });
  assert.deepEqual(twice.records[0].sourceFiles, ['v.json']);

  const after = C.mergeRecords(twice.records, parse([line('a', 'x', false)], 'full.json'));
  assert.equal(after.records[0].verified, true);
  assert.deepEqual(after.records[0].sourceFiles, ['v.json', 'full.json']);
});
