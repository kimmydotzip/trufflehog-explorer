const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const scan = [
  { DetectorName: 'Github', Raw: 'ghp_1234567890abcdef', Verified: true, SourceMetadata: { Data: { Git: { file: 'a.js', line: 3 } } } },
  { DetectorName: 'URI', Raw: '=HYPERLINK("x")', Verified: false, SourceMetadata: { Data: { Git: { file: 'b "q".js' } } } },
];
const load = () => {
  const { records } = C.parseFindings(scan.map((o) => JSON.stringify(o)).join('\n'), 'scan.json');
  C.assignIds(records);
  records.forEach((r) => { r.review = { confirmed: false, pruned: null }; });
  return records;
};

test('toNdjson round-trips through parseFindings with the original schema', () => {
  const records = load();
  const text = C.toNdjson(records);
  assert.equal(text.split('\n').filter(Boolean).length, 2);
  assert.deepEqual(JSON.parse(text.split('\n')[0]), scan[0]);
  const again = C.parseFindings(text, 'export.ndjson').records;
  assert.deepEqual(C.assignIds(again).map((r) => r.id), records.map((r) => r.id));
  assert.equal(C.toNdjson([]), '');
});

test('maskSecret hides the middle of a secret', () => {
  assert.equal(C.maskSecret(''), '');
  assert.equal(C.maskSecret('abc'), 'a•••');
  const m = C.maskSecret('ghp_1234567890abcdef');
  assert.ok(m.startsWith('ghp') && m.endsWith('def (20 chars)'));
  assert.ok(!m.includes('4567890'));
});

test('toCsv quotes cells, neutralises formulas and masks secrets by default', () => {
  const records = load();
  records[1].review.pruned = 'Rule: noise';
  const lines = C.toCsv(records).trim().split('\r\n');
  assert.equal(lines.length, 3);
  assert.ok(lines[0].startsWith('"detector","trufflehog_verified"'));
  assert.ok(!lines[1].includes('ghp_1234567890abcdef'));
  assert.ok(lines[2].includes('"Rule: noise"'));
  assert.ok(lines[2].includes('"b ""q"".js"'));
  assert.ok(C.toCsv(records, { includeSecret: true }).includes(`"'=HYPERLINK(""x"")"`));
});

test('review files carry decisions and rules but no secrets, and re-apply by id', () => {
  const records = load();
  records[0].review.confirmed = true;
  records[1].review.pruned = 'Pruned manually';
  const rules = [{ id: 'r1', name: 'Noise', fields: { detector: 'URI' }, verified: '' }];
  const file = C.buildReviewFile(records, rules, { label: 'pass 1' });
  assert.equal(C.isReviewFile(file), true);
  assert.equal(C.isReviewFile([]), false);
  assert.equal(file.label, 'pass 1');
  assert.deepEqual(file.rules, [{ name: 'Noise', fields: { detector: 'URI' }, verified: '' }]);
  const text = JSON.stringify(file);
  assert.ok(!text.includes('ghp_1234567890abcdef') && !text.includes('HYPERLINK'));

  const fresh = load();
  assert.deepEqual(C.applyReviewFile(fresh, { review: { ...file.review, gone: { pruned: 'x' } } }), { applied: 2, unmatched: 1 });
  assert.deepEqual(fresh.map((r) => r.review), [{ confirmed: true, pruned: null }, { confirmed: false, pruned: 'Pruned manually' }]);
});

test('slugify makes safe file names', () => {
  assert.equal(C.slugify('  Pass #1: lockfiles/URI  '), 'pass-1-lockfiles-uri');
  assert.equal(C.slugify('***'), 'version');
});
