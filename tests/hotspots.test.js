const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const rec = (detector, file, secret = 's', repository = 'r') => ({
  detector, file, secret, secretV2: '', repository, secretKey: C.hash(detector + secret),
  email: '', commit: '', decoder: '', sourceFiles: [], extra: null, verified: false, timestamp: null,
});

test('hotspots ranks detector + file name pairs', () => {
  const records = [
    rec('Github', 'a/yarn.lock', 'x'), rec('Github', 'b/yarn.lock', 'y', 'r2'), rec('Github', 'yarn.lock', 'x'),
    rec('URI', 'README.md'), rec('URI', ''),
  ];
  const spots = C.hotspots(records, 2);
  assert.deepEqual(spots[0], { detector: 'Github', fileName: 'yarn.lock', count: 3, secrets: 2, repos: 2, hasFile: true });
  assert.equal(spots.length, 2);
  assert.equal(C.hotspots(records).find((s) => s.fileName === '(no file)').hasFile, false);
});

test('hotspotFields match exactly the hotspot findings', () => {
  const records = [
    rec('Github', 'a/yarn.lock'), rec('Github', 'yarn.lock'), rec('Github', 'a\\yarn.lock'),
    rec('Github', 'myyarn.lock'), rec('GithubApp', 'yarn.lock'), rec('Github', 'yarn.lock.bak'),
  ];
  const [spot] = C.hotspots(records, 1);
  const { test: keep } = C.buildPredicate({ fields: C.hotspotFields(spot) });
  assert.deepEqual(records.map(keep), [true, true, true, false, false, false]);

  const odd = { detector: 'A.B', fileName: 'we*ird,name', hasFile: true };
  const f = C.hotspotFields(odd);
  const k = C.buildPredicate({ fields: f }).test;
  assert.equal(k(rec('A.B', 'x/we*ird,name')), true);
  assert.equal(k(rec('AxB', 'x/we*ird,name')), false);
  assert.equal(k(rec('A.B', 'x/weXird,name')), false);
});
