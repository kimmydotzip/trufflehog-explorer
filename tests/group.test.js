const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const finding = (detector, raw, file, extra = {}) => ({
  DetectorName: detector, Raw: raw, Verified: false,
  SourceMetadata: { Data: { Git: { repository: 'https://example.com/r.git', file, commit: 'c1', line: 1 } } }, ...extra,
});

test('groupBySecret groups by detector and secret, largest first', () => {
  const lines = [
    finding('Github', 'tokA', 'a.lock'),
    finding('Github', 'tokB', 'b.lock'),
    finding('Github', 'tokB', 'c.lock'),
    finding('Generic', 'tokB', 'c.lock'),
    finding('Github', 'tokB', 'd.lock', { Verified: true }),
  ].map((f) => JSON.stringify(f)).join('\n');
  const { records } = C.parseFindings(lines, 'scan.json');
  C.assignIds(records);
  records.forEach((r) => { r.review = { confirmed: false, pruned: null }; });
  records[1].review.pruned = 'x';

  const groups = C.groupBySecret(records);
  assert.deepEqual(groups.map((g) => [g.detector, g.secret, g.records.length]),
    [['Github', 'tokB', 3], ['Github', 'tokA', 1], ['Generic', 'tokB', 1]]);
  assert.deepEqual(C.summarizeGroup(groups[0]), { count: 3, repos: 1, files: 3, verified: 1, confirmed: 0, pruned: 1 });
});
