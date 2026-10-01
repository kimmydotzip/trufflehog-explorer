const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const rec = (over = {}) => ({
  detector: 'Github', file: 'yarn.lock', repository: 'repo', secret: 's', secretV2: '', email: '', commit: '',
  decoder: 'PLAIN', sourceFiles: ['scan.json'], extra: null, verified: false, timestamp: null,
  review: { confirmed: false, pruned: null }, ...over,
});

test('planPrune skips verified, confirmed and already-pruned findings', () => {
  const records = [
    rec(),
    rec({ verified: true }),
    rec({ review: { confirmed: true, pruned: null } }),
    rec({ review: { confirmed: false, pruned: 'earlier' } }),
    rec({ file: 'src/app.js' }),
  ];
  const lock = C.buildPredicate({ fields: { file: '*.lock' } }).test;
  const plan = C.planPrune(records, lock);
  assert.deepEqual(plan.prune, [records[0]]);
  assert.equal(plan.protectedCount, 2);
  assert.equal(plan.alreadyPruned, 1);

  const forced = C.planPrune(records, lock, { includeProtected: true });
  assert.equal(forced.prune.length, 3);
});

test('ruleFromSpec keeps only known, non-empty fields and drops dates', () => {
  const rule = C.ruleFromSpec('  Lockfiles ', { fields: { file: ' *.lock ', bogus: 'x', email: '' }, verified: 'false', from: 1, to: 2 });
  assert.equal(rule.name, 'Lockfiles');
  assert.deepEqual(rule.fields, { file: '*.lock' });
  assert.equal(rule.verified, 'false');
  assert.equal('from' in rule, false);
  assert.match(rule.id, /^r[0-9a-z]+$/);
  assert.equal(C.ruleFromSpec('Lockfiles', { fields: { file: '*.lock' }, verified: 'false' }).id, rule.id);
});

test('describeRule summarises patterns', () => {
  assert.equal(C.describeRule(C.ruleFromSpec('x', { fields: { detector: 'Github', file: '*.lock' } })), 'Detector: Github · File path: *.lock');
  assert.equal(C.describeRule({ fields: {}, verified: '' }), 'Matches everything');
});

test('parseRules accepts both shapes and rejects empty or invalid rules', () => {
  const good = { name: 'Locks', fields: { file: '*.lock' } };
  assert.equal(C.parseRules([good]).rules.length, 1);
  const { rules, errors } = C.parseRules(JSON.stringify({ rules: [good, { name: 'Empty', fields: {} }, { name: 'Bad', fields: { secret: '/[x/' } }, 3] }));
  assert.equal(rules.length, 1);
  assert.equal(errors.length, 3);
  assert.throws(() => C.parseRules('{"nope":1}'), /rules/);
});
