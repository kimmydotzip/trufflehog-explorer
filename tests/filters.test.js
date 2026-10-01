const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../js/core.js');

const rec = (over = {}) => ({
  detector: 'Github', file: 'frontend/yarn.lock', repository: 'https://github.com/o/app.git',
  secret: 'ghp_abc', secretV2: '', email: 'a@example.com', commit: 'abc123', decoder: 'PLAIN',
  sourceFiles: ['scan.json'], extra: { token_type: 'classic' }, verified: false, timestamp: 1000, ...over,
});
const keep = (fields, r = rec(), extra = {}) => C.buildPredicate({ fields, ...extra }).test(r);

test('splitPatterns keeps commas inside regex tokens', () => {
  assert.deepEqual(C.splitPatterns('a, b ,,c'), ['a', 'b', 'c']);
  assert.deepEqual(C.splitPatterns('/a{1,2}/, !x'), ['/a{1,2}/', '!x']);
  assert.deepEqual(C.splitPatterns('!/a,b/'), ['!/a,b/']);
  assert.deepEqual(C.splitPatterns('/tmp, foo'), ['/tmp', 'foo']);
});

test('glob patterns match the whole value, case-insensitively', () => {
  assert.equal(keep({ file: '*.lock' }), true);
  assert.equal(keep({ file: '*.LOCK' }), true);
  assert.equal(keep({ file: '*.json' }), false);
  assert.equal(keep({ file: 'frontend/????.lock' }), true);
});

test('plain text is a substring match', () => {
  assert.equal(keep({ file: 'yarn' }), true);
  assert.equal(keep({ repository: 'APP.git' }), true);
  assert.equal(keep({ repository: 'other' }), false);
});

test('regex tokens', () => {
  assert.equal(keep({ secret: '/^ghp_/' }), true);
  assert.equal(keep({ secret: '/^xyz/' }), false);
  const bad = C.buildPredicate({ fields: { secret: '/(/' } });
  assert.match(bad.errors.secret, /Invalid regex/);
});

test('include and exclude lists combine as (any include) AND NOT (any exclude)', () => {
  assert.equal(keep({ detector: 'AWS, Github' }), true);
  assert.equal(keep({ detector: 'AWS, Azure*' }), false);
  assert.equal(keep({ file: '!*.lock' }), false);
  assert.equal(keep({ file: '!*.lock, !*package.json' }, rec({ file: 'src/app.py' })), true);
  assert.equal(keep({ detector: 'Git*, !Github' }), false);
});

test('empty values: excludes do not drop them, includes require a match', () => {
  const r = rec({ file: '' });
  assert.equal(keep({ file: '!*.lock' }, r), true);
  assert.equal(keep({ file: '*.lock' }, r), false);
  assert.equal(keep({ secret: '!*' }), false);
});

test('multi-value fields: secret checks Raw and RawV2, extra checks key=value', () => {
  assert.equal(keep({ secret: '*host=db*' }, rec({ secretV2: 'postgres://u@host=db' })), true);
  assert.equal(keep({ extra: 'token_type=classic' }), true);
  assert.equal(keep({ extra: '!token_type=*' }), false);
  assert.equal(keep({ source: 'scan.json' }), true);
});

test('verified and date constraints', () => {
  assert.equal(keep({}, rec(), { verified: 'true' }), false);
  assert.equal(keep({}, rec({ verified: true }), { verified: 'true' }), true);
  assert.equal(keep({}, rec(), { from: 2000 }), false);
  assert.equal(keep({}, rec({ timestamp: null }), { to: 5000 }), false);
  assert.equal(keep({}, rec(), { from: 0, to: 5000 }), true);
});

test('wildcards match across newlines in multi-line secrets', () => {
  assert.equal(keep({ secret: '-----BEGIN*' }, rec({ secret: '-----BEGIN KEY-----\nabc\n-----END KEY-----' })), true);
});
