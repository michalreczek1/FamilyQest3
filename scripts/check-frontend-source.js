const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(rootDir, file), 'utf8');
const exists = (file) => fs.existsSync(path.join(rootDir, file));

const indexHtml = read('index.html');
const compiled = read('familyquest-app.compiled.js');
const serviceWorker = read('service-worker.js');
const packageJson = JSON.parse(read('package.json'));

assert(
  indexHtml.includes('/familyquest-app.compiled.js'),
  'index.html must load familyquest-app.compiled.js as the frontend entrypoint',
);
assert(
  !exists('familyquest-app.jsx'),
  'familyquest-app.jsx was legacy localStorage UI and must not be reintroduced without a real build step',
);
assert(
  compiled.startsWith('// FamilyQuest frontend source of truth.'),
  'familyquest-app.compiled.js must declare itself as the current frontend source of truth',
);
assert(
  serviceWorker.includes('self.registration.unregister()'),
  'service-worker.js must unregister itself while offline caching is disabled',
);
assert(
  serviceWorker.includes('caches.delete'),
  'service-worker.js must clear old caches while offline caching is disabled',
);
assert(
  indexHtml.includes('<link rel="manifest" href="/manifest.json">'),
  'index.html must keep the web app manifest link for installability',
);
assert.strictEqual(
  packageJson.scripts['test:frontend-source'],
  'node scripts/check-frontend-source.js',
  'package.json must expose the frontend source guard',
);

console.log('Frontend source OK: compiled JS is explicit entrypoint, legacy JSX is absent, PWA cache cleanup is documented in code');
