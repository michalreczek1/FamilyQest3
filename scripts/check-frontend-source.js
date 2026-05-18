const assert = require('assert');
const fs = require('fs');
const path = require('path');

const rootDir = path.join(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(rootDir, file), 'utf8');
const exists = (file) => fs.existsSync(path.join(rootDir, file));

const indexHtml = read('index.html');
const appSource = read('src/App.jsx');
const mainSource = read('src/main.jsx');
const serviceWorker = read('public/service-worker.js');
const packageJson = JSON.parse(read('package.json'));
const expectedSourceFiles = [
  'src/constants.js',
  'src/lib/api.js',
  'src/lib/dates.js',
  'src/lib/tasks.js',
  'src/lib/leaderboard.js',
  'src/components/common/ModalOverlay.jsx',
  'src/components/auth/LoginView.jsx',
  'src/components/auth/ChildSelectionView.jsx',
  'src/components/leaderboard/WeeklyLeaderboardPanel.jsx',
  'src/components/leaderboard/FamilyGoalWidget.jsx',
  'src/components/rewards/RewardHistoryPanel.jsx',
  'src/components/rewards/RewardOverlay.jsx',
  'src/components/settings/SettingsSecurityPanel.jsx',
  'src/components/settings/SettingsBackupPanel.jsx',
  'src/components/parent/ExtraTaskApprovalCard.jsx',
  'src/components/modals/PointAdjustmentModal.jsx',
  'src/components/modals/AddChildModal.jsx',
  'src/components/modals/EditChildModal.jsx',
  'src/components/modals/AddTaskModal.jsx',
  'src/components/modals/EditTaskModal.jsx',
  'src/components/modals/AddRewardModal.jsx',
];

assert(
  indexHtml.includes('<script type="module" src="/src/main.jsx"></script>'),
  'index.html must load src/main.jsx as the Vite frontend entrypoint',
);
assert(
  !indexHtml.includes('unpkg.com') && !indexHtml.includes('document.createElement'),
  'index.html must not load React from CDN or inject a cache-busted compiled script',
);
assert(
  exists('src/App.jsx') && exists('src/main.jsx') && exists('src/styles.css'),
  'Vite frontend source must live in src/App.jsx, src/main.jsx and src/styles.css',
);
assert(
  expectedSourceFiles.every(exists),
  'frontend source must keep shared constants, lib helpers and extracted component modules in src/',
);
assert(
  appSource.includes('export default App'),
  'src/App.jsx must export the React application',
);
assert(
  appSource.includes("from './lib/api.js'") && appSource.includes("from './components/modals/EditTaskModal.jsx'"),
  'src/App.jsx must consume extracted lib helpers and component modules instead of inlining everything',
);
assert(
  mainSource.includes("import App from './App.jsx'") && mainSource.includes("import './styles.css'"),
  'src/main.jsx must import App and src/styles.css',
);
assert(
  !exists('familyquest-app.jsx') && !exists('familyquest-app.compiled.js'),
  'legacy browser-loaded frontend files must not be reintroduced after the Vite migration',
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
  exists('public/manifest.json') && exists('public/service-worker.js') && exists('public/icons/icon-192.png'),
  'PWA public assets must live in public/',
);
assert.strictEqual(
  packageJson.scripts['test:frontend-source'],
  'node scripts/check-frontend-source.js',
  'package.json must expose the frontend source guard',
);
assert.strictEqual(packageJson.scripts['frontend:build'], 'vite build', 'package.json must expose Vite build');
assert.strictEqual(packageJson.scripts['frontend:dev'], 'vite', 'package.json must expose Vite dev server');

console.log('Frontend source OK: Vite src/ entrypoint, public PWA assets and cleanup-only service worker are in place');
