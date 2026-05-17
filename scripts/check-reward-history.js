const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
let staticServer = null;

const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

const startStaticServer = () =>
  new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const url = new URL(req.url, 'http://127.0.0.1');
      const rawPath = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
      const filePath = path.normalize(path.join(rootDir, rawPath));
      if (!filePath.startsWith(rootDir)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
      }
      fs.readFile(filePath, (error, content) => {
        if (error) {
          res.writeHead(404);
          res.end('Not found');
          return;
        }
        res.writeHead(200, {
          'Content-Type': contentTypes[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
          'Cache-Control': 'no-store',
        });
        res.end(content);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      staticServer = server;
      resolve(`http://127.0.0.1:${port}`);
    });
  });

const children = [
  { id: 'child-lucja', name: 'Łucja', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7] },
  { id: 'child-ignacy', name: 'Ignacy', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7] },
];

const rewards = [
  {
    id: 'reward-games',
    title: '30 minut grania',
    description: 'Dodatkowy czas po kolacji',
    requiredPoints: 50,
    requiredStreak: null,
    requiredIdealWeeks: null,
    active: true,
  },
  {
    id: 'reward-cinema',
    title: 'Kino rodzinne',
    description: 'Wspólny seans w weekend',
    requiredPoints: 80,
    requiredStreak: null,
    requiredIdealWeeks: null,
    active: true,
  },
];

const visibleRewardUnlocks = [
  {
    id: 'unlock-available',
    childId: 'child-lucja',
    rewardId: 'reward-games',
    unlockedAt: '2026-05-10T10:00:00.000Z',
    claimedAt: null,
    revokedAt: null,
    restoredAt: null,
  },
  {
    id: 'unlock-restored',
    childId: 'child-ignacy',
    rewardId: 'reward-cinema',
    unlockedAt: '2026-05-09T10:00:00.000Z',
    claimedAt: null,
    revokedAt: null,
    restoredAt: '2026-05-12T12:00:00.000Z',
  },
];

const rewardUnlockHistory = [
  {
    id: 'unlock-restored',
    childId: 'child-ignacy',
    childName: 'Ignacy',
    rewardId: 'reward-cinema',
    rewardTitle: 'Kino rodzinne',
    rewardDescription: 'Wspólny seans w weekend',
    requiredPoints: 80,
    status: 'RESTORED',
    latestAt: '2026-05-12T12:00:00.000Z',
    events: [
      { type: 'UNLOCKED', at: '2026-05-09T10:00:00.000Z' },
      { type: 'REVOKED', at: '2026-05-11T08:30:00.000Z' },
      { type: 'RESTORED', at: '2026-05-12T12:00:00.000Z' },
    ],
  },
  {
    id: 'unlock-revoked',
    childId: 'child-lucja',
    childName: 'Łucja',
    rewardId: 'reward-cinema',
    rewardTitle: 'Kino rodzinne',
    rewardDescription: 'Wspólny seans w weekend',
    requiredPoints: 80,
    status: 'REVOKED',
    latestAt: '2026-05-11T08:30:00.000Z',
    events: [
      { type: 'UNLOCKED', at: '2026-05-08T10:00:00.000Z' },
      { type: 'REVOKED', at: '2026-05-11T08:30:00.000Z' },
    ],
  },
  {
    id: 'unlock-available',
    childId: 'child-lucja',
    childName: 'Łucja',
    rewardId: 'reward-games',
    rewardTitle: '30 minut grania',
    rewardDescription: 'Dodatkowy czas po kolacji',
    requiredPoints: 50,
    status: 'AVAILABLE',
    latestAt: '2026-05-10T10:00:00.000Z',
    events: [{ type: 'UNLOCKED', at: '2026-05-10T10:00:00.000Z' }],
  },
];

const storageValues = {
  children,
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  pointLedger: [],
  rewards,
  streaks: {},
  points: { 'child-lucja': 62, 'child-ignacy': 88 },
  rewardUnlocks: visibleRewardUnlocks,
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
};

const runUiCheck = async () => {
  const baseUrl = process.env.REWARD_HISTORY_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 820 } });
  const consoleErrors = [];
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ user: { id: 'parent-reward-history', role: 'PARENT', familyId: 'family-reward-history' } }),
      });
      return;
    }

    if (apiPath === '/api/auth/parents') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ users: [] }) });
      return;
    }

    if (apiPath === '/api/rewards/history') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ rewardUnlockHistory }),
      });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ children, points: storageValues.points, streaks: {} }),
      });
      return;
    }

    const storageMatch = apiPath.match(/^\/api\/storage\/get\/([^/]+)$/);
    if (storageMatch) {
      const key = decodeURIComponent(storageMatch[1]);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ key, value: storageValues[key] ?? null }),
      });
      return;
    }

    if (apiPath === '/api/storage/merge') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    await route.continue();
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Panel rodzica/ }).click();
  await page.getByRole('button', { name: /Nagrody/ }).click();

  await page.getByText('Historia nagród').waitFor({ state: 'visible', timeout: 10000 });
  await page.getByText('3 wpisów').waitFor({ state: 'visible', timeout: 10000 });
  await page.getByText('Kino rodzinne').first().waitFor({ state: 'visible', timeout: 10000 });

  const historyItems = await page.locator('.reward-history-item').count();
  assert.strictEqual(historyItems, 3, 'reward history should render all entries');
  assert((await page.getByText('Przywrócona').count()) >= 1, 'restored status should be visible');
  assert((await page.getByText('Cofnięta').count()) >= 1, 'revoked status should be visible');
  assert((await page.getByText('Dostępna').count()) >= 1, 'available status should be visible');
  assert((await page.getByText('Odblokowana').count()) >= 1, 'unlocked event should be visible');

  await page.screenshot({ path: 'tmp/reward-history-check.png', fullPage: true });
  await browser.close();

  const relevantErrors = consoleErrors.filter((line) => !line.includes('/api/auth/me') && !line.includes('401'));
  assert.deepStrictEqual(relevantErrors, []);
};

(async () => {
  await runUiCheck();
  if (staticServer) staticServer.close();
  console.log('Reward history UI OK: available, revoked and restored statuses are visible.');
  console.log('Screenshot: tmp/reward-history-check.png');
})().catch((error) => {
  console.error(error);
  if (staticServer) staticServer.close();
  process.exit(1);
});
