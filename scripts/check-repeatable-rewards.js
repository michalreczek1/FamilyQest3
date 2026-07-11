const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
const contentTypes = {
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
};
const child = {
  id: 'child-ignacy',
  name: 'Ignacy',
  avatar: '⭐',
  accessCode: '1370',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
};
const reward = {
  id: 'reward-30',
  title: '30 zł',
  description: '30 zł do wydania w sklepie',
  requiredPoints: 50,
  active: true,
};
const family = {
  children: [child],
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  pointLedger: [],
  rewards: [reward],
  streaks: { [child.id]: { current: 0, best: 0, idealWeeksCount: 0, idealWeeksInRow: 0 } },
  points: { [child.id]: 137 },
  rewardUnlocks: [
    { id: 'unlock-50', childId: child.id, rewardId: reward.id, cycle: 1, unlockedAt: '2026-07-10T10:00:00.000Z' },
    { id: 'unlock-100', childId: child.id, rewardId: reward.id, cycle: 2, unlockedAt: '2026-07-11T10:00:00.000Z' },
  ],
  rewardUnlockHistory: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
  parentUsers: [],
  familyLeaderboard: { children: [child], points: { [child.id]: 137 }, streaks: {} },
};

const startStaticServer = () => new Promise((resolve) => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1');
    const filePath = path.normalize(path.join(rootDir, decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname)));
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
  server.listen(0, '127.0.0.1', () => resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` }));
});

(async () => {
  const externalBaseUrl = process.env.REPEATABLE_REWARDS_BASE_URL || '';
  const { server, baseUrl } = externalBaseUrl ? { server: null, baseUrl: externalBaseUrl } : await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  let loggedIn = false;

  await page.route('**/api/**', async (route) => {
    const apiPath = new URL(route.request().url()).pathname;
    const user = { id: `child:${child.id}`, role: 'CHILD', familyId: 'family-repeatable-rewards', childId: child.id, childName: child.name, sessionRef: 'repeatable-session' };
    if (apiPath === '/api/auth/me') {
      await route.fulfill({ status: loggedIn ? 200 : 401, contentType: 'application/json', body: JSON.stringify(loggedIn ? { user } : { error: 'Brak sesji' }) });
      return;
    }
    if (apiPath === '/api/auth/login-child') {
      loggedIn = true;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ user }) });
      return;
    }
    if (apiPath === '/api/family-state') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ familyId: 'family-repeatable-rewards', version: 1, generatedAt: '2026-07-11T10:00:00.000Z', viewer: user, permissions: { canManageOwnChildTasks: true }, family }),
      });
      return;
    }
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
  });

  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('button', { name: 'Dziecko' }).click();
    await page.getByPlaceholder('Kod dziecka (4 cyfry)').fill(child.accessCode);
    await page.getByRole('button', { name: 'Zaloguj dziecko' }).click();
    await page.getByRole('heading', { name: child.name }).waitFor({ timeout: 10000 });

    await page.getByTitle('Pokaż moje nagrody').click();
    const dialog = page.getByRole('dialog', { name: /Moje nagrody/ });
    await dialog.waitFor({ state: 'visible', timeout: 10000 });
    await dialog.getByText('Brakuje jeszcze').waitFor();
    assert((await dialog.getByText(/13 pkt.*150 pkt/).count()) === 1, 'the next cycle should be shown as the 150-point threshold');
    assert.strictEqual(await dialog.locator('.task-item').count(), 2, 'both earned copies of the same reward should be visible');
    assert.strictEqual(await dialog.getByText('30 zł', { exact: true }).count(), 2, 'the repeated reward should render twice');
    assert.strictEqual(await dialog.getByText('Próg 2 (100 pkt)').count(), 1, 'the second reward should identify its earned threshold');

    await page.screenshot({ path: 'tmp/repeatable-rewards-check.png', fullPage: true });
    console.log('Repeatable rewards UI OK: two reward copies and the 150-point next threshold are visible.');
  } finally {
    await browser.close();
    if (server) server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
