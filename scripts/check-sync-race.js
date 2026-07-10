/* eslint-disable no-console */

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
const child = {
  id: 'sync-race-child',
  name: 'Zosia',
  avatar: '⭐',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  archived: false,
};

const snapshot = () => ({
  familyId: 'family-sync-race',
  version: 1,
  generatedAt: '2026-07-10T12:00:00.000Z',
  viewer: {
    id: `child:${child.id}`,
    role: 'CHILD',
    familyId: 'family-sync-race',
    childId: child.id,
    childName: child.name,
    sessionRef: 'session-sync-race',
  },
  permissions: { canManageFamily: false, canManageOwnChildTasks: true },
  family: {
    children: [child], tasks: [], completions: [], extraTasks: [], pointAdjustments: [], pointLedger: [], rewards: [],
    streaks: {}, points: { [child.id]: 0 }, rewardUnlocks: [], rewardUnlockHistory: [],
    familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' }, auditLogs: [],
    dayPointGrants: {}, weekBonusGrants: {}, taskPointGrants: {}, parentUsers: [],
    familyLeaderboard: { children: [child], points: { [child.id]: 0 }, streaks: {} },
  },
});

const startStaticServer = () => new Promise((resolve) => {
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    const filePath = path.normalize(path.join(rootDir, pathname === '/' ? 'index.html' : pathname));
    if (!filePath.startsWith(rootDir)) return res.writeHead(403).end();
    fs.readFile(filePath, (error, content) => {
      if (error) return res.writeHead(404).end();
      res.writeHead(200, { 'Content-Type': filePath.endsWith('.js') ? 'application/javascript' : filePath.endsWith('.css') ? 'text/css' : 'text/html' });
      res.end(content);
    });
  });
  server.listen(0, '127.0.0.1', () => resolve({ server, baseUrl: `http://127.0.0.1:${server.address().port}` }));
});

(async () => {
  const { server, baseUrl } = await startStaticServer();
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 } });
  let snapshotCount = 0;
  let releaseSecondSnapshot;
  const secondSnapshotStarted = new Promise((resolve) => { releaseSecondSnapshot = resolve; });
  let unlockSecondSnapshot;
  const secondSnapshotGate = new Promise((resolve) => { unlockSecondSnapshot = resolve; });
  await page.addInitScript(() => sessionStorage.setItem('fq_child_session_active', '1'));
  await page.route('**/api/**', async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/family-state') {
      snapshotCount += 1;
      if (snapshotCount === 2) {
        releaseSecondSnapshot();
        await secondSnapshotGate;
      }
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(snapshot()) });
      return;
    }
    if (pathname === '/api/auth/logout') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: pathname }) });
  });

  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    await page.getByRole('heading', { name: child.name }).waitFor();
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await secondSnapshotStarted;
    await page.getByRole('button', { name: 'Wyloguj' }).click();
    unlockSecondSnapshot();
    await page.getByRole('button', { name: 'Zaloguj się' }).waitFor({ timeout: 10000 });
    await page.waitForTimeout(150);
    assert.strictEqual(await page.getByRole('heading', { name: child.name }).count(), 0, 'stary snapshot nie może przywrócić widoku dziecka po wylogowaniu');
    assert.strictEqual(snapshotCount, 2, 'test powinien wymusić drugi, opóźniony snapshot');
    console.log('Sync race OK: stale snapshot cannot restore a child session after logout.');
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
