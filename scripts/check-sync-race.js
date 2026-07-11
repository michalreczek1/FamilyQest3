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
const nextChild = {
  id: 'sync-race-child-next',
  name: 'Maks',
  avatar: '🦊',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  archived: false,
};

const snapshot = (viewerChild, sessionRef, version) => ({
  familyId: 'family-sync-race',
  version,
  generatedAt: '2026-07-10T12:00:00.000Z',
  viewer: {
    id: `child:${viewerChild.id}`,
    role: 'CHILD',
    familyId: 'family-sync-race',
    childId: viewerChild.id,
    childName: viewerChild.name,
    sessionRef,
  },
  permissions: { canManageFamily: false, canManageOwnChildTasks: true },
  family: {
    children: [viewerChild], tasks: [], completions: [], extraTasks: [], pointAdjustments: [], pointLedger: [], rewards: [],
    streaks: {}, points: { [viewerChild.id]: 0 }, rewardUnlocks: [], rewardUnlockHistory: [],
    familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' }, auditLogs: [],
    dayPointGrants: {}, weekBonusGrants: {}, taskPointGrants: {}, parentUsers: [],
    familyLeaderboard: { children: [viewerChild], points: { [viewerChild.id]: 0 }, streaks: {} },
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
  let activeChild = child;
  let activeSessionRef = 'session-sync-race-a';
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
      const isStaleSecondSnapshot = snapshotCount === 2;
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify(snapshot(
          isStaleSecondSnapshot ? child : activeChild,
          isStaleSecondSnapshot ? 'session-sync-race-a' : activeSessionRef,
          isStaleSecondSnapshot ? 1 : 2,
        )),
      });
      return;
    }
    if (pathname === '/api/auth/logout') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }
    if (pathname === '/api/auth/login-child') {
      activeChild = nextChild;
      activeSessionRef = 'session-sync-race-b';
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: `child:${nextChild.id}`,
            role: 'CHILD',
            familyId: 'family-sync-race',
            childId: nextChild.id,
            childName: nextChild.name,
            sessionRef: activeSessionRef,
          },
        }),
      });
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
    await page.getByRole('button', { name: 'Zaloguj się' }).waitFor({ timeout: 10000 });
    await page.getByRole('button', { name: 'Dziecko' }).click();
    await page.getByPlaceholder('Kod dziecka (4 cyfry)').fill('2222');
    await page.getByRole('button', { name: 'Zaloguj dziecko' }).click();
    await page.getByRole('heading', { name: nextChild.name }).waitFor({ timeout: 10000 });
    unlockSecondSnapshot();
    await page.waitForTimeout(150);
    assert.strictEqual(await page.getByRole('heading', { name: child.name }).count(), 0, 'stary snapshot nie może przywrócić widoku poprzedniego dziecka');
    assert.strictEqual(await page.getByRole('heading', { name: nextChild.name }).count(), 1, 'odpowiedź poprzedniej sesji nie może nadpisać nowej sesji');
    assert(snapshotCount >= 3, 'test powinien wymusić drugi, opóźniony snapshot i snapshot nowej sesji');
    console.log('Sync race OK: stale snapshot cannot restore a logged-out or replaced child session.');
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
