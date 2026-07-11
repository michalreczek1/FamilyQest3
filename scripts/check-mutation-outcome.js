/* eslint-disable no-console */

const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');

const rootDir = path.join(__dirname, '..', 'dist');
const today = new Date().toISOString().slice(0, 10);
const child = { id: 'outcome-child', name: 'Ola', avatar: '⭐', activeDays: [1, 2, 3, 4, 5, 6, 7], archived: false };
const task = {
  id: 'outcome-task', childId: child.id, title: 'Zadanie z utraconą odpowiedzią', tier: 'MIN', points: 1,
  daysOfWeek: [1, 2, 3, 4, 5, 6, 7], active: true, createdAt: `${today}T00:00:00.000Z`,
};

const snapshot = () => ({
  familyId: 'family-outcome', version: 1, generatedAt: `${today}T00:00:00.000Z`,
  viewer: { id: `child:${child.id}`, role: 'CHILD', familyId: 'family-outcome', childId: child.id, childName: child.name, sessionRef: 'session-outcome' },
  permissions: { canManageOwnChildTasks: true },
  family: {
    children: [child], tasks: [task], completions: [], extraTasks: [], pointAdjustments: [], pointLedger: [], rewards: [],
    streaks: {}, points: { [child.id]: 0 }, rewardUnlocks: [], rewardUnlockHistory: [],
    familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' }, auditLogs: [], dayPointGrants: {}, weekBonusGrants: {}, taskPointGrants: {}, parentUsers: [],
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
  const dialogs = [];
  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.message());
    await dialog.dismiss();
  });
  await page.addInitScript(() => sessionStorage.setItem('fq_child_session_active', '1'));
  await page.route('**/api/**', async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/family-state') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify(snapshot()) });
      return;
    }
    if (pathname === '/api/completions' && route.request().method() === 'POST') {
      await route.abort('failed');
      return;
    }
    await route.fulfill({ status: 404, contentType: 'application/json', body: JSON.stringify({ error: pathname }) });
  });
  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle' });
    const taskItem = page.locator('.task-item').filter({ hasText: task.title });
    await taskItem.click();
    await page.getByText('Sprawdzam wynik operacji…').waitFor({ state: 'visible', timeout: 10000 });
    const pending = await page.evaluate(() => JSON.parse(localStorage.getItem('fq_pending_mutations') || '[]'));
    assert.strictEqual(pending.length, 1, 'utracona mutacja musi zostać zapisana do rozstrzygnięcia');
    assert.strictEqual(pending[0].sessionRef, 'session-outcome');
    assert(pending[0].idempotencyKey, 'rekord musi zachować Idempotency-Key');
    assert.strictEqual(dialogs.length, 0, 'wynik nieznany nie może być pokazany jako błąd wykonania');
    console.log('Mutation outcome OK: lost response is persisted and shown as pending without a failure dialog.');
  } finally {
    await browser.close();
    server.close();
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
