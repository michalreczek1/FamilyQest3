const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');
require('./test-env');
const { __test, prisma } = require('../server');

const projectRootDir = path.join(__dirname, '..');
const rootDir = path.join(projectRootDir, 'dist');
const tmpDir = path.join(projectRootDir, 'tmp');
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

const today = new Date().toISOString().slice(0, 10);
const restoredChild = {
  id: 'restored-child',
  name: 'Restorek',
  avatar: '👦',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '7777',
  createdAt: '2026-01-01T00:00:00.000Z',
};
const restoredTask = {
  id: 'restored-task',
  childId: restoredChild.id,
  title: 'Zadanie z backupu',
  tier: 'MIN',
  points: 5,
  daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
  active: true,
  createdAt: '2026-01-01T00:00:00.000Z',
};
const restoredCompletion = {
  id: 'restored-completion',
  taskId: restoredTask.id,
  childId: restoredChild.id,
  date: today,
  doneByChild: true,
  doneAt: `${today}T08:00:00.000Z`,
  approvedByParent: true,
  approvedAt: `${today}T09:00:00.000Z`,
  rejectedByParent: false,
  rejectedAt: null,
  createdAt: `${today}T08:00:00.000Z`,
  updatedAt: `${today}T09:00:00.000Z`,
};

const backupPayload = {
  version: 1,
  exportedAt: `${today}T09:30:00.000Z`,
  data: {
    children: [restoredChild],
    tasks: [restoredTask],
    completions: [restoredCompletion],
    extraTasks: [],
    pointAdjustments: [],
    rewards: [],
    streaks: {},
    points: { [restoredChild.id]: 999 },
    rewardUnlocks: [],
    familyGoal: { title: 'Backup cel', target: 100, mode: 'points' },
    auditLogs: [{ id: 'old-audit', action: 'OLD', createdAt: `${today}T07:00:00.000Z` }],
    dayPointGrants: {},
    weekBonusGrants: {},
    taskPointGrants: {},
  },
};

const emptyState = () => ({
  children: [],
  tasks: [],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  rewards: [],
  streaks: {},
  points: {},
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
});

const runLogicCheck = () => {
  const restored = __test.normalizeRestoredBackupData(
    backupPayload,
    'parent-test',
    `${today}T10:00:00.000Z`,
  );
  assert(restored, 'restore should return normalized data');
  assert.strictEqual(restored.children.length, 1);
  assert.strictEqual(restored.children[0].name, 'Restorek');
  assert.strictEqual(restored.points[restoredChild.id], 7, 'restore must recompute points from approved completion');
  assert.notStrictEqual(restored.points[restoredChild.id], 999, 'restore must not trust snapshot points');
  assert.strictEqual(restored.dayPointGrants[`${restoredChild.id}:${today}`], true);
  assert.strictEqual(restored.auditLogs[0].action, 'RESTORE_BACKUP');
};

const runUiCheck = async () => {
  fs.mkdirSync(tmpDir, { recursive: true });
  const backupPath = path.join(tmpDir, 'restore-backup-fixture.json');
  fs.writeFileSync(backupPath, JSON.stringify(backupPayload, null, 2));

  const baseUrl = process.env.RESTORE_BACKUP_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1366, height: 760 } });
  let storageValues = {
    ...emptyState(),
    children: [{ id: 'old-child', name: 'Stare dziecko', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7] }],
    familyGoal: { title: 'Stary cel', target: 500, mode: 'points' },
  };
  let restoreCalled = false;
  let mergeCalled = false;
  const dialogMessages = [];

  page.on('dialog', async (dialog) => {
    dialogMessages.push(dialog.message());
    await dialog.accept();
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: 'parent-test',
            email: 'parent@example.test',
            role: 'PARENT',
            familyId: 'family-test',
            active: true,
            hasPinCode: true,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/auth/parent-pin/verify') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    if (apiPath === '/api/auth/parents') {
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ users: [] }) });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          children: storageValues.children.map((child) => ({ id: child.id, name: child.name, avatar: child.avatar })),
          points: storageValues.points,
          streaks: storageValues.streaks,
        }),
      });
      return;
    }

    if (apiPath === '/api/storage/restore-backup') {
      restoreCalled = true;
      const body = JSON.parse(route.request().postData() || '{}');
      assert.strictEqual(body.backup.data.points[restoredChild.id], 999);
      storageValues = __test.normalizeRestoredBackupData(body.backup, 'parent-test', `${today}T10:00:00.000Z`);
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          ok: true,
          restored: {
            children: storageValues.children.length,
            tasks: storageValues.tasks.length,
            completions: storageValues.completions.length,
            extraTasks: storageValues.extraTasks.length,
            rewardUnlocks: storageValues.rewardUnlocks.length,
          },
          points: storageValues.points,
          streaks: storageValues.streaks,
        }),
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
      mergeCalled = true;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    await route.continue();
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  await page.getByRole('button', { name: /Panel rodzica/ }).click();
  await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByRole('button', { name: 'Ustawienia' }).click();
  await page.waitForTimeout(1200);
  mergeCalled = false;
  await page.locator('input[type="file"]').setInputFiles(backupPath);
  await page.getByText('Backup został odtworzony. Dzieci: 1, zadania: 1.').waitFor({
    state: 'visible',
    timeout: 10000,
  });
  await page.getByRole('button', { name: /Dzieci/ }).click();
  await page.getByText('Restorek').waitFor({ state: 'visible', timeout: 10000 });

  assert(restoreCalled, 'UI must call /api/storage/restore-backup');
  assert(dialogMessages.some((message) => message.includes('Import backupu zastąpi aktualne dane rodziny')));
  assert.strictEqual(storageValues.points[restoredChild.id], 7);
  assert.strictEqual(storageValues.children.some((child) => child.name === 'Stare dziecko'), false);
  assert.strictEqual(mergeCalled, false, 'restore import should not use storage merge');

  await page.screenshot({ path: 'tmp/restore-backup-check.png', fullPage: true });
  await browser.close();
};

(async () => {
  runLogicCheck();
  await runUiCheck();
  await prisma.$disconnect();
  if (staticServer) staticServer.close();
  console.log('Restore backup logic OK: points recomputed from 999 snapshot to 7');
  console.log('Restore backup UI OK: import calls restore endpoint and replaces family data');
  console.log('Screenshot: tmp/restore-backup-check.png');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  if (staticServer) staticServer.close();
  process.exit(1);
});
