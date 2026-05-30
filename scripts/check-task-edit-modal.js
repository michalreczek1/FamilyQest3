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
  { id: 'edit-child-1', name: 'Łucja', avatar: '👧', activeDays: [1, 2, 3, 4, 5, 6, 7] },
  { id: 'edit-child-2', name: 'Ignacy', avatar: '👦', activeDays: [1, 2, 3, 4, 5, 6, 7] },
];

const storageValues = {
  children,
  tasks: [
    {
      id: 'edit-task-1',
      childId: 'edit-child-1',
      title: 'Stara nazwa',
      tier: 'MIN',
      points: 2,
      description: 'Stary opis',
      daysOfWeek: [1, 2, 3, 4, 5],
      active: true,
      createdAt: '2024-01-01T00:00:00.000Z',
    },
  ],
  completions: [],
  extraTasks: [],
  pointAdjustments: [],
  pointLedger: [],
  rewards: [],
  streaks: {},
  points: {},
  rewardUnlocks: [],
  familyGoal: { title: 'Cel rodzinny', target: 500, mode: 'points' },
  auditLogs: [],
  dayPointGrants: {},
  weekBonusGrants: {},
  taskPointGrants: {},
};

let updatePayload = null;

const runUiCheck = async () => {
  const baseUrl = process.env.TASK_EDIT_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
  page.on('dialog', async (dialog) => {
    throw new Error(`Unexpected browser dialog while editing task: ${dialog.type()} ${dialog.message()}`);
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ user: { id: 'parent-edit-ui', role: 'PARENT', familyId: 'family-edit-ui', hasPinCode: true } }),
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
        body: JSON.stringify({ children, points: {}, streaks: {} }),
      });
      return;
    }

    if (apiPath === '/api/tasks/edit-task-1' && route.request().method() === 'PUT') {
      updatePayload = route.request().postDataJSON();
      storageValues.tasks = storageValues.tasks.map((task) =>
        task.id === 'edit-task-1'
          ? {
              ...task,
              ...updatePayload,
              updatedAt: '2026-05-13T12:00:00.000Z',
            }
          : task,
      );
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ task: storageValues.tasks[0] }),
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
  await page.getByPlaceholder('6-cyfrowy PIN').fill('123456');
  await page.getByRole('button', { name: 'Wejdź' }).click();
  await page.getByRole('button', { name: /Zadania/ }).click();
  await page.getByRole('button', { name: /Edytuj/ }).click();

  const dialog = page.getByRole('dialog', { name: 'Edytuj zadanie' });
  await dialog.waitFor({ state: 'visible', timeout: 10000 });
  await dialog.locator('input[type="text"]').fill('Nowa nazwa');
  await dialog.getByRole('button', { name: /Bonus/ }).click();
  await dialog.locator('input[type="number"]').fill('7');
  await dialog.getByRole('button', { name: 'Sob' }).click();
  await dialog.getByRole('button', { name: 'Ndz' }).click();
  await dialog.locator('textarea').fill('Nowy opis zadania');
  await dialog.getByRole('button', { name: /Zapisz zmiany/ }).click();

  await dialog.waitFor({ state: 'hidden', timeout: 10000 });
  await page.getByText('Nowa nazwa').waitFor({ state: 'visible', timeout: 10000 });
  await page.locator('.task-item').filter({ hasText: 'Nowy opis zadania' }).waitFor({ state: 'visible', timeout: 10000 });
  await page.getByText('+7 pkt').waitFor({ state: 'visible', timeout: 10000 });

  assert(updatePayload, 'task update payload should be sent');
  assert.strictEqual(updatePayload.title, 'Nowa nazwa');
  assert.strictEqual(updatePayload.tier, 'PLUS');
  assert.strictEqual(updatePayload.points, 7);
  assert.strictEqual(updatePayload.description, 'Nowy opis zadania');
  assert.deepStrictEqual(updatePayload.daysOfWeek, [1, 2, 3, 4, 5, 6, 7]);

  await page.screenshot({ path: 'tmp/task-edit-modal-check.png', fullPage: true });
  await browser.close();
};

(async () => {
  await runUiCheck();
  if (staticServer) staticServer.close();
  console.log('Task edit UI OK: modal edits title, tier, points, description and days');
  console.log('Screenshot: tmp/task-edit-modal-check.png');
})().catch((error) => {
  console.error(error);
  if (staticServer) staticServer.close();
  process.exit(1);
});
