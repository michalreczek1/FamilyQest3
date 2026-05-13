const assert = require('assert');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { chromium } = require('playwright');
const { __test, prisma } = require('../server');

const rootDir = path.join(__dirname, '..');
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

const today = '2024-05-13';
const child = {
  id: 'ledger-child',
  name: 'Ignacy',
  avatar: '👦',
  activeDays: [1, 2, 3, 4, 5, 6, 7],
  accessCode: '2468',
  createdAt: '2024-01-01T00:00:00.000Z',
};
const tasks = [
  {
    id: 'ledger-task-1',
    childId: child.id,
    title: 'Poranne zadanie',
    tier: 'MIN',
    points: 3,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    createdAt: '2024-01-01T00:00:00.000Z',
  },
  {
    id: 'ledger-task-2',
    childId: child.id,
    title: 'Drugie zadanie',
    tier: 'MIN',
    points: 4,
    daysOfWeek: [1, 2, 3, 4, 5, 6, 7],
    active: true,
    createdAt: '2024-01-01T00:00:00.000Z',
  },
];

const makeState = () => ({
  children: [child],
  tasks,
  completions: tasks.map((task, index) => ({
    id: `ledger-comp-${index + 1}`,
    taskId: task.id,
    childId: child.id,
    date: today,
    doneByChild: true,
    doneAt: `${today}T08:0${index}:00.000Z`,
    approvedByParent: true,
    approvedAt: `${today}T09:0${index}:00.000Z`,
    rejectedByParent: false,
    rejectedAt: null,
    createdAt: `${today}T08:0${index}:00.000Z`,
    updatedAt: `${today}T09:0${index}:00.000Z`,
  })),
  extraTasks: [
    {
      id: 'ledger-extra-1',
      childId: child.id,
      title: 'Pomoc w kuchni',
      date: today,
      status: 'APPROVED',
      points: 2,
      approvedByParent: true,
      approvedAt: `${today}T10:00:00.000Z`,
      createdAt: `${today}T08:30:00.000Z`,
      updatedAt: `${today}T10:00:00.000Z`,
    },
  ],
  pointAdjustments: [
    {
      id: 'ledger-bonus-1',
      childId: child.id,
      type: 'BONUS',
      points: 1,
      delta: 1,
      note: 'Premia za wytrwałość',
      createdAt: `${today}T11:00:00.000Z`,
      updatedAt: `${today}T11:00:00.000Z`,
    },
  ],
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
});

const storageValues = makeState();
__test.recomputePointsAndGrants(storageValues);

const runLogicCheck = () => {
  assert.strictEqual(storageValues.points[child.id], 12);
  const types = storageValues.pointLedger.map((entry) => entry.type);
  assert(types.includes('TASK_APPROVED'), 'ledger should include task approvals');
  assert(types.includes('DAY_PASSED'), 'ledger should include passed-day grant');
  assert(types.includes('EXTRA_TASK'), 'ledger should include approved extra task');
  assert(types.includes('BONUS'), 'ledger should include manual bonus');
  assert(storageValues.pointLedger.every((entry) => typeof entry.newPoints === 'number'));
};

const runUiCheck = async () => {
  const baseUrl = process.env.POINT_LEDGER_BASE_URL || (await startStaticServer());
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
  await page.addInitScript(() => {
    sessionStorage.setItem('fq_child_session_active', '1');
  });

  await page.route('**/api/**', async (route) => {
    const url = new URL(route.request().url());
    const apiPath = url.pathname;

    if (apiPath === '/api/auth/me') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          user: {
            id: `child:${child.id}`,
            role: 'CHILD',
            familyId: 'family-test',
            childId: child.id,
            childName: child.name,
          },
        }),
      });
      return;
    }

    if (apiPath === '/api/leaderboard') {
      await route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({
          children: [{ id: child.id, name: child.name, avatar: child.avatar }],
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
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true }) });
      return;
    }

    await route.continue();
  });

  await page.goto(baseUrl, { waitUntil: 'networkidle' });
  const approvalDialog = page.getByRole('dialog', { name: /Zaliczone zadania|Premia punktowa|Zmiana punktów/ });
  if (await approvalDialog.isVisible().catch(() => false)) {
    await approvalDialog.getByRole('button').last().click();
  }
  await page.getByTitle('Pokaż historię punktów').click();
  const historyDialog = page.getByRole('dialog', { name: '⚡ Historia punktów' });
  await historyDialog.waitFor({ state: 'visible', timeout: 10000 });
  await historyDialog.getByText('Poranne zadanie').waitFor({ state: 'visible', timeout: 10000 });
  await historyDialog.getByText('Zaliczony dzień').waitFor({ state: 'visible', timeout: 10000 });
  await historyDialog.getByText('Premia za wytrwałość').waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: 'tmp/point-ledger-history-check.png', fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await historyDialog.waitFor({ state: 'visible', timeout: 10000 });
  await page.screenshot({ path: 'tmp/point-ledger-history-mobile-check.png', fullPage: false });
  const layout = await page.locator('.point-history-entry').evaluateAll((entries) =>
    entries.map((entry) => {
      const rect = entry.getBoundingClientRect();
      return {
        top: rect.top,
        bottom: rect.bottom,
        left: rect.left,
        right: rect.right,
        width: rect.width,
        height: rect.height,
        scrollWidth: entry.scrollWidth,
        clientWidth: entry.clientWidth,
      };
    }),
  );
  assert(layout.length >= 4, 'mobile history should render ledger entries');
  layout.forEach((box, index) => {
    assert(box.height > 44, `mobile history entry ${index} is too short`);
    assert(box.scrollWidth <= box.clientWidth + 1, `mobile history entry ${index} overflows horizontally`);
    if (index > 0) {
      assert(box.top >= layout[index - 1].bottom - 1, `mobile history entry ${index} overlaps previous entry`);
    }
  });

  await browser.close();
};

(async () => {
  runLogicCheck();
  await runUiCheck();
  await prisma.$disconnect();
  if (staticServer) staticServer.close();
  console.log('Point ledger logic OK: task/day/extra/bonus entries generated');
  console.log('Point history UI OK: child opens scrollable point history popup');
  console.log('Screenshot: tmp/point-ledger-history-check.png');
  console.log('Mobile screenshot: tmp/point-ledger-history-mobile-check.png');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  if (staticServer) staticServer.close();
  process.exit(1);
});
