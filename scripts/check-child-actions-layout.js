const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const css = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] || '';
const outDir = path.join(root, 'tmp');

const childCard = (name) => `
  <div class="glass-card">
    <div class="child-avatar">👦</div>
    <h3 style="text-align:center;margin-bottom:1rem">${name}</h3>
    <div class="grid grid-2" style="margin-bottom:1rem">
      <div class="stat-card"><div class="stat-value">48</div><div class="stat-label">punktów</div></div>
      <div class="stat-card"><div class="stat-value">0</div><div class="stat-label">passa</div></div>
    </div>
    <div style="font-size:0.9rem;opacity:0.7;text-align:center">29 zadań • Dni aktywne: 1, 2, 3, 4, 5, 6, 7</div>
    <div style="font-size:0.9rem;opacity:0.85;text-align:center;margin-top:0.35rem">Kod dziecka: <strong>1564</strong></div>
    <div class="child-admin-actions">
      <button class="btn btn-secondary">✏️ Edytuj</button>
      <button class="btn btn-danger">🗃️ Archiwizuj</button>
    </div>
    <div class="child-admin-actions">
      <button class="btn btn-success">🎁 Premia</button>
      <button class="btn btn-danger">⚠️ Kara</button>
    </div>
  </div>
`;

const fixture = `<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>${css}
    body {
      background-image:
        radial-gradient(circle at 82% 0%, rgba(236, 72, 153, 0.65), transparent 35%),
        linear-gradient(135deg, #0f172a, #4c1d95 55%, #111827);
      background-color: #0f172a;
    }
  </style>
</head>
<body>
  <div class="app-container" style="max-width:1420px">
    <div class="grid" style="grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 1rem">
      ${['Łucja', 'Ignacy', 'Franek', 'Filip'].map(childCard).join('')}
    </div>
  </div>
</body>
</html>`;

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1418, height: 760 } });
  await page.setContent(fixture, { waitUntil: 'load' });

  const layout = await page.locator('.child-admin-actions .btn').evaluateAll((buttons) =>
    buttons.map((button) => {
      const rect = button.getBoundingClientRect();
      const parentRect = button.parentElement.getBoundingClientRect();
      return {
        text: button.textContent.trim(),
        left: rect.left,
        right: rect.right,
        width: rect.width,
        scrollWidth: button.scrollWidth,
        clientWidth: button.clientWidth,
        parentLeft: parentRect.left,
        parentRight: parentRect.right,
      };
    }),
  );

  layout.forEach((button) => {
    assert(button.left >= button.parentLeft - 1, `${button.text} escapes left edge`);
    assert(button.right <= button.parentRight + 1, `${button.text} escapes right edge`);
    assert(button.scrollWidth <= button.clientWidth + 1, `${button.text} text overflows button`);
  });

  await page.screenshot({ path: path.join(outDir, 'child-actions-layout-check.png'), fullPage: true });
  await browser.close();
  console.log('Child action buttons layout OK: desktop cards keep labels inside buttons');
  console.log('Screenshot: tmp/child-actions-layout-check.png');
})().catch(async (error) => {
  console.error(error);
  process.exit(1);
});
