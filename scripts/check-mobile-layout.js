const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const css = html.match(/<style>([\s\S]*?)<\/style>/)?.[1] || '';
const outDir = path.join(root, 'tmp', 'playwright-mobile');

const fixture = `<!doctype html>
<html lang="pl">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>${css}
    body {
      background-image:
        radial-gradient(circle at 20% 10%, rgba(236, 72, 153, 0.55), transparent 35%),
        linear-gradient(135deg, #0f172a, #4c1d95 55%, #111827);
      background-color: #0f172a;
    }
  </style>
</head>
<body>
  <div class="app-container">
    <div class="glass-card">
      <div class="header">
        <h1>Panel rodzica</h1>
        <button class="btn btn-primary">+ Dodaj nagrode</button>
      </div>
      <div class="tabs">
        <button class="tab active">Do zatwierdzenia (12)</button>
        <button class="tab">Zadania (48)</button>
        <button class="tab">Nagrody (9)</button>
        <button class="tab">Ustawienia</button>
      </div>
      <h2>Zadania do zatwierdzenia</h2>
      <div class="task-item">
        <div style="font-size: 2rem">👦</div>
        <div style="flex: 1">
          <div style="font-weight: 600">Bardzo dlugie zadanie do zatwierdzenia po obiedzie</div>
          <div style="font-size: 0.9rem; opacity: 0.7">Ignacy - 2026-05-08</div>
        </div>
        <div class="badge badge-min">MIN</div>
        <div class="badge badge-points">+20 pkt</div>
        <button class="btn btn-success">Zatwierdz</button>
        <button class="btn btn-danger">Odrzuc</button>
      </div>
      <h2>Zarzadzanie zadaniami</h2>
      <div class="task-item">
        <div style="flex: 1">
          <div style="font-weight: 600">Sprzatanie pokoju i ulozenie ksiazek na polce</div>
          <div style="font-size: 0.9rem; opacity: 0.7">Opis zadania, ktory potrafi byc dluzszy</div>
        </div>
        <div class="badge badge-plus">PLUS</div>
        <div class="badge badge-points">+5 pkt</div>
        <button class="btn btn-secondary">✏️ Edytuj</button>
        <button class="btn btn-danger">🗃️ Usun</button>
      </div>
      <h2>Katalog nagrod</h2>
      <div class="task-item">
        <div style="font-size: 2rem">🎁</div>
        <div style="flex: 1">
          <div style="font-weight: 600">Wyjscie na lody albo dodatkowy czas gry</div>
          <div style="font-size: 0.9rem; opacity: 0.7">Nagroda rodzinna</div>
          <div style="margin-top: 0.5rem; display: flex; gap: 0.5rem">
            <div class="badge badge-points">120 punktow</div>
            <div class="badge badge-min">7 dni passy</div>
            <div class="badge badge-weekly">2 idealne tygodnie</div>
          </div>
        </div>
        <button class="btn btn-secondary">✏️ Edytuj</button>
        <button class="btn btn-danger">🗃️ Usun</button>
      </div>
      <h2>Zadanie dodatkowe</h2>
      <div class="task-item">
        <div style="font-size: 2rem">👧</div>
        <div style="flex: 1">
          <div style="font-weight: 700">Pomoc przy kolacji i posprzatanie stolu</div>
          <div style="font-size: 0.9rem; opacity: 0.7">zadanie dodatkowe</div>
        </div>
        <input class="input" type="number" value="3" />
        <button class="btn btn-success">Zatwierdz</button>
        <button class="btn btn-danger">Odrzuc</button>
      </div>
    </div>
  </div>
</body>
</html>`;

const viewports = [
  { name: 'iphone-390', width: 390, height: 844 },
  { name: 'narrow-360', width: 360, height: 740 },
];

(async () => {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const results = [];

  for (const viewport of viewports) {
    const page = await browser.newPage({ viewport });
    await page.setContent(fixture, { waitUntil: 'load' });
    const result = await page.evaluate(() => {
      const width = window.innerWidth;
      const docOverflow = document.documentElement.scrollWidth - width;
      const bad = [];
      document.querySelectorAll('.task-item, .task-item .btn, .task-item .badge, .tabs, .tab').forEach((node) => {
        const rect = node.getBoundingClientRect();
        if (rect.left < -1 || rect.right > width + 1) {
          bad.push({
            text: node.textContent.trim().slice(0, 80),
            left: Math.round(rect.left),
            right: Math.round(rect.right),
            width: Math.round(rect.width),
          });
        }
      });
      return { width, scrollWidth: document.documentElement.scrollWidth, docOverflow, bad };
    });
    const screenshot = path.join(outDir, `${viewport.name}.png`);
    await page.screenshot({ path: screenshot, fullPage: true });
    results.push({ viewport, screenshot, ...result });
    await page.close();
  }

  await browser.close();

  const failures = results.filter((result) => result.docOverflow > 1 || result.bad.length > 0);
  console.log(JSON.stringify(results, null, 2));
  if (failures.length > 0) {
    process.exit(1);
  }
})();
