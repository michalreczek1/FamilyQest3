# FamilyQuest Proxmox Deploy

Aktualny produkcyjny deploy nie uzywa Railway. Aplikacja dziala w stacku Proxmox:

- publiczny URL: `https://fq.familyos.pl`
- aplikacja Node: `CT 103 familyquest`, IP `192.168.33.122`
- katalog aplikacji: `/opt/familyquest`
- systemd service: `familyquest`
- baza PostgreSQL: `CT 102 pgsql`, IP `192.168.33.121`
- reverse proxy i Cloudflare Tunnel: `CT 101 caddy`

## Pliki Konfiguracyjne

Sekrety produkcyjne sa tylko na Proxmoxie w:

```bash
/opt/familyquest/.env
```

Ten plik nie jest commitowany. `DATABASE_URL` powinien wskazywac baze PostgreSQL w kontenerze `CT 102`, a nie Railway.

Minimalny zestaw produkcyjny:

```env
DATABASE_URL="postgresql://familyquest:<password>@192.168.33.121:5432/familyquest?schema=public"
JWT_SECRET="<losowy-sekret-min-32-znaki>"
JWT_EXPIRES_IN="7d"
BCRYPT_ROUNDS=12
NODE_ENV=production
PORT=3000
CORS_ORIGINS="https://fq.familyos.pl"
RATE_LIMIT_MAX_REQUESTS=0
AUTH_RATE_LIMIT_MAX_REQUESTS=20
CHILD_LOGIN_FAILED_MAX_ATTEMPTS=40
```

## Standardowy Deploy

Deploy robimy przez `git pull` w CT 103, po snapshotcie i backupie aktualnych plikow:

```bash
ssh proxmox
SNAP="predeploy-familyquest-$(date +%Y%m%d-%H%M%S)"
pct snapshot 103 "$SNAP"
pct exec 103 -- bash
cd /opt/familyquest
BACKUP_DIR="/opt/familyquest/.deploy-backups/local-before-pull-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
git rev-parse HEAD > "$BACKUP_DIR/git-commit.txt"
for file in familyquest-app.compiled.js familyquest-app.jsx index.html server.js service-worker.js package.json AUDYT_LOGIKI.md prisma/schema.prisma; do
  if [ -e "$file" ]; then cp -a "$file" "$BACKUP_DIR/"; fi
done
git pull --ff-only
npm ci
systemctl restart familyquest
systemctl status familyquest --no-pager -l
wget -qO- http://127.0.0.1:3000/health
```

Publiczna weryfikacja po deployu:

```bash
curl -fsS https://fq.familyos.pl/health
```

Oczekiwane:

```json
{"status":"ok","db":"ok"}
```

## CSP

Frontend laduje React z `https://unpkg.com` i ma inline script cache-bustera. W `server.js` CSP musi zawierac:

```js
scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com']
```

Jesli aplikacja zatrzyma sie na ekranie `Ladowanie FamilyQuest...`, sprawdz konsole przegladarki i CSP, potem:

```bash
pct exec 103 -- systemctl restart familyquest
```

W przegladarce wykonaj twarde odswiezenie: `Ctrl + F5`.

## Testy Po Wdrozeniu

Testy Playwright mozna uruchomic przeciw publicznie serwowanemu frontendowi:

```powershell
$env:RANKING_BASE_URL='https://fq.familyos.pl'; npm run test:ranking; Remove-Item Env:RANKING_BASE_URL
$env:POINT_LEDGER_BASE_URL='https://fq.familyos.pl'; npm run test:point-ledger; Remove-Item Env:POINT_LEDGER_BASE_URL
$env:TASK_ARCHIVE_BASE_URL='https://fq.familyos.pl'; npm run test:task-archive; Remove-Item Env:TASK_ARCHIVE_BASE_URL
```

Lokalne testy integracyjne API wymagaja osobnej lokalnej bazy testowej. Nie nalezy podpinac lokalnego `.env` do starej bazy Railway.
