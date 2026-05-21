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
CHILD_CODE_PEPPER="<losowy-pepper-min-32-znaki>"
CHILD_JWT_EXPIRES_IN="24h"
BCRYPT_ROUNDS=12
NODE_ENV=production
PORT=3000
CORS_ORIGINS="https://fq.familyos.pl"
RATE_LIMIT_MAX_REQUESTS=0
AUTH_RATE_LIMIT_MAX_REQUESTS=20
CHILD_LOGIN_FAILED_MAX_ATTEMPTS=40
CHILD_LOGIN_CODE_FAILED_MAX_ATTEMPTS=8
```

## Standardowy Deploy

Standardowo deploy uruchamiamy z lokalnego repo przez skrypt PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/deploy-proxmox.ps1
```

Skrypt wykonuje:

1. sprawdzenie lokalnego brancha `main` i czystego working tree,
2. `git push origin main`,
3. snapshot CT 103,
4. backup plikow w `/opt/familyquest/.deploy-backups/`,
5. `git fetch`, `git checkout main`, `git reset --hard origin/main` w CT 103,
6. `npm ci`,
7. uzupelnienie brakujacego `CHILD_CODE_PEPPER` w `.env`, jesli to pierwsze wdrozenie po hardeningu,
8. oznaczenie baseline migracji jako zastosowanej dla istniejacej bazy,
9. `npx prisma migrate deploy`,
10. `node scripts/bootstrap-child-access-credentials.js`,
11. `npm run frontend:build`,
12. `systemctl restart familyquest`,
13. lokalny healthcheck w kontenerze,
14. publiczny health/CSP check,
15. produkcyjne Playwrighty: bulk reject, approval queue, reverse approval, ranking, point ledger, reward history, task edit.

Pakiet hardeningu sesji wymusza ponowne logowanie po wdrozeniu: tokeny bez `jti` sa odrzucane, a token dziecka jest powiazany z konkretnym aktywnym credentialem.

Przydatne warianty:

```powershell
# Pokazuje plan bez dotykania Proxmoxa
powershell -ExecutionPolicy Bypass -File scripts/deploy-proxmox.ps1 -DryRun -SkipTests -SkipPush -SkipSnapshot -AllowDirty

# Awaryjnie bez testow produkcyjnych po restarcie
powershell -ExecutionPolicy Bypass -File scripts/deploy-proxmox.ps1 -SkipTests

# Deploy innego brancha, jesli kiedys bedzie potrzebny
powershell -ExecutionPolicy Bypass -File scripts/deploy-proxmox.ps1 -Branch main
```

Parametry domyslne:

- `-ProxmoxHost proxmox`
- `-ContainerId 103`
- `-AppDir /opt/familyquest`
- `-Branch main`
- `-PublicUrl https://fq.familyos.pl`

Ręczny deploy przez `git pull` w CT 103 zostaje tylko procedura awaryjna. Jesli trzeba go wykonac recznie, zachowaj ten sam porzadek: snapshot, backup, pull/reset, install, baseline migracji, `npx prisma migrate deploy`, bootstrap child credentials, build, restart, healthcheck.

## Backup I Logi Produkcyjne

Po wdrozeniu host Proxmox powinien miec niezalezny backup PostgreSQL poza kontenerami oraz limity journald dla `familyquest.service` w CT 103. Instalator:

```powershell
# Dry-run i podglad obecnej konfiguracji
powershell -ExecutionPolicy Bypass -File scripts/install-proxmox-hardening.ps1

# Instalacja timera backupu i limitow logow
powershell -ExecutionPolicy Bypass -File scripts/install-proxmox-hardening.ps1 -Apply
```

Domyslnie skrypt tworzy:

- `/usr/local/sbin/familyquest-pg-backup.sh` na hoscie Proxmox,
- `familyquest-postgres-backup.service` i `familyquest-postgres-backup.timer`,
- backupi w `/var/backups/familyquest-postgres`, z retencja 30 dni,
- log backupu w `/var/log/familyquest/postgres-backup.log`,
- limity journald i rate-limit logow uslugi w CT 103.

Weryfikacja po instalacji:

```bash
systemctl list-timers 'familyquest*' --no-pager
systemctl start familyquest-postgres-backup.service
tail -n 20 /var/log/familyquest/postgres-backup.log
ls -lh /var/backups/familyquest-postgres
pct exec 103 -- journalctl --disk-usage
```

```bash
ssh proxmox
SNAP="predeploy-familyquest-$(date +%Y%m%d-%H%M%S)"
pct snapshot 103 "$SNAP"
pct exec 103 -- bash
cd /opt/familyquest
BACKUP_DIR="/opt/familyquest/.deploy-backups/local-before-pull-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
git rev-parse HEAD > "$BACKUP_DIR/git-commit.txt"
for file in index.html server.js package.json package-lock.json vite.config.js AUDYT_LOGIKI.md prisma/schema.prisma; do
  if [ -e "$file" ]; then cp -a "$file" "$BACKUP_DIR/"; fi
done
for dir in src public dist; do
  if [ -e "$dir" ]; then cp -a "$dir" "$BACKUP_DIR/"; fi
done
git pull --ff-only
npm ci
npx prisma migrate deploy
node scripts/bootstrap-child-access-credentials.js
npm run frontend:build
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

Frontend jest budowany przez Vite i laduje lokalny modul JS z `dist/assets`. React nie jest juz pobierany z `https://unpkg.com`, a `index.html` nie ma inline cache-bustera. `script-src` moze byc ograniczony do:

```js
scriptSrc: ["'self'"]
```

`style-src` nadal zawiera Google Fonts oraz `unsafe-inline`, bo aplikacja ma sporo inline stylow Reactowych. Jesli aplikacja zatrzyma sie na ekranie `Ladowanie FamilyQuest...`, sprawdz konsole przegladarki, CSP oraz czy po `git pull` wykonano `npm run frontend:build`, potem:

```bash
pct exec 103 -- systemctl restart familyquest
```

W przegladarce wykonaj twarde odswiezenie: `Ctrl + F5`.

## Frontend I PWA

Aktualnym zrodlem prawdy frontendu sa pliki w `src/`:

- `src/main.jsx` - entrypoint React/Vite
- `src/App.jsx` - przeniesiona aplikacja React
- `src/styles.css` - style wyciagniete z dawnego inline `<style>`

`index.html` jest entrypointem Vite. Produkcyjnie Express serwuje `dist/`, generowane przez:

```bash
npm run frontend:build
```

Pliki PWA sa w `public/` i trafiaja do katalogu `dist/` podczas buildu.

PWA dziala w trybie instalowalnej aplikacji przez `public/manifest.json` i przycisk instalacji. Offline cache jest celowo wylaczony: `public/service-worker.js` czysci stare cache, wyrejestrowuje service worker i przepuszcza requesty do sieci. To chroni przed sytuacja, w ktorej telefon trzyma stary JS po deployu.

## Testy Po Wdrozeniu

Testy Playwright mozna uruchomic przeciw publicznie serwowanemu frontendowi:

```powershell
npm run frontend:build
$env:RANKING_BASE_URL='https://fq.familyos.pl'; npm run test:ranking; Remove-Item Env:RANKING_BASE_URL
$env:POINT_LEDGER_BASE_URL='https://fq.familyos.pl'; npm run test:point-ledger; Remove-Item Env:POINT_LEDGER_BASE_URL
$env:TASK_ARCHIVE_BASE_URL='https://fq.familyos.pl'; npm run test:task-archive; Remove-Item Env:TASK_ARCHIVE_BASE_URL
```

Lokalne testy integracyjne API uzywaja osobnej bazy `familyquest_test` w `CT 102`, a nie produkcyjnej bazy `familyquest`:

```powershell
npm run test:db:setup
npm run test:api
```

`test:api` resetuje wylacznie baze `familyquest_test`, otwiera tunel SSH przez `proxmox`, wykonuje `prisma db push` dla schematu testowego i uruchamia pelne testy Jest. Produkcyjny start uzywa `prisma migrate deploy`; nie nalezy podpinac lokalnego `.env` do starej bazy Railway ani do produkcyjnego `familyquest`.
