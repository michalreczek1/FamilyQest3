# FamilyOS Proxmox Stack

Stan na `2026-05-06`.

Ten plik opisuje caly aktualny serwer Proxmox: kontenery, domeny, dostep, loginy, podstawowe operacje i miejsca, od ktorych warto zaczynac diagnostyke.

## Architektura

- Host Proxmox:
  - LAN: `192.168.33.100`
  - panel: `https://192.168.33.100:8006`
- Zarzadzanie:
  - w domu: przez LAN
  - poza domem: przez Tailscale
- Publiczne aplikacje:
  - `familyos.pl`
  - `www.familyos.pl` -> redirect do `familyos.pl`
  - `fq.familyos.pl`
  - `n8n.familyos.pl`
  - `kitchen.familyos.pl`
  - `kitchenos.pl`
  - `budget.familyos.pl`
  - `secret.familyos.pl`
  - `propertyapp.familyos.pl`
  - `property.familyos.pl`
- Publiczny routing:
  - Cloudflare DNS
  - Cloudflare Tunnel przez kontener `caddy`

## Kontenery

| CT | Nazwa | IP | CPU | RAM | Dysk | Rola |
| --- | --- | --- | --- | --- | --- | --- |
| `100` | `vpnwg` | `192.168.33.110` | `1` | `512 MB` | `8 GB` | Tailscale subnet router do `192.168.33.0/24` |
| `101` | `caddy` | `192.168.33.120` | `1` | `512 MB` | `6 GB` | reverse proxy + Cloudflare Tunnel |
| `102` | `pgsql` | `192.168.33.121` | `1` | `768 MB` | `8 GB` | PostgreSQL dla FamilyQuest |
| `103` | `familyquest` | `192.168.33.122` | `2` | `1024 MB` | `5 GB` | aplikacja FamilyQuest |
| `104` | `files` | `192.168.33.123` | `1` | `512 MB` | `4 GB + 3 GB share` | udzial SMB `rodzina` |
| `105` | `n8n` | `192.168.33.124` | `2` | `1536 MB` | `8 GB + 8 GB data` | n8n |
| `106` | `kitchenos` | `192.168.33.125` | `2` | `2048 MB` | `8 GB` | aplikacja KitchenOS |
| `107` | `budgetapp` | `192.168.33.126` | `1` | `768 MB` | `2 GB` | aplikacja BudgetApp |
| `108` | `secreth` | `192.168.33.127` | `1` | `768 MB` | `4 GB` | aplikacja Secret Hitler |
| `109` | `propertyapp` | `192.168.33.128` | `1` | `1024 MB` | `6 GB` | aplikacja PropertyApp / Property Manager |

## Kolejnosc startu po boocie

1. `100 vpnwg`
2. `101 caddy`
3. `102 pgsql`
4. `103 familyquest`
5. `105 n8n`
6. `106 kitchenos`
7. `107 budgetapp`
8. `108 secreth`
9. `109 propertyapp`
10. `104 files`

Wszystkie kontenery maja `onboot: 1`.

## Storage Proxmox

### local-lvm

- glowny thin pool: `pve/data`
- autoextend thin pool jest wlaczony w `/etc/lvm/lvm.conf`:
  - `thin_pool_autoextend_threshold = 70`
  - `thin_pool_autoextend_percent = 10`
- monitoring LVM jest wlaczony:
  - `lvm2-monitor.service`
  - `pve/data` ma status `monitored`

Po migracji BudgetApp posprzatane zostaly stare snapshoty migracyjne z `CT 101`, `CT 102` i `CT 106`, bo zawyzaly zadeklarowany rozmiar thin volumes. Zmniejszone zostaly tez rootfs-y malych aplikacji:

- `CT 106 kitchenos`: `16 GB` -> `8 GB`
- `CT 107 budgetapp`: `8 GB` -> `2 GB`
- `CT 103 familyquest`: `10 GB` -> `5 GB`

Szybka diagnostyka storage:

```bash
pvesm status
vgs -o vg_name,vg_size,vg_free
lvs -a -o lv_name,lv_size,data_percent,metadata_percent,segtype,pool_lv,seg_monitor
systemctl status lvm2-monitor.service
pct fstrim 106
pct fstrim 107
```

## Domeny i uslugi

| Domena | Usluga | Dostep |
| --- | --- | --- |
| `https://fq.familyos.pl` | FamilyQuest | publiczny |
| `https://familyos.pl` | FamilyOS home / hub aplikacji | publiczny |
| `https://www.familyos.pl` | redirect do `familyos.pl` | publiczny |
| `https://n8n.familyos.pl` | n8n | Cloudflare Access + login n8n |
| `https://kitchen.familyos.pl` | KitchenOS | publiczny |
| `https://kitchenos.pl` | KitchenOS | publiczny |
| `https://budget.familyos.pl` | BudgetApp | publiczny |
| `https://secret.familyos.pl` | Secret Hitler | publiczny |
| `https://propertyapp.familyos.pl` | PropertyApp | publiczny z logowaniem aplikacji |
| `https://property.familyos.pl` | Property Manager legacy endpoint | publiczny / stary endpoint |
| `http://100.69.144.64:18001` | RAG Ask UI z hosta `192.168.33.17` | prywatny przez Tailscale |

## Dostep administracyjny

### Proxmox GUI

- adres: `https://192.168.33.100:8006`
- dostep:
  - z LAN
  - przez Tailscale do LAN

### SSH do Proxmoxa

- host: `192.168.33.100`
- user: `root`
- logowanie: klucz SSH
- haslo po SSH jest wylaczone
- lokalny alias SSH na tym PC: `proxmox`
- komenda logowania:

```powershell
ssh proxmox
```

Alias jest zapisany w `C:\Users\micha\.ssh\config` i uzywa klucza:

```sshconfig
Host proxmox
    HostName 192.168.33.100
    User root
    IdentityFile ~/.ssh/id_ed25519_proxmox_pc
```

### Tailscale

Tailscale jest zestawiony na:

- `CT 100 vpnwg`
- Tailscale IP: `100.69.144.64`
- reklamowana trasa: `192.168.33.0/24`

To oznacza:

- poza domem wlaczasz Tailscale na telefonie lub komputerze
- potem wchodzisz na zasoby LAN po ich zwyklych adresach `192.168.33.x`

Przyklady:

- Proxmox: `https://192.168.33.100:8006`
- SMB: `\\\\192.168.33.123\\rodzina`

### Prywatny interfejs RAG

RAG dziala na hoście roboczym w LAN:

- host LAN: `192.168.33.17`
- aplikacja: `http://192.168.33.17:8001`
- karta Windows `Ethernet` ma ustawiony statyczny IPv4 `192.168.33.17/24`
- gateway/DNS: `192.168.33.1`

Skrypty administracyjne na hoście Windows:

- ustawienie statycznego IP: `G:\rag_adv\scripts\set-static-ethernet-ip.ps1`
- powrot do DHCP: `G:\rag_adv\scripts\restore-ethernet-dhcp.ps1`

Poniewaz na tailnecie `Serve` nie jest wlaczone administracyjnie, prywatny dostep z telefonu jest zrobiony przez lokalny proxy-service na `CT 100 vpnwg`.

Adres do otwarcia na telefonie z wlaczonym Tailscale:

- `http://100.69.144.64:18001`

Po otwarciu UI mozna juz nie tylko zadawac pytania, ale tez wybrac konkretny model z uruchomionego `LM Studio headless`.
Lista modeli laduje sie dynamicznie z backendowego endpointu:

- `GET /llm-models`

Co robi ten proxy:

- `vpnwg (100.69.144.64:18001)` -> `192.168.33.17:8001`

Uruchamiana usluga systemd w kontenerze:

- `rag-ask-proxy.service`

Firewall Proxmoxa dla `CT 100` musi przepuszczac port proxy:

- `tcp/18001` z `192.168.33.0/24` i `100.64.0.0/10`

Szybka diagnostyka:

```bash
pct exec 100 -- systemctl status rag-ask-proxy.service
pct exec 100 -- ss -tulpen | grep 18001
pct exec 100 -- curl http://127.0.0.1:18001/health
pve-firewall status
cat /etc/pve/firewall/100.fw
```

Jesli aplikacja na hoście `192.168.33.17` nie dziala, proxy dalej bedzie aktywne, ale endpoint nie odpowie. Wtedy najpierw sprawdz proces RAG na hoście Windows.

### Prywatny dashboard administracyjny

Osobny panel z linkami administracyjnymi dziala tylko po Tailscale:

- URL: `http://100.69.144.64:18080`
- kontener: `CT 100 vpnwg`
- bind: tylko `100.69.144.64:18080` na interfejsie `tailscale0`
- katalog strony:
  - `/srv/familyos-admin`
- serwer:
  - `/opt/familyos-admin-dashboard/server.py`
- systemd service:
  - `familyos-admin-dashboard.service`
- logowanie:
  - HTTP Basic Auth
  - dane sa w `CT 100` w pliku root-only:
    - `/etc/familyos-admin-dashboard.env`

Odczyt loginu/hasla:

```bash
pct exec 100 -- cat /etc/familyos-admin-dashboard.env
```

Szybka diagnostyka:

```bash
pct exec 100 -- systemctl status familyos-admin-dashboard.service
pct exec 100 -- ss -ltnp 'sport = :18080'
pct exec 100 -- curl -I http://100.69.144.64:18080/
```

Bez logowania endpoint powinien zwracac `401 Unauthorized`.

## Wake-on-LAN dla tego PC

Docelowa maszyna do wybudzania:

- host w LAN: `192.168.33.17`
- MAC: `2C:F0:5D:7F:B8:F5`
- karta: `Realtek PCIe GbE Family Controller`

Po stronie Proxmoxa na hoscie `pve` zostal doinstalowany pakiet `wakeonlan`.

Komenda budzenia:

```bash
wakeonlan -i 192.168.33.255 -p 9 2C:F0:5D:7F:B8:F5
```

Najprostszy sposob z telefonu:

1. wlacz `Tailscale`
2. polacz sie po SSH do `192.168.33.100` jako `root`
3. uruchom:

```bash
wakeonlan -i 192.168.33.255 -p 9 2C:F0:5D:7F:B8:F5
```

Na iPhone najwygodniej zrobic z tego skrot w aplikacji `Skroty` przez akcje `Uruchom skrypt przez SSH`.

Jeszcze prostszy wariant bez SSH:

- prywatny URL przycisku: `http://192.168.33.100:8123/wake/d86k-wwL7486erF1l-tK`
- dziala tylko z LAN albo przez Tailscale
- na telefonie mozesz otworzyc ten adres i dodac go do ekranu glownego
- wtedy masz praktycznie "apke" do wybudzania jednym tapnieciem

Po stronie Windows przygotowany jest skrypt:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\enable-wol.ps1
```

Uruchom go jako administrator. Skrypt:

- wlacza `Wake on Magic Packet`
- wlacza `Wake from shutdown (S5)`
- ustawia tylko budzenie magic packetem
- wylacza Fast Startup
- uzbraja karte sieciowa do wybudzania

Jesli po pelnym zamknieciu komputer nadal sie nie budzi, sprawdz w BIOS:

- `Resume By PCI-E Device` = enabled
- `ErP` / oszczedzanie standby = disabled

### Wazna poprawka po restarcie

Po jednym z restartow zdalny dostep przez Tailscale przestal routowac do LAN, bo w `CT 100` po boocie wracalo:

- `net.ipv4.ip_forward = 0`

Naprawa trwala:

- ustawiony systemd service:
  - `tailscale-subnet-router-boot.service`
- service przy boocie ustawia:
  - `net.ipv4.ip_forward=1`

Jesli po restarcie znow kiedys zdalny dostep do LAN zniknie, pierwsza rzecz do sprawdzenia:

```bash
pct exec 100 -- systemctl status tailscale-subnet-router-boot.service
pct exec 100 -- sysctl net.ipv4.ip_forward
```

## FamilyQuest

### Aplikacja

- URL: `https://fq.familyos.pl`
- backend app: `CT 103`
- baza: `CT 102`
- katalog aplikacji: `/opt/familyquest`
- service: `familyquest`
- dokument deployu aplikacji: `PROXMOX_DEPLOY.md`
- konfiguracja runtime: `/opt/familyquest/.env` w `CT 103`; `DATABASE_URL` wskazuje PostgreSQL w `CT 102`, nie Railway

### Komponenty

- app health po LAN:
  - `http://192.168.33.122:3000/health`
- reverse proxy:
  - `CT 101 caddy`
- publiczny healthcheck:
  - `https://fq.familyos.pl/health`

### Frontend i PWA

- zrodlo prawdy frontendu: `familyquest-app.compiled.js`
- entrypoint: `index.html` laduje `familyquest-app.compiled.js` z cache-busterem
- stary `familyquest-app.jsx` byl legacy/localStorage i zostal usuniety z repo
- nie ma obecnie build step z JSX; do czasu wprowadzenia bundlera zmiany UI trafiaja do `familyquest-app.compiled.js`
- straznik repo: `npm run test:frontend-source`
- PWA: `manifest.json`, ikony i przycisk instalacji pozostaja aktywne
- offline cache: celowo wylaczony; `service-worker.js` czysci stare cache i wyrejestrowuje service worker, zeby urzadzenia dostawaly swiezy JS po deployu

### Testy API

- lokalne testy API uzywaja osobnej bazy `familyquest_test` w `CT 102`, nie produkcyjnej bazy `familyquest`
- konfiguracja startowa: `.env.test.example`
- przygotowanie bazy i reguly Proxmox/pg_hba: `npm run test:db:setup`
- pelny test API na prawdziwej bazie: `npm run test:api`
- `test:api` resetuje tylko `familyquest_test`, tuneluje PostgreSQL przez `ssh proxmox`, wykonuje `prisma db push` i odpala Jest z coverage

## FamilyOS home

### Aplikacja

- URL: `https://familyos.pl`
- redirect: `https://www.familyos.pl` -> `https://familyos.pl`
- typ: statyczna strona główna / hub aplikacji
- reverse proxy i hosting plików:
  - `CT 101 caddy`
- katalog plików:
  - `/srv/familyos`

### Gry edukacyjne

- URL: `https://familyos.pl/games/`
- logowanie: formularz aplikacji gier
- konto startowe:
  - user: `bracia`
  - haslo bylo ustawione przy wdrozeniu i moze byc zmienione po zalogowaniu
- opcja zmiany hasla:
  - `https://familyos.pl/games/change-password`
- backend:
  - lokalnie w `CT 101 caddy`
  - bind: `127.0.0.1:18110`
  - systemd service: `familyos-games.service`
  - serwer: `/opt/familyos-games/server.py`
  - pliki gier: `/srv/familyos-games`
  - hash hasla i sekret sesji: `/var/lib/familyos-games`

Bezposrednie stare URL-e gier:

- `https://familyos.pl/typing_adventure.html`
- `https://familyos.pl/matematyczna%20przygoda.html`

powinny zwracac `404`, zeby nie omijac logowania.

### Routing

- Cloudflare DNS:
  - `familyos.pl` -> Cloudflare Tunnel `fq-familyos`
  - `www.familyos.pl` -> Cloudflare Tunnel `fq-familyos`
- Cloudflare Tunnel w `CT 101`:
  - `/etc/cloudflared/config.yml`
- Caddy:
  - `familyos.pl` -> `/srv/familyos`
  - `familyos.pl/games/*` -> `127.0.0.1:18110`
  - `www.familyos.pl` -> redirect do `https://familyos.pl{uri}`

## BudgetApp

### Aplikacja

- URL: `https://budget.familyos.pl`
- backend app: `CT 107`
- baza: SQLite w kontenerze aplikacji

### Komponenty

- app po LAN:
  - `http://192.168.33.126:8080`
- reverse proxy:
  - `CT 101 caddy`

### Kontener

- `CT 107`
- LAN: `192.168.33.126`
- port aplikacji po LAN: `8080`
- systemd service:
  - `budgetapp.service`
- katalog aplikacji:
  - `/opt/budgetapp/app`
- dane:
  - `/opt/budgetapp/data/budget.db`
  - `/opt/budgetapp/data/backups`

Szybka diagnostyka:

```bash
pct exec 107 -- systemctl status budgetapp.service
pct exec 107 -- curl http://127.0.0.1:8080/
pct exec 107 -- sqlite3 /opt/budgetapp/data/budget.db ".tables"
```

## PropertyApp

### Aplikacja

- URL produkcyjny: `https://propertyapp.familyos.pl`
- stary endpoint: `https://property.familyos.pl`
- backend app: `CT 109`
- zrodlo: `https://github.com/michalreczek1/propertyAPP2`
- baza: SQLite w kontenerze aplikacji
- logowanie: panel aplikacji, bez BasicAuth

### Funkcje

- nieruchomosci, lokale, najemcy, umowy, platnosci, koszty i raporty
- dokumenty umow jako zalaczniki `PDF/JPG/PNG`, trzymane na serwerze
- raport podatkowy, koszty wlasciciela, kredyty i zarzadzanie nieruchomosciami
- automatyczne kary za opoznione platnosci
- zmiany najemcow z mozliwoscia nakladania sie umow w tym samym miesiacu
- powiadomienia SMS przez SMSPlanet: przypomnienia przed terminem i po terminie, test SMS, szablony wiadomosci, logi i statusy
- PWA: manifest, favicony i ikony Android/iOS sa serwowane bez logowania

### Komponenty

- app po LAN:
  - `http://192.168.33.128:8090`
- health:
  - `http://192.168.33.128:8090/health`
- reverse proxy:
  - `CT 101 caddy`
- routing Caddy:
  - `propertyapp.familyos.pl` -> `192.168.33.128:8090`
  - `property.familyos.pl` -> `192.168.33.128:3000`

### Kontener

- `CT 109`
- LAN: `192.168.33.128`
- port aplikacji po LAN: `8090`
- systemd service:
  - `propertyapp.service`
- katalog aplikacji:
  - `/opt/propertyapp/app`
- dane:
  - `/opt/propertyapp/data/property.db`
  - `/opt/propertyapp/data/uploads`
  - `/opt/propertyapp/data/backups`
- logi i backupy pomocnicze:
  - `/opt/propertyapp/logs`
  - `/opt/propertyapp/backups`
- konfiguracja sekretow:
  - `/etc/propertyapp/auth.env`

Plik `/etc/propertyapp/auth.env` zawiera sekrety aplikacji, m.in. dane sesji i token SMSPlanet. Nie wpisywac jego zawartosci do README ani do repozytorium.

### Deploy

Standardowy deploy jest wykonywany z repozytorium GitHub do `CT 109`, z restartem `propertyapp.service`.

Szybka diagnostyka:

```bash
pct exec 109 -- systemctl status propertyapp.service
pct exec 109 -- journalctl -u propertyapp.service -n 120 --no-pager
pct exec 109 -- curl http://127.0.0.1:8090/health
pct exec 109 -- ss -ltnp | grep 8090
pct exec 109 -- sqlite3 /opt/propertyapp/data/property.db ".tables"
```

Restart aplikacji:

```bash
pct exec 109 -- systemctl restart propertyapp.service
```

Sprawdzenie proxy:

```bash
pct exec 101 -- caddy validate --config /etc/caddy/Caddyfile
pct exec 101 -- systemctl reload caddy
curl -I https://propertyapp.familyos.pl
```

### SMSPlanet

- token API jest trzymany w `/etc/propertyapp/auth.env`
- ustawienia operacyjne sa w UI aplikacji:
  - `Ustawienia` -> `Powiadomienia SMS`
- w UI ustawiane sa m.in.:
  - aktywnosc wysylki
  - tryb testowy
  - nadawca
  - telefon testowy
  - godzina wysylki
  - dni przed terminem i po terminie
  - szablony wiadomosci
- historia wysylek i bledy API sa widoczne w sekcji SMS w ustawieniach

Uwaga: pole nadawcy SMSPlanet musi byc zaakceptowane w panelu SMSPlanet. Dopoki ma status oczekujacy, wysylka z takim nadawca moze byc odrzucona przez API.

## Secret Hitler

### Aplikacja

- URL: `https://secret.familyos.pl`
- backend app: `CT 108`
- zrodlo: `https://github.com/michalreczek1/secreth`
- baza: pliki NeDB w kontenerze aplikacji

### Komponenty

- app po LAN:
  - `http://192.168.33.127:3000`
- health:
  - `http://192.168.33.127:3000/healthz`
- reverse proxy:
  - `CT 101 caddy`

### Kontener

- `CT 108`
- LAN: `192.168.33.127`
- port aplikacji po LAN: `3000`
- systemd service:
  - `secreth.service`
- katalog aplikacji:
  - `/opt/secreth/app`
- dane:
  - `/opt/secreth/data`
- deploy z GitHuba:
  - `/opt/secreth/deploy.sh`
- dane admina startowego:
  - `/root/secreth-admin.txt` w `CT 108`

Szybka diagnostyka:

```bash
pct exec 108 -- systemctl status secreth.service
pct exec 108 -- curl http://127.0.0.1:3000/healthz
pct exec 108 -- ls -lah /opt/secreth/data
pct exec 108 -- /opt/secreth/deploy.sh
```

## n8n

### URL

- `https://n8n.familyos.pl`

### Ochrona dostepu

`n8n` jest schowane za `Cloudflare Access`.

Flow logowania:

1. wejscie na `n8n.familyos.pl`
2. Cloudflare Access prosi o mail
3. kod jednorazowy przychodzi na mail
4. po przejsciu przez Access logujesz sie jeszcze do samego `n8n`

### Cloudflare Access

- dozwolony mail: `michalreczek@gmail.com`
- metoda logowania: `One-time PIN`

### Konto n8n

Konto owner zostalo utworzone w UI. Ten plik nie powiela loginu do `n8n`, bo konto bylo konczone interaktywnie po wdrozeniu.

### Kontener

- `CT 105`
- LAN: `192.168.33.124`
- port aplikacji po LAN: `5678`

### Dodatkowe uwagi

- workflowy sa importowane i dzialaja
- czesc credentials musiala byc odtworzona recznie po imporcie
- publiczny panel `n8n` nie powinien byc zostawiany bez Access

## SMB / pliki rodzinne

### Udzial

- serwer: `\\\\192.168.33.123\\rodzina`
- iPhone: `smb://192.168.33.123`

### Dane logowania

- user: `familyshare`
- haslo: `Rodzina2026!`

### Jak uzywac

Windows:

1. Otworz Eksplorator plikow
2. Wpisz `\\\\192.168.33.123\\rodzina`
3. Zaloguj sie kontem `familyshare`

iPhone:

1. `Pliki`
2. `...`
3. `Polacz z serwerem`
4. wpisz `smb://192.168.33.123`

Poza domem:

- najpierw wlacz Tailscale
- potem lacz sie tak samo na `192.168.33.123`

### Gdy Windows zgubi mapowanie

Jesli Windows zapamieta stara sesje SMB i nie chce odtworzyc dysku, zwykle pomaga:

```powershell
net use Z: /delete /y
net use \\\\192.168.33.123\\rodzina /delete /y
```

a potem ponowne mapowanie.

## Cloudflare i reverse proxy

### Caddy

- kontener: `CT 101`
- LAN: `192.168.33.120`

### Cloudflare

- DNS strefy `familyos.pl` jest w Cloudflare
- publiczne wejscie do uslug idzie przez Cloudflare Tunnel
- `n8n` ma dodatkowo Cloudflare Access

## Co sprawdzac przy problemach

### 1. Proxmox niedostepny zdalnie przez Tailscale

```bash
pct exec 100 -- tailscale status
pct exec 100 -- sysctl net.ipv4.ip_forward
pct exec 100 -- systemctl status tailscale-subnet-router-boot.service
sed -n '1,240p' /etc/pve/nodes/pve/host.fw
```

### 1a. RAG z telefonu nie otwiera sie po Tailscale

Sprawdz po kolei:

```bash
pct exec 100 -- systemctl status rag-ask-proxy.service
pct exec 100 -- curl http://127.0.0.1:18001/health
```

Na hoście Windows / Geekom:

- aplikacja RAG musi sluchac na `0.0.0.0:8001`
- telefon ma wchodzic na `http://100.69.144.64:18001`, nie bezposrednio na `192.168.33.17:8001`

### 2. SMB nie dziala

```bash
sed -n '1,240p' /etc/pve/firewall/104.fw
pct exec 104 -- systemctl status smbd
```

Windows:

```powershell
net use
```

### 3. n8n nie otwiera sie

Sprawdz:

- Cloudflare Access
- czy `CT 105` dziala
- czy `CT 101` dziala

### 4. PropertyApp nie otwiera sie albo SMS nie dziala

Sprawdz aplikacje:

```bash
pct status 109
pct exec 109 -- systemctl status propertyapp.service
pct exec 109 -- journalctl -u propertyapp.service -n 120 --no-pager
pct exec 109 -- curl http://127.0.0.1:8090/health
```

Sprawdz routing:

```bash
pct exec 101 -- systemctl status caddy
pct exec 101 -- caddy validate --config /etc/caddy/Caddyfile
curl -I https://propertyapp.familyos.pl
```

Przy problemach z SMS:

- sprawdz w UI sekcje `Ustawienia` -> `Powiadomienia SMS`
- sprawdz, czy `/etc/propertyapp/auth.env` istnieje w `CT 109`
- sprawdz, czy nadawca jest zaakceptowany w SMSPlanet
- sprawdz logi wysylek w aplikacji

## Przydatne komendy

### Lista kontenerow

```bash
pct list
```

### Status konkretnego kontenera

```bash
pct status 100
pct status 105
```

### Restart kontenera

```bash
pct restart 100
pct restart 105
```

### Podglad konfiguracji kontenera

```bash
pct config 100
```

### Firewall hosta

```bash
sed -n '1,240p' /etc/pve/nodes/pve/host.fw
```

## Dalszy rozwoj

Najbardziej sensowne kolejne kroki:

1. zrobic backupy konfiguracji kontenerow poza tym SSD
2. dodac prosty monitoring i alerty
3. odseparowac jeszcze bardziej panele prywatne od publicznych uslug
