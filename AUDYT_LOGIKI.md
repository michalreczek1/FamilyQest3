# Audyt logiki aplikacji FamilyQuest

Data audytu: 2026-05-09  
Ostatnia aktualizacja: 2026-05-13

Zakres: backend `server.js`, uruchamiany frontend `familyquest-app.compiled.js`, `index.html`, `prisma/schema.prisma`, testy integracyjne, smoke, Playwrightowy test rankingu i wdrozenie na Proxmox.

## Status Po Ostatnich Zmianach

Naprawiony i wdrozony zostal krytyczny pakiet logiki punktow i rankingu:

- Ranking rodzinny sortuje po punktach jako glownym wyniku.
- Ekran `Ranking rodzinny` na wyborze profilu uzywa danych z `/api/leaderboard`, a nie tylko lokalnej kolejnosci `children`.
- Dodano Playwrightowy test `npm run test:ranking`, ktory renderuje UI i potwierdza kolejnosc: `Ignacy > Franek > Filip > Jozek > Lucja`.
- Backend przelicza passe z zatwierdzonych zadan `MIN`.
- Odczyt `points`, `streaks`, grant maps i `/api/leaderboard` uruchamia przeliczenie punktow/grantow z danych historycznych.
- Zablokowano cofanie/odrzucanie zatwierdzonego `completion` bez jawnej korekty punktow.
- Backend waliduje harmonogram zadania, aktywny dzien dziecka i daty dla `completion`.
- Backend waliduje date `extraTask`.
- `WEEKLY` dostal tygodniowy klucz naliczania punktow, wiec to samo zadanie tygodniowe nie powinno naliczac punktow codziennie.
- Aktywny dzien bez zadan `MIN` nie jest juz automatycznie `PASSED`, tylko `NO_REQUIRED_TASKS`.
- Produkcja `https://fq.familyos.pl` zostala zaktualizowana do `c5a0a81`.
- CSP na produkcji zawiera `script-src 'self' 'unsafe-inline' https://unpkg.com`, wiec frontend nie powinien zatrzymywac sie na ekranie `Ladowanie FamilyQuest...` z powodu blokady inline script.
- Dodano jawne cofniecie zatwierdzenia zadania przez rodzica: `POST /api/completions/:id/reverse-approval`.
- Cofniecie zatwierdzenia przelicza punkty i passe ze zrodel prawdy, zapisuje jawny wpis `REVERSAL` w `pointAdjustments` i nie nalicza tej korekty drugi raz przy kolejnym `recomputePointsAndGrants`.
- Panel rodzica pokazuje przycisk `Cofnij` przy zatwierdzonym zadaniu na wybrany dzien i wyswietla realny efekt punktowy po operacji.
- Dodano osobny restore backupu: `POST /api/storage/restore-backup`, dostepny tylko dla rodzica.
- Import JSON w UI uzywa teraz restore, a nie lokalnej podmiany stanu i pozniejszego `storage/merge`.
- Restore backupu normalizuje snapshot, nadpisuje stan rodziny, przelicza punkty/passę na serwerze i dopisuje audit log `RESTORE_BACKUP`.
- Dodano wersjonowanie `FamilyState` jako osobne pole Prisma `version`.
- `saveStateData` zapisuje warunkowo po `id + version` i podbija wersje po kazdym udanym zapisie.
- Staly zapis ze starej wersji zwraca konflikt `FAMILY_STATE_VERSION_CONFLICT` zamiast cicho nadpisac nowsze dane.
- Dodano `pointLedger` do stanu rodziny jako serwerowy cache historii punktow.
- `recomputePointsAndGrants` generuje ledger z zatwierdzonych zadan, zaliczonych dni, idealnych tygodni, extra taskow oraz premii/kar/cofniec.
- Saldo `points` jest teraz cachem wynikajacym z tych samych wpisow zrodlowych co ledger, a nie osobna prawda biznesowa.
- Dziecko moze kliknac liczbe punktow i zobaczyc przewijalny popup `Historia punktow` z deltami, opisem, data i saldem po operacji.
- Dodano bezpieczna archiwizacje zadan: zadanie dostaje `archivedAt`, a historyczne zatwierdzenia sprzed archiwizacji nadal zostaja w punktach i ledgerze.
- Dodano backendowy endpoint `POST /api/tasks/:id/archive-matching`, ktory archiwizuje wszystkie aktywne zadania o tej samej definicji u dzieci.
- Panel rodzica w zakladce `Zadania` pokazuje przycisk `U wszystkich`, gdy istnieje wiecej niz jedna aktywna kopia tego samego zadania.
- Panel rodzica ma widok `Archiwum` zadan oraz przycisk `Przywroc`. Przywrocenie zapisuje `restoredAt`, wiec okres miedzy `archivedAt` i `restoredAt` pozostaje historycznie nieaktywny.
- Panel rodzica ma teraz modal `Edytuj zadanie` zamiast systemowych `prompt()`. Edycja obejmuje dziecko, nazwe, typ `MIN/PLUS/WEEKLY`, punkty, dni tygodnia i opis.
- Uporzadkowano zrodlo frontendu: aktualnym i jedynym browser-loaded zrodlem jest `familyquest-app.compiled.js`; stary `familyquest-app.jsx` zostal usuniety jako legacy/localStorage.
- Dodano `npm run test:frontend-source`, ktory pilnuje entrypointu frontendu, braku legacy JSX i aktualnej polityki PWA bez offline cache.
- README i `PROXMOX_DEPLOY.md` opisuja teraz tryb PWA: manifest/install dziala, a service worker celowo czysci stare cache i wyrejestrowuje sie.

## Weryfikacja Wykonana

- `node --check server.js` - OK.
- `node --check familyquest-app.compiled.js` - OK.
- `npm run test:ranking` - OK, Playwright sprawdzil realny DOM i zapisal screenshot do `tmp/ranking-order-check.png`.
- `RANKING_BASE_URL=https://fq.familyos.pl npm run test:ranking` - OK po wdrozeniu, Playwright sprawdzil publicznie serwowany HTML/JS z kontrolowanymi danymi API.
- `https://fq.familyos.pl/health` - OK, backend i baza odpowiadaja.
- Snapshot przed wdrozeniem: `predeploy-familyquest-20260513-105625`.
- Backup plikow produkcyjnych przed pull: `/opt/familyquest/.deploy-backups/local-before-pull-20260513-105626`.
- `npm run test:reverse-approval` - OK, test sprawdzil logike cofniecia `9 -> 4` punktow bez podwojnego odejmowania po recompute oraz UI rodzica z przyciskiem `Cofnij` i alertem `-5 pkt`.
- `npm run test:restore-backup` - OK, test sprawdzil przeliczenie punktow ze snapshotu `999 -> 7`, zastapienie danych rodziny i brak uzycia `storage/merge` podczas importu.
- `npm run test:state-version` - OK, test zasymulowal dwa rownolegle zapisy i potwierdzil konflikt przy drugim zapisie ze stara wersja.
- `npx prisma validate` - OK, schema z `FamilyState.version` jest poprawna.
- `npm run test:point-ledger` - OK, test sprawdzil wpisy ledgeru `TASK_APPROVED`, `DAY_PASSED`, `EXTRA_TASK`, `BONUS` oraz popup historii punktow dziecka.
- `npm run test:task-archive` - OK, test sprawdzil logike zachowania historycznych punktow po `archivedAt` oraz Playwrightowo przycisk `U wszystkich` i efekt ukrycia go po archiwizacji; lokalny test API zostal pominiety, bo lokalny `DATABASE_URL` jest niedostepny.
- `npm run test:task-restore` - OK, test sprawdzil, ze okres archiwum pozostaje nieaktywny po przywroceniu oraz Playwrightowo przejscie `Archiwum -> Przywroc -> Aktywne`.
- `npm run test:task-edit` - OK, Playwright sprawdzil modal edycji zadania, zmiane nazwy, typu, punktow, opisu i dni tygodnia oraz payload `PUT /api/tasks/:id`.
- `npm run test:frontend-source` - OK, test potwierdza `familyquest-app.compiled.js` jako entrypoint, brak legacy JSX oraz service worker cleanup.
- Repo zostalo oczyszczone z konfiguracji Railway: usunieto `railway.json` i `RAILWAY_DEPLOY.md`, dodano `PROXMOX_DEPLOY.md`, a `.env.example` wskazuje aktualny deploy Proxmox.
- Lokalny `.env` nie powinien wskazywac starej bazy Railway. Testy API maja teraz osobny profil `.env.test.example` i baze `familyquest_test` w `CT 102`.
- `npm run test:api` - OK, runner resetuje tylko baze `familyquest_test`, tuneluje PostgreSQL przez `ssh proxmox`, wykonuje `prisma db push` i pelne testy Jest na prawdziwej bazie.
- `npm run lint` nadal nie dziala, bo projekt nie ma konfiguracji ESLint.

## Co Nadal Jest Do Zrobienia

Po wdrozeniu rankingu i passy nie ma juz otwartego krytycznego bledu w samym porzadku tablicy wynikow. Zostaly ryzyka drugiego poziomu:

1. Kody dzieci moga kolidowac globalnie miedzy rodzinami.
2. Archiwizacja/przywracanie zadan jest wdrozone, ale nie ma jeszcze zbiorczego przywracania wszystkich pasujacych kopii.
3. Zakres testow API warto rozszerzyc o polityke dat, `WEEKLY` i brak zadan MIN.

## Rekomendowany Nastepny Pakiet

Najbardziej sensowny kolejny pakiet po stabilizacji bazy testowej: **backendowa walidacja harmonogramu i polityki dat**.

Dlaczego ten pakiet teraz:

- Globalne kolizje kodow dzieci nadal sa odlozone na koniec, bo obecnie jest jedna rodzina.
- `npm run test:api` daje juz prawdziwa baze i moze wykryc regresje endpointow.
- Harmonogram zadania i polityka dat nadal sa miejscem, gdzie backend powinien byc silniejszy niz frontend.
- To bezposrednio chroni passy, punkty dzienne i tygodniowe przed completionami z niewlasciwego dnia albo zadania.

Minimalny zakres wdrozenia:

1. Backend odrzuca completion, jesli data nie pasuje do harmonogramu aktywnego zadania.
2. Extra task ma jawna polityke dat: bez przyszlosci albo z limitem, zaleznym od decyzji produktowej.
3. Testy API pokrywaja poprawny dzien, zly dzien, przyszla date i historyczna date.

## Najwazniejsze Otwarte Decyzje

### 1. Punktowy Ledger Zamiast Samego Salda

Status: wdrozone w wersji serwerowego ledgeru wyliczanego ze zrodel prawdy.

Obecnie saldo `data.points` jest przeliczane z:

- zatwierdzonych completion,
- punktow za zaliczone dni,
- bonusow tygodniowych,
- zatwierdzonych extra taskow,
- premii i kar z `pointAdjustments`.

To daje praktyczny ledger audytowy. `data.points` pozostaje cachem do szybkiego wyswietlania, ale jest przeliczany razem z `pointLedger`.

Co zostaje dalej:

1. Dodac opcjonalny widok historii punktow w panelu rodzica.
2. Po uporzadkowaniu frontendu przeniesc popup historii punktow do komponentu z prawdziwego zrodla JSX.
3. Jesli kiedys powstanie osobna tabela ledgeru, migrowac `pointLedger` z JSON-a do DB.

Priorytet: zrealizowane, rozszerzenia P3.

### 2. Jawna Korekta Punktow Dla Cofania Zatwierdzen

Status: wdrozone.

Rodzic ma osobna sciezke `reverse-approval`. Completion jest oznaczany jako odrzucony po cofnieciu, punkty i passa sa przeliczane, a wpis `REVERSAL` trafia do `pointAdjustments` jako jawna historia efektu.

Co zostaje dalej:

1. Rozbudowac to pozniej o pelny ledger punktow.
2. Zdecydowac, co robic z nagrodami juz odblokowanymi przez punkty, ktore zostaly potem cofniete.
3. Dodac docelowy test integracyjny na prawdziwej bazie, gdy bedzie stabilny `DATABASE_URL` testowy.

Priorytet: zrealizowane, pozostale decyzje P2/P3.

### 3. Restore Backupu Osobno Od Storage Merge

Status: wdrozone.

`/api/storage/merge` zostaje synchronizacja klienta, a import JSON uzywa osobnego `POST /api/storage/restore-backup`. Restore nadpisuje caly stan rodziny, normalizuje dane i uruchamia `recomputePointsAndGrants`, wiec snapshotowe `points` nie sa autorytatywne.

Co zostaje dalej:

1. Rozwazyc dodatkowy PIN dla restore po wdrozeniu wersjonowania.
2. Dodac docelowy test integracyjny na prawdziwej bazie.

Priorytet: zrealizowane, pozostale decyzje P3.

### 4. Wersjonowanie `FamilyState`

Status: wdrozone.

Stan rodziny nadal jest jednym JSON-em, ale `FamilyState` ma teraz pole `version`, a `saveStateData` robi warunkowy zapis po oczekiwanej wersji. Rownolegly zapis ze stara wersja dostaje konflikt zamiast cichego nadpisania.

Co zostaje dalej:

1. Rozwazyc retry dla wybranych idempotentnych operacji.
2. Dodac docelowy test integracyjny na prawdziwej bazie, gdy lokalny `DATABASE_URL` bedzie stabilny.

Priorytet: zrealizowane, retry/test DB P3.

### 5. Globalne Kolizje Kodow Dzieci

Status: otwarte, celowo odlozone na koniec.

Kody dzieci sa unikalne tylko w rodzinie, ale logowanie dziecka szuka kodu globalnie po wszystkich rodzinach. Dwie rodziny z tym samym kodem dziecka wywoluja konflikt.

Co zrobic dalej:

1. Dodac drugi skladnik logowania dziecka: kod rodziny + kod dziecka.
2. Alternatywnie generowac globalnie unikalne dluzsze kody.
3. Zmienic UI logowania dziecka i endpoint `/api/auth/login-child`.
4. Dodac test na dwie rodziny z tym samym kodem dziecka.

Priorytet: P2.

### 6. Archiwizacja Zadan

Status: wdrozone w wariancie bulk archive + pojedyncze restore.

Rodzic moze archiwizowac pojedyncze zadanie albo jednym przyciskiem `U wszystkich` zarchiwizowac wszystkie aktywne kopie o tej samej definicji: tytul, typ, punkty, opis i dni tygodnia. Archiwizacja ustawia `active: false` i `archivedAt`. Widok `Archiwum` pokazuje zarchiwizowane zadania i pozwala je przywrocic.

Wazna zasada logiki:

- zadania zarchiwizowane nie pokazuja sie dzieciom i nie sa wymagane od daty archiwizacji,
- zatwierdzone wykonania sprzed `archivedAt` nadal licza sie w `pointLedger`, `points`, dniu zaliczonym i passie historycznej,
- nowe wykonania dla zarchiwizowanego zadania sa blokowane,
- przywrocenie ustawia `restoredAt`; okres `archivedAt` -> `restoredAt` pozostaje historycznie nieaktywny.

Co zostaje dalej:

1. Opcjonalnie dodac zbiorcze przywracanie wszystkich pasujacych kopii zadania.
2. Po stabilizacji testowej bazy dodac pelny test API bez pomijania lokalnego `DATABASE_URL`.

Priorytet: zrealizowane, rozszerzenia P3.

### 7. Semantyka Nagród Po Spadku Punktow

Status: otwarte/decyzja produktowa.

Nagrody raz odblokowane zostaja w `rewardUnlocks`, nawet gdy punkty spadna po karze albo rodzic zmieni progi nagrod. To moze byc dobre, jesli nagroda jest jednorazowym osiagnieciem, ale powinno byc jawne.

Co zrobic dalej:

1. Ustalic zasade: nagrody sa stale po odblokowaniu czy moga byc cofane.
2. Jesli stale, opisac to w UI rodzica.
3. Jesli cofane, dodac status `revoked` i logike ponownej oceny po karach/edycji progow.

Priorytet: P3/P2.

### 8. Zrodlo Frontendu I Build

Status: uporzadkowane operacyjnie.

Uruchamiana aplikacja laduje `familyquest-app.compiled.js`. Stary `familyquest-app.jsx` byl legacy/localStorage i zostal usuniety z repo, zeby nie sugerowal nieprawdziwego zrodla prawdy.

Co zrobic dalej:

1. Przy wiekszej przebudowie UI wprowadzic realny build pipeline JSX/React.
2. Do tego czasu pilnowac `npm run test:frontend-source`.
3. Trzymac zmiany UI w `familyquest-app.compiled.js`.

Priorytet: zrealizowane operacyjnie, docelowy bundler P3.

### 9. Dokumentacja PWA I Service Worker

Status: uporzadkowane.

`service-worker.js` usuwa cache i wyrejestrowuje SW. README oraz `PROXMOX_DEPLOY.md` opisuja teraz, ze PWA oznacza manifest/install bez offline cache.

Co zrobic dalej:

1. Jesli kiedys potrzebny bedzie offline mode, przywrocic kontrolowany cache z wersjonowaniem assetow.
2. Pilnowac, by service worker nie trzymal starego JS po deployu.

Priorytet: zrealizowane, offline cache P3.

### 10. Stabilne Testy Integracyjne

Status: wdrozone.

Testy API nie uzywaja juz produkcji ani Railway. Dodano:

- `.env.test.example` z `DATABASE_URL` do `familyquest_test`,
- `npm run test:db:setup`, ktory przygotowuje role, baze, `pg_hba.conf` i regule firewalla CT 102 dla tunelu z hosta Proxmox,
- `npm run test:api`, ktory resetuje wylacznie `familyquest_test`, otwiera tunel SSH do PostgreSQL, uruchamia `prisma db push` i pelne testy Jest.

Weryfikacja:

- `npm run test:api` - OK, 2/2 testy API przechodza na prawdziwej bazie PostgreSQL.

Co rozszerzyc dalej:

1. Dodac testy integracyjne dla walidacji harmonogramu i dat.
2. Dodac testy integracyjne dla `WEEKLY` naliczanego raz na tydzien.
3. Dodac testy integracyjne dla `NO_REQUIRED_TASKS`.
4. Dopiac dodatkowe przypadki restore backup i bulk archive zadan z zachowaniem historii punktow.

Priorytet: P2/P3.

## Kolejnosc Następnych Prac

Rekomendowana kolejność od teraz:

1. Backendowa walidacja harmonogramu zadania i polityki dat dla completion oraz extra task.
2. Poprawic semantyke `WEEKLY` z tygodniowym kluczem naliczania punktow.
3. Ustalic zasade dla aktywnego dnia bez zadan MIN.
4. Opcjonalnie dodac zbiorcze przywracanie pasujacych zadan.
5. Dopiero pozniej rozwiazac globalne kolizje kodow dzieci.

## Uwaga O Limicie I Zakresie

Przy niskim limicie tygodniowym nie warto robic wszystkich punktow naraz. Najbezpieczniejsze pakiety prac to:

- Pakiet A: stabilna lokalna baza testowa.
- Pakiet B: zbiorcze przywracanie pasujacych zadan.
- Pakiet C: logowanie dziecka z kodem rodziny.
- Pakiet D: rozszerzony widok ledgeru dla rodzica.
