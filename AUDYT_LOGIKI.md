# Audyt logiki aplikacji FamilyQuest

Data audytu: 2026-05-09  
Ostatnia aktualizacja: 2026-05-18

Zakres: backend `server.js`, frontend Vite/React w `src/`, `index.html`, `prisma/schema.prisma`, testy integracyjne, smoke, Playwrightowy test rankingu i wdrozenie na Proxmox.

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
- Produkcja `https://fq.familyos.pl` zostala zaktualizowana do `7a8c380`.
- CSP na produkcji nie wymaga juz `https://unpkg.com`; Vite buduje lokalny JS, a `script-src` moze zostac ograniczony do `'self'`.
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
- Dodano backendowy endpoint `POST /api/tasks/:id/restore-matching` i przycisk `U wszystkich` w archiwum, ktory przywraca wszystkie zarchiwizowane kopie tej samej definicji zadania.
- Panel rodzica ma teraz modal `Edytuj zadanie` zamiast systemowych `prompt()`. Edycja obejmuje dziecko, nazwe, typ `MIN/PLUS/WEEKLY`, punkty, dni tygodnia i opis.
- Uporzadkowano zrodlo frontendu: aktualnym zrodlem jest Vite/React w `src/`, a produkcyjny frontend powstaje przez `npm run frontend:build` do `dist/`.
- Dodano `npm run test:frontend-source`, ktory pilnuje entrypointu Vite, braku legacy compiled JS i aktualnej polityki PWA bez offline cache.
- README i `PROXMOX_DEPLOY.md` opisuja teraz tryb PWA: manifest/install dziala, a service worker celowo czysci stare cache i wyrejestrowuje sie.
- Rozbito frontend na moduly: `src/App.jsx` jest teraz orkiestratorem stanu i handlerow, a widoki dziecka, panel rodzica, zakladki, modale, helpery i hooki sa w `src/components/`, `src/lib/` i `src/hooks/`.
- Dodano ESLint i `npm run lint`; lint przechodzi, ale zostawia kilka warningow legacy do posprzatania.
- Wyodrebniono hooki `useFamilyData`, `useAutosave` i `useRewardUnlocks`.
- Dodano kolejke akcji rodzica po stronie frontendu. Szybkie klikniecia zatwierdzania, odrzucania, cofania zatwierdzen, premii, kar i mutacji zadan ida sekwencyjnie do API, co usuwa falszywe konflikty wersji FamilyState przy szybkim klikaniu.
- Po mutacjach serwerowych reload danych uzywa `skipNextAutoSave`, zeby klient nie zapisywal natychmiast starego snapshotu po swiezym stanie z backendu.
- Dodano zbiorcze odrzucanie wnioskow o zatwierdzenie: backend `POST /api/completions/reject-bulk`, frontendowy przycisk `Odrzuc wg filtra` oraz test UI/API. To przyspiesza czyszczenie wielu wnioskow bez klikania ich po kolei przez kolejke.
- Dodano stabilny skrypt wdrozenia `scripts/deploy-proxmox.ps1`, ktory automatyzuje snapshot, backup, deploy w CT 103, build Vite, restart uslugi, health/CSP check i produkcyjne testy Playwright.

## Weryfikacja Wykonana

- `node --check server.js` - OK.
- `npm run frontend:build` - OK, Vite generuje `dist/`.
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
- `npm run test:task-restore` - OK, test sprawdzil, ze okres archiwum pozostaje nieaktywny po przywroceniu, API przywraca pasujace zarchiwizowane zadania zbiorczo oraz Playwrightowo przejscie `Archiwum -> U wszystkich -> Aktywne`.
- `npm run test:task-edit` - OK, Playwright sprawdzil modal edycji zadania, zmiane nazwy, typu, punktow, opisu i dni tygodnia oraz payload `PUT /api/tasks/:id`.
- `npm run test:frontend-source` - OK, test potwierdza Vite entrypoint, `src/`, `public/` oraz service worker cleanup.
- Repo zostalo oczyszczone z konfiguracji Railway: usunieto `railway.json` i `RAILWAY_DEPLOY.md`, dodano `PROXMOX_DEPLOY.md`, a `.env.example` wskazuje aktualny deploy Proxmox.
- Lokalny `.env` nie powinien wskazywac starej bazy Railway. Testy API maja teraz osobny profil `.env.test.example` i baze `familyquest_test` w `CT 102`.
- `npm run test:api` - OK, runner resetuje tylko baze `familyquest_test`, tuneluje PostgreSQL przez `ssh proxmox`, wykonuje `prisma db push` i pelne testy Jest na prawdziwej bazie.
- Naprawiono falszywe konflikty `FAMILY_STATE_VERSION_CONFLICT` przy zapisach punktow: odczyty zapisujace przeliczone punkty robia zapis tylko, gdy wynik realnie sie zmienil, `storage/merge` nie podbija wersji przy braku zmian, a premia/kara punktowa ponawia zapis raz na swiezym stanie.
- `npm run test:api` - OK po naprawie konfliktow, dodany test wymusza konflikt wersji przy pierwszym zapisie kary i potwierdza sukces bez drugiego klikniecia.
- Dopisano pelne testy API dla polityki dat i harmonogramu: poprawny dzien, zly dzien harmonogramu, nieaktywny dzien dziecka, przyszla data completion i przyszla data extra task.
- Dopisano test API dla `WEEKLY`: dwa zatwierdzenia tego samego zadania w jednym tygodniu daja punkty tylko raz, z jednym tygodniowym wpisem w `taskPointGrants` i ledgerze.
- Dopisano test API dla `NO_REQUIRED_TASKS`: aktywny dzien bez zadan `MIN` nie daje punktow dziennych ani passy, nawet jesli zatwierdzono zadanie `PLUS`.
- Wdrożono polityke nagrod po spadku punktow: niewydana nagroda punktowa jest ukrywana/cofana, gdy saldo spada ponizej progu, a wraca na konto dziecka po ponownym zdobyciu wymaganego salda.
- Widoki `/api/rewards` i `storage/get/rewardUnlocks` zwracaja tylko aktywne odblokowania nagrod; cofniecia zostaja w stanie jako historia techniczna `revokedAt`, ale nie sa pokazywane dziecku jako dostepne nagrody.
- Dodano rodzicielski widok historii nagrod: `GET /api/rewards/history` zwraca pelny slad odblokowan, cofniec, przywrocen i wydan, a zakladka `Nagrody` pokazuje statusy `Dostepna`, `Cofnieta`, `Przywrocona`, `Wydana`.
- `npm run lint` - OK, z ostrzezeniami legacy: `grantDayPointsIfNeeded`, `grantWeekBonusIfNeeded`, `withAuth`, nieuzyty argument w `server.js`, service worker i jeden helper testowy.
- `npm run test:approval-action-queue` - OK, Playwright klika szybko trzy decyzje rodzica i potwierdza, ze do API trafia maksymalnie jeden request naraz oraz nie pojawia sie dialog konfliktu `FAMILY_STATE_VERSION_CONFLICT`.
- `npm run test:bulk-reject` - OK, Playwright potwierdza, ze przycisk `Odrzuc wg filtra` wysyla jeden request `reject-bulk`, usuwa widoczne wnioski z kolejki i zostawia brak zadan do zatwierdzenia.
- `npm run frontend:build` - OK po kolejce akcji rodzica.
- `npm run test:smoke` - OK na lokalnym backendzie z testowa baza PostgreSQL przez tunel SSH.
- Po wdrozeniu `7a8c380` produkcja ma `/health` 200, DB `ok`, Vite asset w HTML, brak `unpkg.com` i CSP `script-src 'self'`.
- Playwright przeciw produkcyjnemu buildowi `https://fq.familyos.pl` - OK dla: `approval-action-queue`, `reverse-approval`, `ranking`, `point-ledger`, `reward-history`, `task-edit`.
- `powershell -ExecutionPolicy Bypass -File scripts/deploy-proxmox.ps1 -DryRun -SkipTests -SkipPush -SkipSnapshot -AllowDirty` - OK, skrypt poprawnie waliduje lokalny branch i pokazuje plan deployu bez wykonywania zdalnych komend.

## Co Nadal Jest Do Zrobienia

Po wdrozeniu rankingu, passy, ledgeru, wersjonowania i kolejki akcji rodzica nie ma juz otwartego krytycznego bledu w samym liczeniu punktow ani porzadku tablicy wynikow. Zostaly ryzyka drugiego poziomu i dlug techniczny:

1. Kody dzieci moga kolidowac globalnie miedzy rodzinami.
2. Szybkie akcje rodzica sa bezpieczne, ale pojedyncze klikniecia nadal ida przez kolejke. Bulk odrzucanie juz istnieje, a do rozważenia zostaje lepszy UX kolejki i ewentualne bulk cofanie.
3. Warto ewentualnie dopracowac filtrowanie historii nagrod w panelu rodzica, jesli lista urosnie przy dluzszym uzywaniu aplikacji.
4. `src/App.jsx` nadal ma okolo 1200 linii i powinien dalej schodzic do roli `router + wiring`.
5. `npm run lint` przechodzi, ale zostawia warningi legacy.
6. Deploy na Proxmox ma juz stabilny skrypt, ale warto uzywac go przez kilka kolejnych wdrozen i dopiero wtedy usunac z dokumentacji reczna procedure jako glowne zrodlo.

## Rekomendowany Nastepny Pakiet

Najbardziej sensowny kolejny pakiet zalezy od celu:

- jesli priorytetem jest codzienny komfort uzywania: **UX kolejki zapisow i bulk odrzucanie/cofanie**;
- jesli priorytetem jest domkniecie audytu logicznego przed druga rodzina: **globalne kolizje kodow dzieci**;
- jesli priorytetem jest stabilnosc operacyjna: **uzywanie i dopracowanie skryptu deployu Proxmox**.

Domyslna rekomendacja po ostatnim bledzie konfliktow: bulk odrzucanie i skrypt deployu sa wdrozone, wiec nastepny najbardziej praktyczny pakiet to czysty lint bez warningow.

Dlaczego globalne kody nadal sa wazne:

- Testy API dla dat, harmonogramu, `WEEKLY` i `NO_REQUIRED_TASKS` sa juz wdrozone.
- Polityka nagrod po spadku punktow jest juz wdrozona.
- Globalne kody dzieci sa ostatnim istotnym ryzykiem logicznym, ktore moze wyjsc dopiero przy drugiej rodzinie.

Minimalny zakres wdrozenia:

1. Zmienic logowanie dziecka tak, by nie opieralo sie wylacznie na globalnym 4-cyfrowym kodzie.
2. Dodac kod rodziny albo dluzszy globalnie unikalny kod dziecka.
3. Dodac test API dla dwoch rodzin z tym samym kodem dziecka.

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

Status: wdrozone w wariancie bulk archive + bulk restore.

Rodzic moze archiwizowac pojedyncze zadanie albo jednym przyciskiem `U wszystkich` zarchiwizowac wszystkie aktywne kopie o tej samej definicji: tytul, typ, punkty, opis i dni tygodnia. Archiwizacja ustawia `active: false` i `archivedAt`. Widok `Archiwum` pokazuje zarchiwizowane zadania i pozwala je przywrocic.

Wazna zasada logiki:

- zadania zarchiwizowane nie pokazuja sie dzieciom i nie sa wymagane od daty archiwizacji,
- zatwierdzone wykonania sprzed `archivedAt` nadal licza sie w `pointLedger`, `points`, dniu zaliczonym i passie historycznej,
- nowe wykonania dla zarchiwizowanego zadania sa blokowane,
- przywrocenie pojedyncze i zbiorcze ustawia `restoredAt`; okres `archivedAt` -> `restoredAt` pozostaje historycznie nieaktywny.

Co zostaje dalej:

1. Ewentualnie dopracowac teksty/potwierdzenia, jesli przy rodzinie z wieloma dziecmi lista bedzie zbyt dluga.
2. Dopisac dodatkowe przypadki brzegowe do testow API, jesli pojawi sie edycja definicji po archiwizacji.

Priorytet: zrealizowane, rozszerzenia P3.

### 7. Semantyka Nagród Po Spadku Punktow

Status: wdrozone.

Niewydane nagrody punktowe sa teraz traktowane jak dostep do progu punktowego, a nie permanentne osiagniecie. Jesli saldo dziecka spadnie ponizej wymaganego progu, odblokowanie dostaje `revokedAt` i przestaje byc zwracane przez `/api/rewards` oraz `storage/get/rewardUnlocks`. Po ponownym zdobyciu wymaganego salda to samo odblokowanie jest przywracane przez wyczyszczenie `revokedAt` i ustawienie `restoredAt`.

Wazna zasada:

1. Cofamy tylko nagrody niewydane (`claimedAt` puste).
2. Nagrody juz oznaczone jako wydane zostaja historia wydania i nie sa automatycznie odbierane.
3. Polityka jest egzekwowana po premii/karze, cofnieciu zatwierdzenia, zmianach zadan, restore backupu oraz zmianie progow nagrod.
4. Panel rodzica pokazuje historie statusow nagrod z osobnego endpointu rodzicielskiego, bez pokazywania cofniętych nagrod dzieciom jako dostepnych.

Priorytet: zrealizowane, ewentualne filtrowanie historii P3.

### 8. Zrodlo Frontendu I Build

Status: wdrozone, ale z dlugiem porzadkowym.

Uruchamiana aplikacja ma teraz prawdziwy build pipeline Vite + React bez TypeScriptu. Zrodlem prawdy sa `src/main.jsx`, `src/App.jsx` i `src/styles.css`. `index.html` laduje `/src/main.jsx` w dev, a produkcyjnie Express serwuje `dist/` wygenerowane przez `npm run frontend:build`. Stary `familyquest-app.compiled.js` zostal usuniety.

Co zrobic dalej:

1. Dalej odchudzac `src/App.jsx`, ktory ma okolo 1200 linii. Po hookach powinien zejsc do roli `router + wiring`.
2. Wyprowadzic pozostale handlery domenowe do hookow lub modulow akcji: zadania, nagrody, dzieci, admin/security, import/export.
3. Zmniejszyc prop drilling w `ParentPanel`, najlepiej przez obiekty akcji albo mniejsze kontenery per zakladka.
4. Do tego czasu pilnowac `npm run test:frontend-source` i `npm run frontend:build`.
5. Nie przywracac recznie utrzymywanego compiled JS.

Priorytet: logika zrealizowana, dalszy refaktor P2/P3.

### 9. Dokumentacja PWA I Service Worker

Status: uporzadkowane.

`public/service-worker.js` usuwa cache i wyrejestrowuje SW. README oraz `PROXMOX_DEPLOY.md` opisuja teraz, ze PWA oznacza manifest/install bez offline cache.

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

1. Dopiac dodatkowe przypadki restore backup i bulk archive zadan z zachowaniem historii punktow, jesli pojawia sie regresje w tych obszarach.
2. Dodac osobne testy UI dla widoku nagrod po cofnieciu/przywroceniu, jesli panel rodzica ma pokazywac pelna historie statusow.

Priorytet: P2/P3.

### 11. Kolejka Akcji Rodzica I UX Zapisu

Status: backendowo/logicznie zabezpieczone, UX do poprawy.

Po szybkim klikaniu kilku decyzji rodzica pojawial sie konflikt `Stan rodziny zmienił się na innym urządzeniu`, mimo ze nikt inny nie uzywal aplikacji. Przyczyna byl lokalny wyscig: kilka mutacji trafialo do API rownolegle, a odswiezenie stanu moglo pobudzic autosave snapshotu z nieaktualna wersja.

Co jest wdrozone:

1. `runServerMutation` kolejkuje akcje serwerowe rodzica po stronie frontendu.
2. `reloadAfterServerMutation` zawsze odswieza stan z `skipNextAutoSave`.
3. Test `npm run test:approval-action-queue` potwierdza szybkie trzy klikniecia bez konfliktu i z maksymalnie jednym requestem w locie.

Co zrobic dalej:

1. Dac przyciski w stan `saving` po kliknieciu, zeby uzytkownik widzial, ze akcja czeka w kolejce.
2. Optymistycznie ukrywac klikniety wniosek albo oznaczac go jako `W trakcie zapisu`.
3. Bulk odrzucanie wielu wnioskow jednym requestem jest wdrozone.
4. Rozwazyc bulk cofanie zatwierdzen, ale ostroznie, bo kazde cofniecie ma efekt punktowy i komunikat dla rodzica.

Priorytet: P2, bo poprawia codzienny komfort bez zmiany reguly punktow.

### 12. ESLint Warning Cleanup

Status: lint dziala, warningi zostaly.

`npm run lint` przechodzi, ale ostrzega o kilku rzeczach legacy:

- `grantDayPointsIfNeeded` i `grantWeekBonusIfNeeded` w `src/App.jsx`,
- parametr `withAuth` w `src/lib/api.js`,
- nieuzyty argument `next` w `server.js`,
- nieuzyty `event` w `public/service-worker.js`,
- nieuzyty helper `rectWithinViewport` w `scripts/check-mobile-layout.js`.

Co zrobic dalej:

1. Usunac lub przeniesc nieuzywane helpery z `App.jsx`, jesli nie sa juz potrzebne po serwerowym recompute.
2. Usunac `withAuth` albo przywrocic jego realne znaczenie w `apiRequest`.
3. Zmienic nieuzyte argumenty na `_event` / `_next` albo uproscic sygnatury.
4. Po zmianie uruchomic `npm run lint`, `npm run frontend:build` i szybkie Playwrighty dotknietych obszarow.

Priorytet: P3, chyba ze warningi zaczna maskowac nowe problemy.

### 13. Skrypt Deployu Proxmox

Status: wdrozone jako `scripts/deploy-proxmox.ps1`, do uzywania w kolejnych wdrozeniach.

Deploy jest teraz opisany i zautomatyzowany: skrypt robi snapshot CT 103, backup plikow, `git fetch/reset`, `npm ci`, `npm run frontend:build`, restart `familyquest`, lokalny healthcheck, publiczny health/CSP check oraz produkcyjne testy Playwright. Reczna procedura zostaje w `PROXMOX_DEPLOY.md` jako awaryjna.

Co zrobic dalej:

1. Uzywac skryptu jako standardowej sciezki deployu przy kolejnych zmianach.
2. Po kilku udanych deployach ewentualnie dodac tryb `-NoPush`/`-NoVerifyRemote`, jesli pojawi sie realna potrzeba.
3. Rozwazyc zapis logu deployu do `tmp/deploy-*.log`, jesli bedziemy chcieli latwiej porownywac wdrozenia.

Priorytet: zrealizowane, dalsze dopracowanie P3.

## Kolejnosc Następnych Prac

Rekomendowana kolejność od teraz:

1. Posprzatac warningi ESLint, zeby lint byl czystym sygnalem.
2. Dalej odchudzac `src/App.jsx` do roli `router + wiring`.
3. Dopracowac UX pojedynczych akcji w kolejce, jesli nadal beda odczuwalnie wolne.
4. Rozwiazac globalne kolizje kodow dzieci przed obsluga drugiej rodziny.
5. Dodac filtrowanie historii nagrod po dziecku/statusie, jesli lista urosnie.

## Uwaga O Limicie I Zakresie

Przy niskim limicie tygodniowym nie warto robic wszystkich punktow naraz. Najbezpieczniejsze pakiety prac to:

- Pakiet A: czysty lint bez warningow.
- Pakiet B: dalsze odchudzenie `src/App.jsx`.
- Pakiet C: dopracowanie UX pojedynczych akcji w kolejce.
- Pakiet D: logowanie dziecka z kodem rodziny.
- Pakiet E: rozszerzony widok ledgeru dla rodzica.
