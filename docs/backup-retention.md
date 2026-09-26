# Retencja kopii FamilyQuest

- Baza PostgreSQL: codzienna kopia na hoście Proxmox, około 30 dni retencji. Ta zmiana nie modyfikuje istniejącego zadania.
- `.deploy-backups/local-before-deploy-*`: trzy najnowsze kopie. Rotacja dopiero na końcu `deploy-proxmox.ps1`, po udanych kontrolach zdrowia i testach Playwright. Błąd wdrożenia lub `-SkipTests` pomija tę rotację.
- Kopie napraw: `reconcile-reward-unlocks-*`, `point-forensics-*`, `recompute-family-state-*` starsze niż 14 dni są usuwane, ale najnowsza kopia każdego rodzaju zawsze zostaje. Timer systemd uruchamia sprzątanie codziennie około 04:45–05:00, także po przestoju serwera.
- Snapshoty `pre-familyquest-*`: dwa najnowsze, rotacja po udanym wdrożeniu i testach. Inne snapshoty pozostają nietknięte.

Skrypt rozpoznaje wyłącznie kompletne nazwy z datą. Pomija inne katalogi i dowiązania symboliczne. Bez `--apply` tylko wypisuje plan. Limity kopii wdrożeń i snapshotów mogą zostać przekroczone po nieudanych wdrożeniach, aby zachować możliwość odzyskania danych.

Podgląd kopii w kontenerze:
```
python3 /opt/familyquest/scripts/backup-retention.py --deploy-success
```

Test polityki bez dostępu do produkcyjnych danych:
```
python scripts/test-backup-retention.py
```

Instalacja timera w kontenerze (wykonuje ją również skrypt wdrożenia):
```
install -m 0644 scripts/familyquest-backup-retention.service scripts/familyquest-backup-retention.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now familyquest-backup-retention.timer
```

Pełna kopia kontenera na E: pozostaje niezależna od tych reguł. Skrypty nie usuwają jej ani archiwów bazy na hoście.
