# =============================================================================
# FamilyQuest deploy: working dir -> GitHub -> Proxmox CT 103
# =============================================================================
$ErrorActionPreference = "Continue"

function Section([string]$name) {
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "== $name"
    Write-Host "============================================================"
}

Section "FamilyQuest deploy start ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
Set-Location "E:\Projects\FamilyQuestApp"
Write-Host "PWD: $((Get-Location).Path)"
Write-Host "PSVersion: $($PSVersionTable.PSVersion)"

# -----------------------------------------------------------------------------
Section "PHASE A: lokalny commit + push"
# -----------------------------------------------------------------------------
Write-Host "--- git status ---"
& git status --short
Write-Host "--- git remote -v ---"
& git remote -v

$dirty = (& git status --porcelain) -join "`n"
if ($dirty.Trim().Length -gt 0) {
    Write-Host "--- git add -A ---"
    & git add -A
    $msg = "Deploy: sync working dir to prod ($(Get-Date -Format 'yyyy-MM-dd HH:mm'))"
    Write-Host "--- git commit ---"
    & git commit -m $msg
} else {
    Write-Host "Working tree clean - nothing to commit"
}

Write-Host "--- git push origin main ---"
& git push origin main 2>&1
$pushExit = $LASTEXITCODE
if ($pushExit -ne 0) {
    Write-Host "ERROR: git push failed (exit=$pushExit). Aborting."
    exit 1
}

$LocalSha = (& git rev-parse HEAD).Trim()
Write-Host "Local HEAD: $LocalSha"

# -----------------------------------------------------------------------------
Section "PHASE B: deploy na CT 103"
# -----------------------------------------------------------------------------

$RemoteScript = @'
set -uo pipefail
echo "== whoami: $(whoami)  host: $(hostname)  date: $(date -Is)"

APP_DIR=""
for cand in /opt/familyquest /opt/familyquest/app /srv/familyquest /var/www/familyquest /root/familyquest /home/*/familyquest; do
  if [ -d "$cand/.git" ]; then APP_DIR="$cand"; break; fi
done
if [ -z "$APP_DIR" ]; then
  HIT=$(find /opt /srv /var/www /root /home -maxdepth 4 -name familyquest-app.compiled.js 2>/dev/null | head -1)
  if [ -n "$HIT" ]; then APP_DIR=$(dirname "$HIT"); fi
fi
if [ -z "$APP_DIR" ]; then
  echo "ERROR: app dir not found"; exit 2
fi
echo "== APP_DIR: $APP_DIR"
cd "$APP_DIR"

SVC=""
for s in familyquest familyquest-app familyquest-api fq; do
  if systemctl list-unit-files --no-legend --no-pager 2>/dev/null | grep -q "^${s}.service"; then SVC="${s}.service"; break; fi
done
echo "== Service: ${SVC:-<not found>}"

echo "== git remote -v"; git remote -v
BEFORE=$(git rev-parse HEAD)
echo "== HEAD before: $BEFORE"
git status --short

TS=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="$APP_DIR/.deploy-backups/$TS"
mkdir -p "$BACKUP_DIR"
[ -f "$APP_DIR/.env" ] && cp -a "$APP_DIR/.env" "$BACKUP_DIR/.env"
[ -f "$APP_DIR/prisma/schema.prisma" ] && cp -a "$APP_DIR/prisma/schema.prisma" "$BACKUP_DIR/schema.prisma"
echo "== Backup dir: $BACKUP_DIR"

if [ -f "$APP_DIR/.env" ]; then
  DB_URL=$(grep -E '^DATABASE_URL' "$APP_DIR/.env" | head -1 | sed -E 's/^[^=]+=//; s/^"//; s/"$//')
  if [ -n "$DB_URL" ]; then
    echo "== Backup PostgreSQL"
    if command -v pg_dump >/dev/null 2>&1; then
      pg_dump --no-owner --no-privileges "$DB_URL" 2>&1 | gzip > "$BACKUP_DIR/db.sql.gz"
      if [ -s "$BACKUP_DIR/db.sql.gz" ]; then
        echo "   OK: $BACKUP_DIR/db.sql.gz ($(du -h "$BACKUP_DIR/db.sql.gz" | cut -f1))"
      else
        echo "   WARN: pg_dump produced empty file"
      fi
    else
      echo "   WARN: pg_dump not available in CT 103"
      DB_HOST=$(echo "$DB_URL" | sed -E 's|.*@([^:/]+).*|\1|')
      echo "   DB_HOST=$DB_HOST"
    fi
  fi
fi

git fetch --all --prune
git stash push -u -m "pre-deploy-$TS" 2>/dev/null || true
git checkout main 2>&1 | tail -3
git pull --ff-only origin main
AFTER=$(git rev-parse HEAD)
echo "== HEAD after: $AFTER"

if [ "$BEFORE" = "$AFTER" ]; then
  echo "== No new commits."
else
  echo "== Commits pulled:"
  git log --oneline "$BEFORE..$AFTER"
fi

if [ "$BEFORE" != "$AFTER" ] && git diff --name-only "$BEFORE" "$AFTER" | grep -qE '^(package\.json|package-lock\.json)$'; then
  echo "== package.json changed -> npm ci --omit=dev"
  npm ci --omit=dev 2>&1 | tail -20
else
  echo "== package.json unchanged -> skip npm install"
fi

if [ "$BEFORE" != "$AFTER" ] && git diff --name-only "$BEFORE" "$AFTER" | grep -q '^prisma/schema.prisma$'; then
  echo "== schema.prisma changed -> prisma db push (safe, no DROP)"
  npx prisma generate 2>&1 | tail -5
  npx prisma db push --skip-generate 2>&1 | tail -10
else
  echo "== schema.prisma unchanged -> skip migrations"
fi

if [ -n "$SVC" ]; then
  echo "== systemctl restart $SVC"
  systemctl restart "$SVC"
  sleep 3
  systemctl status "$SVC" --no-pager -l 2>&1 | head -25
else
  echo "WARN: no service - manual restart may be needed"
fi

sleep 2
echo "== Health check (local)"
curl -sS --max-time 5 http://127.0.0.1:3000/health 2>&1 || curl -sS --max-time 5 http://127.0.0.1:3010/health 2>&1 || echo "   WARN: health endpoint not responding"
echo

if [ -d "$APP_DIR/.deploy-backups" ]; then
  cd "$APP_DIR/.deploy-backups"
  ls -1t | tail -n +6 | xargs -r rm -rf
  echo "== Backups kept (5 most recent):"
  ls -1t | head -5
fi

echo "== DONE"
'@

$tmpScript = "$env:TEMP\fq-deploy.sh"
$RemoteScript = $RemoteScript -replace "`r`n", "`n"
[System.IO.File]::WriteAllText($tmpScript, $RemoteScript, (New-Object System.Text.UTF8Encoding $false))
Write-Host "Remote script saved: $tmpScript"

Write-Host "--- scp to proxmox ---"
& scp -o StrictHostKeyChecking=accept-new $tmpScript proxmox:/tmp/fq-deploy.sh 2>&1
Write-Host "scp exit: $LASTEXITCODE"

Write-Host "--- ssh proxmox + pct exec 103 ---"
& ssh -o StrictHostKeyChecking=accept-new proxmox "chmod +x /tmp/fq-deploy.sh && pct push 103 /tmp/fq-deploy.sh /tmp/fq-deploy.sh && pct exec 103 -- bash /tmp/fq-deploy.sh" 2>&1
Write-Host "ssh exit: $LASTEXITCODE"

# -----------------------------------------------------------------------------
Section "PHASE C: external verification"
# -----------------------------------------------------------------------------
& curl.exe -sS --max-time 10 https://fq.familyos.pl/health 2>&1
Write-Host ""

# -----------------------------------------------------------------------------
Section "PHASE D: cleanup"
# -----------------------------------------------------------------------------
Remove-Item -Force $tmpScript -ErrorAction SilentlyContinue
Write-Host "Removed $tmpScript"
& ssh proxmox "rm -f /tmp/fq-deploy.sh && pct exec 103 -- rm -f /tmp/fq-deploy.sh" 2>&1
Write-Host "Cleaned /tmp/fq-deploy.sh on host and CT 103"

Section "DEPLOY COMPLETE"
