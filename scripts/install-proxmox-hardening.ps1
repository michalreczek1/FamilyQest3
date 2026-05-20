param(
  [string]$ProxmoxHost = "proxmox",
  [int]$AppCt = 103,
  [int]$DbCt = 102,
  [string]$BackupDir = "/var/backups/familyquest-postgres",
  [int]$RetentionDays = 30,
  [string]$TimerCalendar = "*-*-* 03:15:00",
  [switch]$Apply
)

$ErrorActionPreference = "Stop"

function Write-TempUtf8 {
  param([string]$Content)
  $tmp = New-TemporaryFile
  [System.IO.File]::WriteAllText($tmp, $Content, [System.Text.UTF8Encoding]::new($false))
  return $tmp
}

function Install-RemoteFile {
  param(
    [string]$Content,
    [string]$Path,
    [string]$Mode = "0644"
  )
  $tmp = Write-TempUtf8 $Content
  $remoteTmp = "/tmp/familyquest-hardening-$([guid]::NewGuid().ToString('N'))"
  try {
    scp $tmp "${ProxmoxHost}:$remoteTmp" | Out-Null
    ssh $ProxmoxHost "install -m $Mode $remoteTmp $Path && rm -f $remoteTmp"
  } finally {
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
  }
}

$backupScript = @'
#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export LANG=C

APP_CT="__APP_CT__"
DB_CT="__DB_CT__"
BACKUP_DIR="__BACKUP_DIR__"
RETENTION_DAYS="__RETENTION_DAYS__"
LOG_DIR="/var/log/familyquest"
LOG_FILE="$LOG_DIR/postgres-backup.log"

umask 077
mkdir -p "$BACKUP_DIR" "$LOG_DIR"
exec >> "$LOG_FILE" 2>&1

echo "[$(date -Is)] starting FamilyQuest PostgreSQL backup"

if ! pct status "$APP_CT" | grep -q "status: running"; then
  echo "[$(date -Is)] app CT $APP_CT is not running"
  exit 1
fi

if ! pct status "$DB_CT" | grep -q "status: running"; then
  echo "[$(date -Is)] db CT $DB_CT is not running"
  exit 1
fi

DATABASE_URL="$(pct exec "$APP_CT" -- bash -lc 'set -a; source /opt/familyquest/.env >/dev/null 2>&1; printf "%s" "${DATABASE_URL:-}"')"
if [ -z "$DATABASE_URL" ]; then
  echo "[$(date -Is)] DATABASE_URL not found in app CT"
  exit 1
fi
PG_DUMP_URL="${DATABASE_URL%%\?schema=*}"
PG_DUMP_URL="$(printf '%s' "$PG_DUMP_URL" | sed -E 's#@[^/@?]+(:[0-9]+)?/#@127.0.0.1:5432/#')"

stamp="$(date +%Y%m%d-%H%M%S)"
tmp_file="$BACKUP_DIR/familyquest-$stamp.sql.gz.tmp"
out_file="$BACKUP_DIR/familyquest-$stamp.sql.gz"

if pct exec "$DB_CT" -- env DATABASE_URL="$PG_DUMP_URL" bash -lc 'pg_dump "$DATABASE_URL"' | gzip -9 > "$tmp_file"; then
  mv "$tmp_file" "$out_file"
  find "$BACKUP_DIR" -type f -name 'familyquest-*.sql.gz' -mtime +"$RETENTION_DAYS" -delete
  latest_size="$(du -h "$out_file" | awk '{print $1}')"
  latest_count="$(find "$BACKUP_DIR" -type f -name 'familyquest-*.sql.gz' | wc -l)"
  echo "[$(date -Is)] backup ok: $out_file ($latest_size), retained files: $latest_count"
else
  rm -f "$tmp_file"
  echo "[$(date -Is)] backup failed"
  exit 1
fi
'@
$backupScript = $backupScript.Replace('__APP_CT__', [string]$AppCt).Replace('__DB_CT__', [string]$DbCt).Replace('__BACKUP_DIR__', $BackupDir).Replace('__RETENTION_DAYS__', [string]$RetentionDays)

$serviceUnit = @"
[Unit]
Description=FamilyQuest PostgreSQL backup
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/familyquest-pg-backup.sh
"@

$timerUnit = @"
[Unit]
Description=Run FamilyQuest PostgreSQL backup daily

[Timer]
OnCalendar=$TimerCalendar
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
"@

$journaldConf = @"
[Journal]
SystemMaxUse=500M
SystemKeepFree=1G
RuntimeMaxUse=100M
MaxRetentionSec=30day
"@

$serviceDropIn = @"
[Service]
LogRateLimitIntervalSec=30s
LogRateLimitBurst=1000
"@

$journaldCredentialDropIn = @"
[Service]
ImportCredential=
"@

if (-not $Apply) {
  Write-Host "Dry-run only. Add -Apply to install backup timer and journald limits on $ProxmoxHost."
  ssh $ProxmoxHost "set -e; echo 'Host:'; hostname; echo; echo 'Existing backup timer:'; systemctl list-timers 'familyquest*' --no-pager || true; echo; echo 'App service in CT ${AppCt}:'; pct exec $AppCt -- systemctl cat familyquest --no-pager || true; echo; echo 'Host journal usage:'; journalctl --disk-usage || true"
  exit 0
}

ssh $ProxmoxHost "mkdir -p '$BackupDir' /var/log/familyquest /etc/systemd/system /usr/local/sbin"
Install-RemoteFile -Content $backupScript -Path "/usr/local/sbin/familyquest-pg-backup.sh" -Mode "0750"
Install-RemoteFile -Content $serviceUnit -Path "/etc/systemd/system/familyquest-postgres-backup.service"
Install-RemoteFile -Content $timerUnit -Path "/etc/systemd/system/familyquest-postgres-backup.timer"

$ctJournalTmp = "/tmp/familyquest-journald.conf"
$ctDropInTmp = "/tmp/familyquest-service-logging.conf"
$ctJournalCredentialTmp = "/tmp/familyquest-journald-credentials.conf"
Install-RemoteFile -Content $journaldConf -Path $ctJournalTmp
Install-RemoteFile -Content $serviceDropIn -Path $ctDropInTmp
Install-RemoteFile -Content $journaldCredentialDropIn -Path $ctJournalCredentialTmp

ssh $ProxmoxHost "set -e; pct exec $AppCt -- mkdir -p /etc/systemd/journald.conf.d /etc/systemd/system/familyquest.service.d /etc/systemd/system/systemd-journald.service.d; pct push $AppCt $ctJournalTmp /etc/systemd/journald.conf.d/familyquest-limits.conf --perms 0644; pct push $AppCt $ctDropInTmp /etc/systemd/system/familyquest.service.d/logging.conf --perms 0644; pct push $AppCt $ctJournalCredentialTmp /etc/systemd/system/systemd-journald.service.d/no-import-credential.conf --perms 0644; rm -f $ctJournalTmp $ctDropInTmp $ctJournalCredentialTmp; pct exec $AppCt -- systemctl daemon-reload; pct exec $AppCt -- systemctl restart systemd-journald; systemctl daemon-reload; systemctl enable --now familyquest-postgres-backup.timer; systemctl list-timers 'familyquest*' --no-pager"

Write-Host "Installed FamilyQuest PostgreSQL backup timer and journald limits."
Write-Host "Run a backup now with: ssh $ProxmoxHost 'systemctl start familyquest-postgres-backup.service && tail -n 20 /var/log/familyquest/postgres-backup.log'"
