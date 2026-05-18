param(
  [string]$ProxmoxHost = "proxmox",
  [int]$ContainerId = 103,
  [string]$AppDir = "/opt/familyquest",
  [string]$Branch = "main",
  [string]$PublicUrl = "https://fq.familyos.pl",
  [switch]$SkipSnapshot,
  [switch]$SkipBackup,
  [switch]$SkipPush,
  [switch]$SkipTests,
  [switch]$AllowDirty,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-CheckedCommand {
  param(
    [string]$Label,
    [scriptblock]$Command
  )
  Write-Step $Label
  if ($DryRun) {
    Write-Host "[dry-run] $Label"
    return
  }
  & $Command
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

function Invoke-GitText {
  param([string[]]$Arguments)
  $output = & git @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
  }
  return ($output -join "`n").Trim()
}

function Assert-LocalRepoReady {
  Write-Step "Checking local git state"
  $currentBranch = Invoke-GitText @("rev-parse", "--abbrev-ref", "HEAD")
  if ($currentBranch -ne $Branch) {
    throw "Current branch is '$currentBranch', expected '$Branch'. Use -Branch or switch branches first."
  }

  $status = Invoke-GitText @("status", "--porcelain")
  if ($status -and -not $AllowDirty) {
    throw "Working tree is dirty. Commit/stash changes or pass -AllowDirty intentionally."
  }

  $head = Invoke-GitText @("rev-parse", "--short", "HEAD")
  Write-Host "Branch: $currentBranch"
  Write-Host "Commit: $head"
  if ($status) {
    Write-Host "Working tree has local changes and -AllowDirty was set." -ForegroundColor Yellow
  }
}

function Invoke-SshChecked {
  param(
    [string]$Label,
    [string[]]$Arguments,
    [string]$InputText = $null
  )
  Write-Step $Label
  if ($DryRun) {
    Write-Host "[dry-run] ssh $ProxmoxHost $($Arguments -join ' ')"
    if ($InputText) {
      Write-Host "[dry-run] script input omitted from execution"
    }
    return
  }

  if ($InputText -ne $null) {
    $InputText | ssh $ProxmoxHost @Arguments
  } else {
    ssh $ProxmoxHost @Arguments
  }
  if ($LASTEXITCODE -ne 0) {
    throw "$Label failed with exit code $LASTEXITCODE"
  }
}

function New-ProxmoxSnapshot {
  if ($SkipSnapshot) {
    Write-Step "Skipping Proxmox snapshot"
    return
  }
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $snapshotName = "pre-familyquest-$stamp"
  $description = "Before FamilyQuest deploy $(Invoke-GitText @("rev-parse", "--short", "HEAD"))"
  Invoke-SshChecked `
    -Label "Creating snapshot $snapshotName for CT $ContainerId" `
    -Arguments @("pct snapshot $ContainerId $snapshotName --description '$description'")
}

function Invoke-RemoteDeploy {
  $doBackup = if ($SkipBackup) { "0" } else { "1" }
  $remoteScript = @'
set -euo pipefail

cd "$APP_DIR"
stamp=$(date +%Y%m%d-%H%M%S)

if [ "$DO_BACKUP" = "1" ]; then
  backup_dir="$APP_DIR/.deploy-backups/local-before-deploy-$stamp"
  mkdir -p "$backup_dir"
  git rev-parse HEAD > "$backup_dir/git-commit.txt" 2>/dev/null || true
  for file in index.html server.js package.json package-lock.json vite.config.js AUDYT_LOGIKI.md PROXMOX_DEPLOY.md prisma/schema.prisma; do
    if [ -e "$file" ]; then
      mkdir -p "$backup_dir/$(dirname "$file")"
      cp -a "$file" "$backup_dir/$file"
    fi
  done
  for dir in src public dist scripts __tests__; do
    if [ -e "$dir" ]; then
      cp -a "$dir" "$backup_dir/"
    fi
  done
  printf 'Backup: %s\n' "$backup_dir"
else
  printf 'Backup skipped\n'
fi

git fetch origin "$BRANCH"
git checkout "$BRANCH"
git reset --hard "origin/$BRANCH"
npm ci
npm run frontend:build
systemctl restart familyquest
sleep 3

service_status=$(systemctl is-active familyquest)
printf 'Service: %s\n' "$service_status"
if [ "$service_status" != "active" ]; then
  systemctl status familyquest --no-pager -l || true
  exit 1
fi

printf 'Commit: '
git log -1 --pretty=format:%h:%s
printf '\n'
printf 'Local health: '
curl -fsS http://127.0.0.1:3000/health
printf '\n'
'@

  $containerCommand = "pct exec $ContainerId -- env APP_DIR='$AppDir' BRANCH='$Branch' DO_BACKUP='$doBackup' bash -s"
  Invoke-SshChecked -Label "Deploying in CT $ContainerId" -Arguments @($containerCommand) -InputText $remoteScript
}

function Test-PublicHealthAndCsp {
  Write-Step "Checking public health and CSP"
  if ($DryRun) {
    Write-Host "[dry-run] GET $PublicUrl/health"
    Write-Host "[dry-run] GET $PublicUrl/"
    return
  }

  $health = Invoke-WebRequest -Uri "$PublicUrl/health" -UseBasicParsing -TimeoutSec 20
  if ($health.StatusCode -ne 200) {
    throw "Health returned HTTP $($health.StatusCode)"
  }
  if ($health.Content -notmatch '"db"\s*:\s*"ok"') {
    throw "Health did not report db ok: $($health.Content)"
  }

  $root = Invoke-WebRequest -Uri "$PublicUrl/" -UseBasicParsing -TimeoutSec 20
  if ($root.Content -match "unpkg\.com") {
    throw "Root HTML still references unpkg.com"
  }
  if ($root.Content -notmatch "/assets/index-.*\.js") {
    throw "Root HTML does not reference a Vite JS asset"
  }
  $csp = ($root.Headers["Content-Security-Policy"] -join "; ")
  if ($csp -notmatch "script-src 'self'") {
    throw "CSP does not contain script-src 'self': $csp"
  }

  Write-Host "Health: $($health.Content)"
  Write-Host "CSP: $csp"
}

function Invoke-ProductionPlaywrightTests {
  if ($SkipTests) {
    Write-Step "Skipping production Playwright tests"
    return
  }

  $tests = @(
    @{ Env = "BULK_REJECT_BASE_URL"; Script = "test:bulk-reject" },
    @{ Env = "APPROVAL_ACTION_QUEUE_BASE_URL"; Script = "test:approval-action-queue" },
    @{ Env = "REVERSE_APPROVAL_BASE_URL"; Script = "test:reverse-approval" },
    @{ Env = "RANKING_BASE_URL"; Script = "test:ranking" },
    @{ Env = "POINT_LEDGER_BASE_URL"; Script = "test:point-ledger" },
    @{ Env = "REWARD_HISTORY_BASE_URL"; Script = "test:reward-history" },
    @{ Env = "TASK_EDIT_BASE_URL"; Script = "test:task-edit" }
  )

  foreach ($test in $tests) {
    $envName = $test.Env
    $scriptName = $test.Script
    Invoke-CheckedCommand -Label "Running $scriptName against $PublicUrl" -Command {
      Set-Item -Path "Env:$envName" -Value $PublicUrl
      try {
        npm run $scriptName
      } finally {
        Remove-Item -Path "Env:$envName" -ErrorAction SilentlyContinue
      }
    }
  }
}

Assert-LocalRepoReady

if (-not $SkipPush) {
  Invoke-CheckedCommand -Label "Pushing $Branch to origin" -Command {
    git push origin $Branch
  }
}

New-ProxmoxSnapshot
Invoke-RemoteDeploy
Test-PublicHealthAndCsp
Invoke-ProductionPlaywrightTests

Write-Step "Deploy complete"
Write-Host "FamilyQuest is deployed from $Branch at $(Invoke-GitText @("rev-parse", "--short", "HEAD"))"
