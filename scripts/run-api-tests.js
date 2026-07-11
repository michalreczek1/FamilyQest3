const fs = require('fs');
const net = require('net');
const { spawn, spawnSync } = require('child_process');
const dotenv = require('dotenv');

const SSH_HOST = process.env.FAMILYQUEST_TEST_SSH_HOST || 'proxmox';
const POSTGRES_CT = process.env.FAMILYQUEST_TEST_POSTGRES_CT || '102';
const POSTGRES_VERSION = process.env.FAMILYQUEST_TEST_POSTGRES_VERSION || '17';
const POSTGRES_TARGET = process.env.FAMILYQUEST_TEST_POSTGRES_TARGET || '192.168.33.121:5432';
const PROXMOX_HOST_IP = process.env.FAMILYQUEST_TEST_PROXMOX_HOST_IP || '192.168.33.100';
const LOCAL_HOST = process.env.FAMILYQUEST_TEST_LOCAL_HOST || '127.0.0.1';
const LOCAL_PORT = Number(process.env.FAMILYQUEST_TEST_LOCAL_PORT || 15432);
const DB_NAME = 'familyquest_test';
const DB_USER = 'familyquest_test';
const DB_PASSWORD = 'familyquest_test_password';
const DEFAULT_DATABASE_URL =
  `postgresql://${DB_USER}:${DB_PASSWORD}@${LOCAL_HOST}:${LOCAL_PORT}/${DB_NAME}?schema=public`;

const loadEnvFile = () => {
  const envPath = fs.existsSync('.env.test') ? '.env.test' : '.env.test.example';
  if (fs.existsSync(envPath)) {
    const parsed = dotenv.parse(fs.readFileSync(envPath));
    Object.entries(parsed).forEach(([key, value]) => {
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    });
  }
  process.env.DATABASE_URL = process.env.DATABASE_URL || DEFAULT_DATABASE_URL;
  process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-secret-change-only-if-needed-32chars';
  process.env.CHILD_CODE_PEPPER =
    process.env.CHILD_CODE_PEPPER || 'test-child-code-pepper-change-only-if-needed-32chars';
  process.env.CHILD_JWT_EXPIRES_IN = process.env.CHILD_JWT_EXPIRES_IN || '24h';
  process.env.NODE_ENV = process.env.NODE_ENV || 'test';
  process.env.BCRYPT_ROUNDS = process.env.BCRYPT_ROUNDS || '4';
  process.env.ALLOW_DEBUG_RESET_TOKEN = 'true';
  process.env.ALLOW_PUBLIC_REGISTRATION = 'true';
};

const waitForPort = (host, port, timeoutMs = 15000) =>
  new Promise((resolve, reject) => {
    const started = Date.now();
    const tryConnect = () => {
      const socket = net.createConnection({ host, port });
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() - started > timeoutMs) {
          reject(new Error(`Timed out waiting for ${host}:${port}`));
          return;
        }
        setTimeout(tryConnect, 300);
      });
    };
    tryConnect();
  });

const waitForHealthyServer = async (baseUrl, timeoutMs = 15000) => {
  const startedAt = Date.now();
  let lastError = null;
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      const health = await response.json();
      if (response.ok && health?.db === 'ok') return;
      lastError = new Error(`health=${response.status}, db=${health?.db || 'unknown'}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Test smoke server did not become healthy: ${lastError?.message || 'unknown error'}`);
};

const isPortOpen = (host, port) =>
  new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setTimeout(700);
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.once('error', () => {
      socket.destroy();
      resolve(false);
    });
  });

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: process.platform === 'win32',
    env: process.env,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
  }
};

const runSshScript = (script) => {
  const result = spawnSync('ssh', [SSH_HOST, `pct exec ${POSTGRES_CT} -- bash -s`], {
    stdio: ['pipe', 'inherit', 'inherit'],
    input: script,
    encoding: 'utf8',
    shell: false,
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(`ssh ${SSH_HOST} pct exec ${POSTGRES_CT} failed with status ${result.status}`);
  }
};

const runSmokeTest = async () => {
  const port = Number(process.env.FAMILYQUEST_SMOKE_PORT || 3011);
  const baseUrl = `http://127.0.0.1:${port}`;
  const smokeEnv = {
    ...process.env,
    PORT: String(port),
    NODE_ENV: 'test',
    BCRYPT_ROUNDS: '4',
    CORS_ORIGINS: baseUrl,
    ALLOW_PUBLIC_REGISTRATION: 'true',
    ALLOW_DEBUG_RESET_TOKEN: 'true',
    SMOKE_BASE_URL: baseUrl,
  };
  const server = spawn(process.execPath, ['server.js'], {
    stdio: 'inherit',
    shell: false,
    env: smokeEnv,
  });

  try {
    await waitForHealthyServer(baseUrl);
    run('node', ['scripts/smoke-e2e.js'], { env: smokeEnv });
  } finally {
    server.kill();
  }
};

const ensureProxmoxFirewallRule = () => {
  const rule = `IN ACCEPT -source ${PROXMOX_HOST_IP}/32 -p tcp -dport 5432 # Allow PostgreSQL from Proxmox host for FamilyQuest tests`;
  const script = `
set -euo pipefail
FW_FILE="/etc/pve/firewall/${POSTGRES_CT}.fw"
RULE="${rule}"
touch "$FW_FILE"
if ! grep -qxF "$RULE" "$FW_FILE"; then
  printf "\\n%s\\n" "$RULE" >> "$FW_FILE"
  pve-firewall compile >/dev/null
  pve-firewall restart >/dev/null
fi
`;
  const result = spawnSync('ssh', [SSH_HOST, 'bash -s'], {
    stdio: ['pipe', 'inherit', 'inherit'],
    input: script,
    encoding: 'utf8',
    shell: false,
    env: process.env,
  });
  if (result.status !== 0) {
    throw new Error(`ssh ${SSH_HOST} firewall setup failed with status ${result.status}`);
  }
};

const assertSafeTestDatabase = () => {
  const url = new URL(process.env.DATABASE_URL);
  const database = url.pathname.replace(/^\//, '');
  if (database !== DB_NAME) {
    throw new Error(`Refusing to reset non-test database: ${database}`);
  }
  if (!['127.0.0.1', 'localhost'].includes(url.hostname)) {
    throw new Error(`Refusing to run test reset through non-local host: ${url.hostname}`);
  }
};

const resetRemoteTestDatabase = () => {
  const remoteScript = `
set -euo pipefail
export LC_ALL=C
export LANG=C
PG_HBA=$(ls /etc/postgresql/*/main/pg_hba.conf | head -1)
sed -i '/^host$/d' "$PG_HBA"
ALLOW_LINE="host    ${DB_NAME}    ${DB_USER}    ${PROXMOX_HOST_IP}/32    scram-sha-256"
if ! grep -qxF "$ALLOW_LINE" "$PG_HBA"; then
  printf "\\n# FamilyQuest local integration tests via SSH tunnel\\n%s\\n" "$ALLOW_LINE" >> "$PG_HBA"
fi
runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DB_USER}') THEN
    CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
  ELSE
    ALTER ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
  END IF;
END
$$;
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = '${DB_NAME}' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS ${DB_NAME};
CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d ${DB_NAME} <<'SQL'
ALTER SCHEMA public OWNER TO ${DB_USER};
GRANT ALL ON SCHEMA public TO ${DB_USER};
SQL
pg_ctlcluster ${POSTGRES_VERSION} main reload
`;
  runSshScript(remoteScript);
};

(async () => {
  loadEnvFile();
  assertSafeTestDatabase();
  ensureProxmoxFirewallRule();
  resetRemoteTestDatabase();

  let tunnel = null;
  if (!(await isPortOpen(LOCAL_HOST, LOCAL_PORT))) {
    tunnel = spawn('ssh', ['-N', '-L', `${LOCAL_PORT}:${POSTGRES_TARGET}`, SSH_HOST], {
      stdio: ['ignore', 'inherit', 'inherit'],
      shell: false,
    });
    tunnel.once('exit', (code) => {
      if (code !== null && code !== 0) {
        console.error(`SSH tunnel exited with status ${code}`);
      }
    });
    await waitForPort(LOCAL_HOST, LOCAL_PORT);
  }

  try {
    run('npx', ['prisma', 'db', 'push', '--skip-generate']);
    run('npx', ['jest', '--coverage', '--runInBand']);
    await runSmokeTest();
  } finally {
    if (tunnel) {
      tunnel.kill();
    }
  }
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
