const { spawnSync } = require('child_process');

const SSH_HOST = process.env.FAMILYQUEST_TEST_SSH_HOST || 'proxmox';
const POSTGRES_CT = process.env.FAMILYQUEST_TEST_POSTGRES_CT || '102';
const POSTGRES_VERSION = process.env.FAMILYQUEST_TEST_POSTGRES_VERSION || '17';
const PROXMOX_HOST_IP = process.env.FAMILYQUEST_TEST_PROXMOX_HOST_IP || '192.168.33.100';

const DB_NAME = 'familyquest_test';
const DB_USER = 'familyquest_test';
const DB_PASSWORD = 'familyquest_test_password';

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: false,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with status ${result.status}`);
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
  run('ssh', [SSH_HOST, 'bash -s'], {
    stdio: ['pipe', 'inherit', 'inherit'],
    input: script,
    encoding: 'utf8',
  });
};

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
SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}')\\gexec
ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
SQL
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d ${DB_NAME} <<'SQL'
ALTER SCHEMA public OWNER TO ${DB_USER};
GRANT ALL ON SCHEMA public TO ${DB_USER};
SQL
pg_ctlcluster ${POSTGRES_VERSION} main reload
runuser -u postgres -- psql -Atc "SELECT datname || ':' || pg_catalog.pg_get_userbyid(datdba) FROM pg_database WHERE datname = '${DB_NAME}';"
`;

ensureProxmoxFirewallRule();

run('ssh', [SSH_HOST, `pct exec ${POSTGRES_CT} -- bash -s`], {
  stdio: ['pipe', 'inherit', 'inherit'],
  input: remoteScript,
  encoding: 'utf8',
});

console.log('FamilyQuest test database ready: familyquest_test on CT 102');
console.log('Next: npm run test:api');
