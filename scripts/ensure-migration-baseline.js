const { spawnSync } = require('child_process');
const { PrismaClient } = require('@prisma/client');

const BASELINE_MIGRATION = '00000000000000_baseline';

const prisma = new PrismaClient();

const getRegClass = async (name) => {
  const rows = await prisma.$queryRawUnsafe(
    `SELECT to_regclass('public."${String(name).replace(/"/g, '""')}"')::text AS name`,
  );
  return rows?.[0]?.name || null;
};

const run = async () => {
  const familyTableExists = Boolean(await getRegClass('Family'));
  const migrationsTableExists = Boolean(await getRegClass('_prisma_migrations'));
  if (!familyTableExists) {
    console.log('Existing Family table not found; baseline will be applied by prisma migrate deploy.');
    return;
  }

  if (migrationsTableExists) {
    const rows = await prisma.$queryRawUnsafe(
      'SELECT migration_name FROM "_prisma_migrations" WHERE migration_name = $1 LIMIT 1',
      BASELINE_MIGRATION,
    );
    if (rows.length > 0) {
      console.log(`Migration baseline ${BASELINE_MIGRATION} already marked as applied.`);
      return;
    }
  }

  console.log(`Marking existing schema baseline ${BASELINE_MIGRATION} as applied.`);
  const result = spawnSync('npx', ['prisma', 'migrate', 'resolve', '--applied', BASELINE_MIGRATION], {
    cwd: process.cwd(),
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.status !== 0) {
    throw new Error(`Failed to mark baseline migration as applied (exit ${result.status})`);
  }
};

run()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
