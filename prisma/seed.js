require('dotenv').config();

const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

async function main() {
  if (process.env.AUTO_SEED !== 'true') {
    console.log('Seed skipped (set AUTO_SEED=true to enable).');
    return;
  }

  const email = (process.env.SEED_PARENT_EMAIL || 'rodzic@example.com').toLowerCase();
  const password = process.env.SEED_PARENT_PASSWORD || 'CHANGEME_BEFORE_USE';
  const pinCode = process.env.SEED_PARENT_PIN || '1234';

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    console.log(`Seed user already exists: ${email}`);
    return;
  }

  const passwordHash = await bcrypt.hash(password, Number(process.env.BCRYPT_ROUNDS || 12));

  await prisma.$transaction(async (tx) => {
    const family = await tx.family.create({
      data: { name: process.env.SEED_FAMILY_NAME || 'Moja Rodzina' },
    });

    await tx.user.create({
      data: {
        email,
        passwordHash,
        pinCode,
        familyId: family.id,
      },
    });

    await tx.familyState.create({
      data: {
        familyId: family.id,
        data: {
          children: [],
          tasks: [],
          completions: [],
          rewards: [],
          streaks: {},
          points: {},
        },
      },
    });
  });

  console.log(`Seed complete. Parent account created: ${email}`);
}

main()
  .catch((error) => {
    console.error('Seed failed:', error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
