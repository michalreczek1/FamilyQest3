require('dotenv').config();

const { prisma, __test } = require('../server');

__test.bootstrapChildAccessCredentials()
  .then(() => {
    console.log('Child access credentials bootstrap complete.');
  })
  .catch((error) => {
    console.error('Child access credentials bootstrap failed:', error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
