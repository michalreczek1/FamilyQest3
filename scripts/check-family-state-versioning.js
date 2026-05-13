const assert = require('assert');
const { __test, prisma } = require('../server');

const createFakeFamilyStateClient = () => {
  const records = new Map([
    [
      'state-1',
      {
        id: 'state-1',
        familyId: 'family-1',
        version: 7,
        data: { children: [] },
      },
    ],
  ]);

  return {
    async update({ where, data }) {
      const record = records.get(where.id);
      if (!record) throw new Error('not found');
      record.data = data.data;
      record.version += Number(data.version?.increment || 0);
      return { ...record };
    },
    async updateMany({ where, data }) {
      const record = records.get(where.id);
      if (!record || record.version !== where.version) {
        return { count: 0 };
      }
      record.data = data.data;
      record.version += Number(data.version?.increment || 0);
      return { count: 1 };
    },
    async findUnique({ where }) {
      const record = records.get(where.id);
      return record ? { ...record } : null;
    },
  };
};

(async () => {
  const saveStateData = __test.createSaveStateData(createFakeFamilyStateClient());
  const loadedA = { id: 'state-1', version: 7 };
  const loadedB = { id: 'state-1', version: 7 };

  const afterA = await saveStateData(loadedA, { children: [{ id: 'a' }] });
  assert.strictEqual(afterA.version, 8, 'first write should increment version');

  let conflict = null;
  try {
    await saveStateData(loadedB, { children: [{ id: 'b' }] });
  } catch (error) {
    conflict = error;
  }
  assert(conflict, 'second stale write should throw');
  assert(__test.isFamilyStateConflict(conflict), 'stale write should be FamilyState conflict');

  const skipped = await saveStateData(loadedB, { children: [{ id: 'b' }] }, { skipOnConflict: true });
  assert.strictEqual(skipped, null, 'skipOnConflict should return null on stale version');

  await prisma.$disconnect();
  console.log('FamilyState versioning OK: stale write detected as 409-style conflict');
})().catch(async (error) => {
  console.error(error);
  await prisma.$disconnect().catch(() => {});
  process.exit(1);
});
