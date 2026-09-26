import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('retention', Path(__file__).with_name('backup-retention.py'))
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


class RetentionTest(unittest.TestCase):
    def test_policy_and_dry_run(self):
        with tempfile.TemporaryDirectory(prefix='familyquest-retention-') as directory:
            root = Path(directory)
            names = [f'local-before-deploy-2026090{i}-120000' for i in range(1, 6)]
            names += ['reconcile-reward-unlocks-20260901000000', 'reconcile-reward-unlocks-20260902000000',
                      'point-forensics-20260901000000', 'recompute-family-state-20260925000000',
                      'local-before-deploy-invalid', 'unrelated']
            for name in names:
                (root / name).mkdir()
            now = datetime(2026, 9, 26, tzinfo=timezone.utc)
            planned = retention.prune_files(root, True, False, now)
            self.assertEqual(len(planned), 3)
            self.assertEqual(len(list(root.iterdir())), len(names))
            retention.prune_files(root, False, True, now)
            self.assertTrue((root / names[0]).exists(), 'Daily cleanup must preserve deploy backups')
            self.assertTrue((root / 'reconcile-reward-unlocks-20260902000000').exists())
            self.assertTrue((root / 'point-forensics-20260901000000').exists(), 'Always keep latest per repair kind')
            retention.prune_files(root, True, True, now)
            self.assertFalse((root / names[0]).exists())
            self.assertTrue((root / 'unrelated').exists())
            self.assertEqual(retention.prune_files(root, True, False, now), [])

    def test_snapshot_names(self):
        names = [f'pre-familyquest-2026090{i}-120000' for i in range(1, 5)]
        self.assertEqual(retention.expired(names + ['current', 'manual-backup'], 'pre-familyquest-', '%Y%m%d-%H%M%S', 2), names[1::-1])


if __name__ == '__main__':
    unittest.main()
