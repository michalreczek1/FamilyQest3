"""Prune only recognized FamilyQuest backups. Default is a dry run."""
import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import subprocess


def expired(names, prefix, fmt, keep, cutoff=None):
    dated = []
    for name in names:
        if not name.startswith(prefix):
            continue
        try:
            date = datetime.strptime(name[len(prefix):], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if prefix + date.strftime(fmt) == name:
            dated.append((date, name))
    dated.sort(reverse=True)
    return [name for date, name in dated[keep:] if cutoff is None or date < cutoff]


def prune_files(root, deploy_success=False, apply=False, now=None):
    if root.is_symlink():
        raise ValueError('Backup root must not be a symlink')
    root = root.resolve(strict=True)
    names = [p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink()]
    remove = []
    if deploy_success:
        remove += expired(names, 'local-before-deploy-', '%Y%m%d-%H%M%S', 3)
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=14)
    for prefix in ('reconcile-reward-unlocks-', 'point-forensics-', 'recompute-family-state-'):
        remove += expired(names, prefix, '%Y%m%d%H%M%S', 1, cutoff)
    for name in remove:
        target = root / name
        if target.is_symlink() or target.resolve().parent != root:
            raise ValueError('Unsafe backup path')
        print(('DELETE ' if apply else 'WOULD DELETE ') + str(target))
        if apply:
            shutil.rmtree(target)
    return remove


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/opt/familyquest/.deploy-backups'))
    parser.add_argument('--deploy-success', action='store_true')
    parser.add_argument('--snapshots', type=int, metavar='CTID')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.snapshots:
        if not args.deploy_success:
            parser.error('Snapshot pruning requires --deploy-success')
        rows = json.loads(subprocess.check_output(['pvesh', 'get', f'/nodes/localhost/lxc/{args.snapshots}/snapshot', '--output-format', 'json']))
        for name in expired([r['name'] for r in rows], 'pre-familyquest-', '%Y%m%d-%H%M%S', 2):
            print(('DELETE snapshot ' if args.apply else 'WOULD DELETE snapshot ') + name)
            if args.apply:
                subprocess.run(['pct', 'delsnapshot', str(args.snapshots), name], check=True)
    else:
        prune_files(args.root, args.deploy_success, args.apply)


if __name__ == '__main__':
    main()
