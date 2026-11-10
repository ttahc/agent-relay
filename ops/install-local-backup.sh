#!/bin/sh
# Install only this application's fixed-container local backup helper and units.
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[ "$#" -eq 0 ] || { printf '%s\n' 'This installer accepts no arguments.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Run the local backup installer as WSL root.' >&2; exit 1; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
archive=/var/lib/taskpool-backups
for name in local-backup.sh verify-backup.py taskpool-local-backup.service taskpool-local-backup.timer; do
    [ -f "$source_dir/$name" ] && [ ! -L "$source_dir/$name" ] || {
        printf '%s\n' 'A required installer source is missing or is a symlink.' >&2
        exit 1
    }
done
[ -d "$archive" ] && [ ! -L "$archive" ] && [ "$(stat -c '%a:%u:%g' "$archive")" = '700:10001:10001' ] || {
    printf '%s\n' 'Create the private backup root with mode 700 and owner 10001:10001 first.' >&2
    exit 1
}
podman inspect --format '{{json .Mounts}}' intranet-task-pool-local | python3 -c '
import json, pathlib, sys
try:
    root = pathlib.Path(sys.argv[1])
    if any(part.is_symlink() for part in (root, *root.parents)):
        raise ValueError()
    mounts = [row for row in json.load(sys.stdin) if row.get("Destination") == "/backup"]
    if len(mounts) != 1:
        raise ValueError()
    row = mounts[0]
    if row.get("Type") != "bind" or row.get("RW") is not True or pathlib.Path(row.get("Source", "")).resolve() != root.resolve():
        raise ValueError()
except Exception:
    print("The fixed service container must bind the private root read/write at /backup.", file=sys.stderr)
    sys.exit(1)
' "$archive"
systemd-analyze calendar '*-*-* 03:30:00 Asia/Hong_Kong' >/dev/null
sh -n "$source_dir/local-backup.sh"
install -d -m 0755 /usr/local/libexec
install -m 0755 "$source_dir/local-backup.sh" /usr/local/libexec/taskpool-local-backup.sh
install -m 0644 "$source_dir/verify-backup.py" /usr/local/libexec/verify-backup.py
install -m 0644 "$source_dir/taskpool-local-backup.service" /etc/systemd/system/taskpool-local-backup.service
install -m 0644 "$source_dir/taskpool-local-backup.timer" /etc/systemd/system/taskpool-local-backup.timer
systemctl daemon-reload
systemctl enable --now taskpool-local-backup.timer
printf '%s\n' 'Installed taskpool-local-backup.timer: daily 03:30 Asia/Hong_Kong; snapshots are retained until a separate retention policy is configured.'
