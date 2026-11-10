#!/bin/sh
# Invoked by the dedicated system timer. Never start a second Service or delete snapshots.
set -eu
umask 077
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[ "$#" -eq 0 ] || { printf '%s\n' 'This backup helper accepts no arguments.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'Run this fixed-container backup helper as root.' >&2; exit 1; }
archive=/var/lib/taskpool-backups
[ -d "$archive" ] && [ ! -L "$archive" ] && [ "$(stat -c '%a:%u:%g' "$archive")" = '700:10001:10001' ] || {
    printf '%s\n' 'Private backup directory permissions are not ready.' >&2
    exit 1
}
random=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
tag="daily-$(date -u +%Y%m%d-%H%M%S)-$$-$random"
if ! receipt=$(podman exec intranet-task-pool-local python -B /app/taskpool.py upgrade-control backup \
    --archive /backup --tag "$tag" --timeout 30 2>/dev/null); then
    printf '%s\n' 'Backup was not confirmed; check service status and the private archive. Existing snapshots were retained.' >&2
    exit 1
fi
# Keep raw receipts, private paths and content hashes out of the journal.
printf '%s' "$receipt" | python3 -c '
import json, pathlib, sys
try:
    value = json.load(sys.stdin)
    tag, archive, helper = sys.argv[1:]
    expected = "/backup/" + tag + ".json"
    if value.get("ok") is not True or value.get("status") != "backed_up" or value.get("manifest") != expected:
        raise ValueError()
    path = pathlib.Path(archive) / (tag + ".json")
    if path.is_symlink():
        raise ValueError()
    import importlib.util
    helper = pathlib.Path(helper)
    spec = importlib.util.spec_from_file_location("taskpool_backup_verifier", helper)
    verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(verifier)
    checked = verifier.verify(archive, tag)
    print("Backup succeeded: tag=" + tag + " head=" + str(checked["head"]) + " snapshot=" + checked["snapshot"]
          + " files=" + str(checked["files"]) + " tls_files=" + str(checked["service_files"]))
except Exception:
    print("Backup receipt could not be confirmed; inspect the private archive and original tag.", file=sys.stderr)
    sys.exit(1)
' "$tag" "$archive" "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/verify-backup.py"
