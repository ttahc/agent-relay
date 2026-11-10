#!/bin/sh
# Rehearse or switch a v2 task pool on the existing WSL Podman host.
set -eu

mode=${1:?rehearse or switch}
image=${2:?verified local candidate image ID}
tag=${3:?unique local upgrade ID}
case "$mode" in rehearse|switch) ;; *) exit 2;; esac
python3 -c 'import re,sys; assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,35}",sys.argv[1]); assert re.fullmatch(r"(?:sha256:)?[a-f0-9]{64}",sys.argv[2])' "$tag" "$image"

name=intranet-task-pool-local
retained="$name-before-$tag"
candidate="$name-$tag"
volume="intranet-task-pool-$tag"
old=$(podman inspect --format '{{.Image}}' "$name")
old_volume=$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/app/.state"}}{{.Name}}{{end}}{{end}}' "$name")
id=$(podman image inspect --format '{{.Id}}' "$image")
[ "$(podman inspect --format '{{index .Config.Labels "project"}} {{.State.Status}}' "$name")" = 'intranet-task-pool running' ]
[ -n "$old_volume" ] && [ "$old" != "$id" ]
! podman container exists "$retained"
! podman container exists "$candidate"
! podman volume exists "$volume"
umask 077
backup=$(mktemp -d "/var/tmp/taskpool-$tag.XXXXXXXX")
printf 'Private backup directory: %s\n' "$backup"

stopped=no
renamed=no
live=no
recover() {
    code=$?
    if [ "$code" -eq 0 ] || [ "$stopped" = no ] || [ "$live" = yes ]; then
        return
    fi
    if [ "$renamed" = yes ]; then
        if podman container exists "$name"; then
            podman stop --time 20 "$name" >/dev/null 2>&1 || true
            podman rename "$name" "$candidate"
        fi
        podman rename "$retained" "$name"
    fi
    podman start "$name" >/dev/null
    printf '%s\n' 'Restored original container and its original volume.' >&2
}
trap recover EXIT
trap 'exit 1' HUP INT TERM

podman stop --time 30 "$name" >/dev/null
stopped=yes
podman volume export "$old_volume" --output "$backup/source.tar"
sha256sum "$backup/source.tar" > "$backup/archive.sha256"
if [ "$mode" = rehearse ]; then
    podman start "$name" >/dev/null
    stopped=no
fi

archive_manifest() {
    python3 - "$1" <<'PY'
import hashlib, json, sys, tarfile

def path(raw):
    name = raw.removeprefix("./").rstrip("/")
    if name.startswith("/") or ".." in name.split("/"):
        raise ValueError("volume member escapes archive")
    return name or "."

with tarfile.open(sys.argv[1], "r:*") as archive:
    files, directories, groups = {}, {}, {}
    members = {}
    for item in archive:
        name = path(item.name)
        if item.isdir():
            directories[name] = [item.uid, item.gid, item.mode]
            continue
        if not (item.isfile() or item.islnk()) or name in members:
            raise ValueError("invalid volume member")
        members[name] = item
    for name, item in members.items():
        target, seen = name, set()
        while members[target].islnk():
            if target in seen:
                raise ValueError("hardlink cycle")
            seen.add(target)
            target = path(members[target].linkname)
        original = members[target]
        with archive.extractfile(original) as data:
            files[name] = [original.uid, original.gid, original.mode, original.size,
                           hashlib.file_digest(data, "sha256").hexdigest()]
        groups.setdefault(target, []).append(name)
    print(json.dumps({"files": files, "directories": directories,
                      "links": sorted(sorted(g) for g in groups.values() if len(g) > 1)}, sort_keys=True))
PY
}
archive_manifest "$backup/source.tar" > "$backup/source.json"
podman volume create --label project=intranet-task-pool --label upgrade="$tag" "$volume" >/dev/null
podman volume import "$volume" "$backup/source.tar"
podman volume export "$volume" --output "$backup/restore.tar"
archive_manifest "$backup/restore.tar" > "$backup/restore.json"
cmp "$backup/source.json" "$backup/restore.json"

offline() {
    podman run --rm --pull=never --network none --read-only --cap-drop all --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m -v "$volume:/app/.state" "$id" "$@"
}
offline inspect-store > "$backup/before.json"
python3 - "$backup/before.json" <<'PY'
import json, sys
snapshot = json.load(open(sys.argv[1], encoding="utf-8"))
assert snapshot["format"]["schema"] == 2 and not snapshot["active_claims"], "active work needs verified disposition"
task = next(t for t in snapshot["tasks"] if t["id"] == "T02")
assert task["status"] == "available" and task["contract"]["open"] is False, "T02 is not in agreed waiting state"
PY
offline round-migrate --upgrade "$tag" --image "$id" > "$backup/migrate.json"
offline inspect-store > "$backup/after.json"
python3 - "$backup/before.json" "$backup/after.json" <<'PY'
import json, sys
before, after = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:])
assert before["repo_id"] == after["repo_id"] and before["tasks"] == after["tasks"]
assert before["window_high_water"] == after["window_high_water"] and not after["active_claims"]
assert after["format"]["schema"] == 3 and after["format"]["maintenance"]
PY
podman run --rm --pull=never --network none --read-only --cap-drop all -v "$volume:/app/.state:ro" \
    --entrypoint python "$old" -B -c 'import sys; sys.path.insert(0,"/app/vendor/ledger"); from 协作账本 import Ledger; assert Ledger("/app/.state/local").read()["halted"], "old image read the new contract"'
podman run --rm --pull=never --network none --read-only --cap-drop all -v "$volume:/app/.state:ro" \
    --entrypoint cat "$id" /app/.state/tls/cert-v2.pem > "$backup/public.pem"

if [ "$mode" = switch ]; then
    podman rename "$name" "$retained"
    renamed=yes
    podman run -d --pull=never --name "$name" --label project=intranet-task-pool --label upgrade="$tag" \
        --restart unless-stopped --read-only --cap-drop all --security-opt no-new-privileges --pids-limit 96 \
        -p 127.0.0.1:18765:18443 -v "$volume:/app/.state" "$id" serve --port 18443 --lan-name taskpool.test \
        --lan-alias t22-taskpool.test --tls-cert /app/.state/tls/cert-v2.pem --tls-key /app/.state/tls/key.pem >/dev/null
    health() {
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if curl --noproxy '*' --silent --fail --max-time 3 --cacert "$backup/public.pem" \
                --connect-to taskpool.test:18443:127.0.0.1:18765 https://taskpool.test:18443/healthz; then
                return
            fi
            sleep 1
        done
        return 1
    }
    health
    podman stop --time 30 "$name" >/dev/null
    offline maintenance off --request-id "enable-$tag" > "$backup/maintenance-off.json"
    # After this start, an external request can write to the new volume.
    live=yes
    podman start "$name" >/dev/null
    health
fi

python3 - "$backup" "$old" "$id" "$old_volume" "$volume" "$mode" "$tag" <<'PY'
from pathlib import Path
import hashlib, json, sys
base, prior, image, old_volume, volume, mode, tag = sys.argv[1:]
base = Path(base)
old = json.loads((base / "before.json").read_bytes())
new = json.loads((base / "after.json").read_bytes())
restore = json.loads((base / "restore.json").read_bytes())
print(json.dumps({"mode": mode, "upgrade": tag, "prior_image": prior, "image": image,
                  "prior_volume": old_volume, "volume": volume, "private_backup": str(base),
                  "backup_sha256": (base / "archive.sha256").read_text().split()[0],
                  "files": len(restore["files"]), "hardlink_groups": len(restore["links"]),
                  "certificate_file_sha256": hashlib.sha256((base / "public.pem").read_bytes()).hexdigest(),
                  "old_reader_halted": True, "tasks_preserved": len(old["tasks"]),
                  "window_high_water": new["window_high_water"], "schema": new["format"]["schema"],
                  "old_head": old["head"], "migration_head": new["head"]}, ensure_ascii=False))
PY
