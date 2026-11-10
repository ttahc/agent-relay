#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
image=${1:?Pass the verified candidate image}
upgrade=${2:?Pass the upgrade identifier}
wired=${3:?Pass the current Ethernet IPv4 address}
easy=${4:?Pass the current EasyTier IPv4 address}
python3 -c 'import ipaddress,re,sys; assert re.fullmatch(r"[a-z0-9][a-z0-9-]{0,40}",sys.argv[1]); [ipaddress.IPv4Address(x) for x in sys.argv[2:]]' "$upgrade" "$wired" "$easy"

prior=t22-task-pool-local
name=intranet-task-pool-local
backup_name="$name-before-$upgrade"
volume="intranet-task-pool-$upgrade"
old=$(podman inspect --format '{{.Image}}' "$prior")
old_volume=$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/app/.state"}}{{.Name}}{{end}}{{end}}' "$prior")
candidate=$(podman image inspect --format '{{.Id}}' "$image")
[ "$(podman inspect --format '{{index .Config.Labels "project"}} {{.State.Status}}' "$prior")" = 't22-task-pool running' ]
[ -n "$old_volume" ]
[ "$old" != "$candidate" ]
! podman container exists "$backup_name"
! podman container exists "$name"
! podman volume exists "$volume"
umask 077
backup=$(mktemp -d "/var/tmp/taskpool-$upgrade.XXXXXXXX")
printf 'Backup directory: %s\n' "$backup"
report=dist/upgrade-deployment.json
mkdir -p dist
public=dist/taskpool-lan-cert.pem

one_shot() {
    podman run --rm --pull=never --network none --read-only --cap-drop all --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m -v "$volume:/app/.state:U" "$@"
}

trap 'printf "%s\n" "Interrupted. Inspect the stopped original container and candidate state before continuing." >&2; exit 1' HUP INT TERM
podman stop --time 30 "$prior"
renamed=no
exposed=no
recover() {
    code=$?
    if [ "$code" -eq 0 ] || [ "$exposed" = yes ]; then return; fi
    if [ "$renamed" = yes ]; then
        if podman container exists "$name"; then
            podman stop --time 15 "$name" >/dev/null 2>&1 || true
            podman rm "$name" >/dev/null
        fi
        podman rename "$backup_name" "$prior"
    fi
    podman start "$prior" >/dev/null
    printf '%s\n' 'Original container restarted on its original data volume.' >&2
}
trap recover EXIT

podman volume export "$old_volume" --output "$backup/pre-upgrade.tar"
sha256sum "$backup/pre-upgrade.tar" > "$backup/archive.sha256"
archive_manifest() {
    python3 - "$1" <<'PY'
import hashlib,json,sys,tarfile
def path(raw):
    name = raw.removeprefix("./")
    if name.startswith("/") or ".." in name.split("/"):
        raise ValueError("archive member outside data volume")
    return name

with tarfile.open(sys.argv[1],"r:*") as archive:
    members = {}
    for item in archive:
        name = path(item.name)
        if item.isdir():
            continue
        if not (item.isfile() or item.islnk()):
            raise ValueError("unexpected data-volume member")
        if name in members:
            raise ValueError("duplicate file")
        members[name] = item
    groups = {}
    files = {}
    for name, item in members.items():
        target = name
        followed = set()
        while members[target].islnk():
            if target in followed:
                raise ValueError("hardlink cycle")
            followed.add(target)
            target = path(members[target].linkname)
        original = members[target]
        with archive.extractfile(original) as stream:
            files[name] = {"sha256":hashlib.file_digest(stream,"sha256").hexdigest(),
                           "size":original.size,"uid":item.uid,"gid":item.gid,"mode":item.mode}
        groups.setdefault(target, []).append(name)
    for group in groups.values():
        if len(group) > 1:
            for name in group:
                files[name]["hardlinks"] = sorted(group)
    print(json.dumps(files,sort_keys=True))
PY
}
archive_manifest "$backup/pre-upgrade.tar" > "$backup/files.json"
podman volume create --label project=intranet-task-pool --label upgrade="$upgrade" "$volume"
podman volume import "$volume" "$backup/pre-upgrade.tar"
podman volume export "$volume" --output "$backup/restored.tar"
archive_manifest "$backup/restored.tar" > "$backup/restored-files.json"
cmp "$backup/files.json" "$backup/restored-files.json"
one_shot "$image" inspect-store > "$backup/before.json"
python3 - "$backup/before.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
t=next(t for t in d["tasks"] if t["id"]=="T02")
assert t["status"]=="available" and not any(c["task_id"]=="T02" for c in d["active_claims"]), "T02 requires actual stop"
PY
one_shot "$image" upgrade-migrate --task T02 --upgrade "$upgrade" --image "$candidate" > "$backup/migration.json"
one_shot "$image" inspect-store > "$backup/after.json"
podman run --rm --pull=never --network none --read-only --cap-drop all --security-opt no-new-privileges \
    -v "$volume:/app/.state:ro" --entrypoint python "$old" -B -c \
    'import sys;sys.path.insert(0,"/app/vendor/ledger");from 协作账本 import Ledger;s=Ledger("/app/.state/local").read();assert s["halted"],"old image replayed the new contract"'
one_shot -e "TASKPOOL_WIRED=$wired" -e "TASKPOOL_EASY=$easy" --entrypoint /bin/sh "$image" -ceu '
    tls=/app/.state/tls
    umask 077
    openssl req -x509 -new -key "$tls/key.pem" -days 90 -subj "/CN=taskpool.test" \
        -addext "subjectAltName=DNS:taskpool.test,DNS:t22-taskpool.test,IP:$TASKPOOL_WIRED,IP:$TASKPOOL_EASY" \
        -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
        -out "$tls/cert-v2.pem"
    openssl x509 -in "$tls/cert-v2.pem" -noout -checkip "$TASKPOOL_WIRED" | grep -q "does match certificate"
    openssl x509 -in "$tls/cert-v2.pem" -noout -checkip "$TASKPOOL_EASY" | grep -q "does match certificate"
    openssl x509 -in "$tls/cert-v2.pem" -noout -checkhost taskpool.test | grep -q "does match certificate"
    cat "$tls/cert-v2.pem"
' > "$public.pending"
one_shot "$image" maintenance off --request-id "activate-$upgrade" > "$backup/maintenance-off.json"
podman rename "$prior" "$backup_name"
renamed=yes
exposed=yes
podman run -d --pull=never --name "$name" --label project=intranet-task-pool --label upgrade="$upgrade" \
    --restart unless-stopped --read-only --cap-drop all --security-opt no-new-privileges --pids-limit 96 \
    -p 127.0.0.1:18765:18443 -v "$volume:/app/.state:U" "$image" serve --port 18443 --lan-name taskpool.test --lan-alias t22-taskpool.test \
    --tls-cert /app/.state/tls/cert-v2.pem --tls-key /app/.state/tls/key.pem
# From this point the new volume can accept requests. Keep both volumes for an explicit rollback decision.
mv "$public.pending" "$public"
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl --noproxy '*' --silent --fail --max-time 3 --cacert "$public" \
        --connect-to taskpool.test:18443:127.0.0.1:18765 https://taskpool.test:18443/healthz; then
        break
    fi
    [ "$attempt" -lt 10 ] || exit 1
    sleep 1
done
python3 - "$report" "$backup" "$candidate" "$old" "$old_volume" "$volume" "$backup_name" "$wired" "$easy" "$public" <<'PY'
import hashlib,json,sys
from pathlib import Path
out,backup,image,prior,old_volume,volume,old_container,wired,easy,cert=sys.argv[1:]
backup=Path(backup)
before=json.loads((backup/"before.json").read_bytes())
after=json.loads((backup/"after.json").read_bytes())
files=json.loads((backup/"files.json").read_bytes())
assert before["repo_id"]==after["repo_id"]
assert {t["id"]:t["inputs"] for t in before["tasks"]}=={t["id"]:t["inputs"] for t in after["tasks"]}
assert after["format"]["schema"]==2 and next(t for t in after["tasks"] if t["id"]=="T02")["contract"]["open"] is False
value={"image":image,"prior_image":prior,"old_volume":old_volume,"volume":volume,"retained_container":old_container,
       "private_backup_directory":str(backup),"backup_sha256":(backup/"archive.sha256").read_text().split()[0],
       "restored_files_match":True,"restored_file_count":len(files),
       "hardlink_groups":len({tuple(item["hardlinks"]) for item in files.values() if "hardlinks" in item}),
       "old_reader_halted":True,"before":before,"migration":after,
       "wired":wired,"easytier":easy,"certificate_sha256":hashlib.sha256(Path(cert).read_bytes()).hexdigest()}
temp=Path(out+".pending")
temp.write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding="utf-8")
temp.replace(out)
PY
printf 'Upgraded container: %s\nRestored volume: %s\n' "$name" "$volume"
