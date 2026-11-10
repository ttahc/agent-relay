#!/bin/sh
# Compatible-code switch only. Build and isolated verification must finish first.
# No machine restart, forced task termination, or automatic data restore.
set -eu
umask 077
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
private() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else podman unshare "$@"; fi
}

image=${1:?prebuilt verified image ID}
tag=${2:?unique upgrade tag}
archive=${3:?absolute private backup directory}
verification=${4:?JSON receipt with image ID and verified=true}
legacy=${5:-}
case "$legacy" in ''|--legacy-v020) ;; *) exit 2;; esac
python3 - "$image" "$tag" "$archive" "$verification" <<'PY'
import json, pathlib, re, sys
image, tag, archive, verification = sys.argv[1:]
assert re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', image), 'exact local image ID required'
assert re.fullmatch(r'[a-z0-9][a-z0-9-]{0,35}', tag), 'invalid upgrade tag'
assert pathlib.Path(archive).is_absolute(), 'absolute private backup directory required'
receipt = json.loads(pathlib.Path(verification).read_text(encoding='utf-8'))
assert receipt.get('verified') is True and receipt.get('image', '').removeprefix('sha256:') == image.removeprefix('sha256:'), 'candidate verification receipt mismatch'
PY

name=intranet-task-pool-local
retained="$name-before-$tag"
candidate="$name-$tag"
[ "$(podman inspect --format '{{index .Config.Labels "project"}} {{.State.Status}}' "$name")" = 'intranet-task-pool running' ]
! podman container exists "$retained"
! podman container exists "$candidate"
volume=$(podman inspect --format '{{range .Mounts}}{{if eq .Destination "/app/.state"}}{{.Name}}{{end}}{{end}}' "$name")
[ -n "$volume" ]
id=$(podman image inspect --format '{{.Id}}' "$image")
[ "$id" != "$(podman inspect --format '{{.Image}}' "$name")" ]
mkdir -p "$archive"
[ "$(stat -c %a "$archive")" = 700 ]
# Give only the service UID in Podman's user namespace access to the private archive.
# Read/export it later through podman unshare; do not broaden filesystem permissions.
private chown 10001:10001 "$archive"
launch_config="$archive/$tag.launch.json"
launch_sha=$(podman inspect "$name" | private python3 "$script_dir/launch-config.py" freeze \
    --config "$launch_config" --image "$id" --name "$name" --archive "$archive" --tag "$tag")
printf 'Private launch configuration fixed; digest=%s\n' "$launch_sha"

backup() {
    podman run --rm --pull=never --network none --read-only --cap-drop all --security-opt no-new-privileges \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m -v "$volume:/app/.state" -v "$archive:/backup" \
        --entrypoint python "$id" -B /app/ops/backup-store.py --store /app/.state/local --archive /backup --tag "$tag" "$@"
}
# Seed immutable material while the old application still serves requests.
backup --seed
if [ "$legacy" = --legacy-v020 ]; then
    printf '%s\n' 'Initial v0.2.0 upgrade: brief outage and browser sign-in required; old in-memory sessions cannot be recovered.' >&2
    # -1 disables Podman escalation to SIGKILL. Only this one container is stopped.
    podman stop --time=-1 "$name" >/dev/null
else
    podman exec "$name" python -B /app/taskpool.py upgrade-control drain
    if ! podman exec "$name" python -B /app/taskpool.py upgrade-control freeze --timeout 30; then
        podman exec "$name" python -B /app/taskpool.py upgrade-control cancel || true
        printf '%s\n' 'Drain did not finish; upgrade cancelled and original container retained.' >&2
        exit 1
    fi
    # Explicit container stop suppresses its restart policy; app-only exit can auto-restart.
    # A frozen app has no admitted requests, and -1 forbids timeout escalation to SIGKILL.
    podman stop --time=-1 "$name" >/dev/null
    for attempt in $(seq 1 40); do
        [ "$(podman inspect --format '{{.State.Running}}' "$name")" = false ] && break
        sleep 1
    done
    [ "$(podman inspect --format '{{.State.Running}}' "$name")" = false ] || {
        printf '%s\n' 'Writer has not exited; no new writer started.' >&2
        exit 1
    }
fi

# Acquires both exclusive locks and uses SQLite backup API, including durable sessions.
if ! backup; then
    podman start "$name" >/dev/null
    printf '%s\n' 'Snapshot failed; original container restarted without restoring or modifying task state.' >&2
    exit 1
fi
if [ "$legacy" = --legacy-v020 ]; then
    if ! private python3 "$script_dir/verify-backup.py" --archive "$archive" --tag "$tag" \
        --allow-legacy-config "$launch_config" --launch-config-sha256 "$launch_sha"; then
        podman start "$name" >/dev/null
        exit 1
    fi
else
    if ! private python3 "$script_dir/verify-backup.py" --archive "$archive" --tag "$tag"; then
        podman start "$name" >/dev/null
        exit 1
    fi
fi
# From this command's first attempt, security 4 may have committed. Never start
# the old reader or restore the old snapshot after this boundary, even on error.
if ! podman run --rm --pull=never --network none --read-only --cap-drop all --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m -v "$volume:/app/.state" "$id" \
    security-migrate --target 5 --request-id "migrate-$tag"; then
    printf '%s\n' 'Migration needs compatible recovery. Current volume retained; original image will not be restarted.' >&2
    exit 1
fi
podman rename "$name" "$retained"
# From this launch onward, new writes may exist. Never restore the old snapshot automatically.
if ! private cat "$launch_config" | python3 "$script_dir/launch-config.py" launch --config - \
    --image "$id" --name "$name" --archive "$archive" --tag "$tag"; then
    printf '%s\n' 'Candidate launch failed. Current volume and original container preserved; inspect before any rollback. No backup was restored.' >&2
    exit 1
fi
printf '%s\n' "Candidate launched on original volume: $name. Retained container: $retained. Private snapshot tag: $tag."
printf '%s\n' 'Check authenticated readiness, pending receipts and the original claim/epoch/occupancy before acceptance. Never run retained and candidate together.'
