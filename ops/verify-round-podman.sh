#!/bin/sh
set -eu
image=${1:?candidate image digest}
volume=${2:?unique QA volume}
case "$volume" in intranet-task-pool-round-qa-*) ;; *) exit 2;; esac
! podman volume exists "$volume"
host=$(pwd -P)
test -f "$host/verify_round.py"
podman volume create --label purpose=taskpool-v3-qa "$volume" >/dev/null
podman run --rm --pull=never --network none --cap-drop all --security-opt no-new-privileges --pids-limit 96 \
    -v "$volume:/tests:U" -v "$host:/source:ro" -w /tests --entrypoint /bin/sh "$image" -ceu '
mkdir -p dist
cp /app/dist/task-pool-local.zip dist/
cp /source/verify.py /source/verify_upgrade.py /source/verify_round.py .
python -B -X utf8 verify.py --report dist/round-v3-base-podman.json
python -B -X utf8 verify_upgrade.py --report dist/round-v3-v2-podman.json
python -B -X utf8 verify_round.py --report dist/round-v3-podman.json
'
for file in round-v3-base-podman.json round-v3-v2-podman.json round-v3-podman.json; do
    podman run --rm --pull=never --network none -v "$volume:/tests:ro" --entrypoint cat "$image" "/tests/dist/$file" > "dist/$file"
done
printf 'Verified ext4 fixture volume %s\n' "$volume"
