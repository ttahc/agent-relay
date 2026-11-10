#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
lan_ip=${1:?Pass the current IPv4 address of the Windows Ethernet adapter}
python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$lan_ip"
image=localhost/intranet-task-pool:local
name=intranet-task-pool-local
volume=intranet-task-pool-local
podman image exists "$image"

if podman container exists "$name"; then
    [ "$(podman inspect --format '{{index .Config.Labels "project"}}' "$name")" = intranet-task-pool ]
    [ "$(podman inspect --format '{{.Image}}' "$name")" = "$(podman image inspect --format '{{.Id}}' "$image")" ]
    podman start "$name"
    exit 0
fi

podman volume create --ignore --label project=intranet-task-pool "$volume"
[ "$(podman volume inspect --format '{{index .Labels "project"}}' "$volume")" = intranet-task-pool ]

one_shot() {
    podman run --pull=never --rm --network none --read-only --cap-drop all \
        --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
        -v "$volume:/app/.state:U" "$@"
}

one_shot "$image" init --worker worker-a --worker worker-b --receiver reviewer \
    --authority "内网任务服务本机 Podman 试用"
one_shot --entrypoint /bin/sh "$image" -ceu '
    printf "# 本机试用\n\n请整理本份资料，并上传简短的 Markdown 结果。\n" > /tmp/brief.md
    exec python -B -X utf8 /app/taskpool.py add-task --request-id lan-trial-01 --title "局域网资料整理试用" --input /tmp/brief.md --criterion report-ready
' | python3 -c 'import json,sys; d=json.load(sys.stdin); print("seed", d["task"]["task_id"], d["task"]["status"])'

mkdir -p dist
one_shot -e "TASKPOOL_LAN_IP=$lan_ip" --entrypoint /bin/sh "$image" -ceu '
    umask 077
    tls=/app/.state/tls
    mkdir -p "$tls"
    if [ ! -s "$tls/cert.pem" ] || [ ! -s "$tls/key.pem" ]; then
        if ! openssl req -x509 -newkey rsa:3072 -noenc -days 90 -subj "/CN=taskpool.test" \
            -addext "subjectAltName=DNS:taskpool.test,IP:$TASKPOOL_LAN_IP" \
            -addext "basicConstraints=critical,CA:FALSE" -addext "extendedKeyUsage=serverAuth" \
            -keyout "$tls/key.new" -out "$tls/cert.new" 2>/tmp/openssl.log; then
            cat /tmp/openssl.log >&2
            exit 1
        fi
        mv "$tls/key.new" "$tls/key.pem"
        mv "$tls/cert.new" "$tls/cert.pem"
    fi
    cat "$tls/cert.pem"
' > dist/taskpool-lan-cert.pem.pending
mv dist/taskpool-lan-cert.pem.pending dist/taskpool-lan-cert.pem

podman run -d --pull=never --name "$name" --label project=intranet-task-pool \
    --restart unless-stopped --read-only --cap-drop all --security-opt no-new-privileges \
    --pids-limit 96 -p 127.0.0.1:18765:18443 -v "$volume:/app/.state:U" \
    "$image" serve --port 18443 --lan-name taskpool.test \
    --tls-cert /app/.state/tls/cert.pem --tls-key /app/.state/tls/key.pem
