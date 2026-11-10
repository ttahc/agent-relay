#!/bin/sh
# Fresh Podman install of Agent Relay on a NEW, empty data volume.
# It never touches an existing container or volume; stop any old service yourself
# before reusing its host port.
#
# Usage (inside WSL or Linux, from the repository root):
#   sh ops/fresh-install.sh <LAN-IPv4> [more LAN IPv4 ...]
#
# Optional environment:
#   AR_NAME           container name                (default agent-relay)
#   AR_VOLUME         data volume name              (default agent-relay-data)
#   AR_PORT           loopback host port            (default 18765)
#   AR_TLS_NAME       service host name in the cert (default taskpool.test)
#   AR_PASSWORD_FILE  restricted file holding the first admin password;
#                     omitted = typed interactively
set -eu
umask 077
cd "$(dirname "$0")/.."

[ "$#" -ge 1 ] || { printf '%s\n' 'Pass at least one LAN IPv4 address for the TLS certificate.' >&2; exit 2; }
for ip in "$@"; do python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "$ip"; done

version=$(python3 -c 'import ast,sys; print(next(ast.literal_eval(n.value) for n in ast.parse(open("pool/__init__.py",encoding="utf-8").read()).body if isinstance(n,ast.Assign) and n.targets[0].id=="__version__"))')
name=${AR_NAME:-agent-relay}
volume=${AR_VOLUME:-agent-relay-data}
port=${AR_PORT:-18765}
tls_name=${AR_TLS_NAME:-taskpool.test}
image=localhost/agent-relay:$version
label=project=agent-relay

if podman container exists "$name"; then
    printf 'Container %s already exists; this script only installs fresh.\n' "$name" >&2; exit 1
fi
if podman volume exists "$volume"; then
    printf 'Volume %s already exists; choose another AR_VOLUME.\n' "$volume" >&2; exit 1
fi
if (ss -ltn 2>/dev/null || true) | grep -q "127.0.0.1:$port \|0.0.0.0:$port \|\*:$port "; then
    printf 'Host port %s is in use. Stop the old service or set AR_PORT.\n' "$port" >&2; exit 1
fi

podman build -t "$image" .
id=$(podman image inspect --format '{{.Id}}' "$image")
podman volume create --label "$label" "$volume" >/dev/null

one_shot() {
    podman run --pull=never --rm --network none --read-only --cap-drop all \
        --security-opt no-new-privileges --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m \
        -v "$volume:/app/.state:U" "$@"
}
step() { printf '== %s\n' "$1"; }

step 'Initialize ledger'
one_shot "$image" init --worker setup-worker --receiver setup-reviewer --authority "Agent Relay fresh install" >/dev/null
# The bootstrap admin token is revoked by the password step below; never print it.
one_shot "$image" init-admin >/dev/null

step 'Register first task: deployment acceptance'
one_shot --entrypoint /bin/sh "$image" -ceu '
    printf "# 新部署验收\n\n确认新部署的登录、项目、邀请和任务流程可用。\n" > /tmp/brief.md
    exec python -B -X utf8 /app/taskpool.py add-task --request-id fresh-acceptance \
        --title "新部署验收" --input /tmp/brief.md --criterion deployment-verified
' >/dev/null

step 'Upgrade data contract to the current schema'
one_shot "$image" upgrade-migrate --task T01 --upgrade fresh-v2 --image "$id" >/dev/null
one_shot "$image" round-migrate --upgrade fresh-v3 --image "$id" >/dev/null
one_shot "$image" security-migrate --target 4 --request-id fresh-security-4 >/dev/null
one_shot "$image" security-migrate --target 5 --request-id fresh-security-5 >/dev/null

step 'Set the first admin password'
if [ -n "${AR_PASSWORD_FILE:-}" ]; then
    [ -f "$AR_PASSWORD_FILE" ] && [ ! -L "$AR_PASSWORD_FILE" ]
    one_shot -v "$AR_PASSWORD_FILE:/run/admin-password:ro,U" "$image" \
        admin-recover --request-id fresh-admin-password --password-file /run/admin-password >/dev/null
else
    one_shot -it "$image" admin-recover --request-id fresh-admin-password >/dev/null
fi
one_shot "$image" maintenance off --request-id fresh-open >/dev/null

step 'Create TLS certificate'
san="DNS:$tls_name"
for ip in "$@"; do san="$san,IP:$ip"; done
mkdir -p dist
one_shot -e "AR_TLS_NAME=$tls_name" -e "AR_SAN=$san" --entrypoint /bin/sh "$image" -ceu '
    umask 077
    tls=/app/.state/tls
    mkdir -p "$tls"
    openssl req -x509 -newkey rsa:3072 -noenc -days 90 -subj "/CN=$AR_TLS_NAME" \
        -addext "subjectAltName=$AR_SAN" -addext "basicConstraints=critical,CA:FALSE" \
        -addext "extendedKeyUsage=serverAuth" -keyout "$tls/key.pem" -out "$tls/cert.pem" 2>/dev/null
    cat "$tls/cert.pem"
' > dist/agent-relay-cert.pem

step 'Start service'
podman run -d --pull=never --name "$name" --label "$label" \
    --restart unless-stopped --read-only --cap-drop all --security-opt no-new-privileges \
    --pids-limit 96 -p "127.0.0.1:$port:18443" -v "$volume:/app/.state" \
    "$image" serve --port 18443 --lan-name "$tls_name" \
    --tls-cert /app/.state/tls/cert.pem --tls-key /app/.state/tls/key.pem >/dev/null

for _ in $(seq 30); do
    if curl -fsS --noproxy '*' --cacert dist/agent-relay-cert.pem \
        --connect-to "$tls_name:18443:127.0.0.1:$port" "https://$tls_name:18443/healthz" >/dev/null 2>&1; then
        printf 'Agent Relay %s is running: container %s, volume %s, https://%s:18443 via 127.0.0.1:%s\n' \
            "$version" "$name" "$volume" "$tls_name" "$port"
        printf 'Certificate: dist/agent-relay-cert.pem (SHA256 %s)\n' \
            "$(python3 -c 'import hashlib,ssl,sys; print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(sys.argv[1]).read())).hexdigest())' dist/agent-relay-cert.pem)"
        exit 0
    fi
    sleep 1
done
printf '%s\n' 'Service did not become healthy; check: podman logs '"$name" >&2
exit 1
