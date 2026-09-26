#!/usr/bin/env bash
# Build a static binary and (re)start the rspxy SSU server on the exit host.
#
#   scripts/deploy.sh SSH_HOST                (PORT=5023 by default)
#   JUMP=jump-host scripts/deploy.sh SSH_HOST  (upload via an ssh jump host,
#                                              useful when the direct path is slow)
#
# The key table lives on the server at ~/rspxy/keys.txt (`id secret` per line);
# a random key with id 1 is generated on first deploy. Only the rspxy process
# is restarted; other processes on the host are left alone.
# Extra server query params: SERVER_PARAMS='&mtu=1400&cc=bbr'.
set -euo pipefail
HOST=${1:?usage: scripts/deploy.sh SSH_HOST}
PORT=${PORT:-5023}
JUMP=${JUMP:-}
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15)
[ -n "$JUMP" ] && SSH_OPTS+=(-o ProxyJump="$JUMP")
cd "$(dirname "$0")/.."

CC_x86_64_unknown_linux_musl=${CC_x86_64_unknown_linux_musl:-gcc} \
    cargo build --release --target x86_64-unknown-linux-musl
BIN=target/x86_64-unknown-linux-musl/release/rspxy

ssh "${SSH_OPTS[@]}" "$HOST" 'mkdir -p ~/rspxy' < /dev/null
scp -C -q "${SSH_OPTS[@]}" "$BIN" "$HOST:rspxy/rspxy.new"
ssh "${SSH_OPTS[@]}" "$HOST" "PORT=$PORT SERVER_PARAMS=$(printf %q "${SERVER_PARAMS:-}") bash -s" <<'EOF'
set -e
cd ~/rspxy
mv rspxy.new rspxy
if [ ! -f keys.txt ]; then
    umask 077
    echo "1 $(head -c 18 /dev/urandom | base64 | tr '+/' '-_')" > keys.txt
fi
pkill -x rspxy || true
sleep 0.5
nohup ./rspxy "-L=ssu://:$PORT?keys=$HOME/rspxy/keys.txt${SERVER_PARAMS:-}" > rspxy.log 2>&1 < /dev/null &
sleep 1
ss -lun | grep -q ":$PORT " || { cat rspxy.log; exit 1; }
tail -n 3 rspxy.log
EOF
echo "deployed. client: rspxy -L=socks5://:1080 -L=http://:8080 -F=ssu://ID:SECRET@<host>:$PORT"
echo "(ID and SECRET are in ~/rspxy/keys.txt on $HOST)"
