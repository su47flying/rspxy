#!/usr/bin/env bash
# A/B proxy benchmark. Proxies are exercised alternately each round so they see
# the same network conditions; medians are reported per proxy.
#
#   scripts/bench.sh rspxy=socks5h://127.0.0.1:1080 gost=socks5h://127.0.0.1:6080
#
# env: RUNS=5  DOWN_BYTES=20000000  UP_BYTES=5000000  LAT_URL=https://www.google.com/generate_204
set -uo pipefail
RUNS=${RUNS:-5}
DOWN=${DOWN_BYTES:-20000000}
UP=${UP_BYTES:-5000000}
LAT_URL=${LAT_URL:-https://www.google.com/generate_204}
[ $# -ge 1 ] || { sed -n '2,8p' "$0"; exit 2; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
head -c "$UP" /dev/urandom > "$tmp/up.bin"

median() { sort -n | awk '{a[NR]=$1} END {if (!NR) print "-"; else if (NR%2) print a[(NR+1)/2]; else print (a[NR/2]+a[NR/2+1])/2}'; }
mbps() { awk -v b="$1" 'BEGIN {printf "%.2f", b*8/1e6}'; }

for r in $(seq "$RUNS"); do
    for spec in "$@"; do
        name=${spec%%=*}
        proxy=${spec#*=}
        if d=$(curl -sf -m 120 -x "$proxy" -o /dev/null -w '%{speed_download}' "https://speed.cloudflare.com/__down?bytes=$DOWN"); then
            mbps "$d" >> "$tmp/$name.down"; echo >> "$tmp/$name.down"
        else echo x >> "$tmp/$name.fail"; d=0; fi
        if u=$(curl -sf -m 120 -x "$proxy" -o /dev/null -w '%{speed_upload}' --data-binary @"$tmp/up.bin" "https://speed.cloudflare.com/__up"); then
            mbps "$u" >> "$tmp/$name.up"; echo >> "$tmp/$name.up"
        else echo x >> "$tmp/$name.fail"; u=0; fi
        if l=$(curl -s -m 30 -x "$proxy" -o /dev/null -w '%{time_appconnect} %{time_starttransfer}' "$LAT_URL") && [ "${l%% *}" != "0.000000" ]; then
            echo "${l%% *}" >> "$tmp/$name.tls"; echo "${l##* }" >> "$tmp/$name.ttfb"
        else echo x >> "$tmp/$name.fail"; fi
        echo "round $r  $name: down=$(mbps "$d")Mbps up=$(mbps "$u")Mbps tls/ttfb=${l:-fail}s" >&2
    done
done

printf '\n%-10s %12s %12s %12s %12s %6s\n' proxy down_Mbps up_Mbps tls_s ttfb_s fails
for spec in "$@"; do
    name=${spec%%=*}
    printf '%-10s %12s %12s %12s %12s %6s\n' "$name" \
        "$(grep -v '^$' "$tmp/$name.down" 2>/dev/null | median)" \
        "$(grep -v '^$' "$tmp/$name.up" 2>/dev/null | median)" \
        "$(median < "$tmp/$name.tls" 2>/dev/null)" \
        "$(median < "$tmp/$name.ttfb" 2>/dev/null)" \
        "$(cat "$tmp/$name.fail" 2>/dev/null | wc -l)"
done
