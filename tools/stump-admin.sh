#!/usr/bin/env bash
# Operator moderation commands. They call internal endpoints that Traefik
# does not route, through kubectl port-forward, so they need cluster access.
#
#   stump-admin.sh remove-message <message id> <reason>
#   stump-admin.sh remove-sender  <wallet> <reason>     every live message from a wallet
#   stump-admin.sh block          <wallet> <reason>     revoke its keys, refuse new ones
#   stump-admin.sh unblock        <wallet>
#   stump-admin.sh removals                             the takedown log
#   stump-admin.sh flags                                wallets flagged in the last 14 days
#
# To make the whole board read-only, set STUMP_STATUS: read_only in the
# overlay's config and merge (or sunset, which also stops new keys for good).
set -euo pipefail

NS=${STUMP_NAMESPACE:-stump}
cmd=${1:-}; shift || true

forward() { # service -> prints local port; the forward stops when this script exits
  local port=$((20000 + RANDOM % 10000))
  kubectl -n "$NS" port-forward "svc/$1" "$port:8080" >/dev/null 2>&1 &
  trap "kill $! 2>/dev/null" EXIT
  for _ in $(seq 50); do
    curl -fs -o /dev/null "http://127.0.0.1:$port/healthz" 2>/dev/null && { echo "$port"; return; }
    sleep 0.1
  done
  echo "port-forward to $1 failed" >&2; exit 1
}
call() { # method service path [json]
  local port; port=$(forward "$2")
  curl -sS -X "$1" -H 'Content-Type: application/json' ${4:+--data "$4"} "http://127.0.0.1:$port$3"
  echo
}
reason() { jq -nc --arg r "$1" '{reason: $r}'; }
need() { [ "$#" -ge 3 ] && [ -n "$2" ] && [ -n "$3" ] || { echo "usage: $0 $cmd $1" >&2; exit 2; }; }

case $cmd in
  remove-message) need "<message id> <reason>" "$@"; call POST board "/internal/messages/$1/remove" "$(reason "$2")" ;;
  remove-sender)  need "<wallet> <reason>" "$@";     call POST board "/internal/senders/$1/remove" "$(reason "$2")" ;;
  block)          need "<wallet> <reason>" "$@";     call POST issuer "/internal/wallets/$1/block" "$(reason "$2")" ;;
  unblock)        [ -n "${1:-}" ] || { echo "usage: $0 unblock <wallet>" >&2; exit 2; }
                  call DELETE issuer "/internal/wallets/$1/block" ;;
  removals)       call GET board /internal/removals ;;
  flags)          call GET trust /internal/flags ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
