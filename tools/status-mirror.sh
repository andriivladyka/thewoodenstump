#!/usr/bin/env bash
# Builds the off-server status site: probes the live service, copies its
# discovery files, and keeps the last good copies when it does not answer.
# The status workflow runs it on a schedule and publishes the result to
# GitHub Pages, so agents can still learn the service state when the home
# server or its connection is down.
#
#   PUBLIC_URL   the service, for example https://thewoodenstump.lol (empty before launch)
#   MIRROR_URL   where this site is published, to read the last good copies
#   NOTICE_FILE  operator notice, JSON {"message": "...", "updated": "..."} (optional)
#
# Usage: tools/status-mirror.sh <output dir>
set -euo pipefail

out=${1:?output dir}
PUBLIC_URL=${PUBLIC_URL%/}
MIRROR_URL=${MIRROR_URL%/}
NOTICE_FILE=${NOTICE_FILE:-status/notice.json}
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
files=(.well-known/agent-card.json .well-known/terms.json llms.txt openapi.json)

mkdir -p "$out/.well-known"
fetch() { curl -fsS --max-time 15 --retry 2 --retry-delay 5 -o "$2" "$1"; }

# The previous run's view, so a failed probe keeps the last good files.
prev=$(mktemp)
if [ -n "$MIRROR_URL" ] && fetch "$MIRROR_URL/status.json" "$prev" 2>/dev/null && jq -e . "$prev" >/dev/null 2>&1; then :; else echo '{}' > "$prev"; fi
last_ok=$(jq -r '.last_ok_at // empty' "$prev")

live=$(mktemp)
if [ -z "$PUBLIC_URL" ]; then
  status=not_public
  echo '{}' > "$live"
elif fetch "$PUBLIC_URL/status.json" "$live" && jq -e .status "$live" >/dev/null; then
  status=$(jq -r .status "$live")
  last_ok=$now
  for f in "${files[@]}"; do
    fetch "$PUBLIC_URL/$f" "$out/$f.new" && mv "$out/$f.new" "$out/$f" || rm -f "$out/$f.new"
  done
else
  status=unreachable
  echo '{}' > "$live"
fi

# Files the live service did not give us this time come from the last run.
for f in "${files[@]}"; do
  if [ ! -s "$out/$f" ] && [ -n "$MIRROR_URL" ]; then
    fetch "$MIRROR_URL/$f" "$out/$f" 2>/dev/null || rm -f "$out/$f"
  fi
done

# The copied Agent Card says what this probe saw and where the live one is.
card="$out/.well-known/agent-card.json"
if [ -s "$card" ] && jq -e . "$card" >/dev/null 2>&1; then
  jq --arg st "$status" --arg at "$now" --arg of "$PUBLIC_URL" \
    '."x-stump".status = $st | ."x-stump".mirror = {of: ($of + "/.well-known/agent-card.json"), checked_at: $at}' \
    "$card" > "$card.new" && mv "$card.new" "$card"
fi

notice='null'
if [ -s "$NOTICE_FILE" ] && jq -e '.message // "" | length > 0' "$NOTICE_FILE" >/dev/null 2>&1; then
  notice=$(jq -c . "$NOTICE_FILE")
fi

jq -n --arg st "$status" --arg at "$now" --arg ok "$last_ok" --arg url "$PUBLIC_URL" \
  --argjson live "$(cat "$live")" --argjson notice "$notice" '{
    status: $st,
    checked_at: $at,
    last_ok_at: (if $ok == "" then null else $ok end),
    service_url: (if $url == "" then null else $url end),
    service: (if $live == {} then null else $live end),
    notice: $notice,
    about: "Checked from outside the home server about every 15 minutes. status is the service'"'"'s own report (operating, degraded, read_only, sunset), or unreachable when it did not answer, or not_public before launch. The files next to this one are the last copies fetched while it answered."
  }' > "$out/status.json"

# A small page for people.
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }
label=$(printf %s "$status" | tr _ ' ' | esc)
case $status in
  operating) color='#1a7f37' ;;
  degraded|read_only) color='#9a6700' ;;
  *) color='#cf222e' ;;
esac
msg=$(jq -r '.message // empty' <<<"$notice" | esc)
cat > "$out/index.html" <<HTML
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>The Wooden Stump status</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;color:#222}
.s{font-size:1.4rem;font-weight:600;color:$color}.m{color:#666}
@media (prefers-color-scheme:dark){body{background:#111;color:#ddd}.m{color:#999}}</style></head><body>
<h1>The Wooden Stump status</h1>
<p class="s">$label</p>
$( [ -n "$msg" ] && printf '<p>%s</p>' "$msg" )
<p class="m">Checked $now from outside the home server. Last answered: ${last_ok:-never}.</p>
<p>Service: $( [ -n "$PUBLIC_URL" ] && printf '<a href="%s">%s</a>' "$PUBLIC_URL" "$PUBLIC_URL" || printf 'not public yet' ).
Machine-readable: <a href="status.json">status.json</a>, plus last good copies of the
<a href=".well-known/agent-card.json">Agent Card</a>, <a href=".well-known/terms.json">terms</a>,
<a href="llms.txt">llms.txt</a> and <a href="openapi.json">OpenAPI</a>.</p>
</body></html>
HTML
touch "$out/.nojekyll"
echo "status: $status (last ok: ${last_ok:-never})"
