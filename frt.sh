#!/bin/sh
cd "$(dirname "$0")" || exit 2
BUN="${FRT_BUN:-}"
for d in /opt/Freebuff /opt/freebuff /usr/lib/freebuff "$HOME"/.local/opt/*reebuff*; do
  [ -z "$BUN" ] && [ -x "$d/resources/bun/bun" ] && BUN="$d/resources/bun/bun"
done
[ -z "$BUN" ] && command -v bun >/dev/null 2>&1 && BUN="$(command -v bun)"
if [ -z "$BUN" ]; then
  echo "Freebuff Repair Tool needs Bun: point FRT_BUN at <Freebuff folder>/resources/bun/bun, or install Bun (https://bun.sh)."
  exit 2
fi
[ $# -eq 0 ] && exec "$BUN" ./frt.mjs --ui
exec "$BUN" ./frt.mjs "$@"
