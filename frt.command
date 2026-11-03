#!/bin/bash
cd "$(dirname "$0")" || exit 2
BUN="${FRT_BUN:-}"
for app in "/Applications/Freebuff.app" "$HOME/Applications/Freebuff.app"; do
  [ -z "$BUN" ] && [ -x "$app/Contents/Resources/bun/bun" ] && BUN="$app/Contents/Resources/bun/bun"
done
if [ -z "$BUN" ]; then
  app="$(mdfind "kMDItemCFBundleIdentifier == 'com.freebuff.desktop'" 2>/dev/null | head -n 1)"
  [ -n "$app" ] && [ -x "$app/Contents/Resources/bun/bun" ] && BUN="$app/Contents/Resources/bun/bun"
fi
[ -z "$BUN" ] && command -v bun >/dev/null 2>&1 && BUN="$(command -v bun)"
if [ -z "$BUN" ]; then
  echo "Freebuff Repair Tool could not find Freebuff.app. Run: /path/to/Freebuff.app/Contents/Resources/bun/bun \"$(pwd)/frt.mjs\""
  exit 2
fi
[ $# -eq 0 ] && exec "$BUN" ./frt.mjs --ui
exec "$BUN" ./frt.mjs "$@"
