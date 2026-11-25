#!/usr/bin/env bash
# Geliştirme aracı (Windows/Git Bash'ten): dağıtım paketini Linux konteynerinde üretir.
# Linux'ta paketlemek, çalıştırma izinlerinin ve LF satır sonlarının korunmasını sağlar.
#   bash araclar/paketle.sh   →  dist/hackeryolu-<sürüm>.tar.gz
set -euo pipefail
KONTEYNER=${KONTEYNER:-linux-test}
KOK="$(cd "$(dirname "$0")/.." && pwd)"
SURUM=$(sed -n 's/^SURUM = "\(.*\)"/\1/p' "$KOK/hy/__init__.py")
AD="hackeryolu-$SURUM"
IS=/tmp/hy_paket

MSYS_NO_PATHCONV=1 docker exec "$KONTEYNER" rm -rf "$IS"
MSYS_NO_PATHCONV=1 docker exec "$KONTEYNER" mkdir -p "$IS"
MSYS_NO_PATHCONV=1 docker cp "$(cygpath -w "$KOK")" "$KONTEYNER:$IS/$AD"
MSYS_NO_PATHCONV=1 docker exec -w "$IS" "$KONTEYNER" bash -c "
  set -e
  cd $AD
  rm -rf araclar dist docs .git
  find . -name __pycache__ -prune -exec rm -rf {} +
  find . -type f \( -name '*.py' -o -name '*.sh' -o -name '*.md' \) -exec sed -i 's/\r\$//' {} +
  find . -type d -exec chmod 755 {} +
  find . -type f -exec chmod 644 {} +
  chmod 755 install.sh hackeryolu.py
  cd ..
  tar --owner=0 --group=0 --numeric-owner -czf $AD.tar.gz $AD
  sha256sum $AD.tar.gz > $AD.tar.gz.sha256
  ls -l $AD.tar.gz
"
mkdir -p "$KOK/dist"
MSYS_NO_PATHCONV=1 docker cp "$KONTEYNER:$IS/$AD.tar.gz" "$(cygpath -w "$KOK/dist/$AD.tar.gz")"
MSYS_NO_PATHCONV=1 docker cp "$KONTEYNER:$IS/$AD.tar.gz.sha256" "$(cygpath -w "$KOK/dist/$AD.tar.gz.sha256")"
echo "Paket: $KOK/dist/$AD.tar.gz"
