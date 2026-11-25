#!/usr/bin/env bash
# Geliştirme aracı (Windows/Git Bash'ten): projeyi linux-test konteynerine kopyalayıp
# testleri Kali'deki gibi root olmayan 'kali' kullanıcısıyla çalıştırır.
#   bash araclar/test_konteyner.sh                 # tüm testler
#   bash araclar/test_konteyner.sh c01b02,c00      # sadece bu seviyeler (test_seviyeler)
set -euo pipefail
# Git Bash, /home/... gibi argümanları Windows yoluna çevirir; bütün docker komutları için kapat.
export MSYS_NO_PATHCONV=1
KONTEYNER=${KONTEYNER:-linux-test}
KOK="$(cd "$(dirname "$0")/.." && pwd)"
HEDEF=${HEDEF:-/home/kali/hy}   # paralel çalışan yazarlar farklı HEDEF kullanmalı

docker exec "$KONTEYNER" bash -c 'id kali >/dev/null 2>&1 || useradd -m -s /bin/bash -G sudo kali'
docker exec "$KONTEYNER" rm -rf "$HEDEF"
if docker exec "$KONTEYNER" test -e "$HEDEF"; then
  echo "HATA: $HEDEF silinemedi, eski kodla test edilirdi." >&2
  exit 1
fi
docker cp "$(cygpath -w "$KOK")" "$KONTEYNER:$HEDEF"
docker exec "$KONTEYNER" test -f "$HEDEF/hackeryolu.py" || { echo "HATA: kopya $HEDEF altına inmedi" >&2; exit 1; }
docker exec "$KONTEYNER" bash -c "rm -rf $HEDEF/araclar/kaynak $HEDEF/dist; find $HEDEF -name __pycache__ -prune -exec rm -rf {} +; chown -R kali:kali $HEDEF"

if [ $# -gt 0 ]; then
  docker exec -u kali -w "$HEDEF" -e HY_TEST_SEVIYE="$1" "$KONTEYNER" \
    python3 -m unittest testler.test_seviyeler -v 2>&1 | tail -40
else
  docker exec -u kali -w "$HEDEF" "$KONTEYNER" \
    python3 -m unittest discover -s testler -t . 2>&1 | tail -40
fi
