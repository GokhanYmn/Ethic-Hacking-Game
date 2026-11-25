#!/usr/bin/env bash
# Geliştirme aracı: dist/ altındaki paketi boş bir Debian (Kali'nin tabanı) konteynerine
# kurar; Kali'de varsayılan gelen temel araçları ekler, root olmayan kullanıcıyla
# install.sh + hackeryolu oztest çalıştırır. Konteyner iş bitince silinir.
set -euo pipefail
KOK="$(cd "$(dirname "$0")/.." && pwd)"
PAKET=$(ls -t "$KOK"/dist/hackeryolu-*.tar.gz | head -1)
AD=$(basename "$PAKET")
K=hy-temiz-kurulum

docker rm -f "$K" >/dev/null 2>&1 || true
docker run -d --name "$K" debian:trixie-slim sleep 1800 >/dev/null
trap 'docker rm -f "$K" >/dev/null 2>&1 || true' EXIT

docker exec "$K" bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  python3 procps iproute2 bind9-dnsutils tcpdump netcat-openbsd curl file >/dev/null 2>&1 && useradd -m -s /bin/bash kali"
MSYS_NO_PATHCONV=1 docker cp "$(cygpath -w "$PAKET")" "$K:/home/kali/$AD"
MSYS_NO_PATHCONV=1 docker exec "$K" chown kali:kali "/home/kali/$AD"
MSYS_NO_PATHCONV=1 docker exec -u kali -w /home/kali "$K" bash -c "
  set -e
  tar xzf $AD
  cd ${AD%.tar.gz}
  ls -l install.sh hackeryolu.py
  ./install.sh
  echo '--- surum'; ~/.local/bin/hackeryolu --surum
  echo '--- liste'; ~/.local/bin/hackeryolu liste
  echo '--- oztest'; ~/.local/bin/hackeryolu oztest
  echo '--- ikinci kurulum (guncelleme) ilerlemeyi korumali'
  mkdir -p ~/.hackeryolu && echo '{\"xp\": 123}' > ~/.hackeryolu/kayit.json
  ./install.sh >/dev/null
  python3 -c 'import json,os; print(\"xp korundu:\", json.load(open(os.path.expanduser(\"~/.hackeryolu/kayit.json\")))[\"xp\"])'
  echo '--- kaldir'; ~/.local/share/hackeryolu/install.sh --kaldir; test ! -e ~/.local/bin/hackeryolu && echo 'baslatici silindi'
"
