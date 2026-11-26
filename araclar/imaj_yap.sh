#!/usr/bin/env bash
# Hacker Yolu — çok mimarili Docker imajı üretir (amd64 + arm64).
#
# Kullanım:
#   araclar/imaj_yap.sh                 # multi-arch derle ve ghcr'a push (önce: docker login ghcr.io)
#   araclar/imaj_yap.sh --yerel         # sadece amd64, yerel teste yükle (test/geliştirme)
#   araclar/imaj_yap.sh --offline-arm64 # Pi için arm64 imajı tek tar dosyasına kaydet (USB)
set -euo pipefail
cd "$(dirname "$0")/.."

IMAJ="${HY_IMAJ_ADI:-ghcr.io/gokhanymn/hackeryolu}"
SURUM="$(python3 -c 'import hy; print(hy.SURUM)' 2>/dev/null || echo latest)"
MOD="${1:-push}"

echo "İmaj: ${IMAJ}:${SURUM}"

case "$MOD" in
  --yerel)
    echo "Yerel amd64 derleniyor (hackeryolu:${SURUM}, hackeryolu:latest)..."
    docker build -t "hackeryolu:${SURUM}" -t "hackeryolu:latest" .
    echo "Bitti. Test: docker run -it --rm -v hackeryolu_data:/home/kali hackeryolu:latest"
    ;;
  --offline-arm64)
    TAR="dist/hackeryolu-imaj-${SURUM}-arm64.tar"
    mkdir -p dist
    echo "arm64 derlenip ${TAR} dosyasına kaydediliyor (Pi'ye USB ile taşı)..."
    docker buildx build --platform linux/arm64 -t "hackeryolu:${SURUM}" --load .
    docker save "hackeryolu:${SURUM}" -o "$TAR"
    echo "Bitti: ${TAR}"
    echo "Pi'de:  docker load -i $(basename "$TAR")   sonra  HY_IMAJ=hackeryolu:${SURUM} ./hackeryolu.sh"
    ;;
  push|*)
    PLATFORMLAR="${PLATFORMLAR:-linux/amd64,linux/arm64}"
    echo "Multi-arch (${PLATFORMLAR}) derlenip push ediliyor... (önce: docker login ghcr.io)"
    docker buildx inspect hy-builder >/dev/null 2>&1 || docker buildx create --name hy-builder >/dev/null
    docker buildx use hy-builder
    docker buildx build --platform "$PLATFORMLAR" \
      -t "${IMAJ}:${SURUM}" -t "${IMAJ}:latest" \
      --push .
    echo "Bitti: ${IMAJ}:${SURUM} (ve :latest) yayınlandı."
    ;;
esac
