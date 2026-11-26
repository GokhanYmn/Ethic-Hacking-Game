#!/bin/bash
# Hacker Yolu — Docker ile başlatıcı (macOS).
# Finder'da çift tıklayınca Terminal'de açılır. İlk sefer: chmod +x hackeryolu.command
cd "$(dirname "$0")"

IMAJ="${HY_IMAJ:-ghcr.io/gokhanymn/hackeryolu:latest}"
VOLUME="${HY_VOLUME:-hackeryolu_data}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Desktop kurulu değil."
  echo "Kur:  https://www.docker.com/products/docker-desktop"
  read -r -p "Çıkmak için Enter'a bas..." _ || true
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker Desktop çalışmıyor. Önce Docker Desktop'ı başlat, sonra tekrar dene."
  read -r -p "Çıkmak için Enter'a bas..." _ || true
  exit 1
fi

if ! docker image inspect "$IMAJ" >/dev/null 2>&1; then
  echo "İmaj ilk kez indiriliyor: $IMAJ"
  docker pull "$IMAJ"
fi

exec docker run -it --rm \
  -v "$VOLUME":/home/kali \
  -e TERM=xterm-256color \
  "$IMAJ" "$@"
