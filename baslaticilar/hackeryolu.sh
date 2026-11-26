#!/usr/bin/env bash
# Hacker Yolu — Docker ile başlatıcı (Linux).
# Çift tıkla ya da terminalden çalıştır: ./hackeryolu.sh
set -euo pipefail

IMAJ="${HY_IMAJ:-ghcr.io/gokhanymn/hackeryolu:latest}"
VOLUME="${HY_VOLUME:-hackeryolu_data}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker kurulu değil."
  echo "Kurulum:  sudo apt install docker.io"
  echo "Sonra:    sudo usermod -aG docker \$USER   (oturumu kapatıp aç)"
  read -r -p "Çıkmak için Enter'a bas..." _ || true
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker çalışmıyor ya da yetkin yok."
  echo "Dene:  sudo systemctl start docker    (ya da komutu 'sudo' ile çalıştır)"
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
