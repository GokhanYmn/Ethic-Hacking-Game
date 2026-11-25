#!/usr/bin/env bash
# Hacker Yolu kurulum betiği
#   ./install.sh            kur ya da güncelle (ilerlemen korunur)
#   ./install.sh --kaldir   oyunu kaldır (ilerleme ve lab dosyaları kalır)
#   ./install.sh --hepsini-kaldir   oyunu, ilerlemeyi ve lab dosyalarını sil
set -euo pipefail

KAYNAK="$(cd "$(dirname "$0")" && pwd)"
HEDEF="${HY_KURULUM:-$HOME/.local/share/hackeryolu}"
BIN="$HOME/.local/bin"
BASLATICI="$BIN/hackeryolu"

yesil() { printf '\033[1;32m%s\033[0m\n' "$*"; }
kirmizi() { printf '\033[1;31m%s\033[0m\n' "$*"; }

kaldir() {
  rm -rf "$HEDEF" "$BASLATICI"
  yesil "Hacker Yolu kaldırıldı."
}

case "${1:-}" in
  --kaldir) kaldir; echo "İlerleme (~/.hackeryolu) ve lab dosyaları (~/hackeryolu) duruyor."; exit 0 ;;
  --hepsini-kaldir) kaldir; rm -rf "$HOME/.hackeryolu" "$HOME/hackeryolu"; yesil "İlerleme ve lab dosyaları da silindi."; exit 0 ;;
  "") ;;
  *) echo "Kullanım: ./install.sh [--kaldir | --hepsini-kaldir]"; exit 1 ;;
esac

if ! command -v python3 >/dev/null 2>&1; then
  kirmizi "python3 bulunamadı. Kali'de: sudo apt install python3"
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  kirmizi "Python 3.10 veya üstü gerekiyor. Şu anki: $(python3 --version 2>&1)"
  exit 1
fi
if ! command -v bash >/dev/null 2>&1; then
  kirmizi "bash bulunamadı. Kali'de: sudo apt install bash"
  exit 1
fi

mkdir -p "$HEDEF" "$BIN"
# Eski kod dosyalarını temizle (ilerleme ~/.hackeryolu içinde, ona dokunulmaz)
rm -rf "$HEDEF/hy" "$HEDEF/testler" "$HEDEF/hackeryolu.py"
cp -r "$KAYNAK/hackeryolu.py" "$KAYNAK/hy" "$HEDEF/"
[ -d "$KAYNAK/testler" ] && cp -r "$KAYNAK/testler" "$HEDEF/"
[ -f "$KAYNAK/README.md" ] && cp "$KAYNAK/README.md" "$HEDEF/"
[ "$KAYNAK" != "$HEDEF" ] && cp "$KAYNAK/install.sh" "$HEDEF/"   # kaldırma için
find "$HEDEF" -name '__pycache__' -prune -exec rm -rf {} +

cat > "$BASLATICI" <<EOF
#!/usr/bin/env bash
exec python3 "$HEDEF/hackeryolu.py" "\$@"
EOF
chmod +x "$BASLATICI" "$HEDEF/hackeryolu.py"

YOL_SATIRI='export PATH="$HOME/.local/bin:$PATH"'
case ":$PATH:" in
  *":$BIN:"*) YOL_TAMAM=1 ;;
  *) YOL_TAMAM=0 ;;
esac
if [ "$YOL_TAMAM" = 0 ]; then
  for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$rc" ] && ! grep -qF "$YOL_SATIRI" "$rc"; then
      printf '\n# Hacker Yolu\n%s\n' "$YOL_SATIRI" >> "$rc"
    fi
  done
fi

SURUM=$(python3 "$HEDEF/hackeryolu.py" --surum)
yesil "$SURUM kuruldu: $HEDEF"
echo
if [ "$YOL_TAMAM" = 1 ]; then
  echo "Başlatmak için:  hackeryolu"
else
  echo "Yeni bir terminal aç (ya da 'source ~/.zshrc' yaz), sonra:  hackeryolu"
  echo "Hemen denemek için:  $BASLATICI"
fi
echo "Kurulumu doğrulamak için (isteğe bağlı, ~1 dk):  hackeryolu oztest"
