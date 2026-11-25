"""Geliştirme aracı: kitabın PDF'inden bölüm metinlerini çıkarır.

Pakete girmez. Görev yazarken kaynak metin olarak kullanılır.

Kullanım:
    python pdf_cikar.py <pdf> <cikti_dizini> [cilt_no ...]

Her bölüm için `cXX_<sira>_<baslik>.txt` dosyası yazar. Cilt verilmezse hepsini çıkarır.
"""
import re
import sys
from pathlib import Path

import pypdf


def duz_liste(okuyucu, ana_hat, cilt=None, cikti=None):
    """PDF ana hattını (bookmark) (cilt, başlık, sayfa) listesine düzleştirir."""
    if cikti is None:
        cikti = []
    simdiki_cilt = cilt
    for oge in ana_hat:
        if isinstance(oge, list):
            duz_liste(okuyucu, oge, simdiki_cilt, cikti)
            continue
        sayfa = okuyucu.get_destination_page_number(oge)
        m = re.match(r"Cilt (\d+)", oge.title)
        if m and " — " in oge.title:
            simdiki_cilt = int(m.group(1))
        elif oge.title.startswith("Bölüm 0"):
            simdiki_cilt = 0
        elif oge.title.startswith("Ekler"):
            simdiki_cilt = 99
        cikti.append((simdiki_cilt, oge.title, sayfa))
    return cikti


def dosya_adi(baslik):
    s = baslik.lower()
    for a, b in zip("çğıöşüâ", "cgiosua"):
        s = s.replace(a, b)
    s = re.sub(r"[^a-z0-9]+", "_", s).strip("_")
    return s[:60]


def main():
    pdf, hedef = sys.argv[1], Path(sys.argv[2])
    istenen = {int(x) for x in sys.argv[3:]}
    hedef.mkdir(parents=True, exist_ok=True)
    r = pypdf.PdfReader(pdf)
    liste = duz_liste(r, r.outline)
    for i, (cilt, baslik, bas) in enumerate(liste):
        son = liste[i + 1][2] if i + 1 < len(liste) else len(r.pages)
        if istenen and cilt not in istenen:
            continue
        if son <= bas:
            son = bas + 1
        metin = []
        for s in range(bas, son):
            t = r.pages[s].extract_text() or ""
            # sayfa altbilgisini temizle
            t = re.sub(r"Etik Hacker Yolu — Sıfırdan Pentest'e\s*\d+\s*$", "", t.strip())
            metin.append(f"--- sayfa {s + 1} ---\n{t}")
        ad = f"c{cilt:02d}_{i:03d}_{dosya_adi(baslik)}.txt"
        (hedef / ad).write_text(f"# {baslik}\n\n" + "\n\n".join(metin), encoding="utf-8")
        print(ad, f"(s.{bas + 1}-{son})")


if __name__ == "__main__":
    main()
