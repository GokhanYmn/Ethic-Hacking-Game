"""Oyuncunun yazdığı betikleri (Bash/Python) çalıştırıp çıktısını doğrulamak için yardımcılar.

Cilt 3'ten itibaren oyuncu kendi araçlarını yazar; oyun bu betikleri farklı girdilerle
çalıştırıp çıktısını kontrol eder. Kısa kullanım:

    from hy.ortak import betik as bt

    def _selam_denetle(b, calistir):            # b: Baglam, calistir: bt.Calistirici
        hata = bt.kullanim_denetle(calistir)    # argümansız: kullanım mesajı + exit 1?
        if hata:
            return Sonuc(False, hata)
        c = calistir("Deniz")                   # -> bt.Cikti(kod, stdout, stderr, ...)
        if "Merhaba, Deniz" not in c.stdout:
            return Sonuc(False, "Selam satırı yok." + bt.ozet(c))
        return Sonuc(True)

    Gorev("...", bt.BetikKontrol("selam.sh", _selam_denetle, cozum=SELAM_MD), ...)

Oyuncu `cevap <no>` (betik varsayılan adla lab'da) ya da `cevap <no> yol/betik.sh` yazar.
`BetikKontrol` betiği bulur ve ön denetimden geçirir: lab içinde mi, var mı, boş mu,
Windows satır sonu (CRLF) var mı, shebang var mı, Bash betiği çalıştırılabilir mi
(`chmod +x`). Python betikleri her zaman `python3 betik.py` gibi yorumlayıcıyla çalışır.
Sorun yoksa seviyenin `denetle(baglam, calistir)` fonksiyonunu çağırır.

Diğer yardımcılar:
  - `calistir(yol, args, ...)`: zaman aşımlı çalıştırma. Süreç ayrı bir süreç grubunda
    başlar; zaman aşımında ya da iş bitince arka plana atılmış (&) işler dahil grup
    öldürülür. Çıktı `SINIR` bayta kadar tutulur, fazlası atılır.
  - `cokme_mesaji(cikti)`: betik çöktüyse/takıldıysa öğretici açıklama (Python Traceback'in
    son satırı, bash söz dizimi hatası, bulunamayan komut, zaman aşımı...).
  - `ozet(cikti)`: hata mesajına eklemek için çıktının ilk satırları.
  - `kullanim_denetle(calistir, *args)`: eksik argümanla kullanım mesajı + sıfırdan farklı
    çıkış kodu bekler.
  - `GeciciDinleyici`: kontrol sırasında rastgele 127.x adreslerinde geçici TCP dinleyiciler
    açar (oyuncunun betiğinin sabit kodlanmış cevap değil, gerçekten tarama yaptığını görmek
    için).
  - `betik_yaz(yol, icerik)`: test çözücüsü (coz) için referans betiği yazıp chmod 755 yapar.
  - `ipler(metin)`, `sayilar(metin)`: çıktıdan IP / tam sayı ayıklama.

Betik, oyuncunun kabuğunun bulunduğu dizinde (Baglam.calisma_dizini, lab içindeyse)
ya da lab dizininde çalışır. Kum havuzu (sandbox) yoktur: oyuncu kendi makinesinde kendi
betiğini çalıştırıyor; tek şart betiğin lab içinde olması.
"""
from __future__ import annotations

import contextlib
import difflib
import errno
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from hy.motor.kontrol import Baglam, Kontrol, Sonuc
from hy.motor.seviye import yer_tut

SINIR = 200_000            # tutulacak en fazla çıktı (bayt, stdout ve stderr için ayrı ayrı)
VARSAYILAN_ZAMAN = 20.0    # saniye; Raspberry Pi için cömert
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
KULLANIM_KELIMELERI = ("kullanım", "kullanim", "usage")


# ---------------------------------------------------------------- çıktı

@dataclass
class Cikti:
    komut: list
    kod: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    zaman_asimi: bool = False
    sure: float = 0.0
    kesildi: bool = False
    hata: str = ""            # başlatılamadıysa açıklama
    zaman_siniri: float = VARSAYILAN_ZAMAN

    @property
    def hepsi(self) -> str:
        if self.stdout and self.stderr:
            return self.stdout.rstrip("\n") + "\n" + self.stderr
        return self.stdout or self.stderr

    @property
    def satirlar(self) -> list:
        """stdout'un boş olmayan satırları (kırpılmış)."""
        return [s.strip() for s in self.stdout.splitlines() if s.strip()]

    @property
    def basarili(self) -> bool:
        return self.kod == 0 and not self.zaman_asimi and not self.hata


def ipler(metin: str) -> list:
    """Metindeki IPv4 adresleri (görülme sırasıyla)."""
    return IP_RE.findall(metin)


def sayilar(metin: str) -> list:
    """Metindeki tam sayılar (IP adreslerinin parçaları hariç)."""
    return [int(x) for x in re.findall(r"(?<![\w.])\d+(?!\w)", IP_RE.sub(" ", metin))]


def ozet(c: Cikti, n: int = 6) -> str:
    """Hata mesajına eklenecek kısa çıktı özeti (düz metin, girintili)."""
    satirlar = [s.rstrip() for s in c.hepsi.splitlines() if s.strip()]
    if not satirlar:
        return "\n    (betiğin hiçbir şey yazmadı)"
    govde = "\n".join("    | " + s[:110] for s in satirlar[:n])
    if len(satirlar) > n:
        govde += f"\n    | ... ({len(satirlar) - n} satır daha)"
    return "\n    Betiğinin çıktısı:\n" + govde


def _norm(s: str) -> str:
    return s.replace("İ", "i").casefold().replace("ı", "i")


_ASCII = str.maketrans({"ş": "s", "ü": "u", "ö": "o", "ç": "c", "ğ": "g", "̇": None})


def ascii_kucuk(s: str) -> str:
    """Türkçe harfleri sadeleştirip küçültür: 'ŞÜPHELİ' -> 'supheli'."""
    return _norm(s).translate(_ASCII)


def kullanim_var(c: Cikti) -> bool:
    metin = _norm(c.hepsi)
    return any(k in metin for k in KULLANIM_KELIMELERI)


# ---------------------------------------------------------------- çalıştırma

def _grubu_oldur(pgid: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(pgid, signal.SIGKILL)


def _okuyucu(akis, tampon: list, sinir: int, durum: dict) -> None:
    toplam = 0
    try:
        while True:
            parca = akis.read1(65536) if hasattr(akis, "read1") else akis.read(65536)
            if not parca:
                break
            if toplam < sinir:
                tampon.append(parca[: sinir - toplam])
            toplam += len(parca)
    except (OSError, ValueError):
        pass
    if toplam > sinir:
        durum["kesildi"] = True


def calistir(yol: Path, args=(), cwd: Optional[Path] = None, zaman_asimi: float = VARSAYILAN_ZAMAN,
             girdi: Optional[str] = None, yorumlayici: Optional[str] = None, sinir: int = SINIR,
             ortam_ek: Optional[dict] = None) -> Cikti:
    """Betiği çalıştırır; zaman aşımında tüm süreç grubunu öldürür, çıktıyı sınırlar."""
    komut = ([yorumlayici] if yorumlayici else []) + [str(yol)] + [str(a) for a in args]
    ortam = os.environ.copy()
    ortam.update({"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"})
    if ortam_ek:
        ortam.update(ortam_ek)
    baslangic = time.monotonic()
    try:
        p = subprocess.Popen(
            komut, cwd=str(cwd) if cwd else None, env=ortam,
            stdin=subprocess.PIPE if girdi is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except PermissionError:
        return Cikti(komut, hata="izin")
    except OSError as e:
        if e.errno == errno.ENOEXEC:
            return Cikti(komut, hata="format")
        if e.errno == errno.ENOENT:
            return Cikti(komut, hata="yorumlayici")
        return Cikti(komut, hata=str(e))

    out, err, durum = [], [], {}
    okuyucular = [threading.Thread(target=_okuyucu, args=(p.stdout, out, sinir, durum), daemon=True),
                  threading.Thread(target=_okuyucu, args=(p.stderr, err, sinir, durum), daemon=True)]
    for t in okuyucular:
        t.start()
    if girdi is not None:
        with contextlib.suppress(OSError):
            p.stdin.write(girdi.encode("utf-8"))
            p.stdin.close()
    asim = False
    try:
        p.wait(timeout=zaman_asimi)
    except subprocess.TimeoutExpired:
        asim = True
        _grubu_oldur(p.pid)
        with contextlib.suppress(subprocess.TimeoutExpired):
            p.wait(timeout=3)
    # Ana süreç bitti; arka plana atılmış işler boruyu hâlâ tutuyor olabilir.
    for t in okuyucular:
        kalan = max(0.1, zaman_asimi - (time.monotonic() - baslangic))
        t.join(timeout=kalan)
    if any(t.is_alive() for t in okuyucular):
        asim = True
    _grubu_oldur(p.pid)
    for t in okuyucular:
        t.join(timeout=3)
    for akis in (p.stdout, p.stderr):
        with contextlib.suppress(OSError):
            akis.close()
    return Cikti(
        komut=komut,
        kod=p.returncode,
        stdout=b"".join(out).decode("utf-8", "replace"),
        stderr=b"".join(err).decode("utf-8", "replace"),
        zaman_asimi=asim,
        sure=time.monotonic() - baslangic,
        kesildi=bool(durum.get("kesildi")),
        zaman_siniri=zaman_asimi,
    )


# ---------------------------------------------------------------- hata açıklamaları

_PY_IPUCLARI = [
    (r"IndexError: list index out of range", "Bir listenin olmayan elemanına eriştin: ya argüman eksik "
     "(önce `len(sys.argv)`'yi kontrol et) ya da `split()` ettiğin satırda beklediğin kadar alan yok."),
    (r"ModuleNotFoundError: No module named 'requests'", "Bu sistemde `requests` kurulu değil. Aynı işi "
     "standart kütüphanedeki `urllib.request` ile yapabilirsin."),
    (r"ModuleNotFoundError", "İçe aktardığın (import) modül bulunamadı; adını kontrol et."),
    (r"ValueError: invalid literal for int", "Sayıya çevrilemeyen bir metni `int()`'e verdin. "
     "Girdiyi `try/except ValueError` ile yakala."),
    (r"FileNotFoundError", "Açmaya çalıştığın dosya yok. Dosya yolunu argümandan mı aldın?"),
    (r"ConnectionRefusedError", "`connect()` kapalı portta hata fırlatır. `connect_ex()` kullan ya da "
     "`try/except` ile yakala."),
    (r"(socket\.timeout|TimeoutError)", "Bir bağlantı zaman aşımına uğradı ve yakalanmadı. "
     "`try/except` ile yakala, tarama devam etsin."),
    (r"urllib\.error\.HTTPError", "`urllib` 4xx/5xx cevaplarında `HTTPError` fırlatır. "
     "`except urllib.error.HTTPError as e:` ile yakalayıp `e.code`'u kullan."),
    (r"urllib\.error\.URLError", "Sunucuya bağlanılamadı (URLError). URL'yi ve portu kontrol et; "
     "hatayı `try/except` ile yakala."),
    (r"(IndentationError|TabError)", "Girinti hatası: Python'da bloklar girintiyle belirlenir. "
     "Sekme (tab) ile boşluğu karıştırma; 4 boşluk kullan."),
    (r"SyntaxError", "Söz dizimi hatası: iki nokta (:), parantez ya da tırnak eksik olabilir."),
    (r"NameError: name '(\w+)' is not defined", "Tanımlamadığın bir ad kullandın; yazım hatası ya da "
     "eksik `import` olabilir."),
    (r"PermissionError", "Bir dosyaya erişim izni yok."),
]


def _python_hatasi(stderr: str) -> Optional[str]:
    if "Traceback (most recent call last)" not in stderr and "Error" not in stderr:
        return None
    satirlar = [s for s in stderr.strip().splitlines() if s.strip()]
    if not satirlar:
        return None
    son = satirlar[-1].strip()
    if not re.match(r"^[\w.]+(Error|Exception|Interrupt|Exit)\b", son) and "Traceback" not in stderr:
        return None
    satir_no = None
    for s in satirlar:
        m = re.search(r'File "([^"]+)", line (\d+)', s)
        if m and not m.group(1).startswith("<") and "/lib/python" not in m.group(1):
            satir_no = m.group(2)
    yer = f" (betiğin {satir_no}. satırı)" if satir_no else ""
    mesaj = f"Betiğin Python hatasıyla durdu{yer}:\n    {son[:160]}"
    for desen, ipucu in _PY_IPUCLARI:
        if re.search(desen, stderr):
            mesaj += "\n    " + ipucu
            break
    return mesaj


def _bash_hatasi(stderr: str, betik_metni: str = "") -> Optional[str]:
    for s in stderr.splitlines():
        if "syntax error" in s:
            return ("Bash söz dizimi hatası:\n    " + s.strip()[:160]
                    + "\n    `then`, `do`, `done`, `fi` eksik ya da fazla olabilir.")
    for s in stderr.splitlines():
        if "missing `]'" in s or "missing ']'" in s:
            return ("Köşeli parantez hatası:\n    " + s.strip()[:160]
                    + "\n    `[` ve `]`'nin iki yanında boşluk olmalı: `if [ -z \"$1\" ]; then`")
        if "unary operator expected" in s or "binary operator expected" in s:
            return ("Test ifadesi hatası:\n    " + s.strip()[:160]
                    + "\n    Değişkeni tırnak içine al: `[ -z \"$1\" ]` (boş değişken tırnaksız kaybolur).")
        m = re.search(r":\s*([\w./-]+): (command not found|komut yok|not found)", s)
        if m:
            ad = m.group(1)
            if re.search(rf"^\s*{re.escape(ad)}\s+=", betik_metni, re.M):
                return (f"`{ad}: command not found` hatası. Değişken atamasında `=` işaretinin "
                        f"iki yanında boşluk olmamalı: `{ad}=\"deger\"`.")
            return f"Betikte bulunamayan bir komut var:\n    {s.strip()[:160]}"
    return None


def cokme_mesaji(c: Cikti, betik_metni: str = "") -> Optional[str]:
    """Betik başlatılamadı, takıldı ya da çöktüyse öğretici bir açıklama döndürür."""
    if c.hata == "izin":
        return "Betik çalıştırılamadı: çalıştırma izni yok. `chmod +x <betik>` yaz."
    if c.hata == "format":
        return ("Betik çalıştırılamadı (Exec format error). İlk satıra shebang koy: "
                "`#!/bin/bash` ya da `#!/usr/bin/env python3`.")
    if c.hata == "yorumlayici":
        return "Betik çalıştırılamadı: shebang satırındaki yorumlayıcı bulunamadı. `#!/bin/bash` yazdığından emin ol."
    if c.hata:
        return f"Betik çalıştırılamadı: {c.hata}"
    if c.zaman_asimi:
        return (f"Betiğin {c.zaman_siniri:.0f} saniyede bitmedi, durdurdum. Sonsuz döngü, bitmeyen bir "
                "arka plan işi ya da zaman aşımı (timeout) verilmemiş bir bağlantı olabilir.")
    return _python_hatasi(c.stderr) or (_bash_hatasi(c.stderr, betik_metni) if c.stderr else None)


# ---------------------------------------------------------------- betiği bulma ve hazırlama

def _lab_ici(yol: Path, lab: Path) -> bool:
    lab = lab.resolve()
    yol = yol.resolve()
    return yol == lab or lab in yol.parents


def betik_bul(b: Baglam, girdi: str, varsayilan: str) -> tuple:
    """(yol, hata_mesajı). Girdi verilmişse onun ilk parçası, yoksa varsayılan ad aranır."""
    lab = Path(b.lab)
    cwd = Path(b.calisma_dizini) if b.calisma_dizini else lab
    girdi = (girdi or "").strip()
    ad = girdi.split()[0].strip("\"'") if girdi else varsayilan
    p = Path(os.path.expanduser(ad))
    if p.is_absolute():
        adaylar = [p]
    else:
        adaylar = [cwd / p, lab / p]
        if not girdi:
            adaylar += sorted((x for x in lab.rglob(p.name) if x.is_file()),
                              key=lambda x: (len(x.parts), str(x)))
    for a in adaylar:
        if a.is_dir():
            return None, f"`{ad}` bir klasör. Betiğin kendisini ver: `cevap {b.gorev_no} {ad}/{varsayilan}`"
        if a.is_file():
            if not _lab_ici(a, lab):
                return None, (f"Betik lab klasörünün içinde olmalı ({lab}). Şu an {a.resolve()} "
                              f"dosyasını gösteriyorsun. Oraya kopyala: `cp {a} {lab}/`")
            return a.resolve(), ""
    mesaj = (f"`{ad}` adlı betiği bulamadım. Lab klasöründe ({lab}) tam bu adla bir dosya oluştur "
             f"(örn. `nano {Path(ad).name}`).")
    with contextlib.suppress(OSError):
        dosyalar = sorted({x.name for x in lab.rglob("*") if x.is_file()})
        benzer = difflib.get_close_matches(p.name, dosyalar, n=3, cutoff=0.75)
        if benzer:
            mesaj += f"\n    Benzer adlı dosya(lar) var: {', '.join(benzer)}. Ad birebir `{p.name}` olmalı."
    if girdi:
        mesaj += f"\n    Betik başka bir yerdeyse yolunu ver: `cevap {b.gorev_no} yol/{varsayilan}`"
    return None, mesaj


def tur_bul(yol: Path, ilk_satir: str) -> str:
    if yol.suffix == ".py" or "python" in ilk_satir:
        return "python"
    return "bash"


@dataclass
class Calistirici:
    """`denetle` fonksiyonuna verilen nesne: betiği istenen argümanlarla çalıştırır."""
    yol: Path
    tur: str
    cwd: Path
    zaman_asimi: float = VARSAYILAN_ZAMAN
    shebang: str = ""
    metin: str = ""                         # betiğin kaynak metni (hata açıklamaları için)
    gorunen: str = ""                       # oyuncunun bulunduğu dizine göre yol (mesajlar için)
    gecmis: list = field(default_factory=list)

    def __call__(self, *args, zaman_asimi: Optional[float] = None, girdi: Optional[str] = None,
                 cwd: Optional[Path] = None) -> Cikti:
        yorumlayici = sys.executable if self.tur == "python" else None
        c = calistir(self.yol, args, cwd=cwd or self.cwd, zaman_asimi=zaman_asimi or self.zaman_asimi,
                     girdi=girdi, yorumlayici=yorumlayici)
        self.gecmis.append(c)
        return c

    @property
    def ad(self) -> str:
        return self.yol.name

    def goster(self, *args) -> str:
        """Mesajlarda kullanmak için komut satırı: `./selam.sh Deniz` ya da `python3 x.py a`."""
        yol = self.gorunen or self.ad
        bas = f"python3 {yol}" if self.tur == "python" else (yol if yol.startswith("/") else f"./{yol}")
        return " ".join([bas] + [str(a) for a in args])

    def cokme(self, c: Cikti) -> Optional[str]:
        return cokme_mesaji(c, self.metin)


def hazirla(yol: Path, b: Baglam, tur: Optional[str] = None,
            zaman_asimi: float = VARSAYILAN_ZAMAN) -> tuple:
    """Ön denetim. (Calistirici | None, hata_mesajı, yakın_mı)."""
    try:
        ham = yol.read_bytes()[:200_000]
    except OSError as e:
        return None, f"Betik okunamadı: {e}", False
    cwd = Path(b.calisma_dizini) if b.calisma_dizini and _lab_ici(Path(b.calisma_dizini), Path(b.lab)) \
        else Path(b.lab)
    gorunen = os.path.relpath(yol, cwd)
    if gorunen.startswith(".."):
        gorunen = str(yol)
    if not ham.strip():
        return None, (f"`{gorunen}` boş. Kaydettin mi? nano'da Ctrl+O, Enter, sonra Ctrl+X."), True
    ilk = ham.split(b"\n", 1)[0]
    metin = ham.decode("utf-8", "replace")
    tur = tur or tur_bul(yol, ilk.decode("utf-8", "replace"))
    if b"\r\n" in ham[:4000]:
        return None, (f"`{gorunen}` Windows satır sonları (CRLF) içeriyor; Linux bunu `/bin/bash^M` gibi "
                      f"bozuk bir yorumlayıcı sanar. Düzelt: `sed -i 's/\\r$//' {gorunen}`"), True
    shebang = ilk.decode("utf-8", "replace").strip() if ilk.startswith(b"#!") else ""
    if tur == "bash":
        if not shebang:
            return None, (f"`{gorunen}` shebang ile başlamıyor. İlk satır tam olarak `#!/bin/bash` olmalı; "
                          "işletim sistemi dosyayı hangi programın çalıştıracağını buradan anlar."), True
        if not os.access(yol, os.X_OK):
            return None, (f"`{gorunen}` çalıştırılabilir değil. Önce izin ver: `chmod +x {gorunen}` "
                          f"(sonra `./{gorunen}` ile kendin de dene)."), True
    return Calistirici(yol=yol, tur=tur, cwd=cwd, zaman_asimi=zaman_asimi, shebang=shebang,
                       metin=metin, gorunen=gorunen), "", False


class BetikKontrol(Kontrol):
    """Oyuncunun betiğini bulup ön denetimden geçirir, sonra `denetle(b, calistir)`'ı çağırır.

    `denetle` bir `Sonuc` döndürür. `cozum` (md-lite) `pes` edildiğinde gösterilir;
    genellikle referans betiği kod bloğu içinde verir.
    """
    girdi_gerekmez = True

    def __init__(self, varsayilan: str, denetle: Callable[[Baglam, Calistirici], Sonuc], cozum: str,
                 tur: Optional[str] = None, zaman_asimi: float = VARSAYILAN_ZAMAN,
                 bicim: Optional[str] = None):
        self.varsayilan = varsayilan
        self.denetle = denetle
        self.cozum = cozum
        self.tur = tur
        self.zaman_asimi = zaman_asimi
        self.bicim = bicim or f"değer gerekmez: `cevap <no>` lab'daki {varsayilan} betiğini çalıştırıp dener"

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        yol, hata = betik_bul(b, girdi, self.varsayilan)
        if hata:
            return Sonuc(False, hata)
        calistirici, hata, yakin = hazirla(yol, b, self.tur, self.zaman_asimi)
        if hata:
            return Sonuc(False, hata, yakin=yakin)
        return self.denetle(b, calistirici)

    def cevabi_goster(self, b: Baglam) -> str:
        return yer_tut(self.cozum, b.senaryo)


# ---------------------------------------------------------------- denetim kalıpları

def kullanim_denetle(calistir: Calistirici, *args) -> Optional[str]:
    """Eksik argümanla çalıştırır; kullanım mesajı ve sıfırdan farklı çıkış kodu bekler.

    Sorun yoksa None, varsa öğretici mesaj döndürür.
    """
    c = calistir(*args)
    nasil = calistir.goster(*args)
    cokme = calistir.cokme(c)
    if c.zaman_asimi or c.hata:
        return f"`{nasil}` çalıştırınca sorun çıktı. {cokme}"
    if not kullanim_var(c):
        if cokme:
            return (f"`{nasil}` (eksik argümanla) çalıştırınca kullanım mesajı bekliyordum ama betik "
                    f"hata verdi. {cokme}")
        return (f"`{nasil}` (eksik argümanla) çalıştırınca bir kullanım mesajı bekliyordum, örn. "
                f"`Kullanım: $0 <hedef>`. Mesajda \"Kullanım\" kelimesi geçsin." + ozet(c))
    if c.kod == 0:
        return (f"`{nasil}` kullanım mesajını bastı ama çıkış kodu 0 (başarı). Hatalı kullanımda "
                "`exit 1` (Python'da `sys.exit(1)`) ile çık; böylece başka betikler de hatayı anlar.")
    return None


def betik_yaz(yol: Path, icerik: str) -> Path:
    """Test çözücüsü için: referans betiği yazar ve çalıştırılabilir yapar."""
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(icerik.lstrip("\n"), encoding="utf-8")
    os.chmod(yol, 0o755)
    return yol


# ---------------------------------------------------------------- geçici dinleyiciler

class GeciciDinleyici:
    """Kontrol sırasında 127.x üzerinde geçici TCP dinleyicileri açar (bağlam yöneticisi).

        with bt.GeciciDinleyici([("127.31.7.4", 23456), ("127.31.7.9", 23456)]) as d:
            ...  # betiği bu adreslere karşı çalıştır

    Bağlantıyı çekirdek kabul eder; uygulama tarafında accept gerekmez. `banner` verilirse
    gelen bağlantılara bu satırı gönderen küçük bir iş parçacığı çalışır.
    """

    def __init__(self, adresler: list, banner: Optional[str] = None):
        for host, _ in adresler:
            if not str(host).startswith("127."):
                raise ValueError("Geçici dinleyiciler sadece 127.x.x.x üzerinde açılabilir")
        self.adresler = list(adresler)
        self.banner = banner
        self.soketler: list = []
        self._dur = threading.Event()

    def __enter__(self):
        try:
            for host, port in self.adresler:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen(64)
                self.soketler.append(s)
        except OSError:
            self.__exit__()
            raise
        if self.banner is not None:
            for s in self.soketler:
                threading.Thread(target=self._kabul, args=(s,), daemon=True).start()
        return self

    def _kabul(self, s: socket.socket) -> None:
        s.settimeout(0.2)
        while not self._dur.is_set():
            try:
                c, _ = s.accept()
            except (socket.timeout, OSError):
                continue
            with contextlib.suppress(OSError):
                c.sendall(self.banner.encode("utf-8"))
            with contextlib.suppress(OSError):
                c.close()

    def __exit__(self, *a):
        self._dur.set()
        for s in self.soketler:
            with contextlib.suppress(OSError):
                s.close()
        self.soketler = []


def gecici_dinleyici_ac(rng, adres_uret: Callable, deneme: int = 6, banner: Optional[str] = None):
    """`adres_uret(rng) -> [(host, port), ...]` ile dinleyici açmayı birkaç kez dener.

    Port doluysa yeni adreslerle tekrar dener. Açılmış `GeciciDinleyici` döndürür
    (çağıran `with` ile kapatmalı ya da `__exit__()` çağırmalı).
    """
    son_hata = None
    for _ in range(deneme):
        d = GeciciDinleyici(adres_uret(rng), banner=banner)
        try:
            return d.__enter__()
        except OSError as e:
            son_hata = e
    raise RuntimeError(f"Geçici dinleyici açılamadı: {son_hata}")
