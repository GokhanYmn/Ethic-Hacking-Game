"""Cilt 9 seviyelerinin ortak yardımcıları (motoru ve hy/ortak'ı değiştirmeden).

- `yaml_oku`: PyYAML olmadan, docker-compose dosyalarının kullandığı YAML alt kümesini ayrıştırır
  (blok haritalar/listeler, [a, b] listeleri, {a: b} haritaları, tırnaklı/tırnaksız değerler).
  Satır numaralı hata verir; girintideki TAB karakterini YAML gibi reddeder.
- `portlar`, `ulasabilir`, `riskler`...: compose dosyasını statik çözümler (port bağları, ağlar, riskler).
- `dosya_bul`, `sh`: oyuncunun yazdığı dosyayı bulmak ve test çözücüsünün komut çalıştırması için.
- `docker_canli`: Docker kuruluysa `docker compose config -q` ile canlı sınama (yoksa None).
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional


class YamlHata(ValueError):
    def __init__(self, mesaj: str, satir: Optional[int] = None):
        self.mesaj = mesaj
        self.satir = satir
        super().__init__(f"satır {satir}: {mesaj}" if satir else mesaj)


# ------------------------------------------------------------------ mini YAML

def _yorum_at(s: str) -> str:
    tirnak = None
    for i, ch in enumerate(s):
        if tirnak:
            if ch == tirnak:
                tirnak = None
        elif ch in "\"'" and (i == 0 or s[i - 1] in " [,:{"):
            tirnak = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


def _virgul_bol(s: str) -> list:
    parcalar, simdiki, tirnak, derin = [], "", None, 0
    for ch in s:
        if tirnak:
            simdiki += ch
            if ch == tirnak:
                tirnak = None
        elif ch in "\"'":
            tirnak = ch
            simdiki += ch
        elif ch in "[{":
            derin += 1
            simdiki += ch
        elif ch in "]}":
            derin -= 1
            simdiki += ch
        elif ch == "," and derin == 0:
            parcalar.append(simdiki)
            simdiki = ""
        else:
            simdiki += ch
    if simdiki.strip():
        parcalar.append(simdiki)
    return [p.strip() for p in parcalar]


def _skaler(v: str, no: Optional[int] = None) -> Any:
    v = v.strip()
    if v.startswith('"'):
        if len(v) < 2 or not v.endswith('"'):
            raise YamlHata("kapanmamış çift tırnak", no)
        return v[1:-1].replace('\\"', '"')
    if v.startswith("'"):
        if len(v) < 2 or not v.endswith("'"):
            raise YamlHata("kapanmamış tek tırnak", no)
        return v[1:-1].replace("''", "'")
    if v.startswith("["):
        if not v.endswith("]"):
            raise YamlHata("kapanmamış [ ] listesi", no)
        return [_skaler(p, no) for p in _virgul_bol(v[1:-1])]
    if v.startswith("{"):
        if not v.endswith("}"):
            raise YamlHata("kapanmamış { } haritası", no)
        harita = {}
        for p in _virgul_bol(v[1:-1]):
            if ":" not in p:
                raise YamlHata("{ } içinde anahtar: değer bekleniyordu", no)
            k, _, d = p.partition(":")
            harita[str(_skaler(k, no))] = _skaler(d, no)
        return harita
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", v):
        return int(v)
    return v


_ANAHTAR = re.compile(r"""^("[^"]*"|'[^']*'|[^\s:"'\[\{][^:]*?)\s*:(?:\s+(.*))?$""")
_ANAHTAR_MI = re.compile(r"""^[^\s\[\{"'\-][^:]*:(\s|$)|^("[^"]*"|'[^']*')\s*:(\s|$)""")


def _liste_mi(govde: str) -> bool:
    return govde == "-" or govde.startswith("- ")


def _liste(s: list, i: int, g: int):
    sonuc = []
    while i < len(s) and s[i][0] == g and _liste_mi(s[i][1]):
        ic = s[i][1][1:].strip()
        no = s[i][2]
        if ic == "":
            i += 1
            if i < len(s) and s[i][0] > g:
                d, i = _blok(s, i, s[i][0])
                sonuc.append(d)
            else:
                sonuc.append(None)
        elif _ANAHTAR_MI.match(ic):
            ofset = len(s[i][1]) - len(ic)
            s[i] = [g + ofset, ic, no]
            d, i = _harita(s, i, g + ofset)
            sonuc.append(d)
        else:
            sonuc.append(_skaler(ic, no))
            i += 1
    if i < len(s) and s[i][0] > g:
        raise YamlHata("girinti tutarsız", s[i][2])
    return sonuc, i


def _harita(s: list, i: int, g: int):
    d: dict = {}
    while i < len(s) and s[i][0] == g:
        govde, no = s[i][1], s[i][2]
        if _liste_mi(govde):
            raise YamlHata("harita içinde beklenmeyen liste öğesi (girinti hatası olabilir)", no)
        m = _ANAHTAR.match(govde)
        if not m:
            raise YamlHata(f"`anahtar: değer` biçimi bekleniyordu: {govde[:40]!r}", no)
        anahtar = str(_skaler(m.group(1), no)) if m.group(1)[0] in "\"'" else m.group(1).strip()
        if anahtar in d:
            raise YamlHata(f"`{anahtar}` anahtarı iki kez yazılmış", no)
        deger = m.group(2)
        i += 1
        if deger is None or deger.strip() == "":
            if i < len(s) and s[i][0] > g:
                v, i = _blok(s, i, s[i][0])
            elif i < len(s) and s[i][0] == g and _liste_mi(s[i][1]):
                v, i = _liste(s, i, g)
            else:
                v = None
        elif deger.strip()[0] in "|>":
            parcalar = []
            while i < len(s) and s[i][0] > g:
                parcalar.append(s[i][1])
                i += 1
            v = "\n".join(parcalar)
        else:
            v = _skaler(deger, no)
            if i < len(s) and s[i][0] > g:
                raise YamlHata("beklenmeyen girinti", s[i][2])
        d[anahtar] = v
    if i < len(s) and s[i][0] > g:
        raise YamlHata("girinti tutarsız", s[i][2])
    return d, i


def _blok(s: list, i: int, g: int):
    return _liste(s, i, g) if _liste_mi(s[i][1]) else _harita(s, i, g)


def yaml_oku(metin: str) -> Any:
    satirlar = []
    for no, ham in enumerate(metin.splitlines(), 1):
        govde = _yorum_at(ham).rstrip()
        if not govde.strip() or govde.strip() == "---":
            continue
        kalin = len(govde) - len(govde.lstrip(" \t"))
        if "\t" in govde[:kalin]:
            raise YamlHata("girintide TAB karakteri var (YAML yalnızca boşlukla girinti kabul eder)", no)
        satirlar.append([kalin, govde.strip(), no])
    if not satirlar:
        return {}
    deger, i = _blok(satirlar, 0, satirlar[0][0])
    if i < len(satirlar):
        raise YamlHata("girinti tutarsız", satirlar[i][2])
    return deger


# ------------------------------------------------------------------ compose çözümleme

def compose_oku(yol: Path) -> dict:
    """compose dosyasını okur; geçerli bir `services:` haritası yoksa YamlHata fırlatır."""
    d = yaml_oku(Path(yol).read_text(encoding="utf-8", errors="replace"))
    if not isinstance(d, dict):
        raise YamlHata("dosyanın en üstünde `services:` gibi anahtarlar olmalı")
    sv = d.get("services")
    if not isinstance(sv, dict) or not sv:
        raise YamlHata("`services:` bölümü yok ya da boş")
    for ad, s in sv.items():
        if not isinstance(s, dict):
            raise YamlHata(f"`{ad}` servisinin altında ayarlar (image: ...) bulunmalı")
    return d


def servisler(d: dict) -> dict:
    return d["services"]


def imaj_depo(imaj: Any) -> str:
    """'ghcr.io/x/y:1.2' -> 'ghcr.io/x/y' (etiketi ve özeti atar)."""
    s = str(imaj or "").split("@")[0]
    son = s.rsplit("/", 1)[-1]
    if ":" in son:
        s = s[: s.rfind(":")]
    return s


def imaj_etiket(imaj: Any) -> str:
    s = str(imaj or "")
    son = s.rsplit("/", 1)[-1]
    return son.split(":", 1)[1] if ":" in son and "@" not in s else ""


def etiket_sabit_mi(imaj: Any) -> bool:
    """Etiket yazılmış ve 'latest' değil mi?"""
    e = imaj_etiket(imaj)
    return bool(e) and e != "latest"


def portlar(servis: dict) -> list:
    """Servisin port eşlemeleri: [{'ip', 'host', 'konteyner', 'lokal'}]. Çözülemeyen girdi 'hata' taşır."""
    sonuc = []
    ham = servis.get("ports") or []
    if not isinstance(ham, list):
        return [{"hata": "ports bir liste olmalı", "ip": "", "host": None, "konteyner": None, "lokal": False}]

    def _int(x):
        try:
            return int(x)
        except (TypeError, ValueError):
            return None

    for p in ham:
        ip, host, kon = "", None, None
        if isinstance(p, dict):
            ip = str(p.get("host_ip") or "")
            host = p.get("published")
            kon = p.get("target")
        else:
            t = str(p).split("/")[0]
            m6 = re.fullmatch(r"\[(.+?)\]:(\d*):(\d+)", t)
            if m6:
                ip, host, kon = m6.group(1), m6.group(2) or None, m6.group(3)
            else:
                parca = t.split(":")
                if len(parca) == 1:
                    kon = parca[0]
                elif len(parca) == 2:
                    host, kon = parca
                elif len(parca) == 3:
                    ip, host, kon = parca
                else:
                    sonuc.append({"hata": f"anlaşılmayan port: {p}", "ip": "", "host": None,
                                  "konteyner": None, "lokal": False})
                    continue
        sonuc.append({"ip": ip, "host": _int(host), "konteyner": _int(kon),
                      "lokal": ip.startswith("127.") or ip == "::1"})
    return sonuc


def servis_aglari(d: dict, ad: str) -> list:
    s = servisler(d)[ad]
    a = s.get("networks")
    if isinstance(a, dict):
        return list(a.keys())
    if isinstance(a, list):
        return [str(x) for x in a]
    return ["default"]


def ag_ic_mi(d: dict, ag: str) -> bool:
    tanim = (d.get("networks") or {}).get(ag)
    return isinstance(tanim, dict) and tanim.get("internal") is True


def ag_sorunlari(d: dict) -> list:
    """Tanımsız ağ başvurusu gibi docker'ın da reddedeceği hatalar."""
    tanimli = set((d.get("networks") or {}).keys()) | {"default"}
    sorun = []
    for ad in servisler(d):
        for ag in servis_aglari(d, ad):
            if ag not in tanimli:
                sorun.append(f"`{ad}` servisi `{ag}` ağını kullanıyor ama üstteki `networks:` bölümünde tanımlı değil.")
    return sorun


def ulasabilir(d: dict, ad: str) -> set:
    """`ad` servisiyle en az bir ağı paylaşan (doğrudan ulaşabildiği) diğer servisler."""
    benim = set(servis_aglari(d, ad))
    return {o for o in servisler(d) if o != ad and benim & set(servis_aglari(d, o))}


def internete_cikar(d: dict, ad: str) -> bool:
    s = servisler(d)[ad]
    if s.get("network_mode") == "host":
        return True
    return any(not ag_ic_mi(d, a) for a in servis_aglari(d, ad))


def mem_mb(deger: Any) -> Optional[float]:
    """'512m', '1g', '1.5G', 268435456 -> MB."""
    if deger is None:
        return None
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([bkmg]?)b?", str(deger).strip().lower())
    if not m:
        return None
    n = float(m.group(1))
    return n * {"": 1 / 1048576, "b": 1 / 1048576, "k": 1 / 1024, "m": 1.0, "g": 1024.0}[m.group(2)]


def riskler(d: dict) -> list:
    """Lab güvenlik kuralları: [(servis, kural_kodu)]. Kodlar: port, privileged, sock, host_ag, etiket."""
    bulunan = []
    for ad, s in servisler(d).items():
        for p in portlar(s):
            if not p.get("lokal"):
                bulunan.append((ad, "port"))
        if s.get("privileged") is True:
            bulunan.append((ad, "privileged"))
        if any("docker.sock" in str(v) for v in (s.get("volumes") or [])):
            bulunan.append((ad, "sock"))
        if s.get("network_mode") == "host":
            bulunan.append((ad, "host_ag"))
        if "image" in s and not etiket_sabit_mi(s.get("image")):
            bulunan.append((ad, "etiket"))
    return bulunan


RISK_ACIKLAMA = {
    "port": "127.0.0.1'e bağlı olmayan port (ağdaki herkese açık)",
    "privileged": "`privileged: true` (konteyner neredeyse ana makine yetkisinde)",
    "sock": "`docker.sock` bağlanmış (konteyner Docker'ı, yani makineyi yönetebilir)",
    "host_ag": "`network_mode: host` (konteyner ana makinenin ağına doğrudan çıkar)",
    "etiket": "sabit sürüm etiketi yok (`latest` ya da etiketsiz)",
}


# ------------------------------------------------------------------ dosya/komut yardımcıları

def dosya_bul(b, ad: str) -> Optional[Path]:
    for kok in (b.calisma_dizini, b.lab):
        if kok and (Path(kok) / ad).is_file():
            return Path(kok) / ad
    return None


def bulunamadi(ad: str):
    from hy.motor.kontrol import Sonuc
    return Sonuc(False, f"`{ad}` bulunamadı. Dosyayı lab klasöründe (ya da bulunduğun klasörde) `{ad}` adıyla oluştur.")


def sh(komut: str, cwd: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=cwd, capture_output=True, text=True).stdout.strip()


def docker_var() -> bool:
    return shutil.which("docker") is not None


def docker_canli(yol: Path) -> Optional[str]:
    """Docker varsa `docker compose config -q` çalıştırır. Docker'ın şikâyeti varsa metnini döndürür;
    Docker yok/erişilemiyor/compose eklentisi yoksa None (statik kontrol yeterli sayılır)."""
    if not docker_var():
        return None
    try:
        r = subprocess.run(["docker", "compose", "-f", str(yol), "config", "-q"], cwd=Path(yol).parent,
                           capture_output=True, text=True, timeout=25)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode == 0:
        return None
    hata = (r.stderr or "").strip()
    dusuk = hata.lower()
    if any(x in dusuk for x in ("unknown", "not a docker command", "permission denied", "cannot connect")):
        return None
    return hata.splitlines()[0][:300] if hata else "bilinmeyen hata"


def compose_denetle(yol: Path, ad: str):
    """Ortak ilk adım: dosyayı oku/çözümle. (Sonuc, None) hata ya da (None, d) başarı döndürür."""
    from hy.motor.kontrol import Sonuc
    try:
        d = compose_oku(yol)
    except YamlHata as e:
        return Sonuc(False, f"`{ad}` YAML olarak okunamadı ({e}). Girintileri (2 boşluk), `:` işaretlerini ve "
                            "TAB karakteri olmadığını kontrol et."), None
    sorun = ag_sorunlari(d)
    if sorun:
        return Sonuc(False, sorun[0]), None
    canli = docker_canli(yol)
    if canli:
        return Sonuc(False, f"Docker bu dosyayı reddetti: {canli}"), None
    return None, d


def adlar_tr(adlar) -> str:
    return ", ".join(f"`{a}`" for a in sorted(adlar))


# ------------------------------------------------------------------ "anahtar: değer | anahtar: değer" kayıtları

def alanlar(satir: str) -> dict:
    """'hedef: ad | ram_mb: 512 | tur: vm' -> {'hedef': 'ad', 'ram_mb': '512', 'tur': 'vm'}"""
    sonuc = {}
    for parca in satir.split("|"):
        k, _, v = parca.partition(":")
        if k.strip():
            sonuc[k.strip()] = v.strip()
    return sonuc


def kayitlar(metin: str, onek: str) -> list:
    """`onek:` ile başlayan satırların alanlar() sözlükleri (yorum satırları atlanır)."""
    return [alanlar(s) for s in (x.strip() for x in metin.splitlines()) if s.startswith(onek + ":")]
