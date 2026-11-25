"""Cevap kontrol türleri.

Her kontrol `dogrula(girdi, baglam) -> Sonuc` ve `cevabi_goster(baglam) -> str` sağlar.
Beklenen değerler senaryo['cevaplar'][anahtar] içinden okunur; senaryo tohumdan
yeniden üretildiği için kayıt dosyasında cevap tutulmaz.

Sık hata geri bildirimi: `sik_hatalar` ya bir sözlük {normalize_yanlis_cevap: mesaj}
ya da `fonk(girdi_norm, beklenen, baglam) -> mesaj | None` olabilir.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

IP_DESENI = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Sonuc:
    dogru: bool
    mesaj: str = ""
    yakin: bool = False


@dataclass
class Baglam:
    senaryo: dict
    lab: Path
    gorev_no: int
    calisma_dizini: Optional[Path] = None   # cevap komutunun çalıştırıldığı dizin


def norm(s: Any) -> str:
    """Karşılaştırma için normalize eder: kırp, tırnakları at, boşlukları tekle, küçült.

    Türkçe İ/ı farkı esnetilir (admın == admin) ki klavye sorunu cezalandırılmasın.
    """
    s = str(s).strip().strip("\"'`").strip()
    s = re.sub(r"\s+", " ", s)
    return s.replace("İ", "i").casefold().replace("ı", "i")


def _liste(deger: Any) -> list:
    if isinstance(deger, (list, tuple, set, frozenset)):
        return list(deger)
    return [deger]


def _sik_hata(sik_hatalar, girdi_norm: str, beklenen: Any, b: Baglam) -> Optional[str]:
    if not sik_hatalar:
        return None
    if callable(sik_hatalar):
        return sik_hatalar(girdi_norm, beklenen, b)
    for anahtar, mesaj in sik_hatalar.items():
        if norm(anahtar) == girdi_norm:
            return mesaj
    return None


class Kontrol:
    girdi_gerekmez = False
    bicim = "cevabın"                      # oyuncuya gösterilen cevap biçimi ipucu

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:  # pragma: no cover - soyut
        raise NotImplementedError

    def cevabi_goster(self, b: Baglam) -> str:  # pragma: no cover - soyut
        raise NotImplementedError

    def ek_metin(self, b: Baglam) -> str:
        """Soru altına eklenecek metin (örn. şıklar)."""
        return ""

    def beklenen(self, b: Baglam) -> Any:
        return b.senaryo["cevaplar"][self.anahtar]  # type: ignore[attr-defined]


class Bayrak(Kontrol):
    """FLAG{...} biçimli bayrak. Tam eşleşme (büyük/küçük harf duyarsız)."""
    bicim = "FLAG{...}"

    def __init__(self, anahtar: str):
        self.anahtar = anahtar

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        beklenen = str(self.beklenen(b)).strip()
        g = girdi.strip().strip("\"'")
        if g.casefold() == beklenen.casefold():
            return Sonuc(True)
        ic = re.sub(r"^FLAG\{(.*)\}$", r"\1", beklenen)
        if g.casefold() == ic.casefold():
            return Sonuc(False, "Doğru bayrak ama tamamını yaz: FLAG{...} dahil.", yakin=True)
        if re.match(r"^FLAG\{.*\}$", g, re.I):
            return Sonuc(False, "Bu bir bayrak, ama bu görevin bayrağı değil.")
        return Sonuc(False, "Bayrak FLAG{...} biçiminde olmalı.")

    def cevabi_goster(self, b: Baglam) -> str:
        return str(self.beklenen(b))


class Metin(Kontrol):
    """Serbest metin; beklenen tek değer veya kabul edilen değerler listesi.

    `on_ekleri_at`: karşılaştırmadan önce girdinin başından atılacak kalıplar
    (örn. ("cd ",) ile "cd ../loglar" de kabul edilir).
    """

    def __init__(self, anahtar: Optional[str] = None, kabul: Optional[list] = None,
                 sik_hatalar=None, on_ekleri_at: tuple = (), son_ekleri_at: tuple = (),
                 bicim: str = "cevabın", sadece_ad: bool = False):
        self.anahtar = anahtar
        self.kabul = kabul
        self.sik_hatalar = sik_hatalar
        self.on_ekleri_at = on_ekleri_at
        self.son_ekleri_at = son_ekleri_at
        self.bicim = bicim
        self.sadece_ad = sadece_ad   # girdi bir yolsa sadece son parçası (dosya adı) karşılaştırılır

    def _beklenenler(self, b: Baglam) -> list:
        degerler = []
        if self.anahtar is not None:
            degerler += _liste(self.beklenen(b))
        if self.kabul:
            degerler += list(self.kabul)
        return degerler

    def _temizle(self, s: str) -> str:
        s = norm(s)
        for on in self.on_ekleri_at:
            p = on.replace("İ", "i").casefold()
            if s.startswith(p):
                s = s[len(p):].strip()
        for son in self.son_ekleri_at:
            p = son.replace("İ", "i").casefold()
            if s.endswith(p) and len(s) > len(p):
                s = s[: -len(p)].strip()
        if self.sadece_ad:
            s = s.rstrip("/").rsplit("/", 1)[-1]
        return s

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        g = self._temizle(girdi)
        beklenenler = self._beklenenler(b)
        if any(g == self._temizle(str(x)) for x in beklenenler):
            return Sonuc(True)
        mesaj = _sik_hata(self.sik_hatalar, g, beklenenler[0] if beklenenler else None, b)
        return Sonuc(False, mesaj or "", yakin=bool(mesaj))

    def cevabi_goster(self, b: Baglam) -> str:
        return str(self._beklenenler(b)[0])


def sayi_cek(girdi: str) -> Optional[int]:
    """Girdiden ilk tam sayıyı çeker; IP adreslerindeki sayıları yok sayar."""
    temiz = IP_DESENI.sub(" ", girdi)
    m = re.search(r"-?\d+", temiz.replace(".", ""))
    return int(m.group(0)) if m else None


class Sayi(Kontrol):
    bicim = "bir sayı"

    def __init__(self, anahtar: str, tolerans: int = 0, sik_hatalar=None):
        self.anahtar = anahtar
        self.tolerans = tolerans
        self.sik_hatalar = sik_hatalar

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        n = sayi_cek(girdi)
        if n is None:
            return Sonuc(False, "Cevap olarak bir sayı yaz.")
        beklenen = int(self.beklenen(b))
        if abs(n - beklenen) <= self.tolerans:
            return Sonuc(True)
        mesaj = _sik_hata(self.sik_hatalar, str(n), beklenen, b)
        return Sonuc(False, mesaj or "", yakin=bool(mesaj))

    def cevabi_goster(self, b: Baglam) -> str:
        return str(self.beklenen(b))


class IP(Kontrol):
    """Girdideki ilk IPv4 adresi beklenen(ler)den biri olmalı."""
    bicim = "bir IP adresi"

    def __init__(self, anahtar: str, sik_hatalar=None):
        self.anahtar = anahtar
        self.sik_hatalar = sik_hatalar

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        m = IP_DESENI.search(girdi)
        if not m:
            return Sonuc(False, "Cevap olarak bir IP adresi yaz (örn. 10.0.0.5).")
        beklenenler = [str(x) for x in _liste(self.beklenen(b))]
        if m.group(0) in beklenenler:
            return Sonuc(True)
        mesaj = _sik_hata(self.sik_hatalar, m.group(0), beklenenler[0], b)
        return Sonuc(False, mesaj or "", yakin=bool(mesaj))

    def cevabi_goster(self, b: Baglam) -> str:
        return str(_liste(self.beklenen(b))[0])


class Kume(Kontrol):
    """Sırası önemsiz değer kümesi (virgül/boşlukla ayrılmış). Eksik/fazla sayısını söyler."""

    def __init__(self, anahtar: str, tur: str = "metin", sik_hatalar=None,
                 bicim: str = "virgülle ayrılmış liste"):
        self.anahtar = anahtar
        self.tur = tur
        self.sik_hatalar = sik_hatalar
        self.bicim = bicim

    def _parcala(self, girdi: str) -> set:
        if self.tur == "ip":
            return set(IP_DESENI.findall(girdi))
        parcalar = [p for p in re.split(r"[\s,;]+", girdi) if p]
        if self.tur == "sayi":
            return {int(p) for p in parcalar if re.fullmatch(r"-?\d+", p)}
        return {norm(p) for p in parcalar}

    def _beklenen_kume(self, b: Baglam) -> set:
        ham = _liste(self.beklenen(b))
        if self.tur == "sayi":
            return {int(x) for x in ham}
        if self.tur == "ip":
            return {str(x) for x in ham}
        return {norm(x) for x in ham}

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        verilen = self._parcala(girdi)
        beklenen = self._beklenen_kume(b)
        if not verilen:
            return Sonuc(False, f"Cevabı {self.bicim} olarak yaz.")
        if verilen == beklenen:
            return Sonuc(True)
        dogru = len(verilen & beklenen)
        eksik = len(beklenen - verilen)
        fazla = len(verilen - beklenen)
        mesaj = _sik_hata(self.sik_hatalar, " ".join(sorted(map(str, verilen))), beklenen, b)
        if not mesaj:
            parca = [f"{dogru} doğru"]
            if eksik:
                parca.append(f"{eksik} eksik")
            if fazla:
                parca.append(f"{fazla} fazla")
            mesaj = "Yaklaştın: " + ", ".join(parca) + "." if dogru else ""
        return Sonuc(False, mesaj, yakin=dogru > 0)

    def cevabi_goster(self, b: Baglam) -> str:
        return ", ".join(sorted(map(str, _liste(self.beklenen(b)))))


class Secmeli(Kontrol):
    """Çoktan seçmeli. Şıklar seviye+görev tohumuyla karıştırılır.

    `secenekler`: [(metin, aciklama), ...]; ilk `dogru` indeksli şık doğrudur.
    Açıklama, o şık seçildiğinde gösterilir (yanlış şıklar için öğretici geri bildirim).
    """
    bicim = "a, b, c veya d"

    def __init__(self, secenekler: list, dogru: int = 0, karistir: bool = True):
        self.secenekler = secenekler
        self.dogru = dogru
        self.karistir = karistir

    def _sira(self, b: Baglam) -> list:
        sira = list(range(len(self.secenekler)))
        if self.karistir:
            tohum = f"{b.senaryo.get('_tohum', '')}:{b.gorev_no}"
            random.Random(tohum).shuffle(sira)
        return sira

    def ek_metin(self, b: Baglam) -> str:
        harfler = "abcdefgh"
        return "\n".join(f"   {harfler[i]}) {self.secenekler[j][0]}" for i, j in enumerate(self._sira(b)))

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        g = norm(girdi)[:1]
        harfler = "abcdefgh"
        sira = self._sira(b)
        if not g or g not in harfler[: len(sira)]:
            return Sonuc(False, f"Şıklardan birini yaz: {', '.join(harfler[:len(sira)])}.")
        secilen = sira[harfler.index(g)]
        aciklama = self.secenekler[secilen][1] if len(self.secenekler[secilen]) > 1 else ""
        return Sonuc(secilen == self.dogru, aciklama)

    def cevabi_goster(self, b: Baglam) -> str:
        harf = "abcdefgh"[self._sira(b).index(self.dogru)]
        return f"{harf}) {self.secenekler[self.dogru][0]}"


class Durum(Kontrol):
    """Girdi gerekmez: `cevap <no>` yazıldığında sistemin durumunu kontrol eder.

    `fonk(baglam) -> Sonuc` — örn. dosya izni 600 mü, süreç öldürüldü mü.
    """
    girdi_gerekmez = True
    bicim = "(değer gerekmez, sadece `cevap <no>`)"

    def __init__(self, fonk: Callable[[Baglam], Sonuc], cozum: str):
        self.fonk = fonk
        self.cozum = cozum

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        return self.fonk(b)

    def cevabi_goster(self, b: Baglam) -> str:
        return self.cozum


class Dinamik(Kontrol):
    """Beklenen değer kontrol anında hesaplanır (oyuncunun kendi sistemine bağlı sorular).

    `hesapla(baglam)` tek değer ya da kabul listesi döndürür. `tur`: metin | sayi | kume
    """

    def __init__(self, hesapla: Callable[[Baglam], Any], tur: str = "metin", tolerans: int = 0,
                 sik_hatalar=None, bicim: str = "cevabın", on_ekleri_at: tuple = ()):
        self.hesapla = hesapla
        self.tur = tur
        self.tolerans = tolerans
        self.sik_hatalar = sik_hatalar
        self.bicim = bicim
        self.on_ekleri_at = on_ekleri_at

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        beklenen = self.hesapla(b)
        if self.tur == "sayi":
            n = sayi_cek(girdi)
            if n is None:
                return Sonuc(False, "Cevap olarak bir sayı yaz.")
            if abs(n - int(beklenen)) <= self.tolerans:
                return Sonuc(True)
            mesaj = _sik_hata(self.sik_hatalar, str(n), beklenen, b)
            return Sonuc(False, mesaj or "", yakin=bool(mesaj))
        if self.tur == "kume":
            verilen = {norm(p) for p in re.split(r"[\s,;]+", girdi) if p}
            hedef = {norm(x) for x in _liste(beklenen)}
            if verilen == hedef:
                return Sonuc(True)
            dogru = len(verilen & hedef)
            return Sonuc(False, f"Yaklaştın: {dogru}/{len(hedef)} doğru." if dogru else "", yakin=dogru > 0)
        g = norm(girdi)
        for on in self.on_ekleri_at:
            p = on.replace("İ", "i").casefold()
            if g.startswith(p):
                g = g[len(p):].strip()
        if any(g == norm(x) for x in _liste(beklenen)):
            return Sonuc(True)
        mesaj = _sik_hata(self.sik_hatalar, g, beklenen, b)
        return Sonuc(False, mesaj or "", yakin=bool(mesaj))

    def cevabi_goster(self, b: Baglam) -> str:
        beklenen = self.hesapla(b)
        if self.tur == "kume":
            return ", ".join(map(str, _liste(beklenen)))
        return str(_liste(beklenen)[0])


class Serbest(Kontrol):
    """Açık uçlu cevap (rapor cümlesi, gerekçe). Yeterli uzunluktaysa kabul edilir
    ve oyuncu kendi cevabını örnek cevapla karşılaştırır."""
    bicim = "kendi cümlelerinle (tırnak içinde)"

    def __init__(self, ornek: str, min_kelime: int = 6):
        self.ornek = ornek
        self.min_kelime = min_kelime

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        if len(girdi.split()) < self.min_kelime:
            return Sonuc(False, f"Biraz daha aç: en az {self.min_kelime} kelimelik bir cevap yaz.")
        from hy.motor.seviye import yer_tut
        return Sonuc(True, "Kendi cevabını örnekle karşılaştır:\n" + yer_tut(self.ornek, b.senaryo))

    def cevabi_goster(self, b: Baglam) -> str:
        from hy.motor.seviye import yer_tut
        return yer_tut(self.ornek, b.senaryo)


class Hepsi(Kontrol):
    """Aynı girdi birden fazla kontrolden geçmeli (örn. 'IP ve istek sayısı')."""

    def __init__(self, kontroller: list, bicim: str = "cevabın"):
        self.kontroller = kontroller
        self.bicim = bicim

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        sonuclar = [k.dogrula(girdi, b) for k in self.kontroller]
        if all(s.dogru for s in sonuclar):
            return Sonuc(True)
        tutan = sum(s.dogru for s in sonuclar)
        mesajlar = [s.mesaj for s in sonuclar if not s.dogru and s.mesaj]
        mesaj = " ".join(mesajlar)
        if tutan:
            mesaj = f"Parçalardan {tutan}/{len(sonuclar)} doğru. " + mesaj
        return Sonuc(False, mesaj.strip(), yakin=tutan > 0)

    def cevabi_goster(self, b: Baglam) -> str:
        return " ".join(k.cevabi_goster(b) for k in self.kontroller)
