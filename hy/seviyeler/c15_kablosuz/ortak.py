"""Cilt 15 ortak yardımcıları: kurgusal tarama CSV'si (airodump benzeri), MAC üretimi, basit INI okuyucu.

Her şey kurgusaldır. MAC adresleri rastgele üretilir; SSID'ler ve alan adları kurgusaldır.
Saldırı aracı komutu yoktur: oyuncu yalnızca metin dosyalarını analiz eder ve yapılandırmayı düzeltir.
"""
from __future__ import annotations

from pathlib import Path

from hy.seviyeler.c14_mobil.ortak import sec_doldur, sh  # noqa: F401  (aynı yardımcılar)

VAKALAR = [
    {"kod": "atolye", "ad": "Atölye Kahve", "kurum": "AtolyeKahve", "misafir": "AtolyeKahve-Misafir",
     "sektor": "kafe zinciri", "weak": "kahve1234", "yer": "kafenin kasa ve POS ağı",
     "hikaye": "Kafe sahibi Berk, müşterilerin kullandığı Wi-Fi ile kasa/POS cihazlarının aynı ağda olduğunu yeni fark etti."},
    {"kod": "kuzgun", "ad": "Kuzgun Lojistik", "kurum": "KuzgunDepo", "misafir": "KuzgunDepo-Ziyaretci",
     "sektor": "lojistik", "weak": "depo2024", "yer": "depo el terminalleri ve sevkiyat ağı",
     "hikaye": "Depo el terminalleri kablosuz ağa bağlanıyor; bir şoför aynı Wi-Fi'dan sevkiyat panelini görebildiğini söyledi."},
    {"kod": "medora", "ad": "Medora Sağlık", "kurum": "MedoraPersonel", "misafir": "MedoraHasta",
     "sektor": "hastane", "weak": "hasta1234", "yer": "personel istasyonları ve tıbbi cihaz ağı",
     "hikaye": "Hasta yakınlarının kullandığı Wi-Fi ile hemşire istasyonlarının ağı arasındaki sınır net değil."},
    {"kod": "ferah", "ad": "Ferah Bank", "kurum": "FerahSube", "misafir": "FerahMisafir",
     "sektor": "banka şubesi", "weak": "sube12345", "yer": "şube personel ve ATM yönetim ağı",
     "hikaye": "Şube müdürü, otoparkta oturan birinin şube Wi-Fi'ına telefonundan bağlanabildiğini fark etti."},
]

KOMSU_ADLARI = ["TurkNet_Fiber_4F2A", "Ev_Wifi_91", "SUPERONLINE-7C1D", "Villa_Kat2", "Ofis_Plaza_5G",
                "DenizEv", "Konak_Net", "GizliBahce", "Kombi_Servis", "ARDA_HOME", "Mavi_Ev_2G", "Pencere_Net"]


def vaka_sec(rng) -> dict:
    return dict(rng.choice(VAKALAR))


def mac(rng, haric=()) -> str:
    while True:
        m = ":".join(f"{rng.randrange(256):02X}" for _ in range(6))
        if m not in haric:
            return m


def macler(rng, n: int, haric=()) -> list:
    cikti = []
    for _ in range(n):
        cikti.append(mac(rng, set(haric) | set(cikti)))
    return cikti


BASLIK = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, "
          "Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key")
ISTASYON_BASLIK = "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs"

# (Privacy, Cipher, Authentication)
SIFRELEME = {
    "OPN": ("OPN", "", ""),
    "WEP": ("WEP", "WEP", ""),
    "WPA": ("WPA", "TKIP", "PSK"),
    "WPA2": ("WPA2", "CCMP", "PSK"),
    "WPA2-MGT": ("WPA2", "CCMP", "MGT"),
    "WPA3": ("WPA3", "CCMP", "SAE"),
}


def ap_satiri(bssid, ilk, son, kanal, tur, guc, essid, hiz=130, beacon=100) -> str:
    p, c, a = SIFRELEME[tur]
    return (f"{bssid}, {ilk:%Y-%m-%d %H:%M:%S}, {son:%Y-%m-%d %H:%M:%S}, {kanal}, {hiz}, {p}, {c}, {a}, "
            f"{guc}, {beacon}, 0, 0.  0.  0.  0, {len(essid)}, {essid}, ")


def tarama_csv(aplar: list, istasyonlar: list = ()) -> str:
    """aplar: ap_satiri çıktıları; istasyonlar: (mac, ilk, son, guc, paket, bssid) demetleri."""
    s = BASLIK + "\n" + "\n".join(aplar) + "\n\n" + ISTASYON_BASLIK + "\n"
    for m, ilk, son, g, p, b in istasyonlar:
        s += f"{m}, {ilk:%Y-%m-%d %H:%M:%S}, {son:%Y-%m-%d %H:%M:%S}, {g}, {p}, {b},\n"
    return s


def ini_oku(yol: Path) -> tuple:
    """(hata, {bolum: {anahtar: değer}}) — basit INI; '#' ve ';' yorumdur."""
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return f"{yol.name} okunamadı ({e})", {}
    bolumler: dict = {}
    mevcut = None
    for no, ham in enumerate(satirlar, 1):
        s = ham.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            mevcut = s[1:-1].strip().lower()
            bolumler.setdefault(mevcut, {})
        elif "=" in s and mevcut is not None:
            k, _, d = s.partition("=")
            bolumler[mevcut][k.strip().lower()] = d.strip()
        else:
            return f"{yol.name} satır {no}: anlaşılamadı ({s!r}). `anahtar=değer` biçimini koru.", {}
    return None, bolumler
