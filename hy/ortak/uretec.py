"""Senaryo üreteçleri için ortak yardımcılar (IP, isim, bayrak, zaman, log satırları).

Hepsi verilen `rng` (random.Random) ile çalışır; aynı tohum her zaman aynı senaryoyu verir.
Dış IP'ler için belgelendirmeye ayrılmış TEST-NET blokları kullanılır (gerçek kimseye ait değil):
192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
"""
from __future__ import annotations

import os
import random
from datetime import datetime, timedelta
from pathlib import Path

ISIMLER = [
    "ayse", "mehmet", "zeynep", "ali", "can", "elif", "emre", "deniz", "burak", "selin",
    "murat", "ece", "kerem", "derya", "okan", "gizem", "tolga", "busra", "serkan", "melis",
    "baris", "pinar", "hakan", "irem", "onur", "seda", "volkan", "nazli", "ugur", "esra",
]

DEPARTMANLAR = ["it", "muhasebe", "satis", "ik", "lojistik", "pazarlama", "hukuk"]

BAYRAK_KELIMELERI = [
    "ilk_adim", "gizli_kapi", "sessiz_iz", "golge", "anahtar", "kayip_yedek", "gece_vardiyasi",
    "unutulan_not", "eski_parola", "arka_oda", "kirik_kilit", "acik_pencere", "son_satir",
    "yanlis_izin", "terk_edilmis", "sahte_kimlik", "derin_iz", "kayip_dosya", "sinyal",
    "kor_nokta", "ucuncu_goz", "zayif_halka", "kapali_devre", "eski_yol", "sakli_bahce",
]

TARAYICI_UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36",
]

# Saldırı/tarama araçlarının varsayılan User-Agent'ları (log analizinde iz olarak)
ARAC_UA = {
    "Nikto": "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "sqlmap": "sqlmap/1.8.2#stable (https://sqlmap.org)",
    "gobuster": "gobuster/3.6",
    "WPScan": "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "Nmap NSE": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    "ffuf": "Fuzz Faster U Fool v2.1.0",
}
KOMUT_SATIRI_UA = ["curl/8.5.0", "python-requests/2.31.0", "Wget/1.21.4", "Go-http-client/1.1"]

TEST_NET = ["192.0.2", "198.51.100", "203.0.113"]


def bayrak(rng: random.Random, kelime: str | None = None) -> str:
    kelime = kelime or rng.choice(BAYRAK_KELIMELERI)
    return "FLAG{" + kelime + "_" + "".join(rng.choice("0123456789abcdef") for _ in range(6)) + "}"


def dis_ip(rng: random.Random) -> str:
    """Saldırgan/dış istemci IP'si (TEST-NET bloklarından)."""
    return f"{rng.choice(TEST_NET)}.{rng.randint(2, 254)}"


def ic_ip(rng: random.Random, ag: str | None = None) -> str:
    ag = ag or rng.choice(["192.168.1", "192.168.10", "10.0.0", "10.10.5", "172.16.4"])
    return f"{ag}.{rng.randint(2, 254)}"


def benzersiz(rng: random.Random, uretec, adet: int, haric: set | None = None) -> list:
    """`uretec(rng)` ile birbirinden farklı `adet` değer üretir."""
    goruldu = set(haric or ())
    cikti = []
    while len(cikti) < adet:
        v = uretec(rng)
        if v not in goruldu:
            goruldu.add(v)
            cikti.append(v)
    return cikti


def isimler(rng: random.Random, adet: int, haric: set | None = None) -> list:
    return benzersiz(rng, lambda r: r.choice(ISIMLER), adet, haric)


def parola(rng: random.Random) -> str:
    """Gerçekçi ama zayıf 'insan' parolası (vakalarda sızan parola olarak)."""
    kok = rng.choice(["Yaz", "Kis", "Bahar", "Galata", "Kartal", "Deniz", "Ankara", "Admin", "Sistem", "Depo"])
    yil = rng.choice(["2023", "2024", "2025", "2026", "123", "1903", "1907", "1905"])
    son = rng.choice(["!", ".", "*", "", "?"])
    return f"{kok}{yil}{son}"


def gun(rng: random.Random, yil: int = 2026) -> datetime:
    """Vakanın 'olay günü': yılın içinde rastgele bir iş günü, saat 00:00."""
    d = datetime(yil, 1, 5) + timedelta(days=rng.randint(0, 320))
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


def zamanlar(rng: random.Random, baslangic: datetime, adet: int, en_az: int = 1, en_cok: int = 90) -> list:
    """Artan sırada `adet` zaman damgası (saniye aralıkları en_az..en_cok)."""
    t = baslangic
    cikti = []
    for _ in range(adet):
        t = t + timedelta(seconds=rng.randint(en_az, en_cok))
        cikti.append(t)
    return cikti


AYLAR_EN = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def apache_zamani(t: datetime) -> str:
    return f"{t.day:02d}/{AYLAR_EN[t.month - 1]}/{t.year}:{t:%H:%M:%S} +0300"


def apache_satiri(ip: str, t: datetime, metod: str, yol: str, kod: int, boyut: int,
                  ua: str, referer: str = "-") -> str:
    """Apache/Nginx 'combined' log biçimi."""
    return f'{ip} - - [{apache_zamani(t)}] "{metod} {yol} HTTP/1.1" {kod} {boyut} "{referer}" "{ua}"'


def syslog_zamani(t: datetime) -> str:
    return f"{AYLAR_EN[t.month - 1]} {t.day:>2} {t:%H:%M:%S}"


def ssh_satiri(t: datetime, sunucu: str, pid: int, olay: str) -> str:
    """auth.log satırı. `olay` örn. 'Failed password for root from 1.2.3.4 port 4000 ssh2'."""
    return f"{syslog_zamani(t)} {sunucu} sshd[{pid}]: {olay}"


def mtime_ayarla(yol: Path, t: datetime) -> None:
    zaman = t.timestamp()
    os.utime(yol, (zaman, zaman))


def yaz(yol: Path, icerik: str, mod: int | None = None, t: datetime | None = None) -> Path:
    """Dosyayı (ara dizinleriyle) yazar; istenirse izin ve değiştirme zamanı ayarlar."""
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.write_text(icerik, encoding="utf-8")
    if mod is not None:
        os.chmod(yol, mod)
    if t is not None:
        mtime_ayarla(yol, t)
    return yol
