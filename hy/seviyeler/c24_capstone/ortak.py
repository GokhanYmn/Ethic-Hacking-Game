"""Cilt 24 ortak yardımcıları (sadece bu cildin seviyeleri kullanır).

Capstone mavi takım biçimindedir: oyuncu saldırı yapmaz, kurgusal kanıtları (log, pcap, yapılandırma
kopyası) inceler. Burada log satırı üretimi, zaman zinciri ve ortak kontrol yardımcıları bulunur.
Saldırı yükü ya da çalışır kod içermez; her şey düz metindir.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta

from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import Sira, sec_doldur, sh  # noqa: F401  (yeniden dışa aktarım)

# grep -oP ile saat çıkarma deseni: apache tarihindeki "2026:02:13" parçasına takılmaz.
SAAT = r"(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}"


def zaman_zinciri(rng, bas: datetime, bosluklar: list) -> list:
    """`bas`'tan başlayıp her boşluk (en_az, en_cok saniye) kadar ilerleyen artan zamanlar."""
    t, cikti = bas, [bas]
    for en_az, en_cok in bosluklar:
        t = t + timedelta(seconds=rng.randint(en_az, en_cok))
        cikti.append(t)
    return cikti


class LogYigini:
    """(zaman, satır) toplar, zamana göre sıralı metin verir."""

    def __init__(self):
        self.l: list = []

    def ekle(self, t: datetime, satir: str) -> None:
        self.l.append((t, len(self.l), satir))

    def metin(self) -> str:
        return "\n".join(s for _, _, s in sorted(self.l, key=lambda x: (x[0], x[1]))) + "\n"


def sys_satiri(t: datetime, host: str, program: str, pid: int, mesaj: str) -> str:
    return f"{u.syslog_zamani(t)} {host} {program}[{pid}]: {mesaj}"


def hex_ek(rng, n: int = 3) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


_TR = str.maketrans("ıİöÖüÜşŞçÇğĞ", "iIoOuUsScCgG")


def ascii_kucuk(s: str) -> str:
    return s.translate(_TR).lower()


def sira_cevabi(perm: list) -> list:
    """Listede karışık sırayla yazılan olayların (perm[i] = i+1. satırdaki olay) kronolojik numara dizisi."""
    return [perm.index(e) + 1 for e in range(len(perm))]


def sira_hata(verilen, beklenen, b):
    if verilen == sorted(verilen):
        return "Listedeki sıraya göre yazmışsın; her olayın saatini kanıttan bulup saate göre dizmelisin."
    return None
