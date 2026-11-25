"""Kendini Sına: bitmiş ciltlerden karışık çoktan seçmeli sınav hazırlar."""
from __future__ import annotations

import random

from hy.motor import harita
from hy.motor.kontrol import Secmeli
from hy.motor.seviye import sirali_seviyeler


def uygun_sorular(kayit, sadece_bitmis: bool = True) -> list:
    """(seviye, görev_no) çiftleri: erişilebilir ciltlerdeki çoktan seçmeli sorular."""
    cikti = []
    for sv in sirali_seviyeler():
        if sv.cilt == 0:
            continue
        if sadece_bitmis and not kayit.tamam_mi(sv.kimlik):
            continue
        if not sadece_bitmis and not harita.acik_mi(kayit, sv)[0]:
            continue
        for no, g in enumerate(sv.gorevler, 1):
            if isinstance(g.kontrol, Secmeli):
                cikti.append((sv, no))
    return cikti


def sinav_hazirla(kayit, adet: int = 10, rng: random.Random | None = None) -> list:
    """Her biri {sv, no, senaryo} olan soru listesi. Aynı cilttiği dengeli dağıtmaya çalışır."""
    rng = rng or random.SystemRandom()
    havuz = uygun_sorular(kayit, sadece_bitmis=True)
    if len(havuz) < adet:
        havuz = uygun_sorular(kayit, sadece_bitmis=False)
    if not havuz:
        return []
    rng.shuffle(havuz)
    # Aynı seviyeden üst üste soru gelmesin diye seviyeye göre serpiştir
    havuz.sort(key=lambda sn: sn[0].kimlik)
    secili = havuz[:: max(1, len(havuz) // adet)][:adet] if len(havuz) > adet else havuz
    rng.shuffle(secili)
    sorular = []
    for sv, no in secili[:adet]:
        senaryo = sv.senaryo(rng.randrange(1, 10**9))
        sorular.append({"sv": sv, "no": no, "senaryo": senaryo})
    return sorular
