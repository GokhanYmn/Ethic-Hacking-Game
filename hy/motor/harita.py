"""Bölge (cilt) haritası ve kilit kuralları."""
from __future__ import annotations

from hy.motor.seviye import sirali_seviyeler

CILTLER = {
    0: "Önce Kurallar: Etik ve Hukuk",
    1: "Hacker Gözüyle Linux",
    2: "Ağ Temelleri",
    3: "Otomasyon",
    4: "Keşif ve Bilgi Toplama",
    5: "Web Uygulama Güvenliği",
    6: "Sistem Sızma ve Yetki Yükseltme",
    7: "Savunma Tarafı",
    8: "Meslek",
    9: "Kendi Laboratuvarını Kur",
    10: "Finansal Sistemlerin Güvenliği",
    11: "Active Directory Derinlemesine",
    12: "Bulut Güvenliği",
    13: "Konteyner ve Kubernetes Güvenliği",
    14: "Mobil Uygulama Güvenliği",
    15: "Kablosuz Ağ Güvenliği",
    16: "Sosyal Mühendislik ve Phishing",
    17: "Zararlı Yazılım Analizi",
    18: "AI/LLM Güvenliği",
    19: "Açık Bankacılık API Güvenliği",
    20: "PCI-DSS ve Kart Verisi",
    21: "Dolandırıcılık Tespiti",
    22: "Kripto, Blockchain ve DeFi Güvenliği",
    23: "Türkiye e-Dönüşüm Derinlemesine",
    24: "Capstone: Uçtan Uca Senaryolar",
}

CEKIRDEK_SON = 10   # 1-10 sırayla; 11+ çekirdek bitince serbest sırayla


def cilt_seviyeleri(cilt: int) -> list:
    return [s for s in sirali_seviyeler() if s.cilt == cilt]


def cilt_tamam(kayit, cilt: int) -> bool:
    seviyeler = cilt_seviyeleri(cilt)
    return bool(seviyeler) and all(kayit.tamam_mi(s.kimlik) for s in seviyeler)


def _cilt_acik(kayit, cilt: int) -> tuple:
    if cilt == 0:
        return True, ""
    if not cilt_tamam(kayit, 0):
        return False, "Önce Bölüm 0'ı (Etik ve Hukuk) bitir."
    if cilt <= CEKIRDEK_SON:
        for onceki in range(1, cilt):
            if cilt_seviyeleri(onceki) and not cilt_tamam(kayit, onceki):
                return False, f"Önce Cilt {onceki}'i bitir."
        return True, ""
    for onceki in range(1, CEKIRDEK_SON + 1):
        if cilt_seviyeleri(onceki) and not cilt_tamam(kayit, onceki):
            return False, "Uzmanlık ciltleri, çekirdek Cilt 1-10 bitince açılır."
    return True, ""


def acik_mi(kayit, sv) -> tuple:
    """(açık_mı, neden). Serbest modda Bölüm 0 dışında kilit yoktur."""
    if sv.olay_masasi:
        if not cilt_tamam(kayit, 0):
            return False, "Önce Bölüm 0'ı (Etik ve Hukuk) bitir."
        from hy.motor.seviye import tum_seviyeler
        for kimlik in sv.on_kosul:
            if not kayit.tamam_mi(kimlik) and not kayit.serbest:
                onceki = tum_seviyeler().get(kimlik)
                return False, f"Önce '{onceki.etiket if onceki else kimlik}' görevini bitir."
        return True, ""
    if kayit.serbest and (sv.cilt == 0 or cilt_tamam(kayit, 0)):
        return True, ""
    acik, neden = _cilt_acik(kayit, sv.cilt)
    if not acik:
        return False, neden
    seviyeler = cilt_seviyeleri(sv.cilt)
    i = seviyeler.index(sv)
    if i > 0 and not kayit.tamam_mi(seviyeler[i - 1].kimlik):
        return False, f"Önce '{seviyeler[i - 1].baslik}' görevini bitir."
    return True, ""


def siradaki(kayit):
    """Oyuncunun devam etmesi gereken ilk açık ve bitmemiş seviye."""
    for sv in sirali_seviyeler():
        if not kayit.tamam_mi(sv.kimlik) and acik_mi(kayit, sv)[0]:
            return sv
    return None
