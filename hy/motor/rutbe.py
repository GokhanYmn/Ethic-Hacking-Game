"""Rütbe merdiveni, rozetler ve puan hesabı."""
from __future__ import annotations

# Eşikler, ilk oynanışta (biraz ipucuyla, ~%85 puan) kabaca bir cildin bitişine denk gelecek
# şekilde ayarlandı: tam puan Cilt 1 ≈ 2.300, Cilt 3 ≈ 6.500, Cilt 10 ≈ 21.000, hepsi ≈ 35.000.
RUTBELER = [
    (0, "Sivil"),
    (1000, "Çırak"),
    (2000, "İz Sürücü"),              # Cilt 1 sonu
    (3700, "Terminal Dervişi"),       # Cilt 2 sonu
    (5500, "Kâşif"),                  # Cilt 3 sonu
    (7200, "Ağ Gezgini"),             # Cilt 4 sonu
    (8800, "Sırçözen"),               # Cilt 5 sonu
    (10400, "Bekçi"),                 # Cilt 6 sonu
    (12500, "Fısıltı"),               # Cilt 7 sonu
    (14000, "Yankı"),                 # Cilt 8 sonu
    (15700, "Gölge"),                 # Cilt 9 sonu
    (17900, "Hayalet"),               # Cilt 10 sonu
    (24000, "Kök"),                   # uzmanlık ciltlerinin ortası
    (29500, "Pergezer"),              # Capstone (zirve)
]

# İpucu kademesine göre görev puanından düşülen oran
IPUCU_KESINTI = {0: 0.0, 1: 0.10, 2: 0.25, 3: 0.50}

TEKRAR_CARPANI = 0.5   # pekiştirme vakası (aynı seviye, yeni vaka) XP çarpanı

ROZETLER = {
    "yemin": ("Yemin", "Etik kuralları kabul ettin. Yolculuk başladı."),
    "ilk_bayrak": ("İlk Bayrak", "İlk görevini çözdün."),
    "kendi_basina": ("Kendi Başına", "Bir seviyeyi hiç ipucu almadan bitirdin."),
    "hizli": ("Hızlı Müdahale", "Bir seviyeyi hedef sürenin altında bitirdin."),
    "pes_etmeyen": ("Pes Etmeyen", "5 ya da daha fazla yanlıştan sonra doğruyu buldun."),
    "yalniz_kurt": ("Yalnız Kurt", "Bir cildin tamamını ipucusuz bitirdin."),
    "olay_5": ("Olay Masası Müdavimi", "Olay Masası'nda 5 vaka kapattın."),
    "olay_seri_3": ("Soğukkanlı", "Olay Masası'nda üst üste 3 vakayı ipucusuz kapattın."),
    "cilt_1": ("Terminal Fatihi", "Cilt 1'i bitirdin: Linux artık senin evin."),
    "cilt_2": ("Paket Okuyucu", "Cilt 2'yi bitirdin: ağ trafiği seninle konuşuyor."),
    "cilt_3": ("Araç Ustası", "Cilt 3'ü bitirdin: kendi araçlarını yazıyorsun."),
    "cilt_4": ("Haritacı", "Cilt 4'ü bitirdin: bir hedefin haritasını çıkarabiliyorsun."),
    "cilt_5": ("Kod Tamircisi", "Cilt 5'i bitirdin: web açıklarını bulup kodda kapatıyorsun."),
    "cilt_6": ("İz Okuyucu", "Cilt 6'yı bitirdin: bir sızmanın basamaklarını tek tek söküyorsun."),
    "cilt_7": ("SOC Nöbetçisi", "Cilt 7'yi bitirdin: mavi takımın bir parçasısın."),
    "cilt_8": ("Rapor Ustası", "Cilt 8'i bitirdin: meslek seninle konuşuyor."),
    "cilt_9": ("Lab Mimarı", "Cilt 9'u bitirdin: kendi güvenli laboratuvarını kurabilirsin."),
    "cilt_10": ("Kuruş Avcısı", "Cilt 10'u bitirdin: iş mantığı açıkları seni kandıramaz."),
    "cilt_11": ("Orman Bekçisi", "Cilt 11'i bitirdin: Active Directory'nin yollarını biliyorsun."),
    "cilt_12": ("Bulut Denetçisi", "Cilt 12'yi bitirdin."),
    "cilt_13": ("Konteyner Kaptanı", "Cilt 13'ü bitirdin."),
    "cilt_14": ("Cep Dedektifi", "Cilt 14'ü bitirdin."),
    "cilt_15": ("Sinyal Avcısı", "Cilt 15'i bitirdin."),
    "cilt_16": ("İnsan Kalkanı", "Cilt 16'yı bitirdin."),
    "cilt_17": ("Numune Analisti", "Cilt 17'yi bitirdin."),
    "cilt_18": ("Makine Terbiyecisi", "Cilt 18'i bitirdin."),
    "cilt_19": ("Rıza Bekçisi", "Cilt 19'u bitirdin."),
    "cilt_20": ("Kart Muhafızı", "Cilt 20'yi bitirdin."),
    "cilt_21": ("Desen Avcısı", "Cilt 21'i bitirdin."),
    "cilt_22": ("Zincir Okuyucu", "Cilt 22'yi bitirdin."),
    "cilt_23": ("e-Dönüşüm Denetçisi", "Cilt 23'ü bitirdin."),
    "cilt_24": ("Kalkan Güvenlik Danışmanı", "Capstone'u bitirdin: stajın bitti, masan hazır."),
}


def rutbe(xp: int) -> dict:
    """XP'ye göre rütbe bilgisini döndürür."""
    simdiki = RUTBELER[0]
    sonraki = None
    for i, (esik, ad) in enumerate(RUTBELER):
        if xp >= esik:
            simdiki = (esik, ad)
            sonraki = RUTBELER[i + 1] if i + 1 < len(RUTBELER) else None
    oran = 1.0
    if sonraki:
        oran = (xp - simdiki[0]) / (sonraki[0] - simdiki[0])
    return {
        "ad": simdiki[1],
        "esik": simdiki[0],
        "sonraki_ad": sonraki[1] if sonraki else None,
        "sonraki_esik": sonraki[0] if sonraki else None,
        "oran": oran,
    }


def gorev_puani(taban: int, ipucu_kademe: int, carpan: float,
                ipucu_carpan: float = 1.0, zorluk_xp: float = 1.0) -> int:
    kesinti = IPUCU_KESINTI.get(min(ipucu_kademe, 3), 0.5) * ipucu_carpan
    return max(1, round(taban * (1 - kesinti) * carpan * zorluk_xp))


def rozet_bilgi(kimlik: str) -> tuple:
    if kimlik in ROZETLER:
        return ROZETLER[kimlik]
    if kimlik.startswith("cilt_"):
        return (f"Cilt {kimlik[5:]} Fatihi", f"Cilt {kimlik[5:]}'i bitirdin.")
    return (kimlik, "")
