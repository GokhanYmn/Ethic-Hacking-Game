"""Zorluk seviyeleri ve 'sistem seni arıyor' (tespit metresi) ayarları.

Tespit metresi: Zor ve üstünde, görev kabuğundaki gürültün (yanlış denemeler, çok ipucu)
bir izi doldurur. Belli eşikte SOC uyarır; dolunca savunma devreye girer, hedef kilitleri
değiştirir (lab yeni bir senaryoyla sıfırlanır). Ders: sessiz ve planlı çalış.
"""
from __future__ import annotations

ZORLUKLAR = {
    "kolay": {
        "ad": "Kolay", "simge": "○", "xp": 0.8, "ipucu_carpan": 0.5, "ipucu_tavan": 3,
        "tespit": False,
        "aciklama": "İpuçları ucuz, tespit yok. Rahat öğrenmek için.",
    },
    "normal": {
        "ad": "Normal", "simge": "◐", "xp": 1.0, "ipucu_carpan": 1.0, "ipucu_tavan": 3,
        "tespit": False,
        "aciklama": "Dengeli. Varsayılan deneyim.",
    },
    "zor": {
        "ad": "Zor", "simge": "◉", "xp": 1.3, "ipucu_carpan": 1.0, "ipucu_tavan": 3,
        "tespit": True, "uyari": 55, "yakala": 100, "iz_yanlis": 16, "iz_ipucu": 22,
        "aciklama": "Daha çok XP. SOC seni izliyor: gürültü çıkarırsan yakalanırsın.",
    },
    "gercekci": {
        "ad": "Gerçekçi", "simge": "●", "xp": 1.7, "ipucu_carpan": 1.0, "ipucu_tavan": 2,
        "tespit": True, "uyari": 40, "yakala": 80, "iz_yanlis": 22, "iz_ipucu": 30,
        "aciklama": "En çok XP, 3. ipucu kapalı, savunma hızlı tepki verir. Usta modu.",
    },
}

SIRA = ["kolay", "normal", "zor", "gercekci"]


def al(kayit) -> dict:
    anahtar = kayit.veri["ayarlar"].get("zorluk", "normal")
    return ZORLUKLAR.get(anahtar, ZORLUKLAR["normal"])


def anahtar(kayit) -> str:
    a = kayit.veri["ayarlar"].get("zorluk", "normal")
    return a if a in ZORLUKLAR else "normal"
