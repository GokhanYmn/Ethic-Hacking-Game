"""Cilt 18 ortak yardımcıları: kurgusal müşteri asistanı vakaları.

Bütün kişiler, şirketler ve değerler kurgusaldır; saldırı yükü içermez, kayıtlar düz metindir.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Secmeli


def sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def sec_doldur(cozum: dict, gorevler: list, lab: Path, s: dict) -> dict:
    """Test çözücüsü: çoktan seçmeli görevlerin cevabını kontrolün kendisinden alır."""
    for no, g in enumerate(gorevler, 1):
        if isinstance(g.kontrol, Secmeli):
            cozum[no] = g.kontrol.cevabi_goster(Baglam(s, lab, no))[0]
    return cozum


# araçlar: (ad, yetki, kapsam, açıklama). yetki: oku | yaz | islem | sil
VAKALAR = [
    {
        "kod": "ferah", "vaka": "Ferah Bank — müşteri asistanı", "musteri": "Ferah Bank", "asistan": "Fera",
        "alan": "ferahbank.lab", "kisi": "Kaan Bey (bilgi güvenliği müdürü)",
        "sahne": "Ferah Bank, mobil uygulamasına **Fera** adlı bir yapay zekâ müşteri asistanı koydu. Kaan Bey "
                 "telefonda: \"Fera kampanya soruyor, bakiye söylüyor, havale taslağı hazırlıyor. Pazarlama çok "
                 "mutlu ama ben uyuyamıyorum.\"",
        "araclar": [("bakiye_sorgula", "oku", "musteri", "oturumdaki müşterinin bakiyesi"),
                    ("son_hareketler", "oku", "musteri", "son 10 hesap hareketi"),
                    ("kampanya_ara", "oku", "tum", "kampanya duyuruları (herkese açık)"),
                    ("eposta_gonder", "yaz", "musteri", "müşteriye bilgilendirme e-postası"),
                    ("havale_gonder", "islem", "tum", "para transferini başlatır"),
                    ("kart_kapat", "sil", "tum", "kartı kalıcı kapatır")],
        "sir": ("fb_ic_servis_parolasi", "Fb-Ic-"), "belge": "müşteriden gelen e-posta",
        "cikti_olay": "Asistanın ürettiği yanıttaki bir HTML parçası, hiçbir temizlemeden geçmeden mobil uygulamanın "
                      "web görünümüne olduğu gibi basıldı ve başka müşterilerin ekranında çalıştı.",
    },
    {
        "kod": "pazarix", "vaka": "Pazarix — sipariş destek asistanı", "musteri": "Pazarix", "asistan": "Pazi",
        "alan": "pazarix.lab", "kisi": "Tuncay Bey (sistem yöneticisi)",
        "sahne": "Pazarix, kampanya haftası için sipariş destek hattını **Pazi** adlı bir asistana devretti. Tuncay Bey: "
                 "\"Pazi iade soruyor, kargo takip ediyor, hatta kupon üretiyor. Ama bir müşteri ona tuhaf şeyler "
                 "yazıp durmuş; kayıtlara bakar mısın?\"",
        "araclar": [("siparis_durumu", "oku", "musteri", "müşterinin sipariş durumu"),
                    ("iade_politikasi_ara", "oku", "tum", "iade kuralları (herkese açık)"),
                    ("adres_guncelle", "yaz", "musteri", "teslimat adresini değiştirir"),
                    ("kupon_uret", "yaz", "tum", "indirim kuponu üretir"),
                    ("iade_onayla", "islem", "tum", "geri ödemeyi başlatır"),
                    ("musteri_sil", "sil", "tum", "müşteri kaydını kalıcı siler")],
        "sir": ("pzx_ic_api_anahtari", "Pzx-Ic-"), "belge": "tedarikçi faturası",
        "cikti_olay": "Asistanın ürettiği bir SQL ifadesi, hiçbir denetimden geçmeden doğrudan sipariş veritabanında "
                      "çalıştırıldı ve beklenmedik kayıtlar silindi.",
    },
    {
        "kod": "medora", "vaka": "Medora Sağlık — randevu asistanı", "musteri": "Medora Sağlık", "asistan": "Medi",
        "alan": "medora.lab", "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
        "sahne": "Medora Sağlık, hasta portalına **Medi** adlı bir randevu asistanı ekledi. Dr. Aslı Hanım: \"Medi "
                 "randevu buluyor, doktor takvimine bakıyor, reçete yenileme isteği alıyor. KVKK ekibi 'bu sistem "
                 "neye erişebiliyor' diye soruyor; ben de bilmiyorum, bakar mısın?\"",
        "araclar": [("randevu_ara", "oku", "musteri", "hastanın randevuları"),
                    ("doktor_takvimi", "oku", "tum", "doktorların boş saatleri (herkese açık)"),
                    ("randevu_iptal", "yaz", "musteri", "hastanın randevusunu iptal eder"),
                    ("tahlil_getir", "oku", "tum", "herhangi bir hastanın tahlil sonucu"),
                    ("recete_yenile", "islem", "tum", "reçeteyi eczaneye iletir"),
                    ("hasta_kaydi_sil", "sil", "tum", "hasta kaydını kalıcı siler")],
        "sir": ("mdr_ic_servis_anahtari", "Mdr-Ic-"), "belge": "hasta yakını mektubu",
        "cikti_olay": "Asistanın ürettiği bir komut satırı, hiçbir denetimden geçmeden yönetim sunucusunda otomatik "
                      "çalıştırıldı ve bir yedek klasörü silindi.",
    },
]
