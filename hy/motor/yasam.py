"""Hayat Modu (Aşama 1-2) — hacker kariyeri / yaşam simülasyonu çerçevesi.

Mevcut oyunu **sarar, yeniden yazmaz**: gerçek görevler yine mevcut motorla çalışır
(`lab_kur` + `gorev_kabugu`); bu modül etrafına kariyer çerçevesi örer:

    daire → gelen kutusu (farklı kuruluş/zorluk/hikâye) → kabul/reddet/ertele
          → gerçek terminal görevi → maaş (para/itibar/XP, zorluğa göre)
          → "Gerçek Hayatta" debrief → hikâye kıpırtısı → uyu (gün +1)

Aşama 2 ekler: kalıcı gelen kutusu (günler arası), **itibar kademeleri** (daha çok itibar =
daha büyük işler + daha iyi ödeme), **dükkân/ekipman** (parayı harca, kalıcı fayda al),
rütbe + günlük seri göstergesi, isteğe bağlı "ana ekran yap" düğmesi.

İçerik (ev lab, komplo hikâyesi, 2-3× görev) sonraki aşamalarda. Terminal işi hiç değişmez.
"""
from __future__ import annotations

import random
import re
import time

from hy.motor import arayuz as ui
from hy.motor import zorluk
from hy.motor.kabuk import gorev_kabugu, lab_kur
from hy.motor.kayit import Kayit
from hy.motor.rutbe import rutbe
from hy.olay_masasi import (izin_denetimi, olay_adli, olay_api, olay_avi, olay_bulut, olay_dns,
                            olay_eposta, olay_fidye, olay_firewall, olay_ictehdit, olay_k8s,
                            olay_kimlik, olay_kod, olay_kopru, olay_kurcalama, olay_kvkk, olay_pcap,
                            olay_prompt, olay_siem, olay_sizinti, olay_webshell, olay_yanal,
                            olay_zafiyet, olay_zaman, olay_zincir, ssh_kaba_kuvvet, web_logu)

# ------------------------------------------------------------------ sahne / ASCII

MASA = r"""
        .------------------.
        |  $ _             |
        |                  |
        |                  |
        '------------------'
       /====================\
"""

DK = "╭────╮\n│ DK │\n╰────╯"  # Deniz Kara avatarı

# ------------------------------------------------------------------ iş aileleri (anahtarla)
# Aileler dosya tabanlı ve servissiz; her iş: aile × kuruluş × zorluk × hikâye.

ISLER = {
    "web": {
        "sv": web_logu.SEVIYE,
        "konu": "Erişim logunda bir saldırgan var",
        "cerceve": "{kurulus} ({sektor}) saldırıya uğradı. Erişim logunu gönderdiler — kim, "
                   "nasıl, ne kadar ilerlemiş? Saldırgan IP'leri çıkar, imzaları ayır.",
        "taban": 130,
    },
    "ssh": {
        "sv": ssh_kaba_kuvvet.SEVIYE,
        "konu": "SSH'a gece boyu kaba kuvvet yağmış",
        "cerceve": "{kurulus} ({sektor}) sunucusuna yüzlerce başarısız SSH girişi gelmiş. "
                   "Kayıtları incele: biri içeri girdi mi, kalıcılık bıraktı mı?",
        "taban": 130,
    },
    "izin": {
        "sv": izin_denetimi.SEVIYE,
        "konu": "Bir sunucuda yetki denetimi lazım",
        "cerceve": "{kurulus} ({sektor}) bir sunucuda tuhaflık seziyor. İzinleri, cron'u ve "
                   "SUID'leri denetle: açık kapı, arka kapı hesap, şüpheli SUID var mı?",
        "taban": 150,
    },
    "zaman": {
        "sv": olay_zaman.SEVIYE,
        "konu": "Bir ihlalin zaman çizelgesini çıkar",
        "cerceve": "{kurulus} ({sektor}) ihlal edildi ama kimse sıralamayı bilmiyor. Loglardan "
                   "zaman çizelgesini kur: nereden girdiler, hangi hesap düştü, ne sızdı, ne kadar "
                   "fark edilmediler?",
        "taban": 160,
    },
    "bulut": {
        "sv": olay_bulut.SEVIYE,
        "konu": "Bulut yapılandırmasını denetle",
        "cerceve": "{kurulus} ({sektor}) buluta taşındı ama kimse ayarlara bakmadı. Depolama, IAM "
                   "ve güvenlik gruplarını denetle: herkese açık kaynak, aşırı yetki, internete açık "
                   "port, sızmış anahtar var mı?",
        "taban": 170,
    },
    "firewall": {
        "sv": olay_firewall.SEVIYE,
        "konu": "Güvenlik duvarı kurallarını denetle",
        "cerceve": "{kurulus} ({sektor}) güvenlik duvarı kurallarını denetlemeni istiyor: internete "
                   "açık hassas port, aşırı geniş kural, gölgelenmiş kural, yanlış varsayılan politika?",
        "taban": 160,
    },
    "dns": {
        "sv": olay_dns.SEVIYE,
        "konu": "DNS üzerinden sızıntı şüphesi",
        "cerceve": "{kurulus} ({sektor}) DNS loglarında tuhaflık var. Biri DNS'i tünel gibi kullanıyor "
                   "olabilir: kim, hangi alana, ne kadar?",
        "taban": 160,
    },
    "api": {
        "sv": olay_api.SEVIYE,
        "konu": "API kötüye kullanımı şüphesi",
        "cerceve": "{kurulus} ({sektor}) API loglarında saldırı izi arıyor: parola doldurma, ardışık "
                   "ID gezme (IDOR), aşırı istek. Saldırgan IP'leri çıkar.",
        "taban": 170,
    },
    "ictehdit": {
        "sv": olay_ictehdit.SEVIYE,
        "konu": "İç tehdit şüphesi",
        "cerceve": "{kurulus} ({sektor}) bir çalışanın veri sızdırdığından şüpheleniyor. Erişim, VPN "
                   "ve transfer loglarından şüpheliyi ve kanıtı bul.",
        "taban": 180,
    },
    "adli": {
        "sv": olay_adli.SEVIYE,
        "konu": "Ele geçmiş sunucuda adli inceleme",
        "cerceve": "{kurulus} ({sektor}) bir sunucunun ele geçtiğinden şüpheli. ps, ss ve zamanlama "
                   "anlık görüntülerini incele: şüpheli süreç, C2 bağlantısı, kalıcılık nerede?",
        "taban": 180,
    },
    "fidye": {
        "sv": olay_fidye.SEVIYE,
        "konu": "Fidye saldırısı sonrası müdahale",
        "cerceve": "{kurulus} ({sektor}) fidye yazılımına çarpıldı. Olay loglarını, yedek durumunu ve "
                   "fidye notunu incele: ilk bulaşma nereden, kaç sunucu vuruldu, sağlam yedek var mı?",
        "taban": 200,
    },
    "siem": {
        "sv": olay_siem.SEVIYE,
        "konu": "SIEM korelasyonu lazım",
        "cerceve": "{kurulus} ({sektor}) üç ayrı log kaynağını birleştirip tek saldırı zincirini "
                   "çıkarmanı istiyor: web, auth ve firewall'da ortak iz kim?",
        "taban": 180,
    },
    "webshell": {
        "sv": olay_webshell.SEVIYE,
        "konu": "Web shell şüphesi",
        "cerceve": "{kurulus} ({sektor}) web sunucusuna bir shell yüklenmiş olabilir. Dosya listesi "
                   "ve erişim logundan bul: hangi dosya, kim yükledi, ne zaman?",
        "taban": 170,
    },
    "yanal": {
        "sv": olay_yanal.SEVIYE,
        "konu": "Yanal hareket şüphesi",
        "cerceve": "{kurulus} ({sektor}) iç ağında biri makineden makineye atlıyor. Birleşik auth "
                   "logundan pivot zincirini çıkar: hangi hesap, nereden nereye?",
        "taban": 190,
    },
    "sizinti": {
        "sv": olay_sizinti.SEVIYE,
        "konu": "Kod deposunda sır taraması",
        "cerceve": "{kurulus} ({sektor}) kod/konfig dökümünde sızmış sır arıyor: AWS anahtarı, düz "
                   "parola, token, özel anahtar — hangi dosyada, en kritiği ne?",
        "taban": 170,
    },
    "eposta": {
        "sv": olay_eposta.SEVIYE,
        "konu": "Şüpheli e-posta başlık incelemesi",
        "cerceve": "{kurulus} ({sektor}) tek bir şüpheli e-postanın başlıklarını çözümlemeni istiyor: "
                   "gerçek köken IP, SPF/DKIM/DMARC, Reply-To tuzağı — sahte mi?",
        "taban": 160,
    },
    "kurcalama": {
        "sv": olay_kurcalama.SEVIYE,
        "konu": "Log kurcalama şüphesi",
        "cerceve": "{kurulus} ({sektor}) birinin logları temizlediğinden şüpheli. Sıra numaralarındaki "
                   "boşluğu bul: ne silindi, ne zaman, kimin izinin üstü örtüldü?",
        "taban": 180,
    },
    "zincir": {
        "sv": olay_zincir.SEVIYE,
        "konu": "Çalınan kripto fonun izini sür",
        "cerceve": "{kurulus} ({sektor}) bir cüzdanı boşaltıldı. İşlem defterini gönderdiler — çalınan "
                   "fonu adresten adrese takip et: nereye gitti, mikser'e ne zaman girdi, hangi borsadan "
                   "çıkış denendi, ne kadar dondurulabilir?",
        "taban": 200,
    },
    "kimlik": {
        "sv": olay_kimlik.SEVIYE,
        "konu": "Hesap ele geçirildi — kimlik saldırısını çöz",
        "cerceve": "{kurulus} ({sektor}) bir hesabının ele geçtiğinden şüpheli. Giriş loglarını "
                   "gönderdiler: kim nereden girdi — oturum mu çalındı, MFA mı atlatıldı, hangi "
                   "makineye infostealer (bilgi çalan zararlı) bulaştı?",
        "taban": 200,
    },
    "prompt": {
        "sv": olay_prompt.SEVIYE,
        "konu": "AI ajanı kötüye kullanıldı — logları incele",
        "cerceve": "{kurulus} ({sektor}) bir AI ajanının kandırıldığından şüpheli. Ajan loglarını "
                   "incele: kim talimatı ezdi (prompt injection), hangi aracı kötüye kullandı, hangi "
                   "veri sızdı, hangi MCP aracı aşırı yetkili?",
        "taban": 210,
    },
    "avi": {
        "sv": olay_avi.SEVIYE,
        "konu": "Alarm yok ama bir şey kokuyor — tehdit avı",
        "cerceve": "{kurulus} ({sektor}) hiçbir alarm çalmadı ama içeride bir şeyden şüpheleniyor. "
                   "Loglarda proaktif av yap: gizli bir C2 beacon'u mu var, sessiz bir kalıcılık mı?",
        "taban": 190,
    },
    "pcap": {
        "sv": olay_pcap.SEVIYE,
        "konu": "Paket yakalamada şüpheli trafik",
        "cerceve": "{kurulus} ({sektor}) bir tcpdump yakalaması gönderdi. Trafiği oku: C2 beacon mı, "
                   "veri sızıntısı mı, port taraması mı — kim, nereye?",
        "taban": 170,
    },
    "kod": {
        "sv": olay_kod.SEVIYE,
        "konu": "Kaynak kodda güvenlik denetimi",
        "cerceve": "{kurulus} ({sektor}) birkaç kaynak dosyasını denetletmek istiyor. Kodu oku: "
                   "hangi dosyada, hangi satırda, ne tür bir açık var — ve nasıl kapatılır?",
        "taban": 180,
    },
    "zafiyet": {
        "sv": olay_zafiyet.SEVIYE,
        "konu": "Zafiyet taramasını önceliklendir",
        "cerceve": "{kurulus} ({sektor}) bir tarama raporuyla boğuldu. Önce neyi kapatmalı? İnternete "
                   "açık + exploit'i olan + kritik varlık = acil. Doğru sırayı çıkar.",
        "taban": 170,
    },
    "kvkk": {
        "sv": olay_kvkk.SEVIYE,
        "konu": "Kişisel veri sızıntısı (KVKK)",
        "cerceve": "{kurulus} ({sektor}) loglarında açıkta kişisel veri (TC kimlik, kart) olabilir. "
                   "Bul ve sınıfla: hangi dosya, kaç kişi, en hassas tür, KVKK bildirimi gerekir mi?",
        "taban": 190,
    },
    "k8s": {
        "sv": olay_k8s.SEVIYE,
        "konu": "Kubernetes yanlış yapılandırması",
        "cerceve": "{kurulus} ({sektor}) bir K8s dağıtımını denetletmek istiyor. Manifest + imaj "
                   "taramasını incele: privileged konteyner, açık sır, kritik CVE'li imaj var mı?",
        "taban": 190,
    },
    "kopru": {
        "sv": olay_kopru.SEVIYE,
        "konu": "Çalınan fon köprüden başka zincire kaçtı",
        "cerceve": "{kurulus} ({sektor}) çalınan fon bir blockchain köprüsünden geçip başka bir "
                   "zincire atladı. İki zinciri ve köprü kayıtlarını birleştir: para nereye çıktı, "
                   "ne kadar?",
        "taban": 210,
    },
}

# İtibar kademeleri: (eşik, ad, uygun aileler, uygun zorluklar, ödül çarpanı)
KADEMELER = [
    (0,   "Tanınmayan", ["web", "ssh", "firewall", "eposta"],
          ["kolay", "normal"], 1.00),
    (25,  "Duyulan",      ["web", "ssh", "firewall", "eposta", "izin", "zaman", "dns",
                                "webshell", "sizinti", "pcap", "kod", "zafiyet"],
          ["kolay", "normal", "zor"], 1.15),
    (70,  "Aranan",      ["web", "ssh", "firewall", "eposta", "izin", "zaman", "dns",
                                "webshell", "sizinti", "api", "bulut", "ictehdit", "siem", "kurcalama",
                                "zincir", "kimlik", "prompt", "pcap", "kod", "zafiyet", "kvkk",
                                "k8s", "avi", "kopru"],
          ["normal", "zor"], 1.30),
    (150, "Efsane", ["web", "ssh", "firewall", "eposta", "izin", "zaman", "dns",
                                "webshell", "sizinti", "api", "bulut", "ictehdit", "siem", "kurcalama",
                                "adli", "fidye", "yanal", "zincir", "kimlik", "prompt", "pcap", "kod",
                                "zafiyet", "kvkk", "k8s", "avi", "kopru"],
          ["normal", "zor"], 1.50),
]

# Ekipman: parayla alınır, kalıcı fayda verir (etkiler bu katmanda uygulanır).
EKIPMAN = {
    "kahve":      {"ad": "İyi Kahve Makinesi", "fiyat": 400,  "aciklama": "Her yeni günde +₺50",      "gunluk": 50},
    "genis_masa": {"ad": "Geniş Masa",          "fiyat": 700,  "aciklama": "Gelen kutusu +1 iş tutar", "kutu": 1},
    "pazarlikci": {"ad": "Pazarlıkçı",          "fiyat": 1100, "aciklama": "İş ödemesi +%15",          "pay": 0.15},
    "menajer":    {"ad": "İtibar Menajeri",     "fiyat": 1600, "aciklama": "Tamamlanan işte +2 itibar","itibar": 2},
}

KUTU_TABAN = 3  # gelen kutusunda tutulacak aktif iş sayısı (+ Geniş Masa)

# Ev lab kademeleri: (fiyat, ad, günlük_pasif_gelir, açıklama). Kademe 0 = lab yok.
LAB_KADEMELERI = [
    (0,    "—",                   0,   "Lab yok."),
    (1500, "Köşe Lab",            80,  "Eski bir dizüstü + bir anahtar. Küçük ama seninki."),
    (4000, "Donanımlı Lab",       200, "Raspberry Pi kümesi + switch. Artık ciddi iş çıkar."),
    (9000, "Tam Teşekküllü Lab",  450, "Raf, sanallaştırma, ayrı ağ. Evinde bir SOC."),
]

STORY_BONUS = 1.5  # hikâye (★) işleri daha çok öder

# Ana hikâye omurgası — "Sıfırıncı Gün": ilerledikçe (tamamlanan iş + itibar) sırayla açılır.
# (min_is, min_itibar, kim, metin, ozel_is_ekle[, zorla_aile]) — zorla_aile: özel iş bu aileden gelsin

HIKAYE = [
    (1, 0,  "Deniz", "İlk işini kapattın. Küçük ama temiz — bu çevrede isim böyle yayılır.", False),
    (2, 0,  "Not",   "Masanda bir not: son vakalardaki saldırgan IP'leri garip biçimde aynı bloklardan "
                     "çıkıyor. Tesadüf mü? Deniz omuz silkti ama gözleri gülmüyordu.", False),
    (3, 20, "K.",    "Tanımadığın bir numara: *\"Adını duydum. İyi para, az soru. İlgilenirsen bir iş "
                     "bırakıyorum gelen kutuna. — K.\"*", True),
    (5, 40, "Selin", "Selin dosyaları yan yana koyuyor: *\"Bak — aynı araçlar, aynı saatler, aynı bloklar. "
                     "Bunlar ayrı ayrı olaylar değil. Biri koordine ediyor.\"*", False),
    (6, 40, "Kestane", "Rakip bir isim, 'Kestane', mesaj atıyor: *\"O K. denen adamın işlerine bulaşma. "
                       "Benden söylemesi.\"* Nereden biliyor senin K.'yi?", False),
    (7, 70, "Eren",  "Gazeteci Eren Aydın ulaşıyor: *\"'Sıfırıncı Gün' diye bir grubun peşindeyim; senin "
                     "müşterilerine de dokunmuşlar. Konuşalım mı?\"* (K. bir iş daha bıraktı.)", True),
    (9, 90, "Deniz", "Deniz sesini alçaltıyor: *\"K.'nin kim olduğunu bilmiyorum ama verdiği işler hep "
                     "Sıfırıncı Gün'ün vuracağı yerler. Ya seni avlıyorlar ya da deniyorlar.\"*", False),
    (12, 120, "Sen", "Parçalar yerine oturuyor: Sıfırıncı Gün dağınık değil — tek merkezden, senin çözdüğün "
                     "vakaların arasından geçen bir kampanya. Ve sıradaki hedef tanıdık çıkıyor.", True),
    (13, 135, "Eren", "Eren bir ekran görüntüsü atıyor: *\"Sıfırıncı Gün'ün parası kıpırdadı — bir cüzdan gece "
                      "boşaldı, iz zincirde dolanıp bir mikser'e gidiyor. Sen bu defteri benden iyi okursun: "
                      "nereye çıktığını bul.\"* (Bu işi K. değil, Eren bıraktı.)", True, "zincir"),
    (14, 145, "Selin", "Zincir işini kapattın. Selin ekranı çeviriyor: *\"Takip ettiğin para bir borsada "
                       "durdu — ama o borsadan çıkan başka bir iz, daha önce çözdüğün bir vakaya bağlanıyor. "
                       "Sıfırıncı Gün'ü ilk kez görüyoruz.\"*", False),
    (15, 155, "Deniz", "Deniz başını sallıyor: *\"İzini sürdüğün şeyin içindesin artık. Küçük bir "
                       "freelancer değilsin — bu dünyanın bir parçasısın.\"* *(1. Perde kapanır.)*", False),
    # --- 2. Perde: Modern Cephe ---
    (17, 170, "Selin", "Selin yeni bir dosya atıyor: *\"Sıfırıncı Gün artık kapı kırmıyor — çalınan bir "
                       "kimlikle içeri *giriyorlar*. Bir müşterinin hesabı ele geçmiş, iz loglarda. Çöz.\"*", True, "kimlik"),
    (20, 200, "Eren",  "Eren telaşlı: *\"Bir şirketin AI destek ajanını kandırmışlar — ajan kendi araçlarıyla "
                       "veri sızdırıyor. Logları sana yolladım; bu yeni bir tür saldırı.\"*", True, "prompt"),
    (24, 240, "K.",    "K.'den beklenmedik bir itiraf: *\"Artık tek tek uğraşmıyorlar. Bir pakete zehir koyup "
                       "yüzlerce şirkete aynı anda girdiler. Ben de o paketi kullandım... Dikkatli ol.\"*", False),
    (28, 300, "Deniz", "Deniz sesini iyice kısıyor: *\"Bir sonraki hedef bir veri merkezi değil — bir fabrika. "
                       "Fiziksel dünyaya geçiyorlar. Bu iş artık senden de büyük.\"* *(Final yaklaşıyor…)*", False),
]


# ------------------------------------------------------------------ durum / yardımcılar

def _durumu(kayit: Kayit) -> dict:
    dur = kayit.veri.setdefault("yasam", {})
    dur.setdefault("gun", 1)
    dur.setdefault("para", 0)
    dur.setdefault("itibar", 0)
    dur.setdefault("tamamlanan_is", 0)
    dur.setdefault("ekipman", [])
    dur.setdefault("kutu", [])
    dur.setdefault("sonraki_no", 1)
    dur.setdefault("gorulen_kademe", 0)
    dur.setdefault("tanisildi", False)
    dur.setdefault("lab", 0)        # ev lab kademesi (0 = yok)
    dur.setdefault("hikaye_adim", 0)  # ana hikâye omurgasında kaçıncı an açıldı
    return dur


def _sv(anahtar: str):
    return ISLER[anahtar]["sv"]


def _kademe(itibar: int):
    idx = 0
    for i, k in enumerate(KADEMELER):
        if itibar >= k[0]:
            idx = i
    return idx, KADEMELER[idx]


def _ekipman_etki(dur: dict) -> dict:
    etki = {"gunluk": 0, "kutu": 0, "pay": 0.0, "itibar": 0}
    for a in dur.get("ekipman", []):
        e = EKIPMAN.get(a, {})
        for k in etki:
            etki[k] += e.get(k, 0)
    return etki


def _odul_max(job: dict, dur: dict) -> int:
    """İşin tam çözümde ödeyeceği para (güncel kademe + ekipmanla)."""
    sab = ISLER[job["anahtar"]]
    _, kad = _kademe(dur["itibar"])
    gear = _ekipman_etki(dur)
    kat = zorluk.ZORLUKLAR[job["zorluk"]]["xp"] * kad[4] * (1 + gear["pay"])
    if job.get("hikaye"):
        kat *= STORY_BONUS
    return round(sab["taban"] * len(sab["sv"].gorevler) * kat)


def _teaser(sv) -> str | None:
    m = re.search(r"\*\*(.+?)\*\*", getattr(sv, "gercek_hayat", "") or "")
    return m.group(1).rstrip(":").strip() if m else None


def _temiz(metin: str) -> str:
    return re.sub(r"<<[^>]+>>", "", metin or "")


def _zorluk_rozet(z: str) -> str:
    d = zorluk.ZORLUKLAR[z]
    renk = {"kolay": "yesil", "normal": "camgobegi", "zor": "sari", "gercekci": "kirmizi"}.get(z, "camgobegi")
    return ui.r(f"{d['simge']} {d['ad']}", renk, "kalin")


def _is_uret(anahtar: str, zorluk_key: str, no: int, hikaye: bool = False, patron: str | None = None) -> dict:
    """Serileştirilebilir bir iş teklifi (kutuda saklanır). Tohum sabitlenir: kuruluş/hikâye kalıcı."""
    sv = _sv(anahtar)
    tohum = random.SystemRandom().randrange(1, 10 ** 9)
    metin = sv.senaryo(tohum).get("metin", {})
    job = {
        "no": no, "anahtar": anahtar, "zorluk": zorluk_key, "tohum": tohum,
        "kurulus": metin.get("musteri", "bir müşteri"), "sektor": metin.get("sektor", ""),
        "durum": "yeni",
    }
    if hikaye:
        job["hikaye"] = True
        job["patron"] = patron or "K."
    return job


def _kutu_doldur(kayit: Kayit) -> dict:
    """Gelen kutusunu, mevcut kademeye uygun işlerle hedef sayıya tamamlar. Ertelenenler korunur."""
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    aileler, zorluklar = kad[2], kad[3]
    zor_secenek = [x for x in ("kolay", "normal", "zor") if x in zorluklar]
    hedef = KUTU_TABAN + _ekipman_etki(dur)["kutu"]
    # bitmiş/reddedilmiş işleri at (kutuyu küçük tut); kalanları say
    dur["kutu"] = [j for j in dur["kutu"] if j["durum"] in ("yeni", "ertelendi")]
    varolan = {(j["anahtar"], j["kurulus"]) for j in dur["kutu"]}
    while len(dur["kutu"]) < hedef:
        job = None
        for _ in range(6):   # aynı kuruluş/aile tekrarından kaçınmaya çalış (çeşitlilik)
            aday = _is_uret(random.choice(aileler), random.choice(zor_secenek), dur["sonraki_no"])
            if (aday["anahtar"], aday["kurulus"]) not in varolan:
                job = aday
                break
        if job is None:
            job = aday
        varolan.add((job["anahtar"], job["kurulus"]))
        dur["kutu"].append(job)
        dur["sonraki_no"] += 1
    return dur


def _vaka_kur(kayit: Kayit, sv, tohum: int) -> None:
    """Seviye durumuna SABİT tohumlu bir vaka yazar (yeni_deneme'nin sabit-tohumlu hali)."""
    d = kayit.seviye(sv.kimlik)
    d["tohum"] = tohum
    d["deneme"] = int(d.get("deneme", 0)) + 1
    d["carpan"] = 1.0
    d["cozulen"], d["ipucu"], d["yanlis"] = {}, {}, {}
    d["baslangic"] = time.strftime("%Y-%m-%d %H:%M")
    d["bitis"] = None
    d["iz"], d["iz_uyari"] = 0, False
    kayit.kaydet()


# ------------------------------------------------------------------ ekranlar

def _hud(kayit: Kayit) -> str:
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    rb = rutbe(kayit.veri["xp"])
    seri = kayit.veri.get("seri", {}).get("gun_sayisi", 0)
    ad = kayit.veri["oyuncu"].get("ad") or "Stajyer"
    s1 = (f"  {ui.r('Gün ' + str(dur['gun']), 'kalin')}   "
          f"{ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}   "
          f"{ui.r('İtibar ' + str(dur['itibar']), 'sari')}   {ui.r(ad, 'gri')}")
    s2 = (f"  {ui.r(kad[1], 'mor', 'kalin')}   ·   Rütbe {rb['ad']} ({kayit.veri['xp']} XP)"
          + (f"   ·   🔥 {seri} gün" if seri and seri > 1 else ""))
    return s1 + "\n" + s2


def _daire(kayit: Kayit) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Daire · gece", "mor"))
    print(ui.r(MASA, "gri"))
    print(ui.r("  Pencerede yağmur. Kahven soğumuş, terminal açık.", "gri"))
    print()
    print(_hud(kayit))


def _eposta_goster(job: dict, dur: dict) -> None:
    sv = _sv(job["anahtar"])
    sab = ISLER[job["anahtar"]]
    teaser = _teaser(sv)
    govde = sab["cerceve"].format(kurulus=ui.r(job["kurulus"], "kalin"), sektor=job["sektor"])
    hikaye = job.get("hikaye")
    kimden = job["patron"] if hikaye else "Deniz Kara  (fikser)"
    satirlar = [
        f"**Kimden:** {kimden}",
        f"**Konu:** {sab['konu']}",
        "",
        govde,
    ]
    if hikaye:
        satirlar += ["", ui.r("(Bu iş hikâyenin bir parçası — bonus ödeme.)", "sari")]
    satirlar += [
        "",
        f"Zorluk: {_zorluk_rozet(job['zorluk'])}   ·   Ödül: "
        f"{ui.r('₺' + str(_odul_max(job, dur)), 'yesil')} (tam çözümde) + itibar + XP",
    ]
    if teaser:
        satirlar.append(f"Not: geçmişte benzer bir olay — **{teaser}**.")
    ui.temizle()
    for ln in DK.splitlines():
        print("  " + ui.r(ln, "camgobegi"))
    print(ui.kutu("★ ÖZEL İŞ" if hikaye else "GELEN KUTUSU", "\n".join(satirlar),
                  "sari" if hikaye else "mavi"))


def _dukkan(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        ui.temizle()
        print(ui.baslik_cubugu("Dükkân · ekipman", "camgobegi"))
        print(ui.r("  Kazandığın parayı kalıcı faydaya çevir.", "gri"))
        print(f"\n  Kasanda: {ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}\n")
        secenekler = []
        for i, (a, e) in enumerate(EKIPMAN.items(), 1):
            if a in dur["ekipman"]:
                durum = ui.r("✔ sende", "yesil")
            elif dur["para"] >= e["fiyat"]:
                durum = ui.r("₺" + str(e["fiyat"]), "sari", "kalin")
            else:
                durum = ui.r(f"₺{e['fiyat']} (yetersiz)", "gri")
            print(f"  [{ui.r(str(i), 'camgobegi', 'kalin')}] {e['ad']} — {e['aciklama']}   {durum}")
            secenekler.append((str(i), a, e))
        print(f"\n  [{ui.r('q', 'camgobegi')}] Geri")
        secim = ui.sor("\n  Ne alalım? ").lower().strip()
        if secim == "q":
            return
        es = next((x for x in secenekler if x[0] == secim), None)
        if not es:
            continue
        _, a, e = es
        if a in dur["ekipman"]:
            print(ui.bilgi("Zaten sende."))
            ui.bekle()
        elif dur["para"] < e["fiyat"]:
            print(ui.hata("Paran yetmiyor. Birkaç iş daha kapat."))
            ui.bekle()
        else:
            dur["para"] -= e["fiyat"]
            dur["ekipman"].append(a)
            kayit.kaydet()
            print(ui.basari(f"{e['ad']} alındı! {e['aciklama']}"))
            ui.bekle()


def _lab_gelir(dur: dict) -> int:
    return LAB_KADEMELERI[dur.get("lab", 0)][2]


def _pratik(kayit: Kayit) -> None:
    """Ev lab'ında ücretsiz antrenman: rastgele bir aile; para/itibar yok, sadece XP."""
    sv = _sv(random.choice(list(ISLER)))
    tohum = random.SystemRandom().randrange(1, 10 ** 9)
    _vaka_kur(kayit, sv, tohum)
    xp_once = kayit.veri["xp"]
    lab = lab_kur(sv, sv.senaryo(tohum))
    print(ui.bilgi(f"Antrenman: {sv.baslik}. Para yok, sadece pratik ve XP. "
                   f"Çıkmak için kabukta {ui.r('cik', 'camgobegi')} yaz."))
    ui.bekle("Hazırsan Enter")
    gorev_kabugu(sv, lab)
    kazanc = Kayit().veri["xp"] - xp_once
    print(ui.basari(f"Antrenman bitti. +{kazanc} XP.") if kazanc else ui.r("  Antrenman bitti.", "gri"))
    ui.bekle()


def _lab_ekrani(kayit: Kayit) -> None:
    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        kademe = dur["lab"]
        ui.temizle()
        print(ui.baslik_cubugu("Ev Lab", "camgobegi"))
        if kademe:
            print(f"  Mevcut: {ui.r(LAB_KADEMELERI[kademe][1], 'kalin')}  ·  "
                  f"pasif gelir {ui.r('₺' + str(_lab_gelir(dur)) + '/gün', 'yesil')}")
        else:
            print(ui.r("  Henüz lab'ın yok. Kendi poligonun: hem pasif gelir hem bedava antrenman.", "gri"))
        print(f"  Kasanda: {ui.r('₺' + str(dur['para']), 'yesil', 'kalin')}\n")
        secenekler = []
        if kademe < len(LAB_KADEMELERI) - 1:
            fiyat, ad, gelir, acik = LAB_KADEMELERI[kademe + 1]
            etk = (ui.r("₺" + str(fiyat), "sari", "kalin") if dur["para"] >= fiyat
                   else ui.r(f"₺{fiyat} (yetersiz)", "gri"))
            print(f"  [{ui.r('y', 'camgobegi', 'kalin')}] {'Lab kur' if not kademe else 'Yükselt'}: "
                  f"{ad} — {acik}  (+₺{gelir}/gün)  {etk}")
            secenekler.append("y")
        if kademe:
            print(f"  [{ui.r('p', 'camgobegi', 'kalin')}] Antrenman yap (bedava, XP kazan)")
            secenekler.append("p")
        print(f"\n  [{ui.r('q', 'camgobegi')}] Geri")
        secim = ui.sor("\n  Ne yapalım? ").lower().strip()
        if secim == "q":
            return
        if secim == "y" and "y" in secenekler:
            fiyat, ad, gelir, _ = LAB_KADEMELERI[kademe + 1]
            if dur["para"] < fiyat:
                print(ui.hata("Paran yetmiyor. Birkaç iş daha kapat."))
                ui.bekle()
            else:
                dur["para"] -= fiyat
                dur["lab"] = kademe + 1
                kayit.kaydet()
                print(ui.basari(f"{ad} kuruldu! Her gün +₺{gelir} ve bedava antrenman."))
                ui.bekle()
        elif secim == "p" and "p" in secenekler:
            _pratik(kayit)


def _is_oyna(kayit: Kayit, job: dict, oyuncu_zorluk: str) -> dict:
    """İşi gerçek terminalde oynatır; zorluğu geçici uygular, sonra geri yükler. Maaş döndürür."""
    sv = _sv(job["anahtar"])
    _vaka_kur(kayit, sv, job["tohum"])
    kayit.veri["ayarlar"]["zorluk"] = job["zorluk"]
    kayit.kaydet()
    xp_once = kayit.veri["xp"]
    rutbe_once = rutbe(xp_once)["ad"]

    senaryo = sv.senaryo(job["tohum"])
    lab = lab_kur(sv, senaryo)
    print(ui.bilgi(f"İşe giriyorsun: {ui.r(job['kurulus'], 'kalin')} — {sv.baslik} "
                   f"({_zorluk_rozet(job['zorluk'])}). Menüye dönmek için kabukta "
                   f"{ui.r('cik', 'camgobegi')} yaz."))
    ui.bekle("Hazırsan Enter")
    gorev_kabugu(sv, lab)

    kayit = Kayit()
    d = kayit.seviye(sv.kimlik)
    cozulen = len(d.get("cozulen", {}))
    toplam = len(sv.gorevler)
    dur = _durumu(kayit)
    _, kad = _kademe(dur["itibar"])
    gear = _ekipman_etki(dur)
    z_xp = zorluk.ZORLUKLAR[job["zorluk"]]["xp"]
    bonus = STORY_BONUS if job.get("hikaye") else 1.0
    para = round(ISLER[job["anahtar"]]["taban"] * cozulen * z_xp * kad[4] * (1 + gear["pay"]) * bonus)
    itibar = round(cozulen * z_xp) + (gear["itibar"] if cozulen else 0)
    xp_kazanc = kayit.veri["xp"] - xp_once
    rutbe_sonra = rutbe(kayit.veri["xp"])["ad"]

    dur["para"] += para
    dur["itibar"] += itibar
    tam = cozulen == toplam and bool(toplam)
    if tam:
        dur["tamamlanan_is"] += 1
    kayit.veri["ayarlar"]["zorluk"] = oyuncu_zorluk
    kayit.kaydet()
    return {"kayit": kayit, "cozulen": cozulen, "toplam": toplam, "para": para,
            "itibar": itibar, "xp": xp_kazanc, "tam": tam,
            "rutbe_atladi": rutbe_sonra if rutbe_sonra != rutbe_once else None}


def _maas_ekrani(sonuc: dict, sv) -> None:
    ui.temizle()
    print(ui.baslik_cubugu("Maaş günü", "yesil"))
    oran = sonuc["cozulen"] / max(1, sonuc["toplam"])
    print("  " + ui.ilerleme(oran, 24) + f"  {sonuc['cozulen']}/{sonuc['toplam']} görev")
    print()
    if sonuc["cozulen"] == 0:
        print(ui.r("  İşi yarıda bıraktın — bu sefer ödeme yok. Olur böyle, yeni gün yeni fırsat.", "gri"))
    else:
        print(f"  Kazanç:  {ui.r('+₺' + str(sonuc['para']), 'yesil', 'kalin')}"
              f"   ·   İtibar {ui.r('+' + str(sonuc['itibar']), 'sari')}"
              f"   ·   XP {ui.r('+' + str(sonuc['xp']), 'camgobegi')}")
        if sonuc["tam"]:
            print(ui.basari("Tam çözüm! Müşteri memnun, adın bir çevre daha genişledi."))
    if sonuc.get("rutbe_atladi"):
        print(ui.kutu("RÜTBE ATLADIN", f"Yeni rütbe: **{sonuc['rutbe_atladi']}**. Deniz başını salladı: *\"Hak ettin.\"*", "sari"))
    if getattr(sv, "gercek_hayat", ""):
        print()
        print(ui.kutu("GERÇEK HAYATTA", _temiz(sv.gercek_hayat), "mor"))
    ui.bekle()


def _terfi_kontrol(kayit: Kayit) -> None:
    dur = _durumu(kayit)
    idx, kad = _kademe(dur["itibar"])
    if idx > dur.get("gorulen_kademe", 0):
        dur["gorulen_kademe"] = idx
        kayit.kaydet()
        print(ui.kutu("TERFİ", f"İtibarın yükseldi: **{kad[1]}**. Daha büyük işler ve daha iyi "
                              f"ödemeler açıldı. Gelen kutun artık farklı.", "sari"))
        ui.bekle()


_HIKAYE_ETIKET = {"Not": "Masanda bir not", "Sen": "Fark ediyorsun", "K.": "Tanımadığın numara"}


def _hikaye_ilerlet(kayit: Kayit) -> None:
    """Koşulu gelen sıradaki hikâye anını bir kez gösterir; gerekirse özel (★) iş ekler."""
    dur = _durumu(kayit)
    adim = dur.get("hikaye_adim", 0)
    if adim >= len(HIKAYE):
        return
    satir = HIKAYE[adim]
    min_is, min_it, kim, metin, ozel = satir[:5]
    zorla_aile = satir[5] if len(satir) > 5 else None
    if dur["tamamlanan_is"] < min_is or dur["itibar"] < min_it:
        return
    dur["hikaye_adim"] = adim + 1
    if ozel:
        _, kad = _kademe(dur["itibar"])
        zorlar = [x for x in ("normal", "zor") if x in kad[3]] or list(kad[3])
        aile = zorla_aile if (zorla_aile and zorla_aile in ISLER) else random.choice(kad[2])
        job = _is_uret(aile, random.choice(zorlar), dur["sonraki_no"],
                       hikaye=True, patron=kim)
        dur["sonraki_no"] += 1
        dur["kutu"].append(job)
    kayit.kaydet()
    ui.temizle()
    print(ui.baslik_cubugu("Hikâye · Sıfırıncı Gün", "mor"))
    print(ui.kutu(_HIKAYE_ETIKET.get(kim, kim), metin, "camgobegi"))
    if ozel:
        print(ui.bilgi("Gelen kutuna özel bir iş düştü (★ ÖZEL İŞ) — bonus ödeme."))


# ------------------------------------------------------------------ ana döngü

def yasam_modu(kayit: Kayit) -> None:
    """Hayat Modu: kariyer / günlük iş döngüsü."""
    if not kayit.veri["oyuncu"].get("ad"):
        from hy.motor.oyun import karsilama
        karsilama(kayit)
        kayit = Kayit()
    kayit.gun_isaretle()
    oyuncu_zorluk = zorluk.anahtar(kayit)
    dur = _durumu(kayit)
    kayit.kaydet()

    if not dur["tanisildi"]:
        ui.temizle()
        print(ui.baslik_cubugu("Hayat Modu", "mor"))
        print(ui.md("""
Burası senin köşen. Gelen kutusuna işler düşer; okur, **kabul eder / reddeder / ertelersin**.
Kabul ettiğini **gerçek terminalde** çözersin — **para, itibar ve XP** kazanırsın. Zor işler
daha çok öder ama SOC seni arar. Parayı **dükkânda ekipmana** çevir; itibarın yükseldikçe
daha büyük işler açılır.

*(İlerlemen normal oyunla aynı kayıtta; `[a]` ile bunu oyunun ana ekranı yapabilirsin.)*
"""))
        dur["tanisildi"] = True
        kayit.kaydet()
        ui.bekle("Başlamak için Enter")

    _kutu_doldur(kayit)
    kayit.kaydet()

    while True:
        kayit = Kayit()
        dur = _durumu(kayit)
        _daire(kayit)
        print()
        aktif = [j for j in dur["kutu"] if j["durum"] in ("yeni", "ertelendi")]
        if not aktif:
            print(ui.r("  Gelen kutusu boş. Uyuyup yeni bir gün bekleyebilirsin.", "gri"))
        for j in aktif:
            etiket = ui.r(" (ertelendi)", "gri") if j["durum"] == "ertelendi" else ""
            yildiz = ui.r("★ ", "sari") if j.get("hikaye") else ""
            print(f"  [{ui.r(str(j['no']), 'camgobegi', 'kalin')}] {yildiz}{ISLER[j['anahtar']]['konu']} — "
                  f"{ui.r(j['kurulus'], 'kalin')} · {_zorluk_rozet(j['zorluk'])} · "
                  f"{ui.r('₺' + str(_odul_max(j, dur)), 'yesil')}{etiket}")
        ana = kayit.veri["ayarlar"].get("hayat_ana")
        print(f"\n  [{ui.r('u', 'camgobegi')}] Uyu (yeni gün)   [{ui.r('s', 'camgobegi')}] Dükkân   "
              f"[{ui.r('l', 'camgobegi')}] Ev Lab   "
              f"[{ui.r('a', 'camgobegi')}] {'Normal menüye dön' if ana else 'Ana ekran yap'}   "
              f"[{ui.r('q', 'camgobegi')}] Çıkış")
        secim = ui.sor("\n  Ne yapalım? ").lower().strip()

        if secim == "q":
            kayit.kaydet()
            print(ui.r("\n  İyi geceler. Adın yayılıyor.", "gri"))
            return
        if secim == "u":
            dur["gun"] += 1
            kazanc = _ekipman_etki(dur)["gunluk"] + _lab_gelir(dur)
            if kazanc:
                dur["para"] += kazanc
            kayit.kaydet()
            _kutu_doldur(kayit)
            kayit.kaydet()
            if kazanc:
                print(ui.bilgi(f"Yeni gün. Pasif gelir: +₺{kazanc}."))
                time.sleep(0.8)
            continue
        if secim == "s":
            _dukkan(kayit)
            continue
        if secim == "l":
            _lab_ekrani(kayit)
            continue
        if secim == "a":
            yeni = not kayit.veri["ayarlar"].get("hayat_ana")
            kayit.veri["ayarlar"]["hayat_ana"] = yeni
            kayit.kaydet()
            print(ui.bilgi("Oyun artık doğrudan Hayat Modu'yla açılacak." if yeni
                           else "Oyun normal menüyle açılacak. (Hayat Modu menüde [d].)"))
            ui.bekle()
            continue
        if not secim.isdigit():
            continue
        job = next((j for j in dur["kutu"] if str(j["no"]) == secim and j["durum"] in ("yeni", "ertelendi")), None)
        if not job:
            continue

        _eposta_goster(job, dur)
        print(f"  [{ui.r('k', 'camgobegi', 'kalin')}] Kabul et    "
              f"[{ui.r('e', 'camgobegi')}] Ertele    "
              f"[{ui.r('r', 'camgobegi')}] Reddet    "
              f"[{ui.r('g', 'camgobegi')}] Geri")
        karar = ui.sor("\n  Kararın? ").lower().strip()
        if karar == "r":
            job["durum"] = "reddedildi"
            kayit.kaydet()
        elif karar == "e":
            job["durum"] = "ertelendi"
            kayit.kaydet()
        elif karar == "k":
            sonuc = _is_oyna(kayit, job, oyuncu_zorluk)
            k = sonuc["kayit"]
            for j in _durumu(k)["kutu"]:
                if j["no"] == job["no"]:
                    j["durum"] = "bitti"
            k.kaydet()
            _maas_ekrani(sonuc, _sv(job["anahtar"]))
            _terfi_kontrol(k)
            _kutu_doldur(k)
            k.kaydet()
            _hikaye_ilerlet(k)
            ui.bekle()
