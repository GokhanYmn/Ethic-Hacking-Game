"""Olay Masası — DNS Tünelleme Tespiti.

Bir müşterinin DNS sorgu logunda bir iç istemci, tek bir alan adına çok sayıda ve çok uzun
(base32/hex görünümlü) alt alan sorgusu yapıyor: veri DNS sorgularının içine gizlenip
sızdırılıyor. Yalnızca log kanıtı incelenir; saldırı yapılmaz.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

TUNEL_ALANLARI = ["kotu-alan.lab", "veri-akis.lab", "sessiz-kanal.lab", "yedek-bulut.lab", "gizli-yol.lab"]
ALT_ALANLAR = ["veri", "t", "c2", "d", "x"]
NORMAL_ALANLAR = ["guncelleme.os-ag.lab", "cdn.sunucu-agi.lab", "zaman.ntp-ag.lab", "mail.posta-ag.lab",
                  "yazilim.paket-ag.lab", "bulut.depo-ag.lab"]
HEX = "0123456789abcdef"
B32 = "abcdefghijklmnopqrstuvwxyz234567"


def _etiket(rng, uzunluk, alfabe):
    return "".join(rng.choice(alfabe) for _ in range(uzunluk))


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)
    tunel_ip, *digerleri = u.benzersiz(rng, lambda r: u.ic_ip(r, "10.0.0"), 7)
    alan = rng.choice(TUNEL_ALANLARI)
    alt = rng.choice(ALT_ALANLAR)
    tip = rng.choice(["TXT", "NULL"])
    alfabe = rng.choice([HEX, B32])
    kayitlar = []   # (zaman, ip, ad, tip)

    # normal trafik
    normal_adlar = [f"www.{m['alan']}", f"mail.{m['alan']}", f"vpn.{m['alan']}"] + NORMAL_ALANLAR
    n_normal = rng.randint(220, 300)
    for t in u.zamanlar(rng, gun.replace(hour=8), n_normal, 5, 90):
        ip = rng.choice(digerleri + [tunel_ip])
        ad = rng.choice(normal_adlar)
        kayitlar.append((t, ip, ad, rng.choice(["A", "A", "A", "AAAA", "MX"])))

    # yem: başka bir istemcinin birkaç orta uzunlukta (CDN özet) etiketi ve normal TXT sorgusu
    yem_ip = digerleri[0]
    for t in u.zamanlar(rng, gun.replace(hour=10), rng.randint(3, 5), 600, 1800):
        kayitlar.append((t, yem_ip, f"img-{_etiket(rng, rng.randint(22, 28), HEX)}.cdn-ag.lab", "A"))
    for t in u.zamanlar(rng, gun.replace(hour=11), 2, 900, 2400):
        kayitlar.append((t, digerleri[1], m["alan"], "TXT"))

    # tünel: aynı alana çok sayıda uzun, benzersiz etiket
    n_tunel = rng.randint(70, 140)
    etiketler = []
    for t in u.zamanlar(rng, gun.replace(hour=13), n_tunel, 2, 25):
        et = _etiket(rng, rng.randint(46, 63), alfabe)
        etiketler.append(et)
        kayitlar.append((t, tunel_ip, f"{et}.{alt}.{alan}", tip))

    kayitlar.sort(key=lambda k: k[0])
    log = "".join(f"{t:%Y-%m-%d %H:%M:%S} {ip} {ad} {tp}\n" for t, ip, ad, tp in kayitlar)
    tunel_istemci_toplam = sum(1 for k in kayitlar if k[1] == tunel_ip)
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — DNS sorgu logu",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "alan_musteri": m["alan"]},
        "cevaplar": {
            "istemci": tunel_ip,
            "alan": [alan, f"{alt}.{alan}"],
            "sorgu_sayisi": n_tunel,
            "en_uzun": max(len(e) for e in etiketler),
            "tip": tip,
        },
        "_log": log,
        "_istemci_toplam": tunel_istemci_toplam,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "dns.log", s["_log"])


def _sayi_hata(g, beklenen, b):
    if int(g) == b.senaryo["_istemci_toplam"] and int(g) != beklenen:
        return "Bu, istemcinin **tüm** sorgularının sayısı. Sadece şüpheli alana giden sorguları say."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]


def coz(lab: Path, s: dict) -> dict:
    # etiket (ilk parça) 40 karakterden uzun olan sorgular tünel imzasıdır
    uzun = "awk '{split($4,p,\".\"); if (length(p[1])>40) print}' dns.log"
    istemci = _sh(uzun + " | awk '{print $3}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    alan = _sh(uzun + " | awk '{n=split($4,p,\".\"); print p[n-1]\".\"p[n]}' | sort | uniq -c | sort -rn "
               "| head -1 | awk '{print $2}'", lab)
    sayi = _sh(f"grep -c '{alan} ' dns.log", lab)
    en_uzun = _sh(f"grep '{alan} ' dns.log | awk '{{split($4,p,\".\"); print length(p[1])}}' | sort -rn | head -1", lab)
    tip = _sh(f"grep '{alan} ' dns.log | awk '{{print $5}}' | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'",
              lab)
    return {1: istemci, 2: alan, 3: sayi, 4: en_uzun, 5: tip, 6: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("DNS üzerinden veri sızdıran **iç istemcinin IP adresi** hangisi?",
          IP("istemci"),
          ("Normal bir alt alan kısa olur (`www`, `mail`). Tünelleme olağandışı **uzun** etiketler üretir.",
           "Sorgulanan adın ilk parçasının (ilk noktaya kadar) uzunluğuna bak: `awk '{split($4,p,\".\"); print length(p[1])}'`.",
           "`awk '{split($4,p,\".\"); if (length(p[1])>40) print $3}' dns.log | sort | uniq -c | sort -rn | head -3`"),
          puan=15, baslik="Tünelleyen istemci"),
    Gorev("Tünelleme için kötüye kullanılan **ana alan adı** nedir? (örn. `ornek.lab` biçiminde, son iki parça)",
          Metin("alan", bicim="alan adı"),
          ("Uzun etiketlerin hepsi aynı alan adının altına sorulmuştur.",
           "Adı noktalardan böl, son iki parçayı al: `split($4,p,\".\"); print p[n-1]\".\"p[n]`; sonra `sort | uniq -c`.",
           "`awk '{n=split($4,p,\".\"); if (length(p[1])>40) print p[n-1]\".\"p[n]}' dns.log | sort | uniq -c | sort -rn`"),
          puan=15, baslik="Kötü alan"),
    Gorev("Bu alan adına **toplam kaç sorgu** yapılmış?",
          Sayi("sorgu_sayisi", sik_hatalar=_sayi_hata),
          ("Sadece o alan adıyla biten sorguları say; istemcinin diğer normal sorguları dışarıda kalmalı.",
           "Alan adını `grep` ile süz ve say.",
           "`grep -c '<alan> ' dns.log` (alandan sonraki boşluk, sorgu adının bittiğini garanti eder)"),
          puan=15, baslik="Sorgu sayısı"),
    Gorev("Tünel sorgularındaki **en uzun alt alan etiketi** (ilk parça) kaç karakter?",
          Sayi("en_uzun"),
          ("Sorgu adını noktalardan böl, ilk parçanın uzunluğunu hesapla.",
           "`awk '{split($4,p,\".\"); print length(p[1])}'` ile uzunlukları yazdır, büyükten küçüğe sırala.",
           "`grep '<alan> ' dns.log | awk '{split($4,p,\".\"); print length(p[1])}' | sort -rn | head -1`"),
          puan=20, baslik="En uzun etiket"),
    Gorev("Tünel sorguları hangi **DNS kayıt tipini** kullanıyor? (A, AAAA, MX, TXT, NULL...)",
          Metin("tip", bicim="kayıt tipi"),
          ("Kayıt tipi satırın son alanı. Tünel, veri taşıyabilen bir tip seçer.",
           "Tünel sorgularının son alanını sayıp sırala.",
           "`grep '<alan> ' dns.log | awk '{print $5}' | sort | uniq -c | sort -rn`"),
          puan=15, baslik="Kayıt tipi"),
    Gorev("DNS tünellemesine karşı **en doğru savunma** hangisi?",
          Secmeli([
              ("DNS sorgularını logla; uzun/yüksek hacimli sorguları izleyip sınırla ve kötü alanı engelle",
               "Doğru. Tünelleme tespiti görünürlükle başlar; anormal uzunluk/hacim alarmı ve alan engeli saldırıyı keser."),
              ("UDP 53 trafiğini tamamen kapat",
               "Aşırı: iç ağ DNS'siz çalışmaz. Doğrusu izleme, sınırlama ve belirli alanı engellemektir."),
              ("İstemcinin bilgisayarını kapat ve loga bakma",
               "Kanıtı ve kapsamı kaybedersin; hangi verinin gittiğini anlamadan geçici çözüm olur."),
              ("DNS loglamayı kapat, gürültü azalır",
               "Tam tersi: log olmadan tünelleme asla görünmez. Loglama tespitin temelidir."),
          ]),
          ("Önce görünürlük, sonra kontrol: ne görmediğini engelleyemezsin.",
           "Doğru cevap hem izlemeyi hem sınırlamayı hem de kötü alanı engellemeyi birleştirir.",
           "Logla → uzunluk/hacim alarmı kur → kötü alanı engelle; DNS'i tümden kapatma."),
          puan=20, baslik="Savunma"),
]

SEVIYE = Seviye(
    kimlik="olay_dns",
    cilt=2,
    bolum=105,
    baslik="DNS Tünelleme Tespiti",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<kisi>>, güvenlik
duvarının sorgu günlüğünde garip, okunmaz alan adları görmüş. İç ağdaki DNS sorgu logunu
gönderdi: `dns.log`."

"Biçim: `tarih saat istemci-IP sorgulanan-ad kayıt-tipi`. Normal sorgular kısadır (`www`,
`mail`, `cdn`). Şüphe şu: biri verileri DNS sorgularının içine gizleyip dışarı sızdırıyor.
Tünelleme, tek bir alan adının altına rastgele görünen uzun etiketler yağdırır. Hangi
istemci, hangi alan, ne kadar? Bul."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
DNS tünelleme üç iz bırakır: çok uzun ve rastgele görünen etiketler, tek alana yığılan çok
sayıda benzersiz sorgu ve TXT/NULL gibi veri taşıyabilen kayıt tipleri. Savunmacı DNS
sorgularını loglar, sorgu uzunluğu ve hacmi için eşik alarmı kurar, yalnızca kurumsal DNS
çözücüsünün dışarı çıkmasına izin verir (egress filtreleme) ve kötü alanı engeller.
""",
    gercek_hayat="""
- **SolarWinds / Sunburst, 2020:** Arka kapı, kurbanın bilgisini alt alan etiketine
  kodlayıp `avsvmcloud[.]com` altına DNS sorgusu olarak gönderiyordu; yanıtla da komut
  alıyordu. DNS trafiği çoğu ağda süzülmediği için aylarca fark edilmedi.
- **DNS tünelleme araçları (iodine, dnscat2) ve sızıntı vakaları:** Saldırganlar, kapalı
  ağlardan bile geçen DNS'i veri sızdırma kanalı olarak kullanır; kuruluşlar çoğunlukla
  anormal sorgu uzunluğu ve hacmi analizi ile yakalar.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c02b04",),
)
