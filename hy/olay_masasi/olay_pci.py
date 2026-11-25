"""Olay Masası — Kart Verisi Sızıntısı Avı.

Her vakada başka bir kurumun ödeme uygulaması logları: bazı dosyalar maskelenmemiş kart
numarası (PAN) ya da CVV taşır, bazıları temizdir; bir giden istek bir yabancı alan adına kart
numarası taşır. Kartlar yalnızca herkesçe bilinen test kartlarıdır (4111111111111111 gibi).
"""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

TEST_KARTLARI = ["4111111111111111", "5555555555554444", "4012888888881881", "5105105105105100",
                 "6011111111111117", "3530111333300000"]
YABANCI = ["kart-analiz.lab", "odeme-istatistik.lab", "hizli-rapor.lab", "veri-toplayici.lab", "tr-metrik.lab"]
DOSYALAR = ["odeme-api.log", "web-app.log", "iade-servisi.log", "debug-trace.log", "destek-notlari.txt",
            "ag-cikis.log"]
ZORUNLU_SIZAN = ["debug-trace.log", "ag-cikis.log"]
PAN_RE = re.compile(r"\d{16}")


def maske(pan: str) -> str:
    return pan[:6] + "******" + pan[-4:]


def _satir(dosya, rng, t, pan, cvv=None, durum=None):
    """pan: ham ya da maskeli kart numarası; cvv: ham/'***'/None."""
    tl = t.strftime("%Y-%m-%dT%H:%M:%S+03:00")
    tutar = rng.randint(50, 9000)
    iid = "".join(rng.choice("abcdef") for _ in range(4)) + str(rng.randint(10, 99))
    c_duz = f" cvv={cvv}" if cvv else ""
    if dosya == "odeme-api.log":
        return f"{tl} INFO odeme-api islem={iid} tutar={tutar} TRY kart={pan}{c_duz} durum={durum or 'ONAY'}"
    if dosya == "web-app.log":
        return f"{tl} INFO web POST /odeme/onay istemci={u.ic_ip(rng, '10.0.0')} kart={pan}{c_duz} sepet={rng.randint(1, 9)}"
    if dosya == "iade-servisi.log":
        return f"{tl} INFO iade iade_no=R{rng.randint(1000, 9999)} tutar={tutar} kart={pan}{c_duz} durum=BEKLEMEDE"
    if dosya == "debug-trace.log":
        c = f',"cvv":"{cvv}"' if cvv else ""
        return f'{tl} DEBUG req={iid} payload={{"kart":"{pan}","skt":"{rng.randint(1, 12):02d}/2{rng.randint(7, 9)}"{c}}}'
    if dosya == "destek-notlari.txt":
        return f"{tl[:10]} destek talebi #{rng.randint(1000, 9999)}: musteri kart no {pan} ile ilgili {rng.choice(['itiraz', 'iade', 'limit'])} sordu."
    return f"{tl} INFO cikis-proxy POST http://odeme-gecidi.lab/v2/tahsilat govde=kart:{pan} tutar={tutar} yanit=200"


def uret(rng):
    m = musteri_sec(rng)
    for _ in range(50):
        sizan = list(ZORUNLU_SIZAN) + rng.sample([d for d in DOSYALAR if d not in ZORUNLU_SIZAN], rng.randint(1, 2))
        cvv_dosya = rng.choice([d for d in sizan if d not in ("ag-cikis.log", "destek-notlari.txt")])
        yabanci = rng.choice(YABANCI)
        agirlik = rng.sample(TEST_KARTLARI, 4)
        dosyalar = {}
        pan_sayac = Counter()
        pan_satir = 0
        debug_pan = 0
        t = u.gun(rng).replace(hour=rng.randint(6, 14))
        for d in DOSYALAR:
            satirlar = []
            n_temiz = rng.randint(7, 12)
            n_pan = rng.randint(1, 4) if d in sizan else 0
            if d == "ag-cikis.log":
                n_pan = rng.randint(1, 3)
            kartlar = []
            for _i in range(n_temiz + n_pan):
                satir_t = t.replace(minute=rng.randint(0, 59), second=rng.randint(0, 59))
                pan = rng.choices(TEST_KARTLARI[:4] + TEST_KARTLARI[4:], weights=[5, 3, 2, 2, 1, 1])[0]
                kartlar.append((satir_t, pan))
            kartlar.sort()
            pan_idx = set(rng.sample(range(len(kartlar)), n_pan))
            for i, (satir_t, pan) in enumerate(kartlar):
                cvv_ham = f"{rng.randint(100, 999)}" if (d == cvv_dosya and i in pan_idx) else None
                if i in pan_idx:
                    if d == "ag-cikis.log":
                        s_ = (f"{satir_t:%Y-%m-%dT%H:%M:%S}+03:00 INFO cikis-proxy POST http://{yabanci}/k/topla "
                              f"govde=kart:{pan} yanit=200")
                    else:
                        s_ = _satir(d, rng, satir_t, pan, cvv_ham)
                    pan_sayac[pan] += 1
                    pan_satir += 1
                    if d == "debug-trace.log":
                        debug_pan += 1
                else:
                    cvv_m = "***" if (d in ("odeme-api.log", "web-app.log") and rng.random() < .5) else None
                    s_ = _satir(d, rng, satir_t, maske(pan), cvv_m)
                satirlar.append(s_)
            dosyalar[d] = "\n".join(satirlar) + "\n"
        top = pan_sayac.most_common(2)
        if len(top) < 2 or top[0][1] > top[1][1]:
            break
    sizan_say = sum(1 for d in dosyalar.values() if PAN_RE.search(d))
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — ödeme uygulaması logları",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"],
                  "sunucu": m["sunucu"]},
        "cevaplar": {"pan_satir": pan_satir, "pan_dosya": sizan_say, "cvv_dosya": [cvv_dosya],
                     "alan": [yabanci], "en_cok": [top[0][0]]},
        "_dosyalar": dosyalar,
        "_debug_pan": debug_pan,
        "_debug_satir": dosyalar["debug-trace.log"].count("\n"),
    }


CONF = """# kart verisi log maskeleme ayarları
maskele_pan = hayir
pan_ilk_hane = 6
pan_son_hane = 4
cvv_logla = evet
log_seviyesi = DEBUG
"""


def yaz(lab: Path, s: dict) -> None:
    for ad, icerik in s["_dosyalar"].items():
        u.yaz(lab / "loglar" / ad, icerik)
    u.yaz(lab / "config" / "log_maskeleme.conf", CONF)


def _ayar(b, anahtar):
    yol = b.lab / "config" / "log_maskeleme.conf"
    if not yol.exists():
        return None
    for s_ in yol.read_text(encoding="utf-8").splitlines():
        mm = re.match(rf"\s*{anahtar}\s*=\s*(\S+)", s_)
        if mm:
            return mm.group(1).lower()
    return None


def _kural_duzeldi(b) -> Sonuc:
    if not (b.lab / "config" / "log_maskeleme.conf").exists():
        return Sonuc(False, "`config/log_maskeleme.conf` silinmiş; `sifirla` ile geri getir ve düzenle.")
    pan, cvv = _ayar(b, "maskele_pan"), _ayar(b, "cvv_logla")
    if pan not in ("evet", "true", "on", "1"):
        return Sonuc(False, f"`maskele_pan` hâlâ `{pan}`: kart numarası maskelenmeli.")
    if cvv not in ("hayir", "false", "off", "0"):
        return Sonuc(False, f"`cvv_logla` hâlâ `{cvv}`: CVV hiçbir koşulda loglanmamalı.", yakin=True)
    return Sonuc(True, "Kural düzeldi: PAN maskeleniyor, CVV artık loglanmıyor. Eski loglar için de temizlik gerekir.")


def _debug_maskelendi(b) -> Sonuc:
    yol = b.lab / "loglar" / "debug-trace.log"
    if not yol.exists():
        return Sonuc(False, "`debug-trace.log` yok; silmek yerine içindeki numaraları maskelemelisin.")
    metin = yol.read_text(encoding="utf-8")
    if metin.count("\n") != b.senaryo["_debug_satir"]:
        return Sonuc(False, "Satır sayısı değişmiş. Satırları silme; sadece numaraları maskele.")
    kalan = len(PAN_RE.findall(metin))
    if kalan:
        return Sonuc(False, f"Dosyada hâlâ {kalan} maskesiz kart numarası var.", yakin=kalan < b.senaryo["_debug_pan"])
    if len(re.findall(r"\d{6}\*+\d{4}", metin)) < b.senaryo["_debug_pan"]:
        return Sonuc(False, "Numaralar silinmiş ya da bozulmuş. İlk 6 ve son 4 hane kalsın, ortası `*` olsun.",
                     yakin=True)
    return Sonuc(True, "Temiz: ilk 6 + son 4 hane görünür, ortası yıldız.")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _satir_hata(g, beklenen, b):
    if int(g) > beklenen:
        return "Maskeli satırları da saymış olabilirsin: maskeli numarada `*` var, bitişik 16 rakam yok."
    return None


def coz(lab: Path, s: dict) -> dict:
    satir = _sh("grep -hE '[0-9]{16}' loglar/* | wc -l", lab)
    dosya = _sh("grep -lE '[0-9]{16}' loglar/* | wc -l", lab)
    cvv = _sh("grep -lE 'cvv\"?[:=]\"?[0-9]{3,4}' loglar/*", lab).split("/")[-1]
    alan = _sh("grep -E '[0-9]{16}' loglar/* | grep -oE 'http://[a-z0-9.-]+' | sort -u | grep -v odeme-gecidi "
               "| sed 's#http://##'", lab)
    en_cok = _sh("grep -ohE '[0-9]{16}' loglar/* | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    _sh("sed -i 's/^maskele_pan = hayir/maskele_pan = evet/; s/^cvv_logla = evet/cvv_logla = hayir/' "
        "config/log_maskeleme.conf", lab)
    _sh("sed -i -E 's/([0-9]{6})[0-9]{6}([0-9]{4})/\\1******\\2/g' loglar/debug-trace.log", lab)
    return {1: satir, 2: dosya, 3: cvv, 4: alan, 5: en_cok, 6: "", 7: "", 8: Secmeli_cevap(s, lab)}


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[7].kontrol.cevabi_goster(Baglam(s, lab, 8))[0]


GOREVLER = [
    Gorev("`loglar/` altında **maskelenmemiş kart numarası** (16 bitişik rakam) içeren **satır** sayısı kaç?",
          Sayi("pan_satir", sik_hatalar=_satir_hata),
          ("Maskeli numara `411111******1111` gibi görünür; maskesiz olanda 16 rakam yan yana durur.",
           "`grep -E '[0-9]{16}'` tam 16 bitişik rakamı arar. Tüm dosyalarda ara.",
           "`grep -hE '[0-9]{16}' loglar/* | wc -l` (`-h` dosya adını gizler)"),
          puan=20, baslik="Maskesiz satır"),
    Gorev("Maskesiz kart numarası içeren **dosya** sayısı kaç?",
          Sayi("pan_dosya"),
          ("Bu kez satırı değil dosyayı sayıyorsun.",
           "`grep -l` yalnızca eşleşen dosya adlarını yazar.",
           "`grep -lE '[0-9]{16}' loglar/* | wc -l`"),
          puan=15, baslik="Sızan dosya sayısı"),
    Gorev("**CVV'yi gerçek değeriyle** saklayan dosyanın adı ne? (`cvv=***` gibi maskeli olanlar sayılmaz)",
          Metin("cvv_dosya", bicim="dosya adı", sadece_ad=True),
          ("`cvv` kelimesi birkaç dosyada geçiyor; ama biri gerçek rakam saklıyor.",
           "`cvv=` ya da `\"cvv\":\"` ardından 3-4 rakam gelen satırı ara.",
           "`grep -lE 'cvv\"?[:=]\"?[0-9]{3,4}' loglar/*`"),
          puan=20, baslik="CVV saklayan"),
    Gorev("Maskesiz kart numarasının **kurum dışı bir alan adına gönderildiği** satırı bul. "
          "Alan adı ne? (meşru ödeme geçidi `odeme-gecidi.lab` değil)",
          Metin("alan", bicim="alan adı", on_ekleri_at=("http://",)),
          ("Giden istekler bir proxy logunda tutuluyor.",
           "Maskesiz numara içeren satırlardan `POST http://...` geçenlere bak.",
           "`grep -E '[0-9]{16}' loglar/ag-cikis.log` — URL'deki alan adını oku."),
          puan=25, baslik="Sızıntı hedefi"),
    Gorev("Maskesiz hâlde **en çok geçen** kart numarası hangisi?",
          Metin("en_cok", bicim="16 haneli numara"),
          ("Hangi numaranın kaç kez geçtiğini saymalısın.",
           "Numaraları sadece çıkar (`grep -o`), sırala, say.",
           "`grep -ohE '[0-9]{16}' loglar/* | sort | uniq -c | sort -rn | head -1`"),
          puan=20, baslik="En çok sızan kart"),
    Gorev("`config/log_maskeleme.conf` dosyasında kök neden var: PAN maskelenmiyor ve CVV loglanıyor. "
          "`maskele_pan`'ı `evet`, `cvv_logla`'yı `hayir` yap. Bitince `cevap 6` yaz.",
          Durum(_kural_duzeldi, "sed -i 's/^maskele_pan = hayir/maskele_pan = evet/; "
                                "s/^cvv_logla = evet/cvv_logla = hayir/' config/log_maskeleme.conf"),
          ("Ayar dosyası düz metin; iki satırı değiştirmen yeterli.",
           "Bir metin düzenleyici ya da `sed -i 's/eski/yeni/' dosya` kullanabilirsin.",
           "`sed -i 's/^maskele_pan = hayir/maskele_pan = evet/' config/log_maskeleme.conf` ve CVV için benzeri."),
          puan=25, baslik="Kuralı düzelt"),
    Gorev("Geçmiş logu da temizle: `loglar/debug-trace.log` içindeki kart numaralarını **ilk 6 ve son 4 hane "
          "görünecek, ortası `*` olacak** şekilde maskele (`sed` ile). Satırları silme. Bitince `cevap 7` yaz.",
          Durum(_debug_maskelendi, "sed -i -E 's/([0-9]{6})[0-9]{6}([0-9]{4})/\\1******\\2/g' loglar/debug-trace.log"),
          ("`sed` yer değiştirme yapabilir; `-i` ile dosyayı yerinde değiştirir.",
           "Genişletilmiş düzenli ifade (`-E`) ile 6 rakam, 6 rakam, 4 rakamı gruplayıp ortayı yıldızla.",
           "`sed -i -E 's/([0-9]{6})[0-9]{6}([0-9]{4})/\\1******\\2/g' loglar/debug-trace.log`"),
          puan=30, baslik="Geçmişi maskele"),
    Gorev("PCI DSS'e göre bir işlem yetkilendirildikten sonra CVV neden **hiçbir yerde saklanamaz**?",
          Secmeli([
              ("Kartın fiziksel varlığını kanıtlayan tek veridir; çalınırsa kart sahibi olmadan alışveriş yapılabilir",
               "Doğru. CVV'nin tek amacı kartın elde olduğunu doğrulamaktır; saklanırsa bu kanıt değerini yitirir."),
              ("Çok yer kapladığı için disk dolar",
               "CVV 3-4 rakamdır; yasak performansla ilgili değil."),
              ("Sadece bankaların saklaması yasaktır, satıcılar saklayabilir",
               "Hayır: yetkilendirme sonrası CVV'yi kimse saklayamaz, şifreli olsa bile."),
              ("Şifreli saklandığı sürece serbesttir",
               "Hayır. Yetkilendirme sonrası CVV, şifreli de olsa saklanamaz."),
          ]),
          ("CVV'nin kartta ne işe yaradığını düşün.",
           "Veri tabanı sızsa saldırgan bu veriyle ne yapabilir?",
           "Kartı gerçekten elinde tutan kişiyi ayırt eden bilgi saklanırsa bu ayrım kalmaz."),
          puan=15, baslik="Neden yasak"),
]

SEVIYE = Seviye(
    kimlik="olay_pci",
    cilt=1,
    bolum=94,
    baslik="Kart Verisi Sızıntısı Avı",
    brifing="""
Deniz Kara ekranına yeni bir bildirim düşüyor: "**<<musteri>>** (<<sektor>>) için PCI denetimi
yaklaşıyor. <<hikaye>> <<kisi>> **<<sunucu>>** üzerindeki uygulama loglarını ve log ayarını
`loglar/` ile `config/` altına koydu."

"Loglarda kart numarası görmemeliyiz; görürsek bu bir bulgu. Kaç satır, kaç dosya, CVV var mı,
dışarı sızan bir şey var mı bul. Sonra kök nedeni kapat ve eski logu temizle. (Kartların hepsi
bilinen test kartlarıdır.)"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kart verisi kaza eseri bile loglara sızabilir: hata ayıklama açık unutulur, bir ayar kapalıdır.
Önce ne kadarının sızdığını ölç (satır, dosya), sonra kök nedeni kapat (maskeleme kuralı), en
sonunda geçmişi temizle. CVV ise hiçbir zaman saklanmaz. Her gece log klasörünü
`grep -E '[0-9]{16}'` ile taramak, ucuz ama çok etkili bir PCI kontrolüdür.
""",
    gercek_hayat="""
- **Hata ayıklama logları:** Birçok gerçek ihlalde kart verisi, geliştiricinin açık bıraktığı
  DEBUG loglarından çıkmıştır. Tespit: log klasörlerinde düzenli PAN deseni (Luhn kontrollü)
  taraması; önlem: log kütüphanesinde zorunlu maskeleme filtresi.
- **Web skimming (Magecart tarzı):** Ödeme sayfasına eklenen bir betik kart bilgilerini
  üçüncü bir alan adına yollar. Tespit: giden isteklerde tanınmayan alan adları; önlem: Content
  Security Policy ve ödeme formunu barındıran sayfanın bütünlük denetimi.
""",
    sure_hedef_dk=20,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c20b03",),
)
