"""Olay Masası — Fidye Yazılımı Olay Müdahalesi.

Bir müşteride fidye yazılımı olayı yaşanmış. Elde yalnızca olayın kanıtı var: EDR uyarı
dökümü, yedek durum dosyası ve saldırganın bıraktığı fidye notu. Oyuncu ilk bulaşan hostu,
saati, yayılmayı, sağlam yedeği ve doğru müdahale önceliğini bulur. Savunma odaklıdır;
şifreleyici ya da saldırı kodu yoktur, her şey statik kanıt dosyasıdır.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

PAYLASIMLAR = ["muhasebe", "insan_kaynaklari", "proje", "musteri_kayit", "ortak", "arsiv",
               "yonetim", "depo", "veritabani"]
SUNUCULAR = ["fs01", "db01", "app01", "mail01", "erp01", "dc01"]
GURULTU = ["oturum_acildi", "yazilim_guncellendi", "usb_takildi", "vpn_baglandi", "yazdirma_islemi"]


def _satir(t, host, ip, seviye, olay):
    return f"{t:%Y-%m-%d %H:%M:%S} {host} {ip} {seviye} {olay}"


def uret(rng):
    m = musteri_sec(rng)
    on = m["kod"][:3]
    gun = u.gun(rng)
    ag = rng.choice(["192.168.1", "192.168.10", "10.0.0", "10.10.5", "172.16.4"])
    kullanilan = set()

    def yeni_ip():
        while True:
            ip = u.ic_ip(rng, ag)
            if ip not in kullanilan:
                kullanilan.add(ip)
                return ip

    # ilk bulaşan istasyon
    sifir_host = f"{on}-ws{rng.randint(1, 40):02d}"
    sifir_ip = yeni_ip()
    kullanici = rng.choice(u.ISIMLER)

    olaylar = []
    baslangic = gun + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 59))

    # gürültü: zararsız BILGI satırları (diğer istasyonlardan + ilk bulaşandan bir oturum satırı)
    gurultu_t = u.zamanlar(rng, baslangic, rng.randint(4, 6), 60, 900)
    for i, t in enumerate(gurultu_t):
        if i == 1:
            h, ip = sifir_host, sifir_ip
        else:
            h, ip = f"{on}-ws{rng.randint(41, 90):02d}", yeni_ip()
        olaylar.append((t, h, ip, "BILGI", rng.choice(GURULTU)))
    ilk_satir_saat = f"{gurultu_t[0]:%H:%M:%S}"

    # ilk UYARI: ilk bulaşma
    t0 = gurultu_t[-1] + timedelta(seconds=rng.randint(120, 1500))
    olaylar.append((t0, sifir_host, sifir_ip, "UYARI",
                    f"makro_belge_sonrasi_powershell_calisti kullanici={kullanici}"))

    # yayılma: kimlik bilgisi dökümü + uzaktan yürütme
    sunucu_adlari = rng.sample(SUNUCULAR, rng.randint(3, 5))
    sunucular = [(f"{on}-{x}", yeni_ip()) for x in sunucu_adlari]
    zs = u.zamanlar(rng, t0, 2 + len(sunucular), 40, 400)
    olaylar.append((zs[0], sifir_host, sifir_ip, "UYARI", "kimlik_bilgisi_dokumu_denemesi"))
    olaylar.append((zs[1], sifir_host, sifir_ip, "UYARI", f"smb_uzaktan_yurutme hedef={sunucular[0][0]}"))
    for i, (h, ip) in enumerate(sunucular):
        kaynak = sifir_ip if i == 0 else sunucular[i - 1][1]
        olaylar.append((zs[2 + i], h, ip, "UYARI", f"uzak_hizmet_olusturuldu kaynak={kaynak}"))

    # şifreleme: sunucu başına 1-2 paylaşım
    uzanti = "." + rng.choice(["kilitli", "sifreli", "kapali", "muhur"]) + "_" + \
        "".join(rng.choice("0123456789abcdef") for _ in range(4))
    ts = u.zamanlar(rng, zs[-1], 30, 20, 200)
    kritik = 0
    ti = 0
    for h, ip in sunucular:
        for pay in rng.sample(PAYLASIMLAR, rng.randint(1, 2)):
            olaylar.append((ts[ti], h, ip, "KRITIK",
                            f"toplu_sifreleme paylasim={pay} dosya={rng.randint(300, 9000)} uzanti={uzanti}"))
            ti += 1
            kritik += 1
    olaylar.sort(key=lambda x: x[0])
    log = "\n".join(_satir(*o) for o in olaylar) + "\n"

    # yedek durumu
    dun = (gun - timedelta(days=1)).strftime("%Y-%m-%d")
    haftalik = (gun - timedelta(days=rng.randint(2, 6))).strftime("%Y-%m-%d")
    teyp = f"{on}-teyp-{rng.randint(10, 99)}"
    yedekler = [f"{h}-gunluk cevrimici nas01 {dun} {rng.choice(['SILINMIS', 'SIFRELENDI'])}"
                for h, _ in sunucular]
    yedekler.append(f"{teyp} cevrimdisi kasa {haftalik} SAGLAM")
    yedekler.append(f"{on}-usb-disk cevrimdisi ofis-dolap {haftalik} BOZUK")
    yedekler.append(f"{on}-bulut-kopya cevrimici bulut {dun} SENKRON_SILINMIS")
    rng.shuffle(yedekler)
    yedek = ("# yedek_adi tur konum son_basarili_yedek durum\n" + "\n".join(yedekler) + "\n")

    # fidye notu (kurgusal, zararsız)
    iletisim = "kurtarma-" + "".join(rng.choice("0123456789abcdef") for _ in range(5)) + "@posta.lab"
    kimlik = "".join(rng.choice("ABCDEFGHJKLMNPRSTUVYZ23456789") for _ in range(8))
    miktar = rng.choice([8, 12, 15, 20, 35])
    son = (gun + timedelta(days=3)).strftime("%d.%m.%Y")
    nota = (
        "*** DOSYALARINIZ SIFRELENDI ***\n"
        "\n"
        "(Bu metin kurgusal bir egitim ornegidir; gercek bir odeme talebi degildir.)\n"
        "\n"
        "Agdaki tum onemli dosyalariniz sifrelendi.\n"
        "Dosyalarinizi geri istiyorsaniz:\n"
        "\n"
        f"  1) {miktar} BTC (kurgusal) tutarinda odeme yapin\n"
        f"  2) Son tarih: {son}; sonrasinda fiyat ikiye katlanir\n"
        "  3) Odeme sonrasi asagidaki adrese kurban kimliginizi yazin\n"
        "\n"
        f"KURBAN-KIMLIGI: {kimlik}\n"
        "ILETISIM:\n"
        f"{iletisim}\n"
        "\n"
        "Polise veya bir guvenlik sirketine haber verirseniz anahtari silecegiz.\n"
    )

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — fidye yazılımı olayı",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"],
                  "hassas": m["hassas_veri"]},
        "cevaplar": {
            "ilk_ip": sifir_ip,
            "saat": f"{t0:%H:%M:%S}",
            "sunucu_sayisi": len(sunucular),
            "uzanti": [uzanti, uzanti.lstrip(".")],
            "yedek": teyp,
            "iletisim": iletisim,
        },
        "_log": log,
        "_yedek": yedek,
        "_nota": nota,
        "_sonraki_ipler": {ip for _, ip in sunucular},
        "_ilk_satir_saat": ilk_satir_saat,
        "_kritik_satir": kritik,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "edr_uyari.log", s["_log"])
    u.yaz(lab / "yedek_durum.txt", s["_yedek"])
    u.yaz(lab / "fidye_notu.txt", s["_nota"])


def _ip_hata(g, beklenen, b):
    if g in b.senaryo["_sonraki_ipler"]:
        return "Bu host sonradan vuruldu. Aradığın, **ilk** `UYARI` satırını veren istasyon (yayılma sunuculara sonra geliyor)."
    return None


def _saat_hata(g, beklenen, b):
    if g == b.senaryo["_ilk_satir_saat"]:
        return "Bu, logun ilk satırı ama o satır `BILGI` düzeyinde (zararsız). İlk `UYARI` satırının saatini ara."
    return None


def _sunucu_hata(g, beklenen, b):
    if int(g) == b.senaryo["_kritik_satir"] and int(g) != beklenen:
        return "Bu, `KRITIK` satır sayısı; bir sunucuda birden fazla paylaşım şifrelenmiş olabilir. Sunucu adlarını tekilleştir (`sort -u`)."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]


def coz(lab: Path, s: dict) -> dict:
    ilk_ip = _sh("awk '$5==\"UYARI\" {print $4; exit}' edr_uyari.log", lab)
    saat = _sh("awk '$5==\"UYARI\" {print $2; exit}' edr_uyari.log", lab)
    sunucu = _sh("awk '$5==\"KRITIK\" {print $3}' edr_uyari.log | sort -u | wc -l", lab)
    uzanti = _sh("grep -oE 'uzanti=[^ ]+' edr_uyari.log | head -1 | cut -d= -f2", lab)
    yedek = _sh("awk '$5==\"SAGLAM\" {print $1}' yedek_durum.txt | head -1", lab)
    iletisim = _sh("grep -oE '[a-z0-9._-]+@[a-z0-9.-]+' fidye_notu.txt | head -1", lab)
    return {1: ilk_ip, 2: saat, 3: sunucu, 4: uzanti, 5: yedek, 6: iletisim,
            7: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("Olay **hangi istasyondan** başlamış? İlk `UYARI` düzeyindeki satırın IP adresini yaz.",
          IP("ilk_ip", sik_hatalar=_ip_hata),
          ("Logda önce zararsız `BILGI` satırları var; ilk gerçek alarm farklı bir düzeyde.",
           "Beşinci alan düzeydir. `UYARI` olan ilk satırı al, dördüncü alanı (IP) yazdır.",
           "`awk '$5==\"UYARI\" {print $4; exit}' edr_uyari.log`"),
          puan=15, baslik="İlk bulaşan"),
    Gorev("Bu ilk uyarının **saati** nedir? (SS:DD:SS)",
          Metin("saat", bicim="SS:DD:SS", sik_hatalar=_saat_hata),
          ("Aynı satırda tarihten sonra gelen alan saattir.",
           "İlk `UYARI` satırının ikinci alanı.",
           "`awk '$5==\"UYARI\" {print $2; exit}' edr_uyari.log`"),
          puan=15, baslik="Bulaşma saati"),
    Gorev("Kaç **farklı sunucuda** dosya şifrelenmiş?",
          Sayi("sunucu_sayisi", sik_hatalar=_sunucu_hata),
          ("Şifreleme, `KRITIK` düzeyindeki satırlarda görünür; üçüncü alan host adıdır.",
           "Bir sunucuda birden çok paylaşım vurulmuş olabilir. Sunucu adlarını tekilleştirip say.",
           "`awk '$5==\"KRITIK\" {print $3}' edr_uyari.log | sort -u | wc -l`"),
          puan=20, baslik="Vurulan sunucu"),
    Gorev("Şifrelenen dosyalara eklenen **uzantı** nedir? (örn. `.xxx_1234`)",
          Metin("uzanti", bicim="nokta ile başlayan uzantı"),
          ("Şifreleme satırlarının sonunda bir alan var.",
           "`uzanti=` ile başlayan alanı süz.",
           "`grep -oE 'uzanti=[^ ]+' edr_uyari.log | head -1`"),
          puan=15, baslik="Uzantı"),
    Gorev("`yedek_durum.txt`: hangi yedek **sağlam**? Yedeğin adını yaz.",
          Metin("yedek", bicim="yedek adı"),
          ("Son sütun durumu gösterir; çoğu yedek silinmiş ya da şifrelenmiş.",
           "Beşinci alanı `SAGLAM` olan satırın ilk alanı. Çevrimiçi yedekler neden hepsi gitmiş olabilir?",
           "`awk '$5==\"SAGLAM\" {print $1}' yedek_durum.txt`"),
          puan=20, baslik="Sağlam yedek"),
    Gorev("`fidye_notu.txt`: saldırganın **iletişim adresi** nedir?",
          Metin("iletisim", bicim="e-posta adresi"),
          ("Not bir adres içeriyor; `@` işaretini ara.",
           "E-posta kalıbını `grep -o` ile çek.",
           "`grep -oE '[a-z0-9._-]+@[a-z0-9.-]+' fidye_notu.txt`"),
          puan=15, baslik="İletişim"),
    Gorev("Müşteri yöneticisi soruyor: elimizde çevrimdışı sağlam bir yedek var. "
          "Müdahalede **öncelik** ne olmalı?",
          Secmeli([
              ("Etkilenen sistemleri ağdan izole et, saldırgan erişimini kapat, sağlam çevrimdışı yedekten geri dön",
               "Doğru. Önce yayılmayı durdur, saldırganı çıkar, temiz sistemleri kurup yedekten dön. Fidye ödemek gerekmez."),
              ("Fidyeyi hemen öde, anahtarı bekle",
               "Hayır. Ödeme dosyaların geri geleceğini garanti etmez, saldırganı finanse eder ve tekrar hedef olmanı kolaylaştırır; elinde zaten sağlam yedek var."),
              ("Sunucuları yeniden başlatıp şifreli dosyaları sil",
               "Hayır. Saldırgan hâlâ ağdadır, kanıt yok olur ve sildiğin dosyalar geri dönmez."),
              ("Sadece fidye notundaki adrese cevap yazıp pazarlık et",
               "Hayır. Pazarlık zaman kazandırmaz; saldırgan içerideyken yayılma sürer. Önce izolasyon."),
          ]),
          ("Saldırgan hâlâ ağda olabilir ve yayılmaya devam ediyor.",
           "Önce yayılmayı durdur; sonra neyle geri döneceğini düşün. Sağlam yedek var mı?",
           "Sıra: izole et → saldırganı temizle → çevrimdışı yedekten geri dön."),
          puan=15, baslik="Müdahale önceliği"),
]

SEVIYE = Seviye(
    kimlik="olay_fidye",
    cilt=7,
    bolum=103,
    baslik="Fidye Yazılımı Olay Müdahalesi",
    brifing="""
Deniz Kara masana telefonla ulaşıyor: "**<<musteri>>** (<<sektor>>) sabah dosyalarına
erişemediğini bildirdi. <<kisi>> ekranlarda bir fidye notu görmüş. Etkilenen veri:
<<hassas>>."

"Elimizde üç kanıt var: `edr_uyari.log` (uç nokta güvenlik uyarıları), `yedek_durum.txt` ve
saldırganın bıraktığı `fidye_notu.txt`. Olay nereden başladı, ne kadar yayıldı, geri dönecek
sağlam bir şeyimiz kaldı mı? Panik yok: kanıtı oku, sırayla cevapla."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Fidye yazılımı çoğu zaman tek bir tıklamayla başlar, ama zarar yayılmasından gelir. Üç ders:
1) Çevrimdışı (ağdan ayrı) yedek tut; çevrimiçi yedekler saldırganın ilk silip şifrelediği
yerdir. 2) Ağı segmentle, istasyondan sunuculara uzaktan yürütme kolay olmasın. 3) İlk
uyarıda erken izole et; ilk `UYARI` ile ilk `KRITIK` arasındaki dakikalar, olayı küçük bir
vakaya da büyük bir felakete de çevirebilir. Fidye ödemek garanti vermez; hazırlıklı olan
ödemek zorunda kalmaz.
""",
    gercek_hayat="""
- **WannaCry, 2017:** Mayıs 2017'de fidye yazılımı, Microsoft'un Mart ayında yama yayımladığı
  Windows SMB açığı (MS17-010) üzerinden yüzlerce bin bilgisayara yayıldı; İngiltere'de
  hastane sistemleri de etkilendi. Yamalanmış ve segmentlenmiş ağlarda yayılma çok kısıtlıydı.
- **Colonial Pipeline, 2021:** ABD'de bir akaryakıt boru hattı şirketi, ele geçirilmiş bir VPN
  hesabı üzerinden girilen saldırı sonrası operasyonlarını önlem olarak durdurdu ve fidye
  ödedi; yakıt tedariki günlerce aksadı. Çok faktörlü kimlik doğrulama ve segmentasyon,
  olayın etkisini azaltabilirdi.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b05",),
)
