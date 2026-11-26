"""Olay Masası — İç Tehdit İncelemesi.

Bir müşteride bir çalışanın veri sızdırdığından şüpheleniliyor. Elinde üç statik kayıt var:
dosya erişim denetim logu, VPN giriş logu ve giden transfer/USB logu. Saldırı yok; yalnızca
davranış kanıtı: mesai dışı toplu erişim, alışılmadık konumdan giriş, büyük bir dışa aktarım.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

HASSAS_AD = ["musteri_listesi", "maas_bordro", "sozlesme", "ar_ge_plani", "fiyat_teklifi",
             "finans_ozeti", "kaynak_kod", "strateji_sunumu", "personel_dosyasi", "ihale_sartname"]
GENEL_AD = ["duyuru", "yemek_listesi", "izin_formu", "takvim", "politika", "sablon", "afis", "rehber"]
EYLEM = ["READ", "OPEN"]
YERLI = ["Istanbul-TR", "Ankara-TR", "Izmir-TR", "Bursa-TR"]
YABANCI = ["Rotterdam-NL", "Singapur-SG", "Vilnius-LT", "Lizbon-PT", "Nairobi-KE"]
USB_MARKA = ["SanDisk", "Kingston", "Samsung", "Transcend"]
BULUT = ["dosyapaylas.lab", "bulutdepo.lab", "hizlitransfer.lab"]


def _t(t) -> str:
    return f"{t:%Y-%m-%d %H:%M:%S}"


def _hassas_yollar(rng, adet):
    ciftler = [(a, y) for a in HASSAS_AD for y in ("2024", "2025", "2026")]
    return [f"/paylasim/hassas/{a}_{y}.xlsx" for a, y in rng.sample(ciftler, adet)]


def _genel_yol(rng):
    return f"/paylasim/genel/{rng.choice(GENEL_AD)}_{rng.randint(1, 40):02d}.pdf"


def uret(rng):
    m = musteri_sec(rng)
    gun = u.gun(rng)
    isimler = u.isimler(rng, 6)
    suphe, ik, normal = isimler[0], isimler[1], isimler[2:]
    yedek = "svc_yedek"

    erisim = []   # (zaman, satır)

    def ekle(t, kisi, yol, boyut=None):
        b = boyut if boyut is not None else rng.randint(20_000, 900_000)
        erisim.append((t, f"{_t(t)} {kisi} {rng.choice(EYLEM)} {yol} {b}"))

    def mesai_zamani(gun_no):
        d = gun - timedelta(days=gun_no)
        return d + timedelta(seconds=rng.randint(8 * 3600 + 600, 17 * 3600 + 1800))

    # normal kullanıcılar: mesai içi, çoğunlukla genel, birkaç hassas
    for k in normal:
        for _ in range(rng.randint(10, 16)):
            ekle(mesai_zamani(rng.randint(0, 4)), k, _genel_yol(rng))
        for y in _hassas_yollar(rng, rng.randint(0, 3)):
            ekle(mesai_zamani(rng.randint(0, 4)), k, y)
    # İK çalışanı: mesai içinde çok hassas dosya açar ama hepsi gündüz (yanıltıcı)
    for y in _hassas_yollar(rng, rng.randint(7, 11)):
        ekle(mesai_zamani(rng.randint(0, 4)), ik, y)
    for _ in range(rng.randint(8, 12)):
        ekle(mesai_zamani(rng.randint(0, 4)), ik, _genel_yol(rng))
    # yedek hesabı: gece genel dosyaları okur (mesai dışı ama hassas değil)
    bas = gun - timedelta(days=1) + timedelta(hours=3, minutes=rng.randint(0, 20))
    for t in u.zamanlar(rng, bas, rng.randint(14, 20), 20, 80):
        ekle(t, yedek, _genel_yol(rng), rng.randint(2_000_000, 9_000_000))

    # şüpheli: gündüz sıradan işler + 2 gece toplu hassas dosya kopyalama
    for _ in range(rng.randint(8, 12)):
        ekle(mesai_zamani(rng.randint(0, 4)), suphe, _genel_yol(rng))
    gunduz_hassas = rng.randint(2, 4)
    for y in _hassas_yollar(rng, gunduz_hassas):
        ekle(mesai_zamani(rng.randint(0, 4)), suphe, y)
    gece_sayi = rng.randint(18, 30)
    n1 = gece_sayi // 2 + rng.randint(-2, 2)
    n2 = gece_sayi - n1
    gece_yollar = _hassas_yollar(rng, 30)
    pencereler = []   # (başlangıç, bitiş)
    for no, (gn, adet) in enumerate(((2, n1), (1, n2))):
        bas = gun - timedelta(days=gn) + timedelta(hours=rng.randint(1, 3), minutes=rng.randint(0, 40))
        zs = u.zamanlar(rng, bas, adet, 4, 50)
        for t in zs:
            ekle(t, suphe, gece_yollar[rng.randrange(len(gece_yollar))], rng.randint(300_000, 4_000_000))
        pencereler.append((bas, zs[-1]))
    erisim.sort(key=lambda x: x[0])
    erisim_log = "\n".join(s for _, s in erisim) + "\n"

    # VPN: herkes kendi şehrinden gündüz bağlanır; şüpheli geceleri yurt dışından
    vpn = []
    evler = {k: (rng.choice(YERLI), u.dis_ip(rng)) for k in [suphe, ik, *normal]}

    def vpn_satiri(t, k, ip, konum, sonuc="OK"):
        vpn.append((t, f"{_t(t)} LOGIN {k} {ip} {konum} {sonuc}"))

    for k, (konum, ip) in evler.items():
        for _ in range(rng.randint(3, 5)):
            vpn_satiri(mesai_zamani(rng.randint(0, 4)).replace(hour=rng.randint(8, 9)), k, ip, konum)
    # yazım hatası yapan masum kullanıcı (başarısız girişler yerli konumdan)
    hatali = rng.choice(normal)
    for _ in range(rng.randint(3, 4)):
        vpn_satiri(mesai_zamani(rng.randint(0, 4)).replace(hour=9), hatali, evler[hatali][1], evler[hatali][0], "FAIL")
    yabanci = rng.choice(YABANCI)
    for bas, _ in pencereler:
        vpn_satiri(bas - timedelta(minutes=rng.randint(12, 25)), suphe, u.dis_ip(rng), yabanci)
    vpn.sort(key=lambda x: x[0])
    vpn_log = "\n".join(s for _, s in vpn) + "\n"

    # giden transferler
    tr = []

    def tr_satiri(t, k, kanal, hedef, mb):
        tr.append((t, f"{_t(t)} {k} {kanal} {hedef} {mb}"))

    for k in [ik, *normal]:
        for _ in range(rng.randint(1, 3)):
            tr_satiri(mesai_zamani(rng.randint(0, 4)), k, "EMAIL",
                      f"{rng.choice(u.ISIMLER)}@{m['alan']}", rng.randint(1, 35))
    # yanıltıcı: iç yedek sunucusuna orta boy gündüz transferi
    tr_satiri(mesai_zamani(1), rng.choice(normal), "HTTPS", f"yedek.{m['alan']}", rng.randint(180, 260))
    # şüpheli: küçük rutin mail + iki büyük gece dışa aktarımı
    tr_satiri(mesai_zamani(rng.randint(0, 4)), suphe, "EMAIL", f"{rng.choice(u.ISIMLER)}@{m['alan']}",
              rng.randint(2, 9))
    kanallar = ["USB", "HTTPS"]
    rng.shuffle(kanallar)
    buyuk_mb = rng.randint(1500, 3900)
    kucuk_mb = rng.randint(320, 900)
    buyuk_gece = rng.randint(0, 1)
    buyuk_hedef = None
    for no, (bas, bit) in enumerate(pencereler):
        kanal = kanallar[0] if no == buyuk_gece else kanallar[1]
        hedef = (f"USB-{rng.choice(USB_MARKA)}-{rng.randint(1000, 9999)}" if kanal == "USB"
                 else rng.choice(BULUT))
        mb = buyuk_mb if no == buyuk_gece else kucuk_mb
        if no == buyuk_gece:
            buyuk_hedef = hedef
        tr_satiri(bit + timedelta(minutes=rng.randint(4, 15), seconds=rng.randint(0, 59)), suphe, kanal, hedef, mb)
    tr.sort(key=lambda x: x[0])
    tr_log = "\n".join(s for _, s in tr) + "\n"

    def sayac(kosul):
        n = 0
        for _, s in erisim:
            p = s.split()
            if kosul(p):
                n += 1
        return n

    def mesai_disi(p):
        h = int(p[1][:2])
        return h < 7 or h >= 20

    hassas_toplam = sayac(lambda p: p[2] == suphe and "/hassas/" in p[4])
    mesai_disi_hassas = sayac(lambda p: "/hassas/" in p[4] and mesai_disi(p))
    toplam_mb = sum(int(s.split()[5]) for _, s in tr if s.split()[2] == suphe)
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — şüpheli çalışan",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"],
                  "hassas_veri": m["hassas_veri"], "alan": m["alan"]},
        "cevaplar": {
            "kullanici": suphe,
            "hassas_toplam": hassas_toplam,
            "mesai_disi": mesai_disi_hassas,
            "vpn_konum": [yabanci, yabanci.split("-")[0]],
            "hedef": buyuk_hedef,
            "toplam_mb": toplam_mb,
        },
        "_dosyalar": {"dosya_erisim.log": erisim_log, "vpn.log": vpn_log, "transfer.log": tr_log},
        "_ik": ik,
        "_yedek": yedek,
        "_tum_mesai_disi": sayac(mesai_disi),
        "_gunduz_hassas": gunduz_hassas,
    }


def yaz(lab: Path, s: dict) -> None:
    for ad, icerik in s["_dosyalar"].items():
        u.yaz(lab / ad, icerik)


def _kullanici_hata(g, beklenen, b):
    if g == b.senaryo["_yedek"]:
        return "`svc_yedek` bir servis hesabı: geceleri çalışması normal ve yalnızca genel dosyaları okuyor, hassas klasöre dokunmuyor."
    if g == b.senaryo["_ik"]:
        return "Bu kullanıcı çok hassas dosya açıyor ama hepsi mesai içinde; işi gereği olabilir. Zamana bak."
    return None


def _hassas_hata(g, beklenen, b):
    if int(g) == b.senaryo["cevaplar"]["mesai_disi"]:
        return "Bu sadece mesai dışı erişimler. Kullanıcının gündüz açtığı hassas dosyalar da toplama dahil."
    return None


def _mesai_disi_hata(g, beklenen, b):
    if int(g) == b.senaryo["_tum_mesai_disi"]:
        return "Servis hesabının genel dosya okumalarını da saymışsın. Yalnızca `/hassas/` yolundakileri say."
    return None


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    kisi = _sh(r"""awk 'index($5,"/hassas/")>0 {h=substr($2,1,2)+0; if (h<7||h>=20) c[$3]++}
        END{for (k in c) print c[k], k}' dosya_erisim.log | sort -rn | head -1 | awk '{print $2}'""", lab)
    hassas = _sh("awk -v u=" + kisi + r""" '$3==u && index($5,"/hassas/")>0' dosya_erisim.log | wc -l""", lab)
    mesai = _sh(r"""awk 'index($5,"/hassas/")>0 {h=substr($2,1,2)+0; if (h<7||h>=20) n++} END{print n+0}' dosya_erisim.log""", lab)
    konum = _sh("awk -v u=" + kisi + r""" '$4==u && $6 !~ /-TR$/ {print $6}' vpn.log | sort -u | head -1""", lab)
    hedef = _sh("sort -k6 -n -r transfer.log | head -1 | awk '{print $5}'", lab)
    toplam = _sh("awk -v u=" + kisi + r""" '$3==u {t+=$6} END{print t+0}' transfer.log""", lab)
    return {1: kisi, 2: hassas, 3: mesai, 4: konum, 5: hedef, 6: toplam, 7: _secmeli_cevap(s, lab)}


def _secmeli_cevap(s, lab):
    from hy.motor.kontrol import Baglam
    return SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]


GOREVLER = [
    Gorev("`dosya_erisim.log` satırları şöyle: `TARİH SAAT KULLANICI EYLEM YOL BOYUT`. Mesai **07:00-20:00** "
          "arasıdır. Mesai dışında `/hassas/` klasöründeki dosyalara en çok erişen kullanıcı kim?",
          Metin("kullanici", sik_hatalar=_kullanici_hata, bicim="kullanıcı adı"),
          ("Önce yalnızca hassas klasöre erişimleri süz, sonra saatine bak (2. alanın ilk iki karakteri).",
           "`awk`'ta `substr($2,1,2)+0` saati verir; saat 7'den küçük ya da 20'ye eşit/büyükse mesai dışıdır. Kullanıcıya göre say.",
           "`awk 'index($5,\"/hassas/\")>0 {h=substr($2,1,2)+0; if (h<7||h>=20) c[$3]++} END{for(k in c) print c[k],k}' "
           "dosya_erisim.log | sort -rn | head -3`"),
          puan=20, baslik="Şüpheli kullanıcı"),
    Gorev("Bu kullanıcı, log boyunca (gündüz dahil) toplam **kaç** hassas dosya erişimi yapmış?",
          Sayi("hassas_toplam", sik_hatalar=_hassas_hata),
          ("Artık kullanıcıyı biliyorsun; zaman şartını kaldır, sadece kullanıcı ve `/hassas/` kalsın.",
           "`awk -v u=KULLANICI '$3==u && index($5,\"/hassas/\")>0'` satırlarını `wc -l` ile say.",
           "`awk -v u=<kullanıcı> '$3==u && index($5,\"/hassas/\")>0' dosya_erisim.log | wc -l`"),
          puan=15, baslik="Hassas erişim"),
    Gorev("Tüm kullanıcılar toplamında, mesai dışı (07:00'den önce ya da 20:00 ve sonrası) kaç **hassas** dosya "
          "erişimi var?",
          Sayi("mesai_disi", sik_hatalar=_mesai_disi_hata),
          ("Gece çalışan tek hesap şüpheli değil; yolu da süzmelisin.",
           "İki şartı birlikte kullan: yolda `/hassas/` geçsin ve saat mesai dışında olsun, sonra satırları say.",
           "`awk 'index($5,\"/hassas/\")>0 {h=substr($2,1,2)+0; if (h<7||h>=20) n++} END{print n+0}' dosya_erisim.log`"),
          puan=20, baslik="Mesai dışı"),
    Gorev("`vpn.log` satırları: `TARİH SAAT OLAY KULLANICI IP KONUM SONUÇ`. Şüpheli, alışılmadık bir konumdan VPN'e "
          "girmiş. Bu **konum** nedir? (örn. `Sehir-ÜlkeKodu`)",
          Metin("vpn_konum", bicim="Şehir-ÜlkeKodu"),
          ("Herkesin kendi, hep aynı konumu vardır; şüphelinin satırlarına bak.",
           "Şüphelinin satırlarını süz, 6. alana (konum) bak; Türkiye (`-TR`) dışında kalanı bul.",
           "`awk -v u=<kullanıcı> '$4==u {print $6}' vpn.log | sort | uniq -c`"),
          puan=15, baslik="VPN konumu"),
    Gorev("`transfer.log` satırları: `TARİH SAAT KULLANICI KANAL HEDEF MB`. **En büyük** giden transferin "
          "**hedefi** nedir? (USB seri etiketi ya da alan adı)",
          Metin("hedef", bicim="hedef (USB etiketi ya da alan adı)"),
          ("En büyük transfer, 6. alanın (MB) en büyük olduğu satırdır.",
           "Sayısal olarak büyükten küçüğe sırala: `sort -k6 -n -r`; ilk satırın 5. alanı hedeftir.",
           "`sort -k6 -n -r transfer.log | head -1 | awk '{print $5}'`"),
          puan=20, baslik="Transfer hedefi"),
    Gorev("Şüpheli kullanıcının giden transferlerinin **toplamı** kaç **MB**?",
          Sayi("toplam_mb"),
          ("Yalnızca şüphelinin satırlarını topla; en büyük transfer tek başına yetmez.",
           "`awk`'ta koşul `$3==u`, toplama için `t+=$6`.",
           "`awk -v u=<kullanıcı> '$3==u {t+=$6} END{print t}' transfer.log`"),
          puan=20, baslik="Sızan veri"),
    Gorev("Kanıtlar şüpheliyi gösteriyor. Güvenlik ekibi olarak **doğru ilk müdahale** hangisi?",
          Secmeli([
              ("Hesabı ve VPN erişimini askıya al, logları ve cihazı koru, İK ve hukuk birimini sürece dahil et",
               "Doğru. Sızıntı durur, kanıt bozulmaz ve süreç yasal/idari olarak da yürür; karar İK ve hukukla birlikte verilir."),
              ("Kullanıcının bilgisayarına uzaktan girip dosyalarını sil ve misilleme yap",
               "Hayır. Yetkisiz müdahale seni de suçlu konumuna düşürür ve kanıtı bozar."),
              ("Hiçbir şey yapma, hesabı açık bırak ve izlemeye devam et",
               "Hayır. Beklerken veri sızmaya devam eder; kanıt zaten yeterli."),
              ("Hesabı sil ve logları temizle, olay kapansın",
               "Hayır. Logları silmek kanıt imhasıdır ve hukuki süreci çökertir."),
          ]),
          ("Önce sızıntıyı durdur, ama kanıtı bozma.",
           "Bir çalışan söz konusu: işten çıkarma/dava kararı kimin yetkisinde?",
           "Askıya al + kanıtı koru + İK/hukuk. Kimseyi kendi başına yargılama, kanıtı silme."),
          puan=20, baslik="Müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_ictehdit",
    cilt=3,
    bolum=104,
    baslik="İç Tehdit İncelemesi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<kisi>> bir çalışanın
şirketin en değerli verisini, yani <<hassas_veri>>, dışarı taşıdığından şüpheleniyor. Kimseyi
suçlamak istemiyor; kanıt istiyor."

"Elimizde üç kayıt var, `<<alan>>` ağından: `dosya_erisim.log` (kim hangi dosyayı ne zaman
açtı), `vpn.log` (kim nereden bağlandı) ve `transfer.log` (dışarı giden dosya ve USB
aktarımları). Saldırgan yok, kırılan sistem yok: yalnızca davranış. Mesaiyi **07:00-20:00**
say. Kim, ne kadar, nereye?"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
İç tehdit, güvenlik duvarına değil davranışa takılır: kullanıcı geçerli bir hesapla, geçerli
yetkilerle çalışır. Fark, **ne zaman, ne kadar, nereden** sorularında ortaya çıkar. Savunma
dört katmandır: **en az yetki** (kimse işi dışındaki klasörü görmesin), **erişim loglama**
(bu incelemeyi mümkün kılan kayıtlar), **UEBA** (kullanıcı davranış analitiği: mesai dışı toplu
erişimi ve alışılmadık konumu otomatik işaretler) ve **görevler ayrılığı** (veriye erişen ile
dışarı aktaran onayı tek elde olmasın). Müdahalede de hızlı ama usulüne uygun ol: erişimi
askıya al, kanıtı koru, kararı İK ve hukukla ver.
""",
    gercek_hayat="""
- **Edward Snowden, 2013:** ABD Ulusal Güvenlik Teşkilatı (NSA) için çalışan bir yüklenici
  çalışan, kendi yetkisiyle eriştiği çok sayıda gizli belgeyi dışarı çıkardı. Olay sonrası
  incelemelerde, geniş erişim yetkileri ve sistem yöneticisi hesaplarının yeterince
  denetlenmemesi öne çıktı: geçerli kimlikle yapılan toplu erişim kimseyi alarma geçirmedi.
- **Morgan Stanley, 2015:** Bir finansal danışman, şirketin müşteri kayıtlarını (yaklaşık
  yüz binlerce kayıt olduğu bildirildi) kendi hesabına aktardı. Şirket, olağandışı veri
  erişimini kendi izleme sisteminin yakaladığını açıkladı.
- **Genel tablo:** Veri ihlali raporları, ihlallerin önemli bir bölümünde içeriden kişilerin
  rol oynadığını gösterir; bu yüzden kurumlar UEBA araçlarıyla "normal"in dışına çıkan
  davranışı arar.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c03b06",),
)
