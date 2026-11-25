"""Cilt 11 · Bölüm 2 — AD Keşfi.

Beceri: kurgusal bir AD dökümünü (JSON) okuyup savunmacı gözüyle şunları bulmak: Domain Admins'in
gerçek üyeleri (iç içe grup dahil), parolası hiç dolmayan aktif hesaplar, SPN tanımlı servis
hesapları, uzun süredir girilmemiş hesaplar ve bunların tehlikeli kesişimi.

Vakalar: banka, lojistik, belediye, hastane. Her dökümde iç içe grup ve "tuzak" kayıtlar
(pasif hesap, bilgisayar SPN'si) farklı yerdedir.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c11_ad.ortak import hesap_adlari, json_satirli, py, sec_doldur, sirket_sec

SVC_ADLARI = ["svc-sql", "svc-yedek", "svc-web", "svc-rapor", "svc-baski", "svc-izleme"]
SPN_SABLON = {
    "svc-sql": "MSSQLSvc/{on}-sql01.{alan}:1433", "svc-yedek": "BackupSvc/{on}-yedek01.{alan}",
    "svc-web": "HTTP/{on}-web01.{alan}", "svc-rapor": "MSSQLSvc/{on}-rapor01.{alan}:1433",
    "svc-baski": "HOST/{on}-baski01.{alan}", "svc-izleme": "HTTP/{on}-izle01.{alan}",
}
SAHNE = {
    "ferahbank": "Ferah Bank'ın BT ekibi, bir sızma testi öncesi 'dışarıdan bir kullanıcı ne görür' diye merak ediyor.",
    "kuzgun": "Kuzgun Lojistik'te depo sistemini kuran firma bir yıl önce işi bıraktı; hesapları kimse temizlemedi.",
    "yesiltepe": "Yeşiltepe Belediyesi, personel çıkışlarından sonra hesap temizliğinin yapılıp yapılmadığını öğrenmek istiyor.",
    "medora": "Medora Sağlık'ta KVKK denetçisi 'yönetici hesaplarınızı listeleyin' dedi.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on, alan = sk["on"], sk["alan"]
    sade = hesap_adlari(rng, 12)
    adm = hesap_adlari(rng, 3, haric=sade)
    da_dogrudan = [f"adm.{a}" for a in adm[:2]]
    ic_grup = "BT-Yoneticileri"
    ic_uye = f"adm.{adm[2]}"
    svc = rng.sample(SVC_ADLARI, rng.randint(3, 4))
    tehlikeli = rng.choice(svc)                      # iç içe grup üzerinden Domain Admin
    kullanicilar = []

    def kayit(ad, aktif=True, hic_dolmaz=False, gun=None, spn=None, aciklama=""):
        kullanicilar.append({"ad": ad, "aktif": aktif, "sifre_hic_dolmaz": hic_dolmaz,
                             "son_giris_gun_once": rng.randint(0, 40) if gun is None else gun,
                             "spn": spn or [], "aciklama": aciklama})

    for a in da_dogrudan + [ic_uye]:
        kayit(a, aciklama="yönetici hesabı")
    bayat_sade = rng.sample(sade, 4)
    for k in sade:
        if k in bayat_sade[:3]:
            kayit(k, gun=rng.randint(120, 420), aciklama="")                   # aktif ama bayat
        elif k == bayat_sade[3]:
            kayit(k, aktif=False, gun=rng.randint(150, 500), aciklama="işten ayrıldı")  # pasif bayat (tuzak)
        else:
            kayit(k)
    for sv in svc:
        bayat = rng.random() < 0.4
        kayit(sv, hic_dolmaz=True, gun=rng.randint(130, 400) if bayat else rng.randint(0, 20),
              spn=[SPN_SABLON[sv].format(on=on, alan=alan)], aciklama="servis hesabı")
    # tuzaklar: pasif ve parolası dolmaz hesap; aktif ama SPN'siz parolası dolmaz hesap
    eski = f"svc-eski{rng.randint(1, 9)}"
    kayit(eski, aktif=False, hic_dolmaz=True, gun=rng.randint(200, 500), aciklama="kapatıldı")
    sade_dolmaz = rng.choice([k for k in sade if k not in bayat_sade])
    for k in kullanicilar:
        if k["ad"] == sade_dolmaz:
            k["sifre_hic_dolmaz"] = True
    rng.shuffle(kullanicilar)
    gruplar = [
        {"ad": "Domain Admins", "uyeler": da_dogrudan + [ic_grup]},
        {"ad": ic_grup, "uyeler": [ic_uye, tehlikeli]},
        {"ad": "Muhasebe", "uyeler": sade[:4]},
        {"ad": "Destek", "uyeler": sade[4:8]},
    ]
    bilgisayarlar = [
        {"ad": f"{on}-dc01", "isletim": "Windows Server 2019", "spn": [f"ldap/{on}-dc01.{alan}", f"HOST/{on}-dc01.{alan}"]},
        {"ad": f"{on}-sql01", "isletim": "Windows Server 2016", "spn": [f"MSSQLSvc/{on}-sql01.{alan}:1433"]},
        {"ad": f"{on}-pc101", "isletim": "Windows 11", "spn": []},
    ]
    etkin = [k for k in kullanicilar if k["aktif"]]
    return {
        "vaka": f"{sk['ad']} — AD keşif dökümü",
        "sirket": sk, "kullanicilar": kullanicilar, "gruplar": gruplar, "bilgisayarlar": bilgisayarlar,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "alan": sk["alan"]},
        "cevaplar": {
            "da": da_dogrudan + [ic_uye, tehlikeli],
            "dolmaz": [k["ad"] for k in etkin if k["sifre_hic_dolmaz"]],
            "spn": [k["ad"] for k in kullanicilar if k["spn"]],
            "bayat": sum(1 for k in etkin if k["son_giris_gun_once"] > 90),
            "tehlikeli": tehlikeli,
        },
        "ic_grup": ic_grup, "da_dogrudan": da_dogrudan, "pasif_dolmaz": eski,
    }


def yaz(lab: Path, s: dict) -> None:
    sk = s["sirket"]
    u.yaz(lab / "ad/ad_dokum.json",
          json_satirli({"domain": sk["alan"], "dokum_notu": "KURGUSAL — düşük yetkili bir hesapla toplandı"},
                       {"kullanicilar": s["kullanicilar"], "gruplar": s["gruplar"], "bilgisayarlar": s["bilgisayarlar"]}))
    u.yaz(lab / "ad/OKU.txt",
          "Bu döküm, bir kullanıcı hesabıyla alınmış AD okuma çıktısının KURGUSAL bir kopyasıdır.\n"
          "Her kayıt tek satırdadır; grep/awk ile süzebilirsin. `son_giris_gun_once`: son girişten bu yana geçen gün.\n"
          "Eşikler: 'bayat' = 90 günden uzun süre girilmemiş.\n")


def coz(lab: Path, s: dict) -> dict:
    j = "import json; d=json.load(open('ad/ad_dokum.json'));"
    return sec_doldur({
        1: py(j + "g={x['ad']:x['uyeler'] for x in d['gruplar']};r=[];"
              "k=lambda n:[m for u in g[n] for m in (k(u) if u in g else [u])];print(' '.join(k('Domain Admins')))", lab),
        2: py(j + "print(' '.join(x['ad'] for x in d['kullanicilar'] if x['aktif'] and x['sifre_hic_dolmaz']))", lab),
        3: py(j + "print(' '.join(x['ad'] for x in d['kullanicilar'] if x['spn']))", lab),
        4: py(j + "print(sum(1 for x in d['kullanicilar'] if x['aktif'] and x['son_giris_gun_once']>90))", lab),
        5: py(j + "g={x['ad']:x['uyeler'] for x in d['gruplar']};"
              "k=lambda n:[m for u in g[n] for m in (k(u) if u in g else [u])];da=set(k('Domain Admins'));"
              "print(' '.join(x['ad'] for x in d['kullanicilar'] if x['spn'] and x['ad'] in da))", lab),
    }, GOREVLER, lab, s)


def _da_hata(g, beklenen, b):
    verilen = set(g.split())
    dogrudan = {x.lower() for x in b.senaryo["da_dogrudan"]}
    if verilen == dogrudan:
        return ("Doğrudan üyeleri buldun ama `Domain Admins` grubunun içinde bir **grup** da var. İç içe gruptaki "
                "herkes de fiilen Domain Admin'dir; o grubun üyelerine de bak.")
    if len(verilen) < len(beklenen) and verilen <= beklenen:
        return "Eksik üye var. Üye listesinde bir grup adı gördüysen, o grubun üyelerini de ekle."
    return None


def _dolmaz_hata(g, beklenen, b):
    verilen = set(g.split())
    if b.senaryo["pasif_dolmaz"].lower() in verilen:
        return "Pasif (devre dışı) hesabı da saymışsın. Soru, **aktif** hesapları soruyor."
    return None


def _spn_hata(g, beklenen, b):
    verilen = set(g.split())
    pcler = {x["ad"].lower() for x in b.senaryo["bilgisayarlar"]}
    if verilen & pcler:
        return "Bilgisayar hesaplarının da SPN'si olur ama onlara sistem yönetir ve parolalarını otomatik yeniler. Sadece **kullanıcı** hesaplarını yaz."
    return None


def _bayat_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla. Devre dışı (aktif=false) bayat hesabı saymış olabilirsin; o zaten kapalı."
    return None


ADIMLAR = [
    Adim("Düşük yetkili kullanıcı çok şey görür", """
Selin: "Bir domain'e sıradan bir kullanıcı olarak girdiğini varsay. Domain'i haritalaman
gerekir: kim kimdir, kim neye erişebilir?"

AD'nin tasarımı gereği nesnelerin birbirini görmesi gerekir; bu yüzden **düşük yetkili bir
kullanıcı bile** kullanıcıları, grupları, bilgisayarları ve ilişkileri okuyabilir. **<<musteri>>**
için böyle bir hesapla alınmış bir döküm var. <<sahne>>

Önce dökümün yapısına bak:
""", komut="python3 -m json.tool ad/ad_dokum.json | head -30", sonra="""
Gerçek ortamda bu dökümü araçlar toplar (örneğin BloodHound'un toplayıcıları); bu görevde
elimizde hazır bir dosya var. Savunmacı da kendi AD'sini aynı gözle taramalıdır.
"""),
    Adim("Grep ile satır satır", """
Dökümde her kayıt tek satırda; yani JSON'u satır satır süzebilirsin. Parolası hiç dolmayan
hesapları listele:
""", komut="grep '\"sifre_hic_dolmaz\": true' ad/ad_dokum.json", sonra="""
Dikkat: `aktif: false` olan hesaplar da çıkar. Kapalı hesap saldırgan için sorun değildir; önce
**aktif** olanlara odaklan.
"""),
    Adim("Gruplar ve iç içe üyelik", """
Gruplar başka grupları üye olarak alabilir. Bir kullanıcı `Domain Admins` içindeki bir grubun
üyesiyse, **o da Domain Admin gibi** davranır. Grup kayıtlarına bak:
""", komut="grep '\"uyeler\"' ad/ad_dokum.json", sonra="""
`Domain Admins` satırında bir kullanıcı adı olmayan, **grup** gibi duran bir kayıt var mı?
Onun satırını da oku.
"""),
    Adim("Servis hesapları ve SPN", """
**SPN** (Service Principal Name), bir servisi AD'de tanımlayan addır. Bir kullanıcı hesabına SPN
tanımlıysa, domain'deki **herhangi biri** o servis için bilet isteyebilir ve bu bilet o hesabın
parolasıyla şifrelidir. Parola eski ve zayıfsa saldırgan bileti alıp çevrimdışı kırmayı dener
(Kerberoasting; Bölüm 3'te izlerini göreceğiz). Hangi **kullanıcı** hesaplarında SPN var?
""", komut="grep '\"spn\": \\[\"' ad/ad_dokum.json", sonra="""
Bilgisayar hesaplarında da SPN olur; ama onlar sistem tarafından yönetilir ve parolaları
otomatik yenilenir. Asıl risk, kullanıcı tipi servis hesaplarındadır.
"""),
    Adim("Bayat hesaplar", """
Uzun süredir girilmeyen hesaplar, kimse bakmadığı için fark edilmeden kötüye kullanılabilir. Dökümde
`son_giris_gun_once` sütunu vardır. 90 günden büyük olanları `awk` ile süz:
""", komut="awk -F'\"son_giris_gun_once\": ' 'NF>1 {split($2,a,\",\"); if (a[1]+0>90) print $0}' ad/ad_dokum.json",
         sonra="""
**Hacker gözüyle:** Saldırgan için ideal hesap: etkin, kimsenin izlemediği, parolası dolmayan ve
yetkili. Savunmacı da bu dört özelliği birlikte arar. Tek tek zararsız görünen bulgular, **kesiştiklerinde**
tehlikelidir.
"""),
    Adim("Kesişim: asıl bulgu", """
Yukarıdaki listeleri yan yana koy: hem SPN'si olan, hem parolası dolmayan, hem de (iç içe grup
yoluyla bile olsa) Domain Admin olan bir hesap var mı? Böyle bir hesap, Kerberoasting'in tam
karşılığını verir: zayıf bir parolayı kıran saldırgan doğrudan domain'in sahibi olur. Görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`Domain Admins` grubunun **gerçek** üyeleri kimler? İç içe grubun üyelerini de say, "
          "grup adının kendisini yazma.",
          Kume("da", sik_hatalar=_da_hata, bicim="hesap adları, virgülle ayrılmış"),
          ("`Domain Admins` satırındaki üyelerden biri bir hesap değil, başka bir grup olabilir.",
           "`grep '\"uyeler\"' ad/ad_dokum.json` ile grup satırlarını oku; iç içe grubun satırını da bul.",
           "Doğrudan üyeler + iç içe grubun üyeleri. Grup adının kendisi hesap değildir."),
          puan=40, baslik="Gerçek Domain Admin'ler"),
    Gorev("**Aktif** olup parolası hiç dolmayan hesapların adlarını yaz.",
          Kume("dolmaz", sik_hatalar=_dolmaz_hata, bicim="hesap adları, virgülle ayrılmış"),
          ("İki koşul var: aktif ve parolası dolmuyor.",
           "`\"sifre_hic_dolmaz\": true` satırlarından `\"aktif\": false` olanları çıkar.",
           "`grep '\"sifre_hic_dolmaz\": true' ad/ad_dokum.json | grep '\"aktif\": true'`"),
          puan=30, baslik="Parolası dolmayanlar"),
    Gorev("SPN tanımlı **kullanıcı** (servis) hesaplarının adlarını yaz.",
          Kume("spn", sik_hatalar=_spn_hata, bicim="hesap adları, virgülle ayrılmış"),
          ("`spn` alanı dolu olan kayıtlar; ama hangi bölümde?",
           "`kullanicilar` listesindeki kayıtlar. `bilgisayarlar` listesi ayrı.",
           "`grep '\"spn\": \\[\"' ad/ad_dokum.json | grep '\"aktif\"'` yalnızca kullanıcı satırlarını verir."),
          puan=30, baslik="SPN'li servis hesapları"),
    Gorev("90 günden uzun süredir giriş yapılmamış **aktif** hesap sayısı kaç?",
          Sayi("bayat", sik_hatalar=_bayat_hata),
          ("`son_giris_gun_once` sütununa bak.",
           "Eşik 90: 90'dan **büyük** olanlar. Pasif (`aktif: false`) hesapları sayma.",
           "`awk -F'\"son_giris_gun_once\": ' 'NF>1 {split($2,a,\",\"); if (a[1]+0>90) print}' ad/ad_dokum.json | grep -c '\"aktif\": true'`"),
          puan=30, baslik="Bayat hesaplar"),
    Gorev("En tehlikeli kesişim: SPN'si olan **ve** (iç içe grup yoluyla) Domain Admin olan servis hesabı hangisi?",
          Metin("tehlikeli", bicim="hesap adı"),
          ("SPN'li hesaplarla gerçek Domain Admin listesini karşılaştır.",
           "Domain Admins'in içindeki grubun üyelerine bak; servis hesabı gibi görünen biri var mı?",
           "Bulduğun SPN listesinden biri, iç içe grubun üyesi. Onun adını yaz."),
          puan=40, baslik="Tehlikeli kesişim"),
    Gorev("Düşük yetkili sıradan bir kullanıcı neden bu kadar çok AD bilgisini okuyabilir?",
          Secmeli([
              ("AD nesnelerin birbirini görmesi gerektiği için tasarlandı; okuma izni varsayılan olarak geniştir",
               "Doğru. Bu bir hata değil tasarımdır; savunmanın işi ayrıcalıklı hesapları buna göre yönetmektir."),
              ("Saldırgan önce DC'nin parolasını kırdığı için tüm dökümü zaten yönetici olarak almıştır",
               "Yanlış. Bu döküm düşük yetkili hesapla alındı; yönetici olmak gerekmez."),
              ("Çünkü Windows kullanıcıların tüm parolalarını düz metin olarak herkese açık bir klasörde tutar",
               "Yanlış. Parolalar düz metin saklanmaz; konu nesne ve ilişki bilgisinin okunabilir olmasıdır."),
              ("Bu yalnızca eski sürümlerdeki bir hatadır; güncel Windows'ta düşük yetkili kullanıcı hiçbir şey okuyamaz",
               "Yanlış. Okuma izni güncel sürümlerde de tasarımın parçasıdır."),
          ], dogru=0),
          ("Kullanıcıların birbirini ve servisleri bulabilmesi için dizinin okunabilir olması gerekir.",
           "Tasarım mı, hata mı?",
           "Nesnelerin birbirini görmesi gerektiği için okuma izni geniş."),
          puan=20, baslik="Neden okunabiliyor"),
    Gorev("SPN'li bir servis hesabının parolası hiç dolmuyorsa ve hesap Domain Admin ise neden en acil bulgudur?",
          Secmeli([
              ("Zayıf parola çevrimdışı kırılabilir ve kırılan hesap tam domain yetkisi taşır",
               "Doğru. Düşük yetkili biri bilet isteyip çevrimdışı deneyebilir; başarı = domain hakimiyeti."),
              ("Çünkü SPN'li hesaplar yalnızca bir kez giriş yapabilir ve sonra otomatik olarak kilitlenir",
               "Yanlış. Böyle bir kural yok; sorun hesabın parolasının eski kalmasıdır."),
              ("Çünkü Domain Admin üyeliği hesabın SPN'sini siler ve servis çalışmaz hale gelir",
               "Yanlış. Üyelik SPN'yi etkilemez; iki özellik birlikte bulunduğunda risk katlanır."),
              ("Çünkü parolası dolmayan hesaplar en çok disk alanı kullanır ve sunucuyu yavaşlatır",
               "Yanlış. Risk performans değil, kimlik güvenliğidir."),
          ], dogru=0),
          ("Üç özelliği (SPN, dolmayan parola, yetki) birleştir.",
           "Bu bölümde SPN'nin neden bilet isteğine açık olduğunu hatırla.",
           "Kırılan parola = Domain Admin yetkisi."),
          puan=20, baslik="Neden acil"),
]


def _kapanis():
    return """
Düşük yetkili bir kullanıcı AD'yi okuyup "en değerli hedef" listesini birkaç saniyede çıkarır:
Domain Admin'ler, SPN'li servis hesapları, parolası dolmayanlar. Savunma dersi: aynı listeyi
sen düzenli çıkar; tek tek zararsız görünen üç bulgunun **kesişimi** gerçek risktir, ve iç içe
gruplar yüzünden "gerçek üye listesi" çoğu zaman sandığından uzundur. BloodHound gibi araçlar bu
haritayı grafik olarak verir; savunmacı onu saldırgandan önce çalıştırmalıdır.
"""


SEVIYE = Seviye(
    kimlik="c11b02",
    cilt=11,
    bolum=2,
    baslik="AD Keşfi",
    brifing="""
Mert dökümü ekrana atıyor: "**<<musteri>>** için düşük yetkili bir hesapla alınmış AD okuma
çıktısı. <<sahne>> Saldırgan bu dosyaya baktığında ilk neyi arardı? Sen de onu ara; ama biz
bulgularımızı raporlayıp kapatacağız."

Selin: "Dört şeye bak: gerçek Domain Admin'ler, parolası hiç dolmayan hesaplar, SPN'li servis
hesapları ve bayat hesaplar. Sonra bunların kesişimini söyle."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Servis hesapları ve eski parolalar:** Pek çok AD sızma testi raporunda "parolası hiç dolmayan,
  SPN'li, aşırı yetkili servis hesabı" bulgusu çok sık görülür. Bu yüzden gMSA gibi otomatik
  parola yönetimi önerilir.
- **BloodHound:** Açık kaynak bir araç olup AD ilişkilerini grafik olarak gösterir; hem saldırı
  ekipleri hem savunma ekipleri kullanır. Savunmada amaç, Domain Admin'e giden kolay yolları
  saldırgandan önce görüp kapatmaktır.
- **Tespit ve önleme:** Ayrıcalıklı grup üyeliklerinde değişiklik, Windows güvenlik günlüğünde
  olay kimlikleriyle (örneğin grup üyesi eklendi olayları) izlenebilir. Düzenli "hesap temizliği"
  (bayat ve pasif hesapların kapatılması) hem önlemdir hem denetim isteğidir.
""",
    sure_hedef_dk=30,
)
