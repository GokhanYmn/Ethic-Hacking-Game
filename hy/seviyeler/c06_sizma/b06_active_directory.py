"""Cilt 6 · Bölüm 6 — Active Directory'ye Giriş (kavramsal).

Beceri: domain, Domain Controller, Kerberos, gruplar ve en az yetki kavramlarını öğrenmek; kurgusal
bir AD üyelik dökümünde aşırı yetkili hesapları bulup gereksiz üyelikleri çıkarmak.

Hiçbir saldırı tekniği anlatılmaz; AD'nin neden "kimlik bilgisi hijyeni" meselesi olduğu savunma gözüyle işlenir.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

SOYADLAR = ["yilmaz", "demir", "kaya", "celik", "sahin", "arslan", "dogan", "ozturk", "koc", "aydin", "polat", "tas",
            "yildiz", "aksoy", "kurt"]
SERVISLER = ["svc_yedek", "svc_rapor", "svc_sql", "svc_web", "svc_tarama"]
PRIV_GRUPLAR = ("Domain Admins", "Enterprise Admins", "Backup Operators", "Account Operators")

VAKALAR = [
    {"kod": "ferahbank", "alan": "FERAHBANK", "dc": "FB-DC01", "bt": "bt",
     "birimler": ["krediler", "muhasebe", "sube_operasyon", "risk"],
     "olay": "Banka, yıllık denetim öncesi ayrıcalıklı hesapların temizlenmesini istiyor."},
    {"kod": "yesiltepe", "alan": "YESILTEPE", "dc": "YTB-DC01", "bt": "bilgi_islem",
     "birimler": ["fen_isleri", "insan_kaynaklari", "zabita", "imar"],
     "olay": "Belediye, geçen ay görevden ayrılan çalışanlardan sonra hesap yetkilerini gözden geçiriyor."},
    {"kod": "kuzgun", "alan": "KUZGUN", "dc": "KZG-DC01", "bt": "it",
     "birimler": ["depo", "filo", "muhasebe", "satis"],
     "olay": "Lojistik firması, bir ofis bilgisayarının ele geçirildiği şüphesi sonrası domain yönetici listesini inceliyor."},
]


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    adlar = u.benzersiz(rng, lambda r: f"{r.choice(u.ISIMLER)}.{r.choice(SOYADLAR)}", 13)
    bt1, bt2, bt3, nb1, nb2, bayat, bayat_dis, h1, h2, h3, h4, h5, h6 = adlar
    svc_da, svc_diger = rng.sample(SERVISLER, 2)
    birim = lambda: rng.choice(v["birimler"])  # noqa: E731
    hesaplar = []
    for ad in (bt1, bt2, bt3):
        hesaplar.append((ad, "kullanici", v["bt"], rng.randint(0, 20)))
    for ad in (nb1, nb2, h1, h2, h3, h4, h5, h6):
        hesaplar.append((ad, "kullanici", birim(), rng.randint(0, 40)))
    hesaplar.append((bayat, "kullanici", birim(), rng.randint(190, 520)))
    hesaplar.append((bayat_dis, "kullanici", birim(), rng.randint(200, 400)))
    hesaplar.append((svc_da, "servis", "uygulama", 0))
    hesaplar.append((svc_diger, "servis", "uygulama", 0))
    bayat_grup = rng.choice(["Backup Operators", "Account Operators"])
    ek = rng.sample([h2, h3, h4], rng.randint(0, 2))
    uyelik = [("Domain Admins", x) for x in (bt1, bt2, nb1, nb2, svc_da)]
    uyelik += [("Enterprise Admins", bt1)]
    uyelik += [("Backup Operators", bt3)]
    uyelik += [("Account Operators", h1)] + [("Account Operators", x) for x in ek]
    uyelik += [(bayat_grup, bayat)]
    uyelik += [("Remote Desktop Users", x) for x in (h5, h6, bayat_dis, nb1)]
    uyelik += [("Helpdesk", x) for x in (h1, h5)]
    rng.shuffle(uyelik)
    rng.shuffle(hesaplar)
    priv = sorted({h for g, h in uyelik if g in PRIV_GRUPLAR})
    kume_nb = sorted([nb1, nb2])
    return {
        "vaka": f"{m['ad']} — {v['alan']} Active Directory",
        "musteri": m, "v": v, "hesaplar": hesaplar, "uyelik": uyelik, "bt_insan": [bt1, bt2],
        "gereksiz": [nb1, nb2, svc_da], "svc_da": svc_da, "bayat": bayat, "nb": kume_nb,
        "brifing": f"""
Selin Aksoy bir dışa aktarım dosyası getiriyor: "**{m['ad']}**'in domain'inden (`{v['alan'].lower()}.lab`) alınmış **kurgusal**
bir hesap ve grup üyeliği dökümü. {v['olay']}"

Deniz masasından yanıt veriyor: "Active Directory'de saldırgan çoğu zaman exploit kullanmaz, **kimlik bilgisi**
kullanır. Bir hesap ne kadar çok yetkiliyse, ele geçirilmesi o kadar pahalıya patlar. Domain Admins gibi
gruplarda **olmaması gereken** hesapları bul, sonra çıkar."
""",
        "metin": {"musteri": m["ad"], "alan": v["alan"], "dc": v["dc"], "bt": v["bt"]},
        "cevaplar": {
            "nb": kume_nb,
            "svc": svc_da,
            "bayat": bayat,
            "priv_sayi": len(priv),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} · {v['alan']} domain dökümü (KURGUSAL). Dosyalar:\n"
          "ad_dokum/domain_bilgi.txt : domain ve Domain Controller bilgisi\n"
          "ad_dokum/hesaplar.csv     : hesap,tur,birim,son_giris_gun_once\n"
          "ad_dokum/uyelik.csv       : grup,hesap\n"
          f"Ayrıcalıklı gruplar bu denetimde: {', '.join(PRIV_GRUPLAR)}.\n")
    u.yaz(lab / "ad_dokum" / "domain_bilgi.txt",
          f"Domain          : {v['alan'].lower()}.lab\n"
          f"Domain Controller: {v['dc']}\n"
          "Kimlik doğrulama : Kerberos\n"
          f"BT birimi (yetkili yöneticiler): {v['bt']}\n")
    satir = ["# hesap,tur,birim,son_giris_gun_once"]
    satir += [f"{a},{t},{b},{g}" for a, t, b, g in s["hesaplar"]]
    u.yaz(lab / "ad_dokum" / "hesaplar.csv", "\n".join(satir) + "\n")
    satir = ["# grup,hesap"] + [f"{g},{h}" for g, h in s["uyelik"]]
    u.yaz(lab / "ad_dokum" / "uyelik.csv", "\n".join(satir) + "\n")


def _uyelik_oku(b) -> list:
    yol = b.lab / "ad_dokum" / "uyelik.csv"
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    cikti = []
    for x in satirlar:
        if x.strip() and not x.startswith("#"):
            p = x.strip().split(",")
            if len(p) == 2:
                cikti.append((p[0], p[1]))
    return cikti


def _da_temiz(b) -> Sonuc:
    s = b.senaryo
    mevcut = _uyelik_oku(b)
    if not mevcut:
        return Sonuc(False, "uyelik.csv boş ya da yok. Dosyayı silme; yalnızca gereksiz satırları çıkar (`sifirla` ile geri getir).")
    da = {h for g, h in mevcut if g == "Domain Admins"}
    kalan = [h for h in s["gereksiz"] if h in da]
    if kalan:
        return Sonuc(False, f"`Domain Admins` içinde hâlâ gereksiz üye var: {kalan[0]} ve {len(kalan) - 1} tane daha."
                     if len(kalan) > 1 else f"`Domain Admins` içinde hâlâ gereksiz üye var: {kalan[0]}.",
                     yakin=len(kalan) < len(s["gereksiz"]))
    eksik = [h for h in s["bt_insan"] if h not in da]
    if eksik:
        return Sonuc(False, f"Yetkili BT yöneticisi {eksik[0]} de Domain Admins'ten çıkmış. Onlar kalmalı; "
                            "domain'i yönetecek biri olmalı.", yakin=True)
    beklenen_diger = sorted((g, h) for g, h in s["uyelik"] if g != "Domain Admins")
    mevcut_diger = sorted((g, h) for g, h in mevcut if g != "Domain Admins")
    if beklenen_diger != mevcut_diger:
        return Sonuc(False, "Diğer grupların üyeliği de değişmiş. Sadece `Domain Admins` satırlarına dokunmalıydın "
                            "(örneğin `Remote Desktop Users` satırlarını silme).", yakin=True)
    return Sonuc(True, "Domain Admins artık yalnızca BT biriminin yönetici hesaplarını içeriyor. Gerçek ortamda "
                       "servis hesabı için ihtiyaç duyduğu **en az** grup tanımlanır, günlük iş için ayrı bir "
                       "sıradan hesap kullanılır.")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    v = s["v"]
    on = ("awk -F, 'NR==FNR{if($0!~/^#/){tur[$1]=$2;birim[$1]=$3;gun[$1]=$4};next} ")
    nb = sh("BT='" + v["bt"] + "' " + on + "$1==\"Domain Admins\" && tur[$2]==\"kullanici\" && birim[$2]!=ENVIRON[\"BT\"]{print $2}' "
            "ad_dokum/hesaplar.csv ad_dokum/uyelik.csv | tr '\\n' ' '", lab)
    svc = sh(on + "$1==\"Domain Admins\" && tur[$2]==\"servis\"{print $2}' ad_dokum/hesaplar.csv ad_dokum/uyelik.csv", lab)
    bayat = sh(on + "($1==\"Backup Operators\"||$1==\"Account Operators\"||$1==\"Domain Admins\"||$1==\"Enterprise Admins\") "
               "&& gun[$2]>90{print $2}' ad_dokum/hesaplar.csv ad_dokum/uyelik.csv", lab)
    sayi = sh("grep -E '^(Domain Admins|Enterprise Admins|Backup Operators|Account Operators),' ad_dokum/uyelik.csv "
              "| cut -d, -f2 | sort -u | wc -l", lab)
    sec = {n: SEVIYE.gorevler[n - 1].kontrol.cevabi_goster(Baglam(s, lab, n))[0] for n in (1, 6, 8)}
    sh("BT='" + v["bt"] + "' " + on + "!($1==\"Domain Admins\" && !(tur[$2]==\"kullanici\" && birim[$2]==ENVIRON[\"BT\"]))' "
       "ad_dokum/hesaplar.csv ad_dokum/uyelik.csv > ad_dokum/.t && mv ad_dokum/.t ad_dokum/uyelik.csv", lab)
    return {1: sec[1], 2: nb, 3: sayi, 4: svc, 5: bayat, 6: sec[6], 7: "", 8: sec[8]}


def _priv_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    toplam = sum(1 for gr, _ in b.senaryo["uyelik"] if gr in PRIV_GRUPLAR)
    if n == toplam:
        return ("Satır sayısını saymışsın. Aynı hesap birden fazla ayrıcalıklı grupta olabilir; **farklı hesapları** "
                "say (`sort -u`).")
    return None


ADIMLAR = [
    Adim("Active Directory nedir?", """
Gerçek kurumların çoğunda kullanıcılar, bilgisayarlar ve yetkiler **Active Directory (AD)** ile merkezî
olarak yönetilir. Dört temel kavram:

- **Domain:** merkezden yönetilen bilgisayar ve kullanıcı topluluğu (örneğin `sirket.lab`).
- **Domain Controller (DC):** AD'yi barındıran ve **kimlik doğrulamayı yapan** sunucu. Ele geçirilirse tüm domain gider.
- **Kerberos:** AD'nin kimlik doğrulama protokolü. Parola ağda dolaşmaz; DC, kullanıcıya **bilet (ticket)** verir ve
  kullanıcı servislere bu biletle girer.
- **Domain Admin:** domain üzerinde tam yetki. Saldırganın nihai hedefi.

Bu bölümde saldırı yapmayacaksın; **kimin ne kadar yetkili olduğunu** okuyacaksın. Lab:
""", komut="cat OKUBENI.txt"),
    Adim("Domain bilgisi", """
Önce domain'e kısa bir bakış:
""", komut="cat ad_dokum/domain_bilgi.txt", sonra="""
Tek bir DC var ve BT birimi yetkili yöneticiler olarak belirtilmiş. Bu, savunmanın **beklenen** tablosudur:
Domain'i yönetenler BT'dir. Başkaları yöneticiyse sormak gerekir: neden?
"""),
    Adim("Gruplar: yetki paketleri", """
AD'de yetkiyi tek tek kullanıcılara değil **gruplara** verirsin. Üye olan, grubun yetkisini alır.
Ayrıcalıklı gruplar:

- **Domain Admins:** domain üzerinde tam yetki.
- **Enterprise Admins:** birden fazla domain içeren ormanda tam yetki.
- **Backup Operators:** yedekleme adına her dosyayı okuyabilir (izinleri aşarak).
- **Account Operators:** kullanıcı ve grup hesaplarını yönetebilir.

Üyelik dökümünde kaç satır hangi grupta?
""", komut="cut -d, -f1 ad_dokum/uyelik.csv | grep -v '^#' | sort | uniq -c", sonra="""
Ayrıcalıklı gruplar küçük olmalı. Bir grubun üye sayısı büyüdükçe, ele geçirilmesi kolay bir hesabın o
gruba üye olma olasılığı büyür.
"""),
    Adim("Domain Admins üyeleri", """
En kritik grup: Domain Admins. Kimler üye?
""", komut="grep '^Domain Admins' ad_dokum/uyelik.csv", sonra="""
Beş satır var, ama bir domain'i beş kişinin yönetmesi gerekmez. Üyeleri **hesap bilgileriyle** karşılaştırmak
şart: hangi birimden, insan mı servis mi, ne zaman giriş yapmış?
"""),
    Adim("Hesap bilgileri", """
`hesaplar.csv` her hesabın türünü (`kullanici` ya da `servis`), birimini ve **kaç gün önce** son giriş yaptığını
söyler.
""", komut="cat ad_dokum/hesaplar.csv", sonra="""
İki kırmızı bayrak:

- **Servis hesabı** Domain Admins'te: servis hesaplarının parolası insanlar tarafından nadiren değişir,
  birçok sistemde saklanır ve izlenmez. Domain Admin yetkisi verilmişse ele geçirilmesi domain'in ele geçirilmesi demektir.
- **Uzun süredir giriş yapmayan** ama ayrıcalıklı grupta duran hesap: kimse fark etmeden ele geçirilebilir.
"""),
    Adim("Neden yanal hareket, neden kimlik?", """
AD ortamında tek bir makineyi ele geçirmek çoğu zaman sadece **başlangıçtır**. Saldırgan (ya da sızma testçisi)
**yanal hareketle** (lateral movement) makineden makineye geçerek asıl hedefe, yani Domain Admin hesabına ya da
DC'ye ulaşmaya çalışır. Bunu çoğu zaman bir exploit'le değil, **kimlik bilgisini** başka bir makinede yeniden
kullanarak yapar: bir makinede bulunan parola ya da parola özeti, başka bir makinede de geçerliyse kapı açılır.

**Hacker gözüyle:** AD güvenliği büyük ölçüde **kimlik bilgisi hijyenidir**:

- Her makinede **benzersiz** yerel yönetici parolası (Microsoft LAPS).
- Domain Admin hesapları **yalnızca** gerektiğinde ve sadece güvenli yönetim makinelerinde kullanılsın;
  günlük iş (e-posta, web) için ayrı, sıradan hesap.
- Ayrıcalıklı gruplar küçük ve düzenli denetlensin.
- Servis hesaplarına gereğinden fazla yetki verilmesin.
""", komut="grep -c servis ad_dokum/hesaplar.csv"),
    Adim("Ayrıcalıklı grupları denetlemek", """
Savunmacının rutini: ayrıcalıklı grupların üyelerini periyodik çıkar, hesap bilgisiyle eşleştir, "bu kişi/hesap
burada ne arıyor?" diye sor. Ayrıcalıklı gruplardaki **farklı** hesapların listesi için `sort -u` kullanılır:
""", komut="grep -E '^(Domain Admins|Enterprise Admins)' ad_dokum/uyelik.csv | cut -d, -f2 | sort -u", sonra="""
Bu çıktıda bir hesap iki grupta olsa bile tek satırda görünür. Bu, **sayarken** de önemlidir: aynı hesabı
iki kez saymak yanlış sonuç verir.
"""),
]

GOREVLER = [
    Gorev("Active Directory'de **Domain Controller (DC)** nedir ve neden bu kadar kritiktir?",
          Secmeli([
              ("AD'yi barındıran, kimlik doğrulayan sunucu; düşerse domain düşer",
               "Doğru. DC, tüm hesapların ve gruplarının tutulduğu yerdir; Kerberos biletlerini de o dağıtır."),
              ("Dosya paylaşımı sunan sunucu; kullanıcıların belgelerini tek yerde toplar ve yedekler",
               "Dosya sunucusu ayrı bir roldür. DC kimlik doğrulama ve dizin hizmetidir."),
              ("Ağ trafiğini filtreleyen güvenlik duvarı; dış saldırıları engeller",
               "Güvenlik duvarı bir ağ cihazıdır. DC AD'nin kendisidir."),
              ("Yedekleme yazılımını çalıştıran sunucu; felaket durumunda sistemi geri yükler",
               "Yedekleme ayrı bir sistemdir. DC, kimlik doğrulamayı sağlar."),
          ]),
          ("DC'nin açılımını hatırla: Domain Controller. Kontrol ettiği şey ne?",
           "Kullanıcıların kim olduğunu doğrulayan sunucu.",
           "Kimlik doğrulama + dizin hizmeti."),
          puan=15, baslik="DC nedir"),
    Gorev("`Domain Admins` grubunda, **BT biriminden olmayan** (`<<bt>>` dışı) **insan** (`kullanici` "
          "türü) hesapların adlarını yaz. (virgülle ayırarak)",
          Kume("nb", bicim="hesap adları, virgülle ayrılmış"),
          ("İki dosyayı birleştir: üyelik hangi hesapları getiriyor, hesaplar dosyası onların birimini söylüyor.",
           "Önce `grep '^Domain Admins' ad_dokum/uyelik.csv`, sonra her hesabı `grep` ile `hesaplar.csv`'de ara; "
           "servis hesaplarını ayrı say.",
           "Birimi `<<bt>>` olmayan ve türü `kullanici` olan iki hesap var."),
          puan=30, baslik="BT dışı yönetici"),
    Gorev("Ayrıcalıklı gruplarda (`Domain Admins`, `Enterprise Admins`, `Backup Operators`, "
          "`Account Operators`) toplam **kaç farklı hesap** var?",
          Sayi("priv_sayi", sik_hatalar=_priv_hata),
          ("Aynı hesap birden fazla grupta olabilir. Satır sayısı farklı hesap sayısı değildir.",
           "Dört grubun satırlarını süz, yalnızca hesap sütununu al, tekrarları at, say.",
           "`grep -E '^(Domain Admins|Enterprise Admins|Backup Operators|Account Operators),' ad_dokum/uyelik.csv | cut -d, -f2 | sort -u | wc -l`"),
          puan=30, baslik="Farklı yetkili hesap"),
    Gorev("`Domain Admins` grubunda bir **servis hesabı** (`tur` = `servis`) var. Adı nedir?",
          Metin("svc", bicim="hesap adı"),
          ("`hesaplar.csv`'de `tur` sütunu `servis` olanları ara.",
           "Domain Admins üyeleri arasında `svc_` ile başlayan ad.",
           "`grep servis ad_dokum/hesaplar.csv` servis hesaplarını verir; hangisi Domain Admins'te?"),
          puan=20, baslik="Servis hesabı"),
    Gorev("Ayrıcalıklı gruplardaki hesaplardan hangisi **90 günden uzun süredir** giriş yapmamış "
          "(`son_giris_gun_once` > 90)?",
          Metin("bayat", bicim="hesap adı"),
          ("Hesaplar dosyasının dördüncü sütunu son girişten bu yana geçen gün sayısı.",
           "Önce 90'dan büyük olanları bul; sonra bunlardan hangisinin ayrıcalıklı bir grupta olduğunu kontrol et. Biri sadece Remote Desktop Users'ta.",
           "`awk -F, '$4>90' ad_dokum/hesaplar.csv` adayları verir; adayları `uyelik.csv`'de ara."),
          puan=30, baslik="Atıl hesap"),
    Gorev("AD saldırılarında saldırgan çoğu zaman **neden** exploit'ten çok kimlik bilgisine yönelir?",
          Secmeli([
              ("Ele geçen kimlik bilgisi başka makinelerde de geçerli olduğu için yayılmayı kolaylaştırır",
               "Doğru. Kimlik bilgisi, güven ilişkileri ve ortak yetkiler sayesinde makineden makineye taşınır; bu yüzden asıl savunma kimlik hijyenidir."),
              ("AD sunucuları yama kabul etmediği için hiçbir zafiyet kapatılamaz ve yama yönetimi anlamsızdır",
               "AD sunucuları da yamalanır. Mesele yama eksikliği değil, kimlik bilgisinin yayılmasıdır."),
              ("Exploit kodları ücretli olduğu için saldırganlar onlara hiçbir şekilde ulaşamaz",
               "Birçok exploit herkese açıktır; saldırganlar kimliği çoğu zaman daha kolay bulduğu için kullanır."),
              ("Kerberos şifrelemeyi kapattığı için kimlik bilgileri ağda tamamen açık dolaşır",
               "Kerberos tam tersine, parolayı ağda açık göndermemek için tasarlanmıştır."),
          ]),
          ("Bir kapıyı zorlamak mı kolay, anahtarı bulup kullanmak mı?",
           "Yayılma, bir makineden öbürüne geçmektir. Neyi taşırsın?",
           "Kimlik bilgisini."),
          puan=20, baslik="Neden kimlik bilgisi"),
    Gorev("`ad_dokum/uyelik.csv` içinde `Domain Admins` grubundan **BT dışı insan hesapları ve "
          "servis hesabını** çıkar. Yetkili BT yöneticileri ve **diğer grupların** üyelikleri "
          "olduğu gibi kalsın. Bitince `cevap 7` yaz.",
          Durum(_da_temiz, "Domain Admins satırlarından gereksiz üç hesabı sil"),
          ("Çıkarılacaklar: 2. ve 4. görevlerde bulduğun üç hesap. Yalnızca `Domain Admins` satırlarına dokun.",
           "`grep -v '^Domain Admins,<hesap>$'` bir satırı çıkarır; birkaç hesap için `-e` ile ekle. Çıktıyı geçici dosyaya yaz, sonra asıl dosyanın yerine koy.",
           "`grep -v -e '^Domain Admins,<hesap1>$' -e '^Domain Admins,<hesap2>$' -e '^Domain Admins,<hesap3>$' ad_dokum/uyelik.csv > t && mv t ad_dokum/uyelik.csv`"),
          puan=35, baslik="Yetkiyi temizle"),
    Gorev("Her bilgisayarda **aynı yerel yönetici parolası** kullanılıyor. Bu neden bir kurum için büyük bir risktir "
          "ve en doğru çözüm hangisidir?",
          Secmeli([
              ("Bir makinedeki kimlik tüm ağı açar; her makineye benzersiz parola (LAPS) verilmeli",
               "Doğru. Benzersiz parola, bir makinenin ele geçirilmesinin diğerlerine yayılmasını engeller; LAPS bunu otomatikleştirir."),
              ("Parola çok uzun olduğu için unutulur; bu yüzden çözüm parolayı kısaltmaktır",
               "Parolayı kısaltmak güvenliği düşürür. Sorun uzunluk değil, her yerde aynı olması."),
              ("Aynı parola her makinede olunca antivirüs çalışmaz; çözüm antivirüsü baştan kurmaktır",
               "Antivirüs parola benzersizliğiyle ilgili değildir."),
              ("Windows aynı parolalı makineleri otomatik olarak kilitler; çözüm parolayı hiç değiştirmemektir",
               "Windows böyle bir kilitleme yapmaz. Hem gerçek risk bu değil, hem de parolayı hiç değiştirmemek kötü bir uygulama."),
          ]),
          ("Bir makinedeki parola başka makinelerde de çalışırsa saldırgan neye sahip olur?",
           "Çözüm, her makinenin parolasının diğerlerinden farklı olması.",
           "Microsoft LAPS."),
          puan=20, baslik="Aynı yerel parola"),
]


def _kapanis():
    return """
Saldırganın gözüyle: AD'de ilerlemek çoğunlukla zafiyet sömürmek değil, hazır bulunan yetkiyi ve kimliği
taşımaktır; fazla yetkili her hesap, ona giden kestirme yoldur. Savunmanın gözüyle: ayrıcalıklı grupları
küçük tut, her üyeyi gerekçelendir, atıl hesapları kapat, servis hesabına domain yönetici yetkisi verme,
yerel yönetici parolasını her makinede benzersiz yap. BloodHound gibi araçlar bu ilişkileri haritalar; hem
savunmacı hem sızma testçisi kullanır. AD'ye uygulamalı giriş için **kendi izole laboratuvarında** açık
kaynaklı bir AD ortamı kurarsın (AD, Windows gerektirdiği için Pi'de değil ayrı bir makinede; bkz. Cilt 9).
"""


SEVIYE = Seviye(
    kimlik="c06b06",
    cilt=6,
    bolum=6,
    baslik="Active Directory'ye Giriş: Aşırı Yetkili Hesaplar",
    brifing="""
**<<musteri>>**'nin domain'i (<<alan>>) için kurgusal bir üyelik dökümü var. Selin: "Ayrıcalıklı
gruplarda olmaması gereken hesapları bul ve çıkar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **NotPetya 2017:** Kamuya açık analizlere göre bir ağın içine girdikten sonra hızla yayılmasında yamasız
  bir SMB açığının yanı sıra ağ içinde yeniden kullanılan kimlik bilgileri de rol oynadı. Bu bölümdeki
  "kimlik bilgisi hijyeni" dersi tam olarak böyle yayılmaları sınırlar.
- **Tespit:** Windows olay günlüklerinde ayrıcalıklı gruplara üye ekleme olayları (örneğin Domain Admins gibi
  global gruplar için 4728, yerel gruplar için 4732, evrensel gruplar için 4756) izlenmeli ve her ekleme
  bir değişiklik talebiyle eşleşmelidir.
- **Önleme:** Ayrıcalıklı grupların periyodik denetimi, katmanlı yönetim (yönetici hesabıyla günlük iş
  yapmamak), Protected Users grubu, LAPS ile benzersiz yerel yönetici parolaları ve servis hesaplarında en az yetki.
""",
    sure_hedef_dk=30,
)
