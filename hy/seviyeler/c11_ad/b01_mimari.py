"""Cilt 11 · Bölüm 1 — AD Mimarisi.

Beceri: kurgusal bir Active Directory'nin yapı dökümünü (DC'ler, OU'lar, GPO bağlantıları,
varlık listesi, oturum kayıtları) okuyup Katman 0 varlıklarını ayırmak ve "düz AD"
ihlalini (Domain Admin'in kullanıcı bilgisayarında oturum açması) bulmak.

Vakalar: banka, lojistik, belediye, hastane; her birinde farklı birim ve GPO adları.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c11_ad.ortak import hesap_adlari, sec_doldur, sh, sirket_sec

GPO_HAVUZU = ["GPO-Ekran-Kilidi", "GPO-USB-Kisitla", "GPO-Yazici-Haritala", "GPO-Guncelleme-Takvimi",
              "GPO-Tarayici-Ayarlari", "GPO-Uzak-Masaustu-Kisit", "GPO-Dosya-Paylasimi", "GPO-Duvar-Kagidi"]

SAHNE = {
    "ferahbank": "Banka, şube bilgisayarlarının bir denetimden önce AD yapısını belgelemek istiyor.",
    "kuzgun": "Lojistik firması, depo ve ofis bilgisayarlarının aynı domain'de olmasından endişe ediyor.",
    "yesiltepe": "Belediye, iki bilgi işlem personelinin ayrıldığı için AD'nin envanterini çıkarmak istiyor.",
    "medora": "Hastane, KVKK denetimi öncesi kimin hangi sisteme ne yetkiyle girdiğini görmek istiyor.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on = sk["on"]
    dcler = [f"{on}-dc{i:02d}" for i in range(1, rng.randint(2, 4) + 1)]
    ouler = list(sk["ouler"])
    gpo = dict(zip(ouler, rng.sample(GPO_HAVUZU, len(ouler))))
    hedef_ou = rng.choice(ouler)
    kisiler = hesap_adlari(rng, 8)
    da = [f"adm.{k}" for k in kisiler[:rng.randint(2, 3)]]
    sade = kisiler[3:]
    sunucular = [f"{on}-dosya01", f"{on}-sql01", f"{on}-web01", f"{on}-yedek01"]
    istasyonlar = [f"{on}-pc{rng.randint(100, 899)}" for _ in range(6)]
    istasyonlar = sorted(set(istasyonlar))
    ihlal = rng.choice(da)

    def saat(a, b):
        return f"{rng.randint(a, b):02d}:{rng.randint(0, 59):02d}"

    oturumlar = []
    for a in da:
        for _ in range(rng.randint(2, 3)):
            oturumlar.append(f"{rng.choice(dcler)}  {a}  yerel/uzak-masaustu  {saat(8, 18)}")
    for _ in range(rng.randint(1, 2)):
        oturumlar.append(f"{rng.choice(istasyonlar)}  {ihlal}  etkilesimli  {saat(9, 17)}")
    for k in sade:
        for _ in range(rng.randint(1, 3)):
            oturumlar.append(f"{rng.choice(istasyonlar)}  {k}  etkilesimli  {saat(8, 18)}")
    rng.shuffle(oturumlar)
    return {
        "vaka": f"{sk['ad']} — AD envanteri",
        "sirket": sk, "dcler": dcler, "ouler": ouler, "gpo": gpo, "da": da, "sade": sade,
        "sunucular": sunucular, "istasyonlar": istasyonlar, "ihlal": ihlal, "oturumlar": oturumlar,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "alan": sk["alan"],
                  "hedef_ou": hedef_ou, "onek": on},
        "cevaplar": {
            "dc_sayi": len(dcler),
            "gpo": gpo[hedef_ou],
            "tier0": dcler + da,
            "ihlal": ihlal,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    sk = s["sirket"]
    ip = lambda i: f"10.20.0.{10 + i}"
    satirlar = [
        f"# {sk['ad']} — Active Directory yapısı (KURGUSAL)",
        f"FOREST: {sk['alan']}",
        f"DOMAIN: {sk['alan']}  (NetBIOS adı: {sk['nb']})",
        "",
        "[DC'ler]  ad  ip  not",
    ]
    for i, d in enumerate(s["dcler"]):
        satirlar.append(f"{d}  {ip(i)}  {'ilk DC, FSMO rolleri' if i == 0 else 'ek DC'}")
    satirlar += ["", "[OU yapısı]"] + [f"OU={o},DC={sk['alan'].split('.')[0]},DC=lab" for o in s["ouler"]]
    satirlar += ["", "[GPO bağlantıları]"] + [f"{g} -> OU={o}" for o, g in s["gpo"].items()]
    u.yaz(lab / "ad/ad_yapisi.txt", "\n".join(satirlar) + "\n")
    v = ["ad,tur,aciklama"]
    for d in s["dcler"]:
        v.append(f"{d},alan-denetleyicisi,AD veritabanını barındırır")
    for a in s["da"]:
        v.append(f"{a},domain-admin-hesabi,Domain Admins üyesi yönetici hesabı")
    for x in s["sunucular"]:
        v.append(f"{x},sunucu,uygulama/dosya sunucusu")
    for x in s["istasyonlar"]:
        v.append(f"{x},istasyon,kullanıcı bilgisayarı")
    for x in s["sade"][:3]:
        v.append(f"{x},kullanici,sıradan personel hesabı")
    u.yaz(lab / "ad/varliklar.csv", "\n".join(v) + "\n")
    ol = ["# bilgisayar  kullanici  oturum-turu  saat"] + s["oturumlar"]
    u.yaz(lab / "ad/oturumlar.txt", "\n".join(ol) + "\n")


def coz(lab: Path, s: dict) -> dict:
    hedef = s["metin"]["hedef_ou"]
    return sec_doldur({
        2: sh("awk '/^\\[DC/ {b=1; next} /^\\[/ {b=0} b && NF' ad/ad_yapisi.txt | wc -l", lab),
        3: sh(f"grep -- '-> OU={hedef}$' ad/ad_yapisi.txt | awk '{{print $1}}'", lab),
        4: sh("awk -F, '$2==\"alan-denetleyicisi\" || $2==\"domain-admin-hesabi\" {print $1}' ad/varliklar.csv | tr '\\n' ' '", lab),
        5: sh("awk '$2 ~ /^adm\\./ && $1 ~ /-pc/ {print $2}' ad/oturumlar.txt | sort -u", lab),
    }, GOREVLER, lab, s)


def _dc_hata(g, beklenen, b):
    if g.strip().lstrip("-").isdigit() and int(g) == beklenen + 1:
        return "`[DC'ler]` bölüm başlığını da saymış olabilirsin; sadece sunucu satırlarını say."
    return None


def _tier0_hata(g, beklenen, b):
    verilen = set(g.split())
    dcler = {x.lower() for x in b.senaryo["dcler"]}
    if verilen == dcler:
        return "Alan denetleyicileri doğru, ama Domain Admin hesapları da Katman 0'dır: DC'yi yönetebilen kimlik DC kadar kritiktir."
    if verilen & {x.lower() for x in b.senaryo["sunucular"]}:
        return "Dosya/SQL/web sunucuları Katman 1'dir. Katman 0 yalnızca domain'in kendisini yöneten varlıklardır."
    return None


def _ihlal_hata(g, beklenen, b):
    if "-pc" in g or "-dc" in g:
        return "Bu bir bilgisayar adı. Sorulan, oturumu açan **hesap**."
    return None


ADIMLAR = [
    Adim("AD'nin yapı taşları", """
Kalkan'ın bu haftaki müşterisi **<<musteri>>**. <<sahne>> Selin: "Önce haritayı okuyacaksın.
Saldırmadan önce yapıyı anlamak gerekir."

- **Domain:** ortak bir kullanıcı/bilgisayar veritabanını paylaşan nesneler topluluğu.
- **Forest (orman):** bir ya da birkaç domain'in en üst sınırı; asıl güven sınırı budur.
- **OU (Organizational Unit):** nesneleri gruplayan klasör; politikalar OU'lara bağlanır.
- **GPO (Group Policy Object):** makinelere ve kullanıcılara uygulanan ayar paketi.
- **DC (Domain Controller):** AD veritabanını tutan sunucu. Nihai hedef.

Müşterinin yapı dökümüne bak:
""", komut="cat ad/ad_yapisi.txt", sonra="""
`[DC'ler]` bölümündeki her satır bir alan denetleyicisidir. Başlık satırı ve boş satırlar
DC değildir; sayarken dikkat.
"""),
    Adim("İki protokol: NTLM ve Kerberos", """
AD iki kimlik doğrulama protokolü kullanır:

- **NTLM:** eski, parola özetine (hash) dayanır; özet ele geçirilirse parola bilinmeden de
  kullanılabilir (pass-the-hash).
- **Kerberos:** modern, **bilet** (ticket) tabanlıdır. Giriş yapınca bir bilet alırsın ve servislere
  o biletle girersin.

**Hacker gözüyle:** Bu cildin saldırılarının çoğu bir yazılım açığı değil, bu protokollerin
tasarımının sonucudur. O yüzden yamayla değil, yapılandırmayla azaltılırlar. Savunma tarafı bunu
bilmelidir.
"""),
    Adim("Katmanlar (tiering)", """
Microsoft'un önerdiği savunma ayrıcalığı **katmanlara** ayırmaktır:

- **Katman 0:** DC'ler ve Domain Admin hesapları. Domain'in kendisi.
- **Katman 1:** sunucular (dosya, SQL, web).
- **Katman 2:** kullanıcı bilgisayarları ve sıradan hesaplar.

Altın kural: **Bir katmanın kimlik bilgisi daha düşük bir katmanda asla kullanılmaz.**
Varlık listesine bak ve her satırın hangi katmana girdiğini düşün:
""", komut="cat ad/varliklar.csv"),
    Adim("Bir tür seç, grep'le", """
Büyük listelerde gözle aramak yerine süz. `awk -F,` virgülle ayrılmış dosyada sütunları ayırır;
`$2` ikinci sütundur (`tur`). Önce kaç varlık türü var, gör:
""", komut="awk -F, 'NR>1 {print $2}' ad/varliklar.csv | sort | uniq -c", sonra="""
Katman 0'a hangi türlerin girdiğine sen karar vereceksin; görev bunu soracak.
"""),
    Adim("Düz AD ve oturum kayıtları", """
**Düz (flat) AD**, ayrıcalıklı hesapların her yerde oturum açabildiği AD'dir. Böyle bir ortamda
bir kullanıcı bilgisayarını ele geçiren, orada kalan yönetici kimlik bilgisini de ele geçirebilir.
Oturum kayıtlarında yönetici hesaplarını (`adm.` ile başlar) süz:
""", komut="grep ' adm\\.' ad/oturumlar.txt", sonra="""
Bir DC'de oturum açan Domain Admin normaldir. Aynı hesabın `-pc` ile biten bir **kullanıcı
bilgisayarında** oturum açması ise katman ihlalidir.

**Hacker gözüyle:** Saldırgan "Domain Admin nerede oturum açmış?" diye bakar. Savunmacı da aynı
soruyu önce sorar.
"""),
    Adim("GPO'lar neden değerli?", """
GPO'lar bir OU'ya bağlanır ve o OU'daki tüm makinelere uygulanır. Bir GPO'yu değiştirebilen biri,
yüzlerce makineye tek hamlede ayar dayatabilir; bu yüzden GPO yazma yetkisi de Katman 0 kadar
korunmalıdır. Hangi GPO hangi OU'ya bağlı, dökümden okunur:
""", komut="grep -- '->' ad/ad_yapisi.txt"),
]

GOREVLER = [
    Gorev("Bir **domain**, **forest** ve **OU** arasındaki ilişkiyi en doğru anlatan cümle hangisi?",
          Secmeli([
              ("Forest en üst güven sınırıdır; OU, domain içindeki nesneleri gruplayan klasördür",
               "Doğru. Güven sınırı forest'tır; OU'lar ise yönetimi ve politika bağlamayı kolaylaştırır."),
              ("OU en üst sınırdır; içinde forest'lar ve domain'ler bulunur, DC'ler ise OU'nun altındaki dosyalardır",
               "Yanlış. Hiyerarşi tersine işler: forest en üstte, OU domain'in içindedir."),
              ("Domain, tek bir bilgisayarın yerel hesap veritabanıdır; forest ise birden çok yerel diskin adıdır",
               "Yanlış. Domain bir bilgisayarın değil, ortak merkezi dizin veritabanını paylaşan nesnelerin topluluğudur."),
              ("GPO bir domain'in en üst sınırıdır; forest ise yalnızca GPO'ları saklayan bir sunucudur",
               "Yanlış. GPO bir politika paketidir; sınır kavramı forest'a aittir."),
          ], dogru=0),
          ("Üç kavramı büyükten küçüğe sırala.",
           "Forest > domain > OU. Güven sınırı hangisinde?",
           "OU'nun görevi 'klasör gibi gruplamak' ve politika bağlamaktır."),
          puan=20, baslik="Forest, domain, OU"),
    Gorev("`ad/ad_yapisi.txt` içinde kaç **alan denetleyicisi (DC)** tanımlı?",
          Sayi("dc_sayi", sik_hatalar=_dc_hata),
          ("DC'ler döküm dosyasında kendi başlığı altında listeleniyor.",
           "`[DC'ler]` başlığından sonraki satırlar; boş satıra kadar.",
           "`awk '/^\\[DC/ {b=1; next} /^\\[/ {b=0} b && NF' ad/ad_yapisi.txt | wc -l`"),
          puan=20, baslik="DC sayısı"),
    Gorev("`<<hedef_ou>>` OU'suna bağlı GPO'nun adı nedir?",
          Metin("gpo", bicim="GPO adı"),
          ("GPO bağlantıları dökümün en altında, `->` işaretiyle.",
           "`grep -- '->' ad/ad_yapisi.txt` bütün bağlantıları gösterir.",
           "`grep -- '-> OU=<<hedef_ou>>$' ad/ad_yapisi.txt` — satırın ilk kelimesi GPO adı."),
          puan=30, baslik="GPO bağlantısı"),
    Gorev("`ad/varliklar.csv` içinde **Katman 0** olan tüm varlıkları yaz (virgülle ayır).",
          Kume("tier0", sik_hatalar=_tier0_hata, bicim="varlık adları, virgülle ayrılmış"),
          ("Katman 0, domain'in kendisini yöneten her şeydir: sadece makineler değil.",
           "İki `tur` değeri Katman 0'a girer: `alan-denetleyicisi` ve `domain-admin-hesabi`.",
           "`awk -F, '$2==\"alan-denetleyicisi\" || $2==\"domain-admin-hesabi\" {print $1}' ad/varliklar.csv`"),
          puan=40, baslik="Katman 0 varlıkları"),
    Gorev("`ad/oturumlar.txt` içinde bir **Domain Admin hesabı** kullanıcı bilgisayarında (Katman 2) oturum "
          "açmış. Bu hesabın adını yaz.",
          Metin("ihlal", sik_hatalar=_ihlal_hata, bicim="hesap adı"),
          ("Yönetici hesaplarının adı `adm.` ile başlıyor.",
           "Bir DC'de oturum açmak normal; `-pc` ile biten bilgisayarlarda açmak ihlal.",
           "`awk '$2 ~ /^adm\\./ && $1 ~ /-pc/ {print $2}' ad/oturumlar.txt | sort -u`"),
          puan=40, baslik="Katman ihlali"),
    Gorev("NTLM ile Kerberos arasındaki temel fark nedir?",
          Secmeli([
              ("NTLM parola özetine dayanan eski bir protokoldür; Kerberos bilet tabanlı, daha yeni bir protokoldür",
               "Doğru. Özet tabanlı yapı pass-the-hash'e kapı açar; bilet tabanlı yapı da biletlerin kötüye kullanımına."),
              ("Kerberos yalnızca internet siteleri için, NTLM yalnızca yazıcılar için kullanılan ayrı protokollerdir",
               "Yanlış. İkisi de AD'de kimlik doğrulama protokolüdür; alan farkı yoktur."),
              ("NTLM biletle çalışır ve süresi dolar; Kerberos ise her seferinde parolanın düz halini DC'ye gönderir",
               "Yanlış. Roller ters yazılmış: bilet tabanlı olan Kerberos'tur."),
              ("İkisi arasında fark yoktur; sadece Windows sürümüne göre farklı adlar alırlar",
               "Yanlış. Çalışma mantıkları tamamen farklıdır."),
          ], dogru=0),
          ("Hangisi 'bilet' kavramını kullanır?",
           "pass-the-hash hangi protokolün özelliğine dayanır?",
           "NTLM = özet (hash) tabanlı, eski; Kerberos = bilet tabanlı, modern."),
          puan=20, baslik="NTLM ve Kerberos"),
    Gorev("'Düz' (flat) bir AD neden tehlikelidir?",
          Secmeli([
              ("Katman ayrımı yoktur; bir kullanıcıyı ele geçiren Domain Admin'e kolayca ulaşır",
               "Doğru. Ayrıcalıklı kimlik bilgileri her yerde bırakıldığı için yol kısadır."),
              ("Çünkü düz AD'de her kullanıcının parolası aynıdır ve bu parola DC üzerinde saklanır",
               "Yanlış. 'Düz' parolayla değil, katman ayrımının yokluğuyla ilgilidir."),
              ("Düz AD yalnızca disk alanını artırır, güvenlik açısından normal AD'den bir farkı yoktur",
               "Yanlış. Fark tam olarak güvenliktedir: saldırı yolunu kısaltır."),
              ("Çünkü düz AD'nin sunucuları yalnızca internetten erişilebilir, iç ağdan erişilemez",
               "Yanlış. Konu erişim yönü değil, yetki ayrımının olmamasıdır."),
          ], dogru=0),
          ("Bu bölümde gördüğün 'katman ihlali' bu sorunun bir örneği.",
           "Ayrıcalıklı hesap sıradan bilgisayarda oturum açarsa ne olur?",
           "Saldırganın Domain Admin'e giden yolu kısalır."),
          puan=20, baslik="Düz AD"),
]


def _kapanis():
    return """
Bir saldırgan, AD'de önce "Domain Admin nerede oturum açıyor, DC'ler hangileri, hangi GPO
nereye bağlı?" diye bakar; bu bilgiler sıradan bir kullanıcıya bile okunabilir. Savunma tarafı için
ders: aynı soruları sen önce sor, Katman 0 varlıklarını sayabil, ihlal eden oturumları bul ve
ayrıcalıklı hesabın düşük katmanda oturum açmasını **kural olarak yasakla**, sonra izle.
"""


SEVIYE = Seviye(
    kimlik="c11b01",
    cilt=11,
    bolum=1,
    baslik="AD Mimarisi",
    brifing="""
Selin yeni müşteri dosyasını masana bırakıyor: "**<<musteri>>**. <<sahne>> Elimizde müşterinin
AD yapı dökümü, bir varlık listesi ve son günlerin oturum kayıtları var. `<<alan>>` domain'ini
tanıyıp Katman 0'ın nerede başladığını göstermeni istiyorum."

Deniz ekliyor: "Domain Admin hesapları normalde sadece DC'lerde görünmeli. Gördüğün her sapma
benim ekran listemde bir alarmdır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **SolarWinds 2020:** Kamuya açık raporlara göre saldırganlar, ele geçirdikleri ortamlarda kimlik
  ve güven mekanizmalarını (örneğin kimlik doğrulama belirteçlerini) kötüye kullandı. AD'de de
  her şey güvene dayanır; bu bölümdeki "güven nerede başlar?" sorusu aynı sorudur.
- **Katmanlı yönetim:** Microsoft'un yayımladığı kurumsal erişim yönergeleri ayrıcalıklı hesapların
  ayrılmasını önerir. Pek çok AD sızma testi raporunda "Domain Admin bir iş istasyonunda oturum
  açmış" bulgusu sık görülür.
- **Tespit ve önleme:** Domain Admin hesabının iş istasyonuna giriş yapması, Windows
  güvenlik günlüğündeki oturum açma olaylarından (örn. 4624) yakalanabilir; önlemek için
  istasyon GPO'sunda bu hesap grubuna "oturum açmayı reddet" hakkı verilir.
""",
    sure_hedef_dk=25,
)
