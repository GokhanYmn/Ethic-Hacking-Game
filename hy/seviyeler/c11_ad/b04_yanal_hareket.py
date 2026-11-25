"""Cilt 11 · Bölüm 4 — Yanal Hareket ve Domain Hakimiyeti.

Beceri: kurgusal bir yetki grafiğini (düğüm/kenar listesi) okuyup sıradan bir kullanıcıdan
Domain Admin'e giden en kısa yolu bulmak ve **hangi kenarı kaldırmanın yolu kestiğini** göstermek
(`yetki_grafigi.txt` dosyasından satırı silerek). Saldırı komutu yoktur; grafik düz metindir.

Vakalar: banka (5 adım), lojistik (6 adım), belediye (4 adım). Her grafikte ölü uç dallar ve
daha uzun bir alternatif yol vardır: yalnızca ortak halkayı keserek yol kapanır.
"""
from __future__ import annotations

import re
from collections import deque
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c11_ad.ortak import hesap_adlari, py, sec_doldur, sh, sirket_sec

KENAR = re.compile(r"^(\S+) -\[(\w+)\]-> (\S+)\s*$")
HEDEF = "DOMAIN_ADMINS"

# Zincir şablonları: (düğüm_türleri, kenar_türleri). Düğüm türleri: u=kullanıcı p=istasyon s=sunucu g=grup a=yönetici hesabı
ZINCIRLER = {
    "ferahbank": ("upusa", ["CanRDP", "HasSession", "AdminTo", "HasSession", "MemberOf"], 5),
    "kuzgun": ("ugugsa", ["MemberOf", "ForceChangePassword", "MemberOf", "AdminTo", "HasSession", "MemberOf"], 6),
    "yesiltepe": ("upua", ["CanRDP", "HasSession", "GenericAll", "MemberOf"], 4),
}
SAHNE = {
    "ferahbank": "Ferah Bank'ın BT ekibi, bir şube çalışanının hesabı ele geçirilirse neler olabileceğini haritalamak istiyor.",
    "kuzgun": "Kuzgun Lojistik'te depo destek ekibinin yetkileri yıllar içinde büyümüş; kimse toplamını bilmiyor.",
    "yesiltepe": "Yeşiltepe Belediyesi'nde bir stajyer hesabı yanlışlıkla çok fazla bilgisayara RDP ile girebiliyor.",
}


def _komsu(kenarlar):
    g = {}
    for a, _, b in kenarlar:
        g.setdefault(a, []).append(b)
    return g


def en_kisa(kenarlar, bas, hedef):
    """BFS: bas'tan hedef'e en kısa yol (düğüm listesi) ya da None."""
    g = _komsu(kenarlar)
    onceki = {bas: None}
    q = deque([bas])
    while q:
        x = q.popleft()
        if x == hedef:
            yol = []
            while x is not None:
                yol.append(x)
                x = onceki[x]
            return yol[::-1]
        for y in g.get(x, []):
            if y not in onceki:
                onceki[y] = x
                q.append(y)
    return None


def uret(rng):
    sk = sirket_sec(rng)
    while sk["kod"] not in ZINCIRLER:
        sk = sirket_sec(rng)
    on, alan = sk["on"], sk["alan"]
    turler, kturler, uzunluk = ZINCIRLER[sk["kod"]]
    adlar = hesap_adlari(rng, 14)
    ad_i = iter(adlar)
    pc_i = iter(rng.sample(range(100, 900), 12))
    sv_i = iter(["dosya01", "sql01", "yedek01", "web01", "rapor01", "baski01"])
    gr_i = iter(rng.sample(["DESTEK-EKIBI", "SUBE-OPERASYON", "DEPO-DESTEK", "SUNUCU-YONETIM", "YEDEK-OPERATORLERI",
                            "BT-STAJ", "RAPOR-KULLANICILARI"], 4))

    def dugum(tur):
        if tur == "u":
            return next(ad_i)
        if tur == "a":
            return "adm." + next(ad_i)
        if tur == "p":
            return f"{on}-pc{next(pc_i)}"
        if tur == "s":
            return f"{on}-{next(sv_i)}"
        return next(gr_i)

    zincir = [dugum(t) for t in turler] + [HEDEF]
    kenarlar = [(zincir[i], kturler[i], zincir[i + 1]) for i in range(len(kturler))]
    bas = zincir[0]
    # daha uzun alternatif: bas -> p2 -> u2 -> zincir[2]
    alt_p, alt_u = f"{on}-pc{next(pc_i)}", next(ad_i)
    kenarlar += [(bas, "CanRDP", alt_p), (alt_p, "HasSession", alt_u), (alt_u, "GenericAll", zincir[2])]
    # ölü uç dallar (Domain Admin'e çıkmaz)
    ayni = f"{on}-pc{next(pc_i)}"
    ol_k = [next(ad_i) for _ in range(3)]
    ol_s = f"{on}-{next(sv_i)}"
    kenarlar += [(bas, "MemberOf", "DOMAIN_USERS"), ("DOMAIN_USERS", "CanRDP", ayni), (ayni, "HasSession", ol_k[0]),
                 (ol_k[0], "MemberOf", "YAZICI-OPERATORLERI"), ("YAZICI-OPERATORLERI", "AdminTo", f"{on}-baski02"),
                 (ol_k[1], "CanRDP", ol_s), (ol_s, "HasSession", ol_k[2]), (ol_k[2], "MemberOf", "RAPOR-OKUYUCULARI"),
                 (bas, "CanRDP", ayni), (HEDEF, "AdminTo", f"{on}-dc01")]
    rng.shuffle(kenarlar)
    yol = en_kisa(kenarlar, bas, HEDEF)
    assert yol == zincir, "en kısa yol zincir olmalı"
    return {
        "vaka": f"{sk['ad']} — yetki grafiği",
        "sirket": sk, "kenarlar": [list(k) for k in kenarlar], "bas": bas, "zincir": zincir,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "alan": alan, "bas": bas, "onek": on},
        "cevaplar": {
            "cikan": sum(1 for a, _, _ in kenarlar if a == bas),
            "uzunluk": len(zincir) - 1,
            "araduganler": zincir[1:-1],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    sk = s["sirket"]
    satirlar = [f"# {sk['ad']} — yetki grafiği (KURGUSAL)",
                f"# Başlangıç: {s['bas']}  (ele geçirildiği varsayılan sıradan kullanıcı)   Hedef: {HEDEF}",
                "# biçim: KAYNAK -[ILISKI]-> HEDEF"]
    satirlar += [f"{a} -[{t}]-> {b}" for a, t, b in s["kenarlar"]]
    u.yaz(lab / "ad/yetki_grafigi.txt", "\n".join(satirlar) + "\n")
    u.yaz(lab / "ad/iliski_turleri.txt",
          "İlişki türleri (özet)\n"
          "MemberOf             kaynak, hedef grubun üyesidir (grubun yetkilerini miras alır)\n"
          "CanRDP               kaynak, hedef bilgisayara uzak masaüstüyle girebilir\n"
          "AdminTo              kaynak, hedef bilgisayarda yerel yöneticidir\n"
          "HasSession           kaynak bilgisayarda hedef hesabın oturumu açıktır (kimlik bilgisi bellekte durabilir)\n"
          "GenericAll           kaynak, hedef nesne üzerinde tam yazma hakkına sahiptir\n"
          "ForceChangePassword  kaynak, hedef hesabın parolasını sıfırlayabilir\n")
    u.yaz(lab / "ad/yetki_grafigi.orijinal", "\n".join(satirlar) + "\n")


def _oku(yol: Path):
    kenar = []
    for ham in yol.read_text(errors="replace").splitlines():
        m = KENAR.match(ham.strip())
        if m:
            kenar.append((m.group(1), m.group(2), m.group(3)))
    return kenar


def _kes_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "ad/yetki_grafigi.txt"
    if not yol.is_file():
        return Sonuc(False, "`ad/yetki_grafigi.txt` dosyası yok. Silme; içinden **bir satırı** çıkar.")
    ilk = {tuple(k) for k in s["kenarlar"]}
    simdi = set(_oku(yol))
    eklenen = simdi - ilk
    if eklenen:
        return Sonuc(False, "Yeni kenar eklemişsin. Bu görevde yalnızca bir satırı silerek yolu kesersin.", yakin=True)
    silinen = ilk - simdi
    if not silinen:
        return Sonuc(False, "Henüz hiçbir kenarı kaldırmadın. Yol hâlâ açık. Bir satırı sil, sonra `cevap <no>` yaz.")
    if len(silinen) > 1:
        return Sonuc(False, f"{len(silinen)} kenar sildin. Tek bir doğru kenar yolu keser; fazla silmek gerçek hayatta "
                            "meşru erişimleri de bozar. Orijinal döküm `ad/yetki_grafigi.orijinal` içinde.", yakin=True)
    kalan = en_kisa(list(simdi), s["bas"], HEDEF)
    k = next(iter(silinen))
    if kalan is not None:
        return Sonuc(False, f"`{k[0]} -[{k[1]}]-> {k[2]}` kenarını kaldırdın ama `{s['bas']}` için hâlâ "
                            f"{len(kalan) - 1} adımlık bir yol var. İki yolun **ortak** kullandığı bir halka aramalısın.", yakin=True)
    return Sonuc(True, f"Doğru: `{k[0]} -[{k[1]}]-> {k[2]}` kenarı kalkınca `{s['bas']}` artık {HEDEF}'e ulaşamıyor.")


def coz(lab: Path, s: dict) -> dict:
    ortak = ("import re;K=[m.groups() for l in open('ad/yetki_grafigi.txt') for m in [re.match(r'^(\\S+) -\\[(\\w+)\\]-> (\\S+)',l)] if m];"
             f"B='{s['bas']}';H='{HEDEF}';"
             "from collections import deque\n"
             "def yol(K):\n g={}\n for a,t,b in K: g.setdefault(a,[]).append(b)\n o={B:None};q=deque([B])\n"
             " while q:\n  x=q.popleft()\n  if x==H:\n   r=[]\n   while x: r.append(x);x=o[x]\n   return r[::-1]\n"
             "  for y in g.get(x,[]):\n   if y not in o: o[y]=x;q.append(y)\n")
    cikan = sh(f"grep -c '^{s['bas']} ' ad/yetki_grafigi.txt", lab)
    uz = py(ortak + "print(len(yol(K))-1)", lab)
    ara = py(ortak + "print(' '.join(yol(K)[1:-1]))", lab)
    # kesen son kenarı bul ve sil
    kes = py(ortak + "p=yol(K);\nfor i in range(len(p)-1):\n a,b=p[i],p[i+1]\n"
             " K2=[k for k in K if not (k[0]==a and k[2]==b)]\n"
             " if yol(K2) is None: print(f'{a} -[' + [k[1] for k in K if k[0]==a and k[2]==b][0] + f']-> {b}'); break\n", lab)
    sh(f"grep -vxF '{kes}' ad/yetki_grafigi.txt > ad/.gecici && mv ad/.gecici ad/yetki_grafigi.txt", lab)
    return sec_doldur({2: cikan, 3: uz, 4: ara, 5: ""}, GOREVLER, lab, s)


def _cikan_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla: başlangıç kullanıcısının kendisine **gelen** bir kenarı ya da yorum satırını saymış olabilirsin; sadece ondan **çıkan** kenarlar."
    return None


def _yol_hata(g, beklenen, b):
    s = b.senaryo
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla. Düğüm sayısını saymış olabilirsin; sorulan **kenar** sayısı (düğüm sayısı - 1)."
    return None


def _ara_hata(g, beklenen, b):
    verilen = set(g.split())
    if HEDEF.lower() in verilen or b.senaryo["bas"].lower() in verilen:
        return "Başlangıç kullanıcısını ve hedefi (`DOMAIN_ADMINS`) yazma; sadece **aradaki** düğümler."
    return None


ADIMLAR = [
    Adim("Haritaya bakmak", """
Bir saldırgan kimlik bilgisini ele geçirince sorduğu soru şudur: "Buradan **Domain Admin'e
giden en kısa yol** nedir?" Bu yol, yanal hareketin (başka makinelere, başka hesaplara atlamanın)
zinciridir: kullanıcı A → bilgisayar B → grup C → Domain Admin.

BloodHound gibi araçlar bu zinciri **grafik** olarak gösterir. Grafik, iki şeyden oluşur:

- **Düğüm:** kullanıcı, bilgisayar ya da grup.
- **Kenar:** iki düğüm arasındaki ilişki ("A, B'nin yerel yöneticisidir").

Bu görevde kenar listesi düz bir metin dosyası. **<<musteri>>**. <<sahne>>
""", komut="cat ad/yetki_grafigi.txt"),
    Adim("İlişki türleri", """
Her kenarın bir türü var. Hepsi saldırganın bir adım atabilmesi anlamına gelir:
""", komut="cat ad/iliski_turleri.txt", sonra="""
`HasSession` özellikle önemlidir: bir bilgisayarda oturumu açık olan hesabın kimlik bilgisi
orada bellekte durabilir. Yönetici hesabı, çok erişilen bir yerde oturum açarsa saldırganın
oraya gelmesi yeterlidir.
"""),
    Adim("Bir düğümden çıkan kenarlar", """
Grafik elle de okunabilir: bir düğümün adını `grep` ile satır başında ara. Başlangıç kullanıcısı
(`<<bas>>`) nereye gidebiliyor?
""", komut="grep '^<<bas>> ' ad/yetki_grafigi.txt", sonra="""
Gördüğün her satır, saldırganın **tek adımda** gidebileceği bir yer. Yeni düğümlerin adını
alıp aynı komutu onlar için tekrarla; yolu böyle adım adım yürürsün.
"""),
    Adim("Yolu yürümek", """
Bir adım ilerle: bir önceki çıktıdaki bir düğümden çıkan kenarlara bak. Örneğin ilk çıktıda
görünen bir bilgisayarın adını `<<onek>>-pc` ile ara. Bir dalın **ölü uç** olduğunu fark
edebilirsin: o dalın sonunda yetkili bir hedef yoktur.
""", komut="grep -c 'HasSession' ad/yetki_grafigi.txt", sonra="""
Dosyada kaç oturum kenarı var? Oturumlar, yanal hareketin en değerli halkalarıdır.
Şimdi görevlere geç: en kısa yolu bulacak, sonra yolu **kesecek** bir kenarı sileceksin.
"""),
    Adim("Savunma: yolu kes", """
Bir yolu kesmenin yolu, o yolun bir **kenarını** gerçek hayatta kaldırmaktır:

- `HasSession`: yönetici hesabının orada oturum açmasını yasakla (tiering) ya da oturumu kapat.
- `AdminTo`: yerel yönetici yetkisini kaldır; LAPS ile her makineye benzersiz parola ver.
- `MemberOf`: gereksiz grup üyeliğini kaldır.
- `GenericAll` / `ForceChangePassword`: nesne üzerindeki gereksiz hakkı sil.

Ama **dikkat**: iki yol ortak bir halkada birleşiyorsa, kısa yolu kesmek yetmez; alternatif
yol devreye girer. Ortak halkayı kesen kenar, ikisini birden kapatır. Gerçek düzeltme budur.
"""),
]

GOREVLER = [
    Gorev("Yetki grafiğinde **düğüm** ve **kenar** ne anlama gelir?",
          Secmeli([
              ("Düğüm bir kullanıcı, bilgisayar ya da grup; kenar yetki ilişkisidir",
               "Doğru. Yol, kenarlarla birbirine bağlanan düğümler dizisidir."),
              ("Düğüm bir ağ kablosudur, kenar ise o kablonun bağlandığı portun numarasıdır",
               "Yanlış. Bu bir ağ topolojisi değil, kimlik ve yetki grafiğidir."),
              ("Düğüm bir parolanın hash değeridir, kenar ise o parolanın kırılma süresidir",
               "Yanlış. Grafik varlıkları ve aralarındaki ilişkileri gösterir; parola süresi değil."),
              ("Düğüm yalnızca Domain Admin'dir, kenarlar ise sıradan kullanıcıların listesidir",
               "Yanlış. Grafikte her türlü varlık düğümdür; Domain Admin sadece hedeflerden biridir."),
          ], dogru=0),
          ("Dosyadaki her satır bir 'ilişki'.",
           "`A -[Tür]-> B` satırı: A ve B nedir?",
           "Varlıklar düğüm, aralarındaki yetki ilişkisi kenar."),
          puan=20, baslik="Düğüm ve kenar"),
    Gorev("Başlangıç kullanıcısı `<<bas>>`'dan **çıkan** doğrudan kaç kenar var?",
          Sayi("cikan", sik_hatalar=_cikan_hata),
          ("Sadece satırın **başındaki** ad `<<bas>>` olanları say.",
           "`grep '^<<bas>> ' ad/yetki_grafigi.txt` o kullanıcıdan çıkan kenarları verir.",
           "`grep -c '^<<bas>> ' ad/yetki_grafigi.txt`"),
          puan=20, baslik="Çıkan kenar sayısı"),
    Gorev("`<<bas>>`'dan `DOMAIN_ADMINS`'a giden **en kısa** yol kaç **adım** (kenar) uzunluğunda?",
          Sayi("uzunluk", sik_hatalar=_yol_hata),
          ("Bir alternatif yol da var ama daha uzun. Hangisi en kısa?",
           "Çıkan kenarlardan başlayıp her düğümün kenarlarını `grep '^DÜĞÜM '` ile izle; ölü uçları ele.",
           "Adım sayısı = yoldaki düğüm sayısı - 1 (başlangıç ve hedef dahil düğümleri say)."),
          puan=40, baslik="En kısa yol"),
    Gorev("En kısa yolun **ara düğümlerini** yaz (başlangıç kullanıcısı ve `DOMAIN_ADMINS` hariç).",
          Kume("araduganler", sik_hatalar=_ara_hata, bicim="düğüm adları, virgülle ayrılmış"),
          ("Önceki görevde yürüdüğün yoldaki düğümler.",
           "Alternatif (daha uzun) yolun düğümlerini değil, **en kısa** yolu kullan.",
           "Başlangıçtan DOMAIN_ADMINS'a ilerlerken her adımda geçtiğin düğümleri yaz."),
          puan=40, baslik="Yoldaki düğümler"),
    Gorev("`ad/yetki_grafigi.txt` dosyasından **tek bir kenarı (satırı) sil** öyle ki `<<bas>>` artık "
          "`DOMAIN_ADMINS`'a **hiçbir yoldan** ulaşamasın. Bitince `cevap 5` yaz. (Orijinal: "
          "`ad/yetki_grafigi.orijinal`.)",
          Durum(_kes_kontrol, "En kısa yoldaki, alternatif yolla ortak olan bir kenarı (örn. son halkalardan birini) sil"),
          ("Kısa yolu kesmek yetmeyebilir: alternatif bir yol da var. İkisinin ortak halkası nerede?",
           "Alternatif yol, kısa yolun ortasındaki bir düğüme bağlanıyor; o düğümden **sonraki** kenarlar ortaktır.",
           "`grep -vxF 'KAYNAK -[TUR]-> HEDEF' ad/yetki_grafigi.txt > ad/.t && mv ad/.t ad/yetki_grafigi.txt` bir satırı siler."),
          puan=50, baslik="Yolu kes"),
    Gorev("Gerçek hayatta bir `HasSession` kenarını kaldırmak ne demektir?",
          Secmeli([
              ("Yönetici hesabının orada oturum açmasını engellemek ya da oturumu kapatmak",
               "Doğru. Oturum yoksa bellekte kimlik bilgisi de kalmaz; saldırganın kullanacağı halka yok olur."),
              ("O bilgisayarın tüm kullanıcılarını silmek ve bilgisayarı bir daha hiç domain'e almamak",
               "Yanlış. Fazla ve gereksiz bir önlem; amaç ayrıcalıklı oturumu o yerde bırakmamaktır."),
              ("Windows saatini ileri alarak oturumun otomatik süresinin dolmasını beklemek",
               "Yanlış. Saat ayarı bir savunma değildir; ayrıca Kerberos saat kaymasında sorun çıkarır."),
              ("O bilgisayarın ağ kartını fiziksel olarak sökmek ve sunucu odasına kilitlemek",
               "Yanlış. Aşırı ve pratik değil; iş devam etmeli, sadece ayrıcalıklı oturum olmamalı."),
          ], dogru=0),
          ("`HasSession`: kimin kimlik bilgisi nerede duruyor?",
           "Savunma: ayrıcalıklı hesap düşük katmanda oturum açmamalı.",
           "Tiering ile oturumu yasakla ya da kapat."),
          puan=20, baslik="Oturum kenarı"),
    Gorev("Bir saldırgan **Domain Admin yetkisine** ulaşınca neden 'oyunun sonu' denir?",
          Secmeli([
              ("Her şey kontrol altına girer; güven kırıldığı için temizlik çok zordur",
               "Doğru. Çoğu zaman AD'yi sıfırdan kurmak gerekir; bu yüzden önlem, bu noktaya hiç gelmemektir."),
              ("Çünkü Domain Admin hesabı bulunca saldırganın bilgisayarı otomatik olarak kapanır",
               "Yanlış. Böyle bir mekanizma yok; sorun yetkinin genişliğidir."),
              ("Çünkü Domain Admin yalnızca bir kullanıcı bilgisayarına erişir ve başka bir şey yapamaz",
               "Yanlış. Domain Admin, tüm domain üzerinde tam yetkidir."),
              ("Çünkü bundan sonra DC'ler otomatik olarak güvenlik güncellemesi alır ve saldırıyı siler",
               "Yanlış. Güncellemeler saldırganı temizlemez; kalıcılık (sahte biletler) kurulmuş olabilir."),
          ], dogru=0),
          ("DCSync ve sahte bilet gibi kavramlar bu yetkiyle mümkün olur.",
           "Kalıcılık kurulduysa temizlik nasıl olur?",
           "Tam yetki + kalıcılık = güvenli temizlik çok zor."),
          puan=20, baslik="Domain hakimiyeti"),
]


def _kapanis():
    return """
Saldırgan için bu grafik bir **yol haritasıdır**; savunmacı için bir **yapılacaklar listesi**. En kısa
yolu bulmak kolay, asıl beceri doğru kenarı kesmektir: iki yol aynı halkada birleşiyorsa kısa yolu
kesmek yetmez. Savunma dersi: BloodHound benzeri bir haritayı saldırgandan önce çıkar, kenarları
gerçek düzeltmelere çevir (oturumu kaldır, yerel yöneticiyi daralt, üyeliği çıkar) ve düzeltmeden
sonra haritayı yeniden çıkarıp yolun gerçekten kesildiğini doğrula.
"""


SEVIYE = Seviye(
    kimlik="c11b04",
    cilt=11,
    bolum=4,
    baslik="Yanal Hareket ve Domain Hakimiyeti",
    brifing="""
Mert, ekrana bir grafik dökümü açıyor: "**<<musteri>>** için bir yetki haritası çıkardık. <<sahne>>
Varsayım şu: `<<bas>>` hesabı ele geçirildi. Domain Admin'e giden kaç adımlık bir yol var, ve
hangi tek kenarı kaldırırsak o yol kapanır?"

Selin ekliyor: "Dikkat: yoldan bahsederken yalnızca en kısa olanı değil, alternatiflerini de
düşün. Biz kapıyı kapatırken pencere açık kalırsa işe yaramaz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **BloodHound:** Açık kaynak bir araçtır; AD'deki oturum, üyelik ve yetki ilişkilerini grafik olarak
  gösterir. Hem saldırı hem savunma ekipleri kullanır; savunmacıların amacı "Domain Admin'e kaç
  kolay yol var?" sorusunu saldırgandan önce cevaplamaktır.
- **Domain hakimiyeti:** SolarWinds 2020 gibi büyük olaylarda, kamuya açık raporlara göre saldırganlar
  ağ içinde yetki zincirlerini izleyerek kimlik altyapısına ulaştı. Böyle bir noktadan sonra
  temizlik çoğu zaman AD'nin yeniden kurulmasını gerektirir.
- **Tespit ve önleme:** Ayrıcalıklı hesabın beklenmedik bir bilgisayarda oturum açması (4624) ve
  yönetici gruplarına üye eklenmesi izlenir. Önlemek için katmanlı model, LAPS ve yönetici
  hesaplarının yalnızca ayrılmış "yönetim iş istasyonlarında" kullanılması önerilir.
""",
    sure_hedef_dk=35,
)
