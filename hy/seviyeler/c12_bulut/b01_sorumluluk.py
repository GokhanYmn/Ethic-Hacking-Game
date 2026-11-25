"""Cilt 12 · Bölüm 1 — Paylaşılan Sorumluluk ve Saldırı Yüzeyi.

Beceri: kurgusal bir bulut envanterini ve olay listesini okuyup kimin neden sorumlu olduğunu
eşlemek (sağlayıcı mı, müşteri mi), internete açık kaynakları (saldırı yüzeyini) çıkarmak ve
IaaS/PaaS/SaaS ayrımını yamalama sorumluluğuyla bağlamak.

Vakalar: e-ticaret, hastane, fintech, lojistik, banka. Her envanterde kaynak adları, sayıları ve
olay listeleri farklıdır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c12_bulut.ortak import sec_doldur, sh, sirket_sec

MUSTERI_OLAYLARI = [
    "Herkese açık bırakılmış bir depolama kovasından {veri} indirildi",
    "Koda gömülü erişim anahtarı kod deposuna yüklendi ve başkaları tarafından kullanıldı",
    "Yönetici hesabında çok faktörlü doğrulama kapalıydı; parola ele geçirilince hesap kullanıldı",
    "Sanal makinenin işletim sistemi yamalanmadığı için bilinen bir açık kullanıldı",
    "Güvenlik grubu uzak yönetim portunu tüm internete açık bırakmıştı",
    "Aşırı geniş yetkili bir uygulama kimliği sızınca tüm veriler okundu",
]
SAGLAYICI_OLAYLARI = [
    "Sağlayıcının veri merkezinde elektrik kesintisi nedeniyle bölge bir saat erişilemedi",
    "Sağlayıcının fiziksel disklerinden biri bozuldu ve sağlayıcı tarafından otomatik değiştirildi",
    "Sağlayıcının veri merkezindeki ağ yönlendirme cihazı arızalandı; müşteri hiçbir ayara dokunmadı",
    "Sağlayıcının sanallaştırma katmanındaki bir hata sağlayıcı tarafından giderildi",
]
SAHNE = {
    "pazarix": "Pazarix, kampanya sezonu öncesi buluttaki sistemlerinin kime ait riskleri taşıdığını anlamak istiyor.",
    "medora": "Medora Sağlık, buluta taşıdığı randevu sisteminde 'bu risk bizim mi sağlayıcının mı' diye soruyor.",
    "paramix": "Paramix'in yönetim kurulu, yaşanan kesintinin sorumluluğunu soruyor.",
    "kuzgun": "Kuzgun Lojistik, bulut maliyeti kadar bulut riskini de anlamak istiyor.",
    "ferahbank": "Ferah Bank'ın denetim birimi, paylaşılan sorumluluk modelini belgelemeni bekliyor.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on = sk["on"]
    vm_say = rng.randint(3, 5)
    kaynaklar = []
    for i in range(vm_say):
        kaynaklar.append((f"{on}-{rng.choice(['web', 'api', 'is', 'rapor', 'yedek'])}-vm{i + 1}", "sanal-makine", "IaaS"))
    kaynaklar += [(f"{on}-yonetilen-db", "yonetilen-veritabani", "PaaS"),
                  (f"{on}-{rng.choice(['dosya', 'yedek', 'resim'])}-kovasi", "depolama-kovasi", "PaaS")]
    if rng.random() < 0.5:
        kaynaklar.append((f"{on}-konteyner-platformu", "yonetilen-konteyner", "PaaS"))
    kaynaklar += [(f"{on}-ofis-eposta", "eposta-paketi", "SaaS"), (f"{on}-musteri-crm", "crm-uygulamasi", "SaaS")]
    rng.shuffle(kaynaklar)
    satirlar = []
    for i, (ad, tur, model) in enumerate(kaynaklar, 1):
        internet = "evet" if (model == "SaaS" or rng.random() < 0.4) else "hayir"
        satirlar.append((f"r-{i:02d}", ad, tur, model, internet))
    if not any(x[4] == "evet" for x in satirlar if x[3] != "SaaS"):
        a = satirlar[0]
        satirlar[0] = (a[0], a[1], a[2], a[3], "evet")
    musteri_n = rng.randint(3, 4)
    secilen = ([(m.format(veri=sk["veri"]), True) for m in rng.sample(MUSTERI_OLAYLARI, musteri_n)]
               + [(m, False) for m in rng.sample(SAGLAYICI_OLAYLARI, rng.randint(3, 4))])
    rng.shuffle(secilen)
    no0 = rng.randint(100, 400)
    olaylar = [(f"O-{no0 + i}", m, sorumlu_musteri) for i, (m, sorumlu_musteri) in enumerate(secilen)]
    return {
        "vaka": f"{sk['ad']} — bulut sorumluluk dökümü",
        "sirket": sk, "kaynaklar": satirlar, "olaylar": olaylar,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "veri": sk["veri"]},
        "cevaplar": {
            "musteri_olay": [o[0] for o in olaylar if o[2]],
            "iaas_sayi": sum(1 for x in satirlar if x[3] == "IaaS"),
            "acik": [x[0] for x in satirlar if x[4] == "evet"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "bulut/envanter.csv", "id,ad,tur,hizmet_modeli,internetten_erisim\n" +
          "".join(",".join(r) + "\n" for r in s["kaynaklar"]))
    u.yaz(lab / "bulut/olaylar.txt",
          f"# {s['sirket']['ad']} — son bir yılın bulut olayları (KURGUSAL)\n# KİMLİK | NE OLDU\n" +
          "".join(f"{i} | {m}\n" for i, m, _ in s["olaylar"]))
    u.yaz(lab / "bulut/OKU.txt",
          "Paylaşılan sorumluluk modeli:\n"
          "- Sağlayıcı bulutun KENDİSİNDEN sorumludur (fiziksel veri merkezi, donanım, ağ altyapısı, sanallaştırma).\n"
          "- Müşteri bulutun İÇİNDEKİLERDEN sorumludur (yapılandırma, veri, erişim/kimlik).\n"
          "- IaaS'ta işletim sistemi yamaları müşteridedir; PaaS'ta sağlayıcıda; SaaS'ta uygulamanın tamamı sağlayıcıdadır\n"
          "  (ama kimin hangi veriye eriştiği hâlâ müşteridedir).\n")


def coz(lab: Path, s: dict) -> dict:
    musteri = sh("awk -F' [|] ' '/^O-/ && ($2 ~ /anahtar|Herkese|çok faktörlü|yamalanmadığı|güvenlik grubu|Güvenlik grubu|Aşırı geniş/) "
                 "{print $1}' bulut/olaylar.txt | tr '\\n' ' '", lab)
    return sec_doldur({
        2: musteri,
        3: sh("awk -F, '$4==\"IaaS\" {n++} END {print n}' bulut/envanter.csv", lab),
        4: sh("awk -F, '$5==\"evet\" {print $1}' bulut/envanter.csv | tr '\\n' ' '", lab),
    }, GOREVLER, lab, s)


def _olay_hata(g, beklenen, b):
    verilen = set(g.split())
    saglayici = {o[0].lower() for o in b.senaryo["olaylar"] if not o[2]}
    if verilen & saglayici:
        return "Listende sağlayıcının kendi altyapısındaki bir olay var (elektrik, donanım, ağ cihazı, sanallaştırma). Onlar sağlayıcı sorumluluğudur."
    return None


def _iaas_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    paas = sum(1 for x in b.senaryo["kaynaklar"] if x[3] == "PaaS")
    if n == beklenen + paas:
        return "PaaS kaynaklarını da saymışsın. PaaS'ta işletim sistemini sağlayıcı yamalar; müşteri yalnızca IaaS sanal makinelerinde yamalar."
    return None


ADIMLAR = [
    Adim("Kim neyden sorumlu?", """
Bulutu anlamanın anahtarı, **kimin neyden sorumlu olduğunu** bilmektir. Buna **paylaşılan sorumluluk
modeli** denir:

- **Sağlayıcı** bulutun *kendisinden* sorumludur: fiziksel veri merkezi, donanım, ağ altyapısı,
  sanallaştırma katmanı.
- **Müşteri** bulutun *içindekinden* sorumludur: yapılandırma, veri ve erişim (kimlikler).

**<<musteri>>**. <<sahne>> Önce müşterinin buradaki özet kuralı:
""", komut="cat bulut/OKU.txt", sonra="""
İhlallerin ezici çoğunluğu **müşteri tarafındaki hatalardan** (yanlış yapılandırma, aşırı yetki,
sızmış anahtar) çıkar; sağlayıcının altyapısı genelde sağlamdır. Yani "bulut güvenli mi?" sorusunun
cevabı çoğu zaman "sen nasıl yapılandırdın?"dır.
"""),
    Adim("IaaS, PaaS, SaaS", """
Hizmet modeli, sorumluluğun nerede bölündüğünü değiştirir:

- **IaaS** (sanal makine kiralamak): işletim sistemi, yamalar ve üstündeki her şey müşteride.
- **PaaS** (yönetilen veritabanı, yönetilen konteyner): işletim sistemini sağlayıcı yönetir.
- **SaaS** (hazır e-posta, CRM): uygulamanın kendisi sağlayıcıda; ama hesaplar ve veri müşteride.

Envantere bak; `hizmet_modeli` sütununa dikkat et:
""", komut="cat bulut/envanter.csv"),
    Adim("Modele göre say", """
`awk -F,` virgülle ayrılmış dosyada sütun ayırır. Dördüncü sütun hizmet modeli. Kaç kaynak hangi
modelde?
""", komut="awk -F, 'NR>1 {print $4}' bulut/envanter.csv | sort | uniq -c", sonra="""
Yamalama yükü **IaaS satırlarında** müşteridedir; bu satırlar genellikle en çok iş çıkaran
satırlardır.
"""),
    Adim("Saldırı yüzeyi: neye internetten dokunulabiliyor?", """
Bulutta saldırı yüzeyinin beş ana alanı: **kimlik ve erişim (IAM)**, **depolama**, **ağ**,
**hesaplama** (metadata servisi dahil) ve **sırlar** (koda gömülü anahtarlar). Envanterde son
sütun, kaynağın internetten erişilebilir olup olmadığını söyler:
""", komut="awk -F, '$5==\"evet\" {print $1, $2}' bulut/envanter.csv", sonra="""
İnternetten erişilebilen her kaynak saldırgan için bir deneme noktasıdır. SaaS satırları
doğal olarak internetten erişilebilir; asıl dikkat, **olmaması gereken** yerde `evet` görmektir
(örneğin bir yönetilen veritabanı).
"""),
    Adim("Olaylar: kimin hatası?", """
Her olayın bir sorumlusu vardır ve bu, düzeltmenin kimde olduğunu belirler. Olay listesini oku;
kendine şunu sor: "Bunu **ben** önleyebilir miydim?"
""", komut="cat bulut/olaylar.txt", sonra="""
**Hacker gözüyle:** Cilt 6'daki yetki yükseltme, çoğu zaman var olan yanlış yapılandırmayı bulmaktı.
Bulutta bu daha da doğrudur: saldırgan sağlayıcının donanımını değil, senin açık bıraktığın ayarı
arar. Savunma tarafında ders: bulut güvenliği büyük ölçüde **doğru yapılandırma ve sürekli denetim**
işidir.
"""),
]

GOREVLER = [
    Gorev("Paylaşılan sorumluluk modelini doğru anlatan cümle hangisi?",
          Secmeli([
              ("Sağlayıcı bulutun kendisinden, müşteri içindeki yapılandırma ve verilerden sorumludur",
               "Doğru. Ayarları ve verileri müşteri kontrol ettiği için bu alanlardaki hatalar müşteriye aittir."),
              ("Bulutta güvenliğin tamamı sağlayıcıya aittir; müşteri yalnızca faturayı öder",
               "Yanlış. Müşteri hâlâ kendi yapılandırmasından, kimliklerinden ve verisinden sorumludur."),
              ("Müşteri bulutun fiziksel veri merkezini güvenceye almakla yükümlüdür; yazılım sağlayıcıdadır",
               "Yanlış. Fiziksel altyapı sağlayıcının sorumluluğundadır."),
              ("Sorumluluk yalnızca ücretsiz hesaplarda paylaşılır; ücretli hesapta hepsi müşteridedir",
               "Yanlış. Model ücret düzeyine değil, hizmet türüne (IaaS/PaaS/SaaS) göre değişir."),
          ], dogru=0),
          ("Bulutun 'kendisi' ile 'içindekiler' ayrımını düşün.",
           "Fiziksel sunucu kimin? Ayarlar ve veri kimin?",
           "Sağlayıcı = altyapı; müşteri = yapılandırma, veri, erişim."),
          puan=20, baslik="Paylaşılan sorumluluk"),
    Gorev("`bulut/olaylar.txt` içindeki olaylardan hangilerinin **sorumlusu müşteridir**? Olay kimliklerini yaz.",
          Kume("musteri_olay", sik_hatalar=_olay_hata, bicim="olay kimlikleri, virgülle ayrılmış"),
          ("Her olayı 'bunu müşteri önleyebilir miydi?' sorusuyla sına.",
           "Yapılandırma, anahtar, MFA, yama, aşırı yetki müşteridir; elektrik, donanım, ağ cihazı, sanallaştırma katmanı sağlayıcıdır.",
           "Müşteri olaylarının kimliklerini (O-xxx) boşlukla ya da virgülle yaz."),
          puan=40, baslik="Müşteri sorumluluğu"),
    Gorev("`envanter.csv` içinde işletim sistemi yamalarını **müşterinin kendisinin** uygulaması gereken "
          "(IaaS) kaç kaynak var?",
          Sayi("iaas_sayi", sik_hatalar=_iaas_hata),
          ("Hangi hizmet modelinde işletim sistemi müşteridedir?",
           "IaaS satırlarını say; PaaS ve SaaS'ı sayma.",
           "`awk -F, '$4==\"IaaS\" {n++} END {print n}' bulut/envanter.csv`"),
          puan=30, baslik="IaaS kaynakları"),
    Gorev("İnternetten erişilebilir (`internetten_erisim=evet`) kaynakların kimliklerini yaz.",
          Kume("acik", bicim="kaynak kimlikleri, virgülle ayrılmış"),
          ("Son sütuna bak.",
           "Değeri `evet` olan satırların ilk sütunu.",
           "`awk -F, '$5==\"evet\" {print $1}' bulut/envanter.csv`"),
          puan=30, baslik="Saldırı yüzeyi"),
    Gorev("Bulut ihlallerinin çoğu neden 'hack' değil de 'yanlış yapılandırma' olarak anılır?",
          Secmeli([
              ("Altyapı genelde güvenlidir; ihlaller müşterinin açık bıraktığı kaynaktan doğar",
               "Doğru. Saldırgan çoğu zaman bir ayarın açık bırakılmasını bulur, bir kodu kırmaz."),
              ("Çünkü bulutta kimse saldırgan değildir ve her olay kullanıcı hatasıyla başlar",
               "Yanlış. Saldırganlar vardır; ama onların işini kolaylaştıran çoğu zaman yapılandırma hatalarıdır."),
              ("Çünkü bulut sağlayıcıları bütün olayları kamuoyuna 'yanlış yapılandırma' diye bildirmek zorundadır",
               "Yanlış. Böyle bir kural yok; ifade, olayların gerçek nedeninin istatistiğidir."),
              ("Çünkü yanlış yapılandırma yalnızca eski yazılımlarda görülür ve güncel bulutta hiç yaşanmaz",
               "Yanlış. Yanlış yapılandırma, güncel bulutta da en yaygın nedendir."),
          ], dogru=0),
          ("Olay listesindeki müşteri kaynaklı nedenlere bak.",
           "Ayar ve yetki kimde?",
           "Altyapı sağlam; sorun yapılandırmada."),
          puan=20, baslik="Yanlış yapılandırma"),
    Gorev("`koda gömülü API anahtarı` bulgusu, bulutun beş saldırı yüzeyi alanından hangisine girer?",
          Secmeli([
              ("Sırlar", "Doğru. Parola, anahtar ve token gibi gizli bilgilerin yanlış yerde durması 'sırlar' alanıdır."),
              ("Ağ", "Yanlış. Ağ alanı güvenlik grupları, açık portlar ve yönetim erişimidir."),
              ("Depolama", "Yanlış. Depolama alanı kovalar, diskler ve içlerindeki verinin erişim ayarıdır."),
              ("Hesaplama", "Yanlış. Hesaplama alanı sanal makineler, konteynerler ve metadata servisidir."),
          ], dogru=0),
          ("Alanlar: IAM, depolama, ağ, hesaplama, sırlar.",
           "Anahtar bir tür gizli bilgi.",
           "Gizli bilgi = sır."),
          puan=20, baslik="Alan eşleme"),
    Gorev("Cilt 6'daki yetki yükseltme felsefesi buluta nasıl taşınır?",
          Secmeli([
              ("İkisinde de asıl iş var olan yanlış yapılandırmayı bulmaktır; bulutta bu daha da baskındır",
               "Doğru. Bulutta yetki yükseltme çoğu zaman IAM ve kaynak ayarlarındaki bir boşluğu bulmaktır."),
              ("Bulutta yetki yükseltme yalnızca fiziksel olarak veri merkezine girerek yapılabilir",
               "Yanlış. Bulutta her şey kimlik ve yapılandırmadır, fiziksel erişim gerekmez."),
              ("Bulutta yetki yükseltme yoktur çünkü sağlayıcı tüm yetkileri otomatik olarak dengeler",
               "Yanlış. Yetkiyi müşteri tanımlar ve yanlış tanımlanan yetki yükseltmeye kapı açar."),
              ("Felsefe değişir: bulutta saldırganlar yapılandırmaya değil yalnızca yazılım açıklarına bakar",
               "Yanlış. Tersine, bulutta yapılandırma ve kimlik daha çok hedeftir."),
          ], dogru=0),
          ("Cilt 6'da yetki yükseltmenin ne olduğunu hatırla.",
           "Sızma = çoğu zaman yanlış yapılandırma bulmak.",
           "Bulutta aynı mantık, daha büyük ölçekte."),
          puan=20, baslik="Felsefe taşınıyor"),
]


def _kapanis():
    return """
Bulutta güvenlik sorusu önce "kimin sorumluluğunda?" diye sorulur. Saldırgan sağlayıcının donanımını
değil, **senin tarafındaki** açık kapıyı arar: internete açık kaynak, aşırı yetkili kimlik, koda
gömülü anahtar. Savunma dersi: envanteri çıkar, hangi kaynağın hangi hizmet modelinde olduğunu bil,
internete açık olanları gerekçelendir ve yanlış yapılandırmayı otomatik tarayıcılarla (CSPM) sürekli
denetle. İyi bir olay raporu, "bu bizim mi sağlayıcının mı?" sorusunu ilk sayfada cevaplar.
"""


SEVIYE = Seviye(
    kimlik="c12b01",
    cilt=12,
    bolum=1,
    baslik="Paylaşılan Sorumluluk ve Saldırı Yüzeyi",
    brifing="""
Selin yeni bir buluta taşınma dosyası açıyor: "**<<musteri>>**. <<sahne>> Elimizde bulut envanteri ve
son yılın olay listesi var. Yönetime iki şey söylemeliyiz: hangi riskler **bizim** sorumluluğumuzda,
ve internetten neye dokunulabiliyor?"

Mert ekliyor: "Sağlayıcının elektriği kesildiyse onun sorunu. Ama açık bıraktığımız kova bizim."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Paylaşılan sorumluluk:** AWS, Azure ve Google Cloud gibi büyük sağlayıcılar kendi belgelerinde
  bu modeli açıkça tarif eder: sağlayıcı "bulutun güvenliğinden", müşteri "bulutun içindeki
  güvenlikten" sorumludur. Pek çok bulut olay raporunda kök neden, müşteri tarafındaki yanlış
  yapılandırmadır.
- **Capital One 2019:** Kamuya açıklanan bilgilere göre, internete açık bir uygulamadaki yapılandırma
  zafiyeti ve aşırı geniş yetkili bir rol, buluttaki verilere erişime yol açtı. Bu olay, sorumluluğun
  müşteri tarafındaki kısmının ne kadar kritik olduğunu gösteren bir örnek olarak anılır.
- **Tespit ve önleme:** Bulut yapılandırma tarayıcıları (CSPM) internete açık kaynakları, herkese açık
  depolamayı ve aşırı yetkili rolleri düzenli arar; sağlayıcıların yerel güvenlik hizmetleri de
  benzer uyarılar verir. Envanter yoksa denetim de yoktur.
""",
    sure_hedef_dk=25,
)
