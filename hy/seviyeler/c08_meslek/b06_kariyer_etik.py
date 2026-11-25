"""Cilt 8 · Bölüm 6 — Kariyer, Etik ve Sürekli Öğrenme.

Beceri: güvenlik alanındaki rolleri tanımak, beş gerçekçi etik ikilemde doğru davranışı seçmek (kapsam dışı
sistem, arkadaşın isteği, bulguyu gizletme baskısı, gerçek veriyle karşılaşma, sorumlu bildirim), "teknik beceri
nötrdür" ilkesini kavramak ve kişisel bir etik taahhüt dosyası yazmak (izin, sorumlu bildirim, veri koruma, zarar vermeme).

Vakalar: banka, dijital cüzdan, e-ticaret, hastane. İkilemlerin hikâyesi her vakada farklıdır;
doğru davranış ilkesi aynıdır. Hiçbir saldırı içeriği yoktur.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

VAKALAR = {
    "ferah": {
        "ad": "Ferah Bank", "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)", "sistem": "SWIFT mesajlaşma sunucusu",
        "yan": "kart ortağı", "veri": "kredi kartı başvuru kayıtları", "bulgu": "transfer limitinin istemcide kontrol edilmesi",
        "eski": "eski işvereni olan bir ödeme kuruluşunun sitesi", "kapsam_disi": "kampanya sitesi",
    },
    "paramix": {
        "ad": "Paramix", "kisi": "Ece Hanım (CTO)", "sistem": "kurumsal müşteri portalı",
        "yan": "banka ortağı", "veri": "cüzdan sahiplerinin kimlik fotokopileri", "bulgu": "cüzdan bakiyesinde yarış durumu",
        "eski": "eski işvereni olan bir fintech şirketinin API'si", "kapsam_disi": "deneme ortamı",
    },
    "pazarix": {
        "ad": "Pazarix", "kisi": "Tuncay Bey (sistem yöneticisi)", "sistem": "iş ortağı lojistik paneli",
        "yan": "kargo ortağı", "veri": "müşteri adresleri ve telefonları", "bulgu": "kupon kodunun tekrar kullanılabilmesi",
        "eski": "eski işvereni olan bir e-ticaret sitesinin yönetim paneli", "kapsam_disi": "eski test ortamı",
    },
    "medora": {
        "ad": "Medora Sağlık", "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)", "sistem": "görüntü arşivi sunucusu",
        "yan": "laboratuvar ortağı", "veri": "hastaların tahlil sonuçları", "bulgu": "hasta portalında randevu numarasından başkasının randevusunun görünmesi",
        "eski": "eski işvereni olan bir özel kliniğin randevu sitesi", "kapsam_disi": "personel intranet sitesi",
    },
}
ROLLER = ["Sızma testçisi (pentester)", "Kırmızı takım operatörü", "SOC analisti", "Olay müdahale uzmanı", "Güvenlik mühendisi",
          "Uygulama güvenliği uzmanı (AppSec)", "Zafiyet araştırmacısı", "Muhasebe müdürü", "Grafik tasarımcı", "Satın alma uzmanı"]
GUVENLIK_ROLLERI = ROLLER[:7]


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    karisik = list(ROLLER)
    rng.shuffle(karisik)
    return {
        "vaka": f"{v['ad']} — etik ikilemler", "v": v, "karisik": karisik,
        "metin": {"musteri": v["ad"], "kisi": v["kisi"], "sistem": v["sistem"], "yan": v["yan"], "veri": v["veri"],
                  "bulgu": v["bulgu"], "eski": v["eski"], "kapsam_disi": v["kapsam_disi"]},
        "cevaplar": {"roller": [i for i, r in enumerate(karisik, 1) if r in GUVENLIK_ROLLERI]},
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "roller.txt", "Aşağıdaki mesleklerin hepsi güvenlik alanı değildir:\n" + "".join(
        f"{i}. {r}\n" for i, r in enumerate(s["karisik"], 1)))
    u.yaz(lab / "ilke_sablonu.md",
          "# Etik taahhüdüm (bunu kopyalayıp doldur: ilkelerim.md)\n"
          "İzin: <yalnızca neye izin verildiğinde çalışacağım>\n"
          "Bildirim: <bulduğum açığı kime, nasıl bildireceğim>\n"
          "Veri: <eriştiğim veriyi nasıl koruyacağım>\n"
          "Zarar: <zarar vermemek için neyi yapmayacağım>\n"
          "Öğrenme: <bu yolculuğu nasıl sürdüreceğim>\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['vaka']}\n\nroller.txt         karışık meslek listesi\nilke_sablonu.md    etik taahhüt şablonu\n"
          "ilkelerim.md       SENİN yazacağın dosya (görev 7)\n\nGörevlerdeki ikilemler birbirinden bağımsız küçük sahnelerdir.\n")


def _ilkeler(b) -> Sonuc:
    yol = b.lab / "ilkelerim.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `ilkelerim.md` yok. `cp ilke_sablonu.md ilkelerim.md` ile başla.")
    t = yol.read_text(encoding="utf-8", errors="replace")
    a = o.alan_oku(t, ["İzin", "Bildirim", "Veri", "Zarar", "Öğrenme"])
    eksik = [ad for ad in ("izin", "bildirim", "veri", "zarar", "ogrenme") if ad not in a]
    if eksik:
        return Sonuc(False, "Şu bölümler eksik: " + ", ".join(eksik) + ". Her biri `Başlık: cümle` biçiminde olmalı.", yakin=True)
    for ad, deger in a.items():
        if deger.startswith("<") or len(deger.split()) < 4:
            return Sonuc(False, f"`{ad}` bölümü boş ya da çok kısa. Kendi cümlelerinle en az dört kelimelik bir taahhüt yaz.", yakin=True)
    kontrol = [("izin", ("izin", "yetki", "kapsam")), ("bildirim", ("bildir", "sorumlu", "ilet")),
               ("veri", ("koru", "gizli", "paylaşma", "paylasma", "sakla")), ("zarar", ("zarar", "hasar", "bozma"))]
    for ad, anahtar in kontrol:
        if not any(x in o.ascii_norm(a[ad]) or x in a[ad].casefold() for x in anahtar):
            return Sonuc(False, f"`{ad}` bölümün konuyla ilgili görünmüyor. ({', '.join(anahtar)} gibi kavramlardan birini içermeli.)", yakin=True)
    return Sonuc(True, "Etik taahhüdün tamam: izin, sorumlu bildirim, veri koruma, zarar vermeme ve sürekli öğrenme bir arada. Bunu duvarına as.")


def coz(lab: Path, s: dict) -> dict:
    roller = o.sh("grep -E 'Sızma|Kırmızı|SOC|Olay|Güvenlik|Uygulama|Zafiyet' roller.txt | cut -d. -f1 | tr '\\n' ' '", lab)
    (lab / "ilkelerim.md").write_text(
        "# Etik taahhüdüm\nİzin: Yalnızca yazılı izin ve açık kapsam olan sistemlerde çalışacağım.\n"
        "Bildirim: Bulduğum açığı sorumlu biçimde, ilgili güvenlik ekibine ileteceğim.\n"
        "Veri: Eriştiğim veriyi koruyacağım, kimseyle paylaşmayacağım ve gereğinden fazlasını saklamayacağım.\n"
        "Zarar: Hiçbir sisteme ya da kişiye zarar vermeyeceğim ve hizmeti bozmayacağım.\n"
        "Öğrenme: Her ay bir CTF çözüp bir writeup yazarak öğrenmeye devam edeceğim.\n", encoding="utf-8")
    cozum = {1: roller, 2: "", 3: "", 4: "", 5: "", 6: "", 7: "", 8: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Güvenlik tek meslek değil", """
Güvenlik bir **alanlar yelpazesidir**: sızma testçisi, kırmızı takım operatörü, SOC analisti, olay müdahale
uzmanı, güvenlik mühendisi, uygulama güvenliği uzmanı (AppSec), zafiyet araştırmacısı. Yazılımcı geçmişi,
özellikle AppSec ve araç geliştirme için büyük bir avantajdır. Meslekler listesine bak:
""", komut="cat roller.txt"),
    Adim("Rolleri ayırt et", """
Listede güvenlik alanı olmayan meslekler de var; bunları ayıklamak bir sonraki görevin işi. Bir ipucu:
`grep -E` birden çok kelimeyi `|` ile aynı anda arar. Yedi güvenlik rolünün anahtar kelimeleriyle deneyelim:
""", komut="grep -E 'Sızma|Kırmızı|SOC|Olay|Güvenlik|Uygulama|Zafiyet' roller.txt | head -4", sonra="""
Gördüğün satırlar güvenlik rolü; hepsini görmek için `| head -4`'ü kaldır. Bu bilgi sana yalnızca "kimin ne yaptığını"
söylemez, hangi rolün hangi yetkinliği (sızma, tespit, müdahale, geliştirme) kullandığını da gösterir.
"""),
    Adim("Sürekli öğrenme", """
Güvenlik durmayan bir alandır: bugün öğrendiğin bir teknik bir yıl sonra değişebilir. Bu yüzden en önemli
beceri öğrenmeyi sürdürmektir: güvenlik haberleri ve CVE duyuruları, araştırmacıların blogları, konferans
konuşmaları (DEF CON ve Black Hat kayıtları ücretsiz izlenebilir), düzenli pratik platformları ve bir topluluk.
""", komut=None),
    Adim("Etik: söz vermek", """
Kitaba etikle başladık, etikle bitiriyoruz. Etik hacker olmak bir **söz vermektir**: becerini yalnızca
**izinli, iyi niyetli ve yapıcı** amaçlarla kullanmak; bulduğun açığı sahibine **sorumlulukla bildirmek**;
eriştiğin **veriyi korumak**; ve **zarar vermemek**. Bir sonraki görevlerde bu sözü zor sahnelerde sınayacaksın.
Taahhüt şablonuna bak:
""", komut="cat ilke_sablonu.md", sonra="""
**Hacker gözüyle:** Teknik beceri etik değildir; **nötrdür**. Aynı bilgi bir şirketi korumak için de bir
hastanenin kayıtlarını çalmak için de kullanılabilir. Seni etik hacker yapan, bildiğin teknikler değil, onları nasıl
kullandığındır: **izin ve niyet**.
"""),
    Adim("İkilemlerde nasıl düşünürsün?", """
Zor bir durumda sırayla şu sorulara bak: **1)** Bu sisteme dokunma iznim var mı, ve bu işlem iznin içinde mi?
**2)** Zarar verme ihtimali var mı? **3)** Veriyle karşılaştıysam ne kadarına dokunmam gerekiyor (azı yeter)?
**4)** Bulguyu kime, nasıl, hangi sırayla bildireceğim? Cevaplar çoğu zaman netleşir. Aşağıdaki görevlerde bu dört
soruyu uygula.
""", komut=None),
]

GOREVLER = [
    Gorev("`roller.txt` içindeki karışık meslek listesinden **güvenlik alanı rolü** olanların numaralarını yaz "
          "(örn. `1 3 4`). Listede güvenlik alanı olmayan meslekler de var.",
          Kume("roller", tur="sayi", bicim="rol numaraları (örn. 1 3 4 5)",
               sik_hatalar=lambda g, b, bg: "Yedi güvenlik rolü var; muhasebe, tasarım ve satın alma güvenlik alanı değildir."),
          ("Kitabın rollerini hatırla: pentester, kırmızı takım, SOC, olay müdahale, güvenlik mühendisi, AppSec, zafiyet araştırmacısı.",
           "Listede tanıdığın bu yedi rolün satır numaralarını yaz; diğer mesleklere (muhasebe, tasarım, satın alma) dokunma.",
           "`grep -E 'Sızma|Kırmızı|SOC|Olay|Güvenlik|Uygulama|Zafiyet' roller.txt` bu yedi satırı gösterir; numaralarını al."),
          puan=30, baslik="Güvenlik rolleri"),
    Gorev("**İkilem 1 — kapsam dışı:** <<musteri>> için yaptığın testte, kapsamda olmayan **<<sistem>>** üzerinde "
          "herkese açık, çok sayıda gerçek müşteriye ait kayıt (<<veri>>) gördün. Ne yaparsın?",
          Secmeli([
              ("Durur, veriyi indirmez, hemen müşteriye bildirir ve yazılı onay beklerim", "Doğru: kapsam dışına çıkmadan, veriyi toplamadan, hemen bildirirsin. Kapsam genişletmek ancak yazılı izinle olur."),
              ("Kayıtları yedeklerim, çünkü bulgu raporuna eklenirse rapor çok daha ikna edici olur", "Yanlış: kapsam dışı sistemden gerçek veri almak izinsiz erişimdir ve ek bir veri ihlali yaratır."),
              ("Sistemi test etmeye devam ederim, çünkü müşteri bunu zaten sonunda öğrenecek", "Yanlış: kapsam dışı sistemde test, sözleşme ve hukuk ihlalidir; 'zaten öğrenecek' gerekçe değildir."),
              ("Bir şey görmemiş gibi davranır, rapora hiç yazmam; böylece sorun çıkmaz", "Yanlış: gizlemek müşteriyi riskte bırakır ve güveni bitirir; doğru yol şeffaf ve hızlı bildirimdir."),
          ], dogru=0),
          ("Bu sistem sözleşmede var mı? Veriye ne kadar dokunman gerekir?",
           "Kapsam dışına çıkmak, genel bir izin olsa bile izinsiz erişimdir. Önce dur.",
           "Doğru şık: durmak, indirmemek, hemen bildirmek, yazılı onay beklemek."),
          puan=30, baslik="Kapsam dışı kayıtlar"),
    Gorev("**İkilem 2 — arkadaşın isteği:** Bir arkadaşın, **<<eski>>** için \"sadece merak, zarar vermeden bir bak\" "
          "diyor; yazılı bir iznin yok. Ne yaparsın?",
          Secmeli([
              ("Yazılı izin yoksa reddederim; merak ya da iyi niyet, izin yerine geçmez", "Doğru: izin yalnızca sistem sahibinden alınır ve yazılı olur. İyi niyet suçu ortadan kaldırmaz."),
              ("Kısa bir tarama yapar, bir şey bulmazsam kimseye söylemem", "Yanlış: tarama da izinsiz erişim girişimidir; bir şey bulmamak izin eksikliğini düzeltmez."),
              ("Eski çalışma arkadaşlarıma sorar, onların gayriresmî onayına güvenirim", "Yanlış: kurumu temsil etmeyen kişilerin sözlü onayı yetki değildir."),
              ("Sadece bir kez ve sadece bir saat bakarım, saati geçersem durur ve unuturum", "Yanlış: süre ya da miktar iznin yerine geçmez; ilk adım bile izinsizdir."),
          ], dogru=0),
          ("İzin kimden ve hangi biçimde alınır?",
           "Kitabın etik bölümünde 'izin' kelimesinin yanındaki sıfatı hatırla: yazılı.",
           "Doğru şık, yazılı izin yoksa reddetmek."),
          puan=30, baslik="Arkadaşın isteği"),
    Gorev("**İkilem 3 — bulguyu gizleme baskısı:** <<musteri>> yenileme sözleşmesi öncesinde, bulduğun kritik bulguyu "
          "(<<bulgu>>) rapordan çıkarmanı istiyor. Ne yaparsın?",
          Secmeli([
              ("Bulguyu raporda tutarım; etkisini ve çözümünü net anlatırım", "Doğru: gerçek riski gizlemek müşteriyi korumaz, sana da zarar verir. Bulgu, önem ve çözümle birlikte rapor edilir."),
              ("Bulguyu rapordan çıkarır ama ayrı bir e-postayla yalnızca teknik ekibe haber veririm", "Yanlış: rapor resmî kayıttır; kritik bir bulguyu resmî kayıttan çıkarmak yanıltıcıdır."),
              ("Önem derecesini 'düşük'e çekerim ki müşteri şikâyet etmesin", "Yanlış: önem derecesi cetvelden gelir; müşteriyi memnun etmek için değiştirilemez."),
              ("Müşterinin isteğine uyarım, çünkü müşteri her zaman haklıdır", "Yanlış: sözleşmenin amacı riski ortaya koymaktır; gizleme, sorumluluğu sana da yükler."),
          ], dogru=0),
          ("Raporun asıl amacı neydi: müşteriyi memnun etmek mi, riski göstermek mi?",
           "Önem derecesini kim belirler: müşteri mi, cetvel mi?",
           "Doğru şık, bulguyu rapora koymak ve etkisini anlatmak."),
          puan=30, baslik="Bulguyu gizleme baskısı"),
    Gorev("**İkilem 4 — gerçek veri:** Testte kapsam içindeki bir sistemde bir açığı kanıtlamak için <<veri>> bilgilerine "
          "ulaştın. Rapora kanıt koyarken ne yaparsın?",
          Secmeli([
              ("En az veriyi maskeleyerek gösteririm; gerisini indirmem ya da saklamam", "Doğru: kanıt, açığı göstermeye yetecek kadar olmalı; gerçek kişilerin verisi korunmalı ve en aza indirilmeli."),
              ("Tüm kayıtların kopyasını rapora eklerim, itiraz edilemez bir kanıt olur", "Yanlış: gereksiz miktarda gerçek veri toplamak, kendi başına bir ihlal ve risktir."),
              ("Kayıtları kendi bilgisayarımda saklarım, müşteri sonra isterse veririm", "Yanlış: veriyi test bitince elinde tutmak yetkisiz saklamadır; ihtiyaç kadar kullanıp güvenli biçimde silmelisin."),
              ("Kanıt olarak hiç ekran görüntüsü koymam, sadece 'açık var' demek yeterlidir", "Yanlış: kanıtsız bulguya inanılmaz; çözüm kanıtı azaltmak ve maskelemektir, tamamen kaldırmak değil."),
          ], dogru=0),
          ("Kanıtın amacı açığı göstermek mi, veriyi toplamak mı?",
           "En az veri, maskeleme, güvenli saklama ve silme ilkelerini hatırla.",
           "Doğru şık, en az veriyi maskeleyerek göstermek."),
          puan=30, baslik="Gerçek veriyle karşılaşmak"),
    Gorev("**İkilem 5 — sorumlu bildirim:** Bir alışveriş yaparken, hiç tanımadığın bir şirketin sitesinde kendiliğinden "
          "başkasının bilgisini gördün; ortada bir bug bounty programı yok. Ne yaparsın?",
          Secmeli([
              ("Durur, şirketin güvenlik iletişim adresine bildirir, kamuya yazmam", "Doğru: tesadüfen karşılaşılan bir açıkta durmak, istismar etmemek ve şirketin resmî kanalına sorumlu bildirmek doğru yoldur."),
              ("Bilgiyi sosyal medyada paylaşıp şirketi utandırırım, böylece hızlı düzeltir", "Yanlış: kamuya duyurmak gerçek kullanıcıları riske atar ve sorumlu bildirim ilkesine aykırıdır."),
              ("Açığı kullanarak daha fazla kayda ulaşır, bildirimde 'geniş etki' diye anlatırım", "Yanlış: ek erişim istismardır; kanıt için tek bir görünüm yeter ve izinsiz erişim hukuki risk yaratır."),
              ("Hiçbir şey yapmam; çünkü bildirirsem suçlanabileceğimden korkarım", "Yanlış: iyi niyetli ve ölçülü bildirim genellikle korunur; sessiz kalmak ise gerçek insanları açıkta bırakır."),
          ], dogru=0),
          ("Şirketin seni test etmeye davet etmediğini hatırla; yine de ne yapmak sorumluluktur?",
           "Duyuru mu, durup bildirim mi?",
           "Doğru şık, durmak ve resmî güvenlik kanalına sorumlu bildirmek."),
          puan=30, baslik="Sorumlu bildirim"),
    Gorev("**Taahhüdünü yaz:** `ilkelerim.md` dosyasına kendi etik taahhüdünü yaz: `İzin:`, `Bildirim:`, `Veri:`, `Zarar:` "
          "ve `Öğrenme:` bölümleri olsun, her biri kendi cümlelerinle en az dört kelime. Bitince `cevap 7` yaz.",
          Durum(_ilkeler, cozum="`cp ilke_sablonu.md ilkelerim.md` ve beş bölümü doldur: izin, sorumlu bildirim, veri koruma, zarar vermeme, öğrenme."),
          ("Etik hacker olmanın verdiği sözün dört unsurunu hatırla; beşinci olarak öğrenmeyi ekle.",
           "Şablonu kopyalayıp her bölümü kendi cümlenle doldur: hangi koşulda çalışacaksın, neyi bildireceksin, veriyi nasıl koruyacaksın, neyi yapmayacaksın?",
           "`cp ilke_sablonu.md ilkelerim.md && nano ilkelerim.md`; örn. `İzin: Yalnızca yazılı izin ve açık kapsam olan sistemlerde çalışacağım.`"),
          puan=50, baslik="Etik taahhüt"),
    Gorev("Aynı teknik bilgiyle bir şirketi koruyabilir ya da bir kuruma zarar verebilirsin. Seni **etik hacker** yapan nedir?",
          Secmeli([
              ("Teknikler değil, onları nasıl kullandığın: izin ve niyet", "Doğru: teknik beceri nötrdür; etik, iznin ve niyetin sonucudur."),
              ("Hangi araçları kullandığın: bazı araçlar etik, bazıları değildir", "Yanlış: araçlar nötrdür; aynı araç izinli bir testte de izinsiz bir saldırıda da kullanılabilir."),
              ("Aldığın sertifikaların sayısı ve bu sertifikaların prestiji", "Yanlış: sertifika becerini gösterir ama etik duruşunu garanti etmez."),
              ("Çalıştığın şirketin büyüklüğü ve sektördeki ünü", "Yanlış: kurumun büyüklüğü eylemin etik olup olmadığını belirlemez."),
          ], dogru=0),
          ("Kitabın en önemli 'Hacker gözüyle' kutusunu hatırla: teknik beceri ... nedir?",
           "Aynı SQL enjeksiyonu bilgisi hem koruma hem hırsızlık için kullanılabilir. Fark nerede?",
           "Doğru şık 'izin ve niyet' sözcüklerini içeren şık."),
          puan=20, baslik="Neyi belirler"),
]


def _kapanis():
    return """
Bu bölümdeki beş ikilemin ortak noktası, doğru cevabın çoğu zaman **teknik olarak mümkün olandan daha az yapmak**
olması: durmak, indirmemek, bildirmek, gizlememek. Saldırgan bakışıyla bunların her biri bir "fırsat" gibi görünür;
etik hacker için her biri bir **sınırdır**. Bu sınırlar sana engel değil koruma sağlar: iznin ve kayıtların olduğu bir
işte hata yaparsan düzeltirsin, iznin olmadığı bir işte hata yaparsan hesap verirsin. Savunma bakışıyla ders: şirketler,
dışarıdan gelen iyi niyetli bildirimlere kolay ve güvenli bir kanal sunmalı (güvenlik iletişim adresi), aksi hâlde bu
bildirimler hiç yapılmaz ya da yanlış yere gider. Kitap boyunca öğrendiğin her şey, bu söze sadık kaldığın sürece değer
üretir.
"""


SEVIYE = Seviye(
    kimlik="c08b06",
    cilt=8,
    bolum=6,
    baslik="Kariyer, Etik ve Sürekli Öğrenme",
    brifing="""
Son bölümdesin ve Selin bu sefer sana teknik bir iş vermiyor: "Artık bir sistemi haritalayabilir, açıklarını
bulabilir, içine girebilirsin. Bu güç seni ya çok değerli bir profesyonel ya da bir suçlu yapar; fark **iznin ve niyetin**.
<<musteri>>'deki <<kisi>> ile çalışırken karşına çıkabilecek beş zor sahneyi birlikte geçelim."

Mert ciddileşiyor: "İlk üçü neredeyse herkesin başına gelir. Dördüncüsü ve beşincisi çoğu zaman 'kimse bakmıyor' anıdır.
Doğru davranışı o anda seçersin."

Sonunda kendi **etik taahhüdünü** yazacaksın.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Gizlemenin bedeli (Uber):** Uber'in eski güvenlik sorumlusu, şirketin 2016'daki bir veri ihlalini
  saklamak ve saldırganlara bir bug bounty programı üzerinden ödeme yapmakla ilişkili suçlamalardan 2022'de
  mahkûm edildi. Olay, güvenlik uzmanları için bulguyu ya da ihlali gizlemenin hukuki sorumluluk
  doğurabileceğinin en bilinen örneklerinden biridir.
- **Sorumlu açıklama kültürü:** Google Project Zero gibi ekipler, açıkları üreticiye önce bildirip
  düzeltme için belirli bir süre (kamuya bilinen politikalarında 90 gün) tanıyan ve ancak sonra ayrıntıyı
  yayımlayan koordineli açıklama politikaları uygular; bu, kullanıcıları korurken şeffaflığı da sağlar.
- **Tespit ve önleme (kurum tarafı):** Şirketler, dışarıdan gelen bildirimler için bir güvenlik iletişim
  adresi (security.txt) ve yazılı bir açıklama politikası yayımlayarak iyi niyetli araştırmacıları
  güvenli bir kanala yönlendirir; içeride de bulguları saklama baskısını önlemek için raporlama
  hattının yönetimden bağımsız olması ve her bulgunun kayıt altına alınması gerekir.
""",
    sure_hedef_dk=25,
)
