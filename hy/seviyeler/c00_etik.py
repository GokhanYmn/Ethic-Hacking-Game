"""Bölüm 0 — Önce Kurallar: Etik ve Hukuk.

Oyunun kapısı: bu seviye bitmeden hiçbir bölge açılmaz. Oyuncu gerçek bir yetkilendirme
mektubunu okuyup kapsamı çözer ve etik ikilemlerde karar verir.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

YASAK_SISTEMLER = {
    "e-ticaret": "canlı ödeme sunucusu",
    "hastane": "canlı hasta kayıt veritabanı",
    "banka": "çekirdek bankacılık sunucusu",
    "lojistik": "depo otomasyon (robot) kontrol sunucusu",
    "belediye": "e-imza ve tapu entegrasyon sunucusu",
    "fintech": "kart saklama (tokenizasyon) sunucusu",
    "küçük işletme": "kasa (POS) bilgisayarı",
}

SAATLER = [("22:00", "06:00"), ("09:00", "18:00"), ("20:00", "02:00"), ("23:00", "05:00")]


def uret(rng):
    m = musteri_sec(rng)
    ag = rng.choice(["10.20.30", "172.16.40", "192.168.50", "10.8.12"])
    hostlar = rng.sample(range(10, 240), 5)
    kapsam = [f"{ag}.{h}" for h in sorted(hostlar[:3])]
    yasak = f"{ag}.{hostlar[3]}"
    mert_ip = f"{ag}.{hostlar[4]}"
    bas, son = rng.choice(SAATLER)
    baslangic = u.gun(rng)
    bitis = baslangic.replace(day=baslangic.day)  # aynı gün + 4 iş günü aşağıda
    from datetime import timedelta
    eklenen = 0
    while eklenen < 4:
        bitis += timedelta(days=1)
        if bitis.weekday() < 5:
            eklenen += 1
    dahili = rng.randint(2000, 4999)
    kisi = m["kisi"]
    saat_kabul = [f"{bas}-{son}", f"{bas} - {son}", f"{bas.replace(':', '.')}-{son.replace(':', '.')}",
                  f"{bas[:2]}-{son[:2]}", f"{bas} {son}", f"{bas}-{son} arası"]
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — yetkilendirme mektubu",
        "musteri": m,
        "kapsam": kapsam,
        "yasak": yasak,
        "mert_ip": mert_ip,
        "pencere": (baslangic, bitis, bas, son),
        "dahili": dahili,
        "metin": {
            "musteri": m["ad"],
            "sektor": m["sektor"],
            "alan": m["alan"],
            "kisi": kisi,
            "yasak_sistem": YASAK_SISTEMLER[m["sektor"]],
        },
        "cevaplar": {"yasak": yasak, "dahili": dahili, "saat": saat_kabul},
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    bas_t, bit_t, bas, son = s["pencere"]
    mektup = f"""YETKİLENDİRME MEKTUBU (SIZMA TESTİ)
=====================================
Müşteri      : {m['ad']} ({m['alan']})
Yüklenici    : Kalkan Güvenlik Danışmanlık
Belge no     : KG-{bas_t:%Y}-{s['dahili'] % 997:03d}

1. KAPSAM (test edilmesine İZİN VERİLEN sistemler)
   - {s['kapsam'][0]}   web sunucusu ({m['sunucu']})
   - {s['kapsam'][1]}   test ortamı veritabanı
   - {s['kapsam'][2]}   iç yönetim paneli
   - {m['alan']} ve tüm alt alan adları (canlı ödeme alt alanı hariç)

2. KAPSAM DIŞI (KESİNLİKLE test edilmeyecek)
   - {s['yasak']}   {s['metin']['yasak_sistem']}
   - Çalışanlara yönelik sosyal mühendislik (telefon, e-posta, ziyaret)

3. ZAMAN PENCERESİ
   - Tarih  : {bas_t:%d.%m.%Y} — {bit_t:%d.%m.%Y}
   - Saat   : her gün {bas}-{son} arası

4. KURALLAR
   - Hizmet engelleme (DoS) testleri YASAKTIR.
   - Kişisel veriye erişilirse yalnızca kanıt için gereken en az veri alınır, maskelenir.
   - Kritik bulgu (uzaktan kod çalıştırma, veri sızıntısı) 1 saat içinde bildirilir.

5. ACİL İLETİŞİM
   - {s['metin']['kisi']} — dahili {s['dahili']}

İmza (müşteri yetkilisi): ____________      İmza (Kalkan Güvenlik): ____________
"""
    u.yaz(lab / "yetkilendirme_mektubu.txt", mektup)
    eposta = f"""Kimden : Mert Yavuz <mert@kalkan.lab>
Kime   : sen
Konu   : {m['ad']} — küçük bir rica

Selam,

{m['ad']} testine başlıyorsun ya, bir de {s['mert_ip']} adresine bir göz atıver.
Müşteriyle konuşmadım ama orada eski bir sunucu var gibi, sorun etmezler bence.
Hızlıca bir tarama yeter, rapora da yazmasan olur :)

Mert
"""
    u.yaz(lab / "eposta_mert.txt", eposta)


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: mektubu gerçekten okuyarak cevapları çıkarır."""
    import re
    metin = (lab / "yetkilendirme_mektubu.txt").read_text(encoding="utf-8")
    dis = metin.split("2. KAPSAM DIŞI")[1].split("3.")[0]
    yasak = re.search(r"(\d+\.\d+\.\d+\.\d+)", dis).group(1)
    dahili = re.search(r"dahili (\d+)", metin).group(1)
    saat = re.search(r"Saat\s*: her gün (\S+) arası", metin).group(1)
    sv = SEVIYE
    harf = {}
    from hy.motor.kontrol import Baglam
    for no in (1, 2, 6, 7, 8):
        k = sv.gorevler[no - 1].kontrol
        b = Baglam(s, lab, no)
        harf[no] = k.cevabi_goster(b)[0]
    return {1: harf[1], 2: harf[2], 3: yasak, 4: dahili, 5: saat, 6: harf[6], 7: harf[7], 8: harf[8],
            9: "önce izin, sonra iz"}


ADIMLAR = [
    Adim(
        "Neden önce kurallar?",
        """
Öğreneceğin her teknik, **izinsiz** kullanıldığında suçtur. Etik hacker ile suçluyu ayıran
tek şey **yazılı izindir**; teknik bilgi ikisinde de aynıdır.

Türk Ceza Kanunu'nun bilişim suçları maddeleri doğrudan bu alanı ilgilendirir:

- **TCK 243 — Bilişim sistemine girme:** İzinsiz girmek ya da orada kalmaya devam etmek.
  "Sadece baktım, bir şey yapmadım" bir savunma değildir.
- **TCK 244 — Sistemi engelleme, bozma, verileri yok etme veya değiştirme:** Servisi
  çökertmek (DoS), veri silmek ya da değiştirmek.
- **TCK 245 — Banka veya kredi kartlarının kötüye kullanılması.**
- **KVKK (6698 sayılı kanun):** Test sırasında eriştiğin kişisel verileri saklamak,
  paylaşmak ya da işlemek ayrıca sorumluluk doğurur.

Bu oyun hukuki danışmanlık değildir; ama pratik kural çok basit: **sahibi olmadığın ve
yazılı izin almadığın hiçbir sisteme dokunma.**
""",
    ),
    Adim(
        "Nerede pratik yapacağız?",
        """
Yasal ve güvenli pratik alanları bol:

- **Kendi laboratuvarın:** sanal makinelerin, kendi cihazların. Bu oyunun bütün görevleri
  senin makinende, oyunun kurduğu `~/hackeryolu/lab` klasöründe geçer.
- **Kendi atış poligonun:** Cilt 9'da Kali'nde kuracağın savunmasız hedefler (DVWA, Juice
  Shop, WebGoat) ve bu oyunun yerel laboratuvarı. Saldırı pratiğinin tamamını burada,
  internete hiç çıkmadan yaparsın.
- **Bug bounty programları:** HackerOne, Bugcrowd — ama yalnızca programın açıkça izin
  verdiği **kapsam** (scope) içinde.
""",
    ),
    Adim(
        "Yetkilendirme mektubu",
        """
Gerçek bir işte, tek bir paket göndermeden önce şunlar yazılı olarak netleşir:

- **Kapsam:** hangi IP ve alan adları test edilecek, hangileri kesinlikle hariç
- **Zaman penceresi:** hangi gün ve saatlerde
- **Kurallar:** DoS serbest mi, kişisel veri görülürse ne yapılacak
- **Acil iletişim kişisi:** kritik bir açıkta kim aranacak

Bu belgeye **yetkilendirme mektubu** denir ve pentester'ı hukuken koruyan şeydir.
<<musteri>> için hazırlanan mektup laboratuvarında duruyor. Bir dosyanın içini ekrana
basmak için `cat` komutu kullanılır (Cilt 1'de ayrıntısıyla göreceğiz).
""",
        komut="cat yetkilendirme_mektubu.txt",
        sonra="""
Mektubun her bölümü bir soruya cevap verir: **neye**, **ne zaman**, **nasıl** dokunabilirsin
ve bir şey ters giderse **kimi** ararsın. Kapsam dışı satırlarını iki kez oku.
""",
    ),
    Adim(
        "Bir e-posta geldi",
        """
İşe başlamadan önce ekipten bir e-posta düştü. Oku ve mektupla karşılaştır.
""",
        komut="cat eposta_mert.txt",
        sonra="""
Kıdemli birinin rica etmesi, müşterinin **yazılı izni** yerine geçmez. Kapsam dışındaki bir
IP'ye atılan tek bir tarama paketi bile hem şirketini hem seni hukuken açıkta bırakır.
""",
    ),
    Adim(
        "Etik hacker'ın zihniyeti",
        """
Teknik bilgi kadar önemli üç alışkanlık:

- **Merak:** Bir şey çalıştığında "neden?", çalışmadığında "neden olmadı?" diye sor.
- **Not tutmak:** Her komutu, her bulguyu kaydet. İyi bir pentest'in yarısı rapordur ve
  rapor notlardan çıkar. Bugünden bir not sistemi kur (Obsidian, CherryTree ya da düz bir
  Markdown klasörü).
- **Sorumluluk:** Bulduğun açık başkasının işini, verisini, belki geçimini etkiler;
  bulguyu sahibine söylersin, başkasına söylemezsin.
""",
    ),
]

GOREVLER = [
    Gorev(
        "Bir arkadaşın, iş yerindeki bir sunucuya izinsiz girdiğini ama \"sadece baktım, hiçbir "
        "şeyi değiştirmedim\" dediğini anlatıyor. Bu davranış en doğrudan hangi düzenlemeye girer?",
        Secmeli([
            ("TCK 243 — Bilişim sistemine girme", "Doğru. İzinsiz girmek ya da orada kalmak suçun kendisidir; bir şeyi değiştirmek gerekmez."),
            ("TCK 244 — Sistemi bozma veya verileri değiştirme", "244, sistemi bozmak ya da veriyi değiştirmek içindir. Burada sadece girilmiş."),
            ("TCK 245 — Kartların kötüye kullanılması", "245 banka ve kredi kartlarıyla ilgilidir."),
            ("Hiçbiri; bir şey değiştirmediyse suç olmaz", "Yanlış. \"Sadece baktım\" bir savunma değildir."),
        ]),
        ("Kanun maddelerini eğitimin ilk adımında gördün.",
         "Fark şurada: sadece girmek mi, yoksa bozmak/değiştirmek mi?",
         "Sisteme izinsiz girmek ve orada kalmak tek başına suçtur: TCK 243."),
        puan=20, baslik="Kanun",
    ),
    Gorev(
        "Muhasebeden bir arkadaşın: \"Bizim muhasebe sunucusu çok yavaş, bir test etsene, "
        "açığı varsa görelim\" diyor. O sunucunun yöneticisi değil. Ne yaparsın?",
        Secmeli([
            ("Sistemin sahibi ya da yetkili yöneticisinden yazılı izin olmadan test etmem",
             "Doğru. İzni yalnızca sistemin sahibi ya da yetkili yöneticisi verebilir; sıradan bir çalışanın böyle bir yetkisi yoktur."),
            ("Arkadaşım o sunucuyu her gün kullanıyor, onun sözlü onayı benim için yeterli olur",
             "Sunucuyu kullanmak, onu test ettirme yetkisi vermez. İzin verme yetkisi arkadaşında yok."),
            ("Sadece port taraması yaparım; zarar vermeyen bir tarama saldırı sayılmaz",
             "Kapsam ve izin olmadan tarama da yetkisiz erişim girişimi olarak değerlendirilebilir."),
            ("Mesai dışında, kimseyi rahatsız etmeden kısa bir test yapar ve sonucu ona söylerim",
             "Zamanlaması ya da iyi niyet, testin yetkisiz olduğu gerçeğini değiştirmez."),
        ]),
        ("Soru, iznin KİMDEN geldiğiyle ilgili.",
         "Bir sistemi test etme izni kimin yetkisindedir?",
         "Yalnızca sistemin sahibi ya da yetkili yöneticisi, yazılı olarak izin verebilir."),
        puan=20, baslik="İzin kimden",
    ),
    Gorev(
        "<<musteri>> mektubuna göre testi **kesinlikle yasak** olan IP adresi hangisi?",
        IP("yasak"),
        ("Laboratuvarındaki `yetkilendirme_mektubu.txt` dosyasını oku.",
         "`cat yetkilendirme_mektubu.txt` yaz ve \"KAPSAM DIŞI\" bölümüne bak.",
         "2. bölümdeki ilk satırda bir IP adresi ve yanında <<yasak_sistem>> yazıyor."),
        puan=20, baslik="Kapsam",
    ),
    Gorev(
        "Gece yarısı kritik bir açık buldun (uzaktan kod çalıştırma). Mektuba göre hangi "
        "**dahili numarayı** arayacaksın?",
        Sayi("dahili"),
        ("Mektupta bir \"ACİL İLETİŞİM\" bölümü var.",
         "`cat yetkilendirme_mektubu.txt` çıktısının en altına bak.",
         "5. bölümde <<kisi>> ve yanında 'dahili' ile başlayan bir numara var."),
        puan=20, baslik="Acil iletişim",
    ),
    Gorev(
        "Testlere günün **hangi saat aralığında** izin var? (örn. 09:00-18:00)",
        Metin("saat", bicim="SS:DD-SS:DD"),
        ("Zaman penceresi mektubun 3. bölümünde.",
         "\"Saat\" satırını bul.",
         "Satır 'her gün ... arası' diyor; aradaki iki saati tire ile yaz."),
        puan=20, baslik="Zaman penceresi",
    ),
    Gorev(
        "Mert'in e-postasındaki ricaya bak. Doğru davranış hangisi?",
        Secmeli([
            ("O IP kapsamda değil; müşteriden yazılı ek onay gelmeden dokunmam ve Mert'e de bunu söylerim",
             "Doğru. Kapsamı genişletmek için müşterinin yazılı onayı gerekir; ekipten birinin sözü yetmez."),
            ("Mert projenin kıdemlisi; onun talimatıyla tarar, sonucu da rapora eklerim",
             "Kıdem, müşterinin yazılı izni yerine geçmez. Mektupta olmayan bir sisteme dokunursan sorumluluk sende."),
            ("Sadece ping atarak canlı olup olmadığına bakarım; ping tarama sayılmaz",
             "Kapsam dışı bir sisteme gönderilen her paket kapsam ihlalidir, ping dahil."),
            ("Aynı ağda olduğu için kapsamın doğal bir parçası sayılır, normal test ederim",
             "Aynı ağda olmak kapsamda olmak demek değildir. Kapsam IP IP yazılır."),
        ]),
        ("E-postadaki IP'yi mektuptaki kapsam listesiyle karşılaştır.",
         "`cat eposta_mert.txt` ve `cat yetkilendirme_mektubu.txt` çıktılarını yan yana düşün.",
         "<<musteri>> mektubunda o IP yok. Kapsam dışı = yazılı onay olmadan dokunma."),
        puan=20, baslik="Kapsam baskısı",
    ),
    Gorev(
        "Test sırasında <<musteri>> veritabanında <<sektor>> müşterilerinin kişisel verilerini "
        "(ad, telefon, adres) gördün. Ne yaparsın?",
        Secmeli([
            ("Kanıt için gereken en az veriyi alır, maskeler, raporla güvenle teslim edip kendi kopyamı silerim",
             "Doğru. KVKK açısından kanıt için gereken en az veriyle yetinilir, veri maskelenir ve test bitince imha edilir."),
            ("Bulgunun ciddiyetini göstermek için tüm tabloyu indirir, raporun ekine koyarım",
             "Fazla veri almak KVKK'ya göre ayrı bir sorumluluk doğurur. Birkaç maskeli satır kanıt için yeterlidir."),
            ("Tekrar test gerekebilir diye veriyi şifreli bir klasörde proje bitene kadar saklarım",
             "Şifreli bile olsa, kanıt için gereken en az veriden fazlasını saklamak KVKK'ya aykırıdır."),
            ("Kişisel veriyi raporlamak riskli olduğu için bu bulguyu rapora hiç yazmam",
             "Kişisel veriye erişim önemli bir bulgudur; raporlanmalıdır, ama en az veriyle ve maskeli."),
        ]),
        ("Mektubun 4. bölümündeki kurallardan biri tam bu durumla ilgili.",
         "KVKK'nın temel ilkesi: veri işlemede ölçülülük ve en az veri.",
         "Kanıt için en az veri, maskeleme, güvenli teslim ve imha."),
        puan=20, baslik="KVKK",
    ),
    Gorev(
        "Bir bug bounty programında, kapsam listesinde olmayan bir alt alan adında açık "
        "gibi görünen bir şey fark ettin. Ne yaparsın?",
        Secmeli([
            ("Test etmem; programın iletişim kanalından yazılı olarak bildirir, test etmediğimi açıkça belirtirim",
             "Doğru. Gördüğünü bildirebilirsin; ama kapsam dışını test etmek izinsiz erişimdir. Ödül beklememek gerekir."),
            ("Yanlış alarm olmasın diye açığı kısaca doğrular, sonra programa kanıtıyla bildiririm",
             "Kapsam dışında 'kısaca doğrulamak' da testtir ve yasal koruma (safe harbor) kapsam dışını kapsamaz."),
            ("Şirketin güvenlik ekibine doğrudan yazar, kapsam dışı olduğu için ödül isterim",
             "Gördüğünü bildirmek iyidir; ama kapsam dışı bir bulgu için ödül beklemek doğru değildir."),
            ("Şirket hemen düzeltsin diye bulguyu sosyal medyada genel hatlarıyla paylaşırım",
             "Bu, sorumlu bildirim (responsible disclosure) ilkesine aykırıdır ve kullanıcıları riske atar."),
        ]),
        ("Kapsam dışı sistem = izin verilmemiş sistem.",
         "Gördüğün bir şeyi bildirmek ile onu test etmek arasındaki farkı düşün.",
         "Test etmeden, programın kanalıyla yazılı bildir ve test etmediğini belirt."),
        puan=20, baslik="Bug bounty",
    ),
    Gorev(
        "Son adım: Kalkan Güvenlik'in duvarındaki ilkeyi yaz ve yolculuğa başla.",
        Metin(kabul=["önce izin, sonra iz", "önce izin sonra iz", "once izin, sonra iz", "once izin sonra iz"],
              bicim="duvardaki 4 kelime"),
        ("Bu bölümün en başında, ofise ilk girdiğin sahnede yazıyordu.",
         "İki parçalı bir cümle: önce bir şey, sonra başka bir şey.",
         "Önce izin, sonra iz."),
        puan=30, baslik="Yemin",
    ),
]

SEVIYE = Seviye(
    kimlik="c00",
    cilt=0,
    bolum=0,
    baslik="Önce Kurallar: Etik ve Hukuk",
    brifing="""
Selin masana bir dosya bırakıyor: "Bu hafta **<<musteri>>** (<<sektor>>) ile çalışmaya
başlıyoruz. Yetkilendirme mektubu imzalandı, laboratuvarında bir kopyası var. Bir de
Mert'ten bir e-posta gelmiş, onu da oku."

"Bugün tek satır saldırı komutu yazmayacaksın. Önce mektubu **okumayı** öğreneceksin:
neye dokunabilirsin, ne zaman, kimi ararsın ve neye asla dokunmazsın. Bunu bilmeyen
biri ne kadar yetenekli olursa olsun bu ofiste çalışamaz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırgan ile pentester **aynı komutları** yazar. Aradaki fark üç şeydir: yazılı izin,
kapsama sadakat ve bulguyu sahibine raporlamak. Savunma tarafından bakınca da ders aynı:
bir şirket, test ettirdiği sistemlerin listesini ve acil durum kişisini net yazmazsa,
kritik bir bulgu gece yarısı kimseye ulaşamaz.
""",
    gercek_hayat="""
- **Iowa mahkeme binası, 2019:** Eyalet mahkeme idaresiyle sözleşmeli iki sızma testi
  uzmanı, bir ilçe mahkeme binasına gece yaptıkları fiziksel test sırasında tutuklandı.
  Binanın kime ait olduğu ve izni kimin verebileceği konusunda kurumlar arasında anlaşmazlık
  vardı. Suçlamalar sonradan düşürüldü; ama olay, sektöre şunu öğretti: izni **gerçekten
  yetkili** kişiden aldığından ve kapsamın net olduğundan emin ol.
- **Bug bounty ve "safe harbor":** Bug bounty programlarının araştırmacıya verdiği yasal
  koruma yalnızca programın yazdığı kapsam içindeki testleri kapsar. Kapsam dışı test yapan
  araştırmacılar programdan çıkarılabilir ve korumadan yararlanamaz.
""",
    sure_hedef_dk=20,
    tamamlama_bonusu=60,
)
