"""Cilt 14 · Bölüm 1 — Mobil Saldırı Yüzeyi.

Beceri: bir mobil uygulamanın iki parçasını (istemci / arka uç) ayırmak, denetim bulgularını
OWASP Mobile Top 10 kategorilerine eşlemek ve "istemciye asla güvenme" ilkesini bulgulara uygulamak.

Vakalar: Ferah Bank, Paramix, Kuzey Yatırım, Pazarix — dört kurgusal mobil finans/alışveriş uygulaması.
Lab'daki her şey kurgusal bir denetim özetidir; gerçek uygulama ya da saldırı aracı yoktur.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c14_mobil.ortak import Esle, harfli, sec_doldur, sh, vaka_sec

KATEGORILER = ["Güvensiz veri depolama", "Zayıf iletişim", "Güvensiz kimlik doğrulama", "Yetersiz istemci koruması"]

# (taraf, kategori kodu, açıklama)
BULGULAR = [
    ("istemci", "depolama", "Oturum token'ı cihazda açık metin dosyada saklanıyor"),
    ("istemci", "depolama", "Ekran görüntüsü önbelleğinde hesap özeti kalıyor"),
    ("istemci", "depolama", "Kaynak kodda gömülü API anahtarı bulundu"),
    ("istemci", "iletisim", "Bazı çağrılar şifresiz http:// ile gidiyor"),
    ("istemci", "kimlik", "PIN yalnızca cihazda doğrulanıyor, sunucu denetlemiyor"),
    ("istemci", "koruma", "Kök (root) tespiti ve kod gizleme kapalı"),
    ("arkauc", "kimlik", "Limit sorgulama uç noktası oturum istemiyor"),
    ("arkauc", "yetki", "Hesap numarası değiştirilince başkasının kaydı geliyor (IDOR)"),
]

OLAYLAR = {
    "Güvensiz veri depolama": [
        "Telefonu ele geçiren biri, dosya yöneticisiyle uygulamanın klasöründeki oturum bilgisini açık metin okuyabiliyor.",
        "Uygulamayı silmeden önce cihazdan alınan yedekte, kullanıcının kayıtlı kart numarası düz yazı olarak duruyor.",
    ],
    "Zayıf iletişim": [
        "Kafedeki ortak Wi-Fi'da uygulama trafiği şifresiz akıyor; aynı ağdaki biri istekleri okuyabiliyor.",
        "Uygulama, sunucu sertifikasını doğrulamadan her sertifikayı kabul ediyor; araya giren biri trafiği görebiliyor.",
    ],
    "Güvensiz kimlik doğrulama": [
        "Uygulama 'giriş başarılı' kararını yalnızca cihazdaki bir değişkene bakarak veriyor; sunucu her isteği kabul ediyor.",
        "Oturum token'ının süresi hiç dolmuyor; çalınan token aylarca geçerli kalıyor.",
    ],
    "Yetersiz istemci koruması": [
        "Uygulama kök (root) açılmış bir cihazda çalıştığını fark etmiyor ve kodu hiç gizlenmemiş.",
        "Uygulamanın değiştirilip yeniden paketlenmesi hiçbir kontrolle algılanmıyor.",
    ],
}


def uret(rng):
    v = vaka_sec(rng)
    kodlar = [f"MB-{n:02d}" for n in rng.sample(range(1, 40), len(BULGULAR))]
    satirlar = list(zip(kodlar, BULGULAR))
    rng.shuffle(satirlar)
    istemci = sum(1 for _, b in satirlar if b[0] == "istemci")
    gomulu = [k for k, b in satirlar if "gömülü" in b[2]][0]
    arkauc = [k for k, b in satirlar if b[0] == "arkauc"]
    ogeler = [(rng.choice(OLAYLAR[k]), k) for k in KATEGORILER]
    esle_metni, esle = harfli(rng, ogeler, KATEGORILER)
    return {
        "vaka": f"{v['ad']} — {v['uyg']} ön denetimi",
        "v": v,
        "satirlar": satirlar,
        "metin": {"musteri": v["ad"], "uyg": v["uyg"], "api": v["api"], "veri": v["veri"],
                  "hikaye": v["hikaye"], "esle": esle_metni, "paket": v["paket"]},
        "cevaplar": {
            "istemci_sayisi": istemci,
            "gomulu": gomulu,
            "arkauc": arkauc,
            "esle": esle,
            "bayrak": u.bayrak(rng, "kor_nokta"),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['uyg']} ({v['paket']}) için KURGUSAL denetim özeti. Gerçek uygulama yoktur.\n"
          "Selin'den not: Önce uygulamanın iki parçasını ayır: telefondaki istemci ve sunucudaki arka uç.\n")
    u.yaz(lab / "denetim" / "bulgular.txt",
          "# kod | taraf | kategori | açıklama\n" +
          "".join(f"{k} | {b[0]} | {b[1]} | {b[2]}\n" for k, b in s["satirlar"]))
    u.yaz(lab / "denetim" / "mimari.txt",
          f"{v['uyg']} mimarisi (kurgusal)\n"
          f"  Telefon: {v['paket']} uygulaması (müşterinin cihazı; saldırgan da bir müşteri olabilir)\n"
          f"  Sunucu : https://{v['api']}/ (arka uç API; {v['veri']} burada tutulur)\n")
    u.yaz(lab / "denetim" / "owasp_mobil.txt",
          "OWASP Mobile Top 10 — bu denetimde kullanılan kategoriler\n"
          "  depolama : güvensiz veri depolama (cihazda açık saklanan sırlar)\n"
          "  iletisim : zayıf iletişim (şifresiz ya da yanlış doğrulanan trafik)\n"
          "  kimlik   : güvensiz kimlik doğrulama\n"
          "  koruma   : yetersiz istemci koruması (kök/kurcalama tespiti, kod gizleme yokluğu)\n"
          "  yetki    : (arka uç) yetkilendirme hataları\n")
    u.yaz(lab / "denetim" / ".denetci_notu",
          f"Gizli not: istemci kodundaki her karar saldırganın elindedir. {s['cevaplar']['bayrak']}\n")


def coz(lab: Path, s: dict) -> dict:
    istemci = sh("grep -c '| istemci |' denetim/bulgular.txt", lab)
    gomulu = sh("grep gömülü denetim/bulgular.txt | awk '{print $1}'", lab)
    arkauc = sh("grep '| arkauc |' denetim/bulgular.txt | awk '{print $1}' | tr '\\n' ' '", lab)
    bayrak = sh("grep -o 'FLAG{[^}]*}' denetim/.denetci_notu", lab)
    # eşleme bir okuma/akıl yürütme işidir; test çözücüsü doğru haritayı kontrolden alır
    esle = GOREVLER[2].kontrol.cevabi_goster(Baglam(s, lab, 3))
    return sec_doldur({2: istemci, 3: esle, 4: gomulu, 5: arkauc, 7: bayrak}, GOREVLER, lab, s)


def _istemci_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Başlık satırını (`#` ile başlayan) da saymış olabilirsin; `grep -c` yalnızca eşleşen satırları sayar."
    if n == len(b.senaryo["satirlar"]) - beklenen:
        return "Bu, arka uç bulgularının sayısı. Sorulan taraf **istemci**."
    return None


def _id_hata(g, beklenen, b):
    if g and g.isdigit():
        return "Bulgunun **kodunu** (`MB-..` biçiminde) yaz, sıra numarasını değil."
    return None


ADIMLAR = [
    Adim("İki parça: istemci ve arka uç", """
Bir mobil uygulama iki parçadan oluşur ve ikisi de saldırı yüzeyidir:

- **İstemci:** müşterinin telefonunda çalışan uygulamanın kendisi. Saldırgan da bir müşteri olabilir; uygulamayı
  indirir, söker, çalışırken davranışını inceler. İstemci **tamamen onun elindedir**.
- **Arka uç (API):** uygulamanın konuştuğu sunucu. Cilt 5 ve Cilt 10'daki web/API güvenliğinin aynısı geçerlidir.

Önce vakanın mimari özetine bak:
""", komut="cat denetim/mimari.txt"),
    Adim("Denetim bulguları", """
Kalkan'ın ön denetim özeti `denetim/bulgular.txt` dosyasında. Her satır: kod | taraf | kategori | açıklama.
""", komut="cat denetim/bulgular.txt", sonra="""
`taraf` sütunu bulgunun **istemcide** (telefonda) mı yoksa **arka uçta** (sunucuda) mı olduğunu söyler.
Bu ayrım düzeltmeyi kimin yapacağını da belirler: mobil geliştirici mi, API ekibi mi?
"""),
    Adim("Bir taraftaki bulguları saymak", """
`grep -c` eşleşen satırların sayısını verir. Aradığın kalıbı ayraçlarıyla birlikte yazarsan başlık satırı karışmaz:
""", komut="grep -c '| arkauc |' denetim/bulgular.txt"),
    Adim("OWASP Mobile Top 10", """
Web için OWASP Top 10 olduğu gibi mobil için de bir liste vardır. En kritikleri: güvensiz veri depolama,
zayıf iletişim, güvensiz kimlik doğrulama ve yetersiz istemci koruması. Denetimde kullanılan kısaltmalar:
""", komut="cat denetim/owasp_mobil.txt"),
    Adim("Kategorilere göre dağılım", """
Hangi kategoride kaç bulgu var? `awk` ile 3. sütunu al, `sort | uniq -c` ile say. (`-F'|'` ayraç olarak
`|` kullanır.)
""", komut="awk -F'|' 'NR>1 {print $3}' denetim/bulgular.txt | sort | uniq -c | sort -rn",
         sonra="""
**Hacker gözüyle:** Mobil güvenliğin altın kuralı Cilt 5'teki "istemciye asla güvenme"nin en uç halidir.
Uygulamaya gömülen bir anahtar, "yalnızca admin görsün" diye arayüzde yapılan bir kontrol ya da cihazda
doğrulanan bir PIN, saldırgan için açık kitaptır. Her güvenlik kararı **arka uçta** alınmalıdır.
"""),
    Adim("Gizli dosyalar", """
Denetçiler bazen not bırakır. Gizli dosyaları da gör:
""", komut="ls -la denetim"),
]

GOREVLER = [
    Gorev("`<<uyg>>` uygulamasının iki parçasından hangisi **tamamen saldırganın (herhangi bir müşterinin) kontrolündedir**?",
          Secmeli([
              ("Telefondaki istemci uygulaması: indirilip sökülür, çalışırken incelenir",
               "Doğru. İstemci müşterinin cihazındadır; her kontrol ve her sır orada okunabilir."),
              ("Sunucudaki API: saldırgan sunucunun işletim sistemine ve veritabanına doğrudan sahiptir",
               "Yanlış. API kurumun kendi altyapısındadır; saldırgan yalnızca ona istek gönderebilir."),
              ("Uygulama mağazası: yayımlanan paketi saldırgan mağaza üzerinde istediği gibi değiştirebilir",
               "Yanlış. Mağazadaki paketi kurum yayımlar; saldırganın elindeki, indirdiği kopyadır."),
              ("Bulut sağlayıcının veri merkezi: oradaki bütün veriler saldırganın erişiminde",
               "Yanlış. Veri merkezi sağlayıcının ve kurumun denetimindedir."),
          ], dogru=0),
          ("Saldırgan uygulamayı nereden edinir ve onu nerede çalıştırır?",
           "Telefonunda çalışan parçayı düşün: kimin cihazında?",
           "Doğru şık, 'cihazda çalışan' parçayı anlatan şık."),
          puan=20, baslik="Kontrol kimde?"),
    Gorev("`denetim/bulgular.txt` içinde **istemci** tarafında kaç bulgu var?",
          Sayi("istemci_sayisi", sik_hatalar=_istemci_hata),
          ("Dosyanın ikinci sütunu bulgunun tarafını gösterir.",
           "`grep -c '| istemci |' denetim/bulgular.txt` eşleşen satırları sayar.",
           "Başlık satırı '| istemci |' kalıbını içermez; komutun çıktısı doğrudan cevaptır."),
          puan=25, baslik="İstemci bulguları"),
    Gorev("Aşağıdaki dört olayı OWASP kategorilerine eşle (numara + harf, örn. `1c 2a 3d 4b`):\n\n<<esle>>",
          Esle("esle"),
          ("Her olayda 'ne yanlış?' sorusunu sor: veri nerede duruyor, nasıl taşınıyor, kim doğruluyor, ne koruyor?",
           "Cihazda açık duran veri = depolama; taşınan şifresiz veri = iletişim; kararı kimin verdiği = kimlik; kök/kurcalama tespiti = istemci koruması.",
           "`denetim/owasp_mobil.txt` her kategorinin tanımını verir; her olayı tanımla karşılaştır."),
          puan=35, baslik="Kategori eşleme"),
    Gorev("Hangi bulgu **kaynak kodda gömülü bir API anahtarı** bulunduğunu söylüyor? Bulgunun kodunu yaz (`MB-..`).",
          Metin("gomulu", bicim="bulgu kodu (MB-..)", sik_hatalar=_id_hata),
          ("Açıklama sütununda 'gömülü' kelimesi geçer.",
           "`grep gömülü denetim/bulgular.txt` ilgili satırı bulur.",
           "Satırın ilk sözcüğü koddur: `grep gömülü denetim/bulgular.txt | awk '{print $1}'`."),
          puan=30, baslik="Gömülü anahtar"),
    Gorev("**Arka uç** (sunucu) tarafında düzeltilmesi gereken bulguların kodlarını yaz (virgülle ayır).",
          Kume("arkauc", bicim="bulgu kodları, virgülle ayrılmış"),
          ("Bu bulgular mobil geliştiricinin değil API ekibinin işi. Hangi sütun bunu söylüyor?",
           "`grep '| arkauc |' denetim/bulgular.txt` ile süz.",
           "`grep '| arkauc |' denetim/bulgular.txt | awk '{print $1}'` yalnızca kodları verir."),
          puan=30, baslik="Arka uç bulguları"),
    Gorev("Geliştirici, 'yalnızca yöneticiler görebilsin' diye bir ekranı sadece uygulamanın arayüzünde gizlemiş. "
          "Doğru düzeltme hangisi?",
          Secmeli([
              ("Yetkiyi arka uçta, her API isteğinde doğrulamak",
               "Doğru. Saldırgan uygulamayı atlayıp API'ye doğrudan istek gönderebilir; karar sunucuda verilmeli."),
              ("Ekranı daha iyi gizleyen bir kod gizleme aracı kullanmak",
               "Yanlış. Kod gizleme işi zorlaştırır ama kararı istemcide bıraktığı için sorunu çözmez."),
              ("Uygulamanın yönetici ekranının adını değiştirmek",
               "Yanlış. Adı değiştirmek gizlilik sağlamaz; arka uçtaki yetki kontrolünün yokluğu aynen sürer."),
              ("Yöneticiler için ayrı bir uygulama sürümü yayımlamak",
               "Yanlış. Ayrı sürüm de bir istemcidir; API yetkiyi denetlemiyorsa sahte istekle aşılır."),
          ], dogru=0),
          ("'İstemciye asla güvenme' ilkesini hatırla.",
           "Saldırgan arayüzü hiç kullanmadan API'ye istek gönderebilir. Kontrol nerede olursa işe yarar?",
           "Kararın verildiği yer sunucudur; doğru şık yetkinin orada denetlendiğini söyleyen şık."),
          puan=30, baslik="Yetki nerede?"),
    Gorev("`denetim/` klasöründe bir de gizli denetçi notu var. İçindeki bayrağı bul.",
          Bayrak("bayrak"),
          ("Gizli dosyaların adı nokta ile başlar.",
           "`ls -la denetim` ile gizli dosyayı gör.",
           "`cat denetim/.denetci_notu` ile oku ve bayrağı yaz."),
          puan=20, baslik="Gizli not"),
]

SEVIYE = Seviye(
    kimlik="c14b01",
    cilt=14,
    bolum=1,
    baslik="Mobil Saldırı Yüzeyi",
    brifing="""
Selin masana bir dosya bırakıyor: "**<<musteri>>** mobil uygulaması **<<uyg>>** için ön denetim istedi.
<<hikaye>> Uygulama <<veri>> ile çalışıyor, yani hata kaldırmaz."

Mert kahvesini karıştırırken ekliyor: "Mobilde ilk soru hep aynı: bu kontrol **telefonda mı, sunucuda mı**?
Telefondaki her şeyi müşteri değiştirebilir, saldırgan da bir müşteridir." Deniz de bulguların istemci mi
arka uç mu olduğunu ayırmanı istiyor: "Düzeltmeyi kimin yapacağı buna bağlı."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Mobil güvenlikte ilk ayrım hep aynıdır: telefondaki istemci saldırganın elindedir, sunucudaki arka uç ise
saldırganın konuşabildiği ama sahip olmadığı yerdir. Saldırgan açısından istemciyi sökmek bir keşiftir; asıl ödül
arka uçtaki API'dir. Savunma dersi: hiçbir sırrı uygulamaya gömme, hiçbir yetki kararını yalnızca arayüze bırakma,
her kararı arka uçta ver. İstemci korumaları (kök tespiti, kod gizleme) yalnızca işi zorlaştırır.
""",
    gercek_hayat="""
- **Mobil sızma testlerinde sık bulgu:** Pek çok mobil uygulama incelemesinde ilk bulgular kaynak kodda gömülü
  anahtarlar, cihazda açık saklanan token'lar ve arka uçta eksik yetki kontrolleridir. Bunlar OWASP Mobile Top 10
  ve OWASP MASVS gibi belgelerin en baştaki konularıdır.
- **Önleme:** Güvenlik kararlarını arka uca taşımak, sırları uygulamaya gömmemek ve geliştirme sürecinde mobil
  güvenlik kontrol listesi (OWASP MASVS) kullanmak. Önleme **tespitle** tamamlanır: arka uç logları, anormal API
  kullanımını (örneğin tek bir token'dan çok sayıda hesap sorgulanması) yakalamalıdır.
- **Finans uygulamaları:** Bankacılık ve ödeme uygulamaları en çok incelenen mobil yüzeylerdir; istemci tarafındaki
  zafiyetin sonunda hep arka uçtaki finansal iş mantığına ulaşılır (Cilt 10).
""",
    sure_hedef_dk=20,
)
