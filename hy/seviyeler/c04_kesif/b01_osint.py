"""Cilt 4 · Bölüm 1 — Keşif Metodolojisi ve OSINT.

Beceri: pasif ve aktif keşfi ayırmak; saldırı yüzeyi kavramı; herkese açık kaynaklardan (şirket web
sayfası, çalışan listesi, iş ilanı, sertifika şeffaflık kaydı) bilgi çıkarmak; sorumlu OSINT sınırı.

Hiçbir gerçek sorgu yapılmaz: bütün "OSINT çıktıları" lab'a konan kurgusal dosyalardır.

Vakalar: e-ticaret (Pazarix), lojistik (Kuzgun Lojistik), belediye (Yeşiltepe Belediyesi).
"""
from __future__ import annotations

import json
from pathlib import Path

from hy.motor.kontrol import Bayrak, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

from . import ortak as o

ADLAR = ["tuncay", "aylin", "okan", "gamze", "serdar", "nurcan", "kaan", "ebru", "cem", "dilara",
         "murat", "sevil", "baris", "hulya", "emre", "fulya"]
SOYADLAR = ["yilmaz", "demir", "kaya", "celik", "sahin", "aydin", "ozturk", "arslan", "koc", "polat",
            "tekin", "erdem", "bulut", "gunes"]
UNVANLAR = ["Muhasebe Uzmani", "Satis Temsilcisi", "Insan Kaynaklari Uzmani", "Yazilim Gelistirici",
            "Musteri Hizmetleri", "Satin Alma Uzmani", "Pazarlama Uzmani", "Hukuk Musaviri"]

KALIPLAR = {
    "ad.soyad": lambda a, s: f"{a}.{s}",
    "a.soyad": lambda a, s: f"{a[0]}.{s}",
    "adsoyad": lambda a, s: f"{a}{s}",
}

VAKALAR = [
    {
        "kod": "pazarix", "web": "web_kopyasi", "csv": "calisanlar.csv", "ilan": "is_ilani.txt",
        "ct": "sertifika_kaydi.json", "bt_unvan": "Sistem Yoneticisi", "bt_tr": "Sistem Yöneticisi", "ci": "Jenkins",
        "eol": ("Magento 1.9", ["magento 1.9", "magento 1.9.x"]),
        "web_adlar": ["odeme", "kampanya", "magaza", "destek", "blog", "api"],
        "gizli_adlar": ["test-odeme", "eski-magaza", "stok-ic"],
        "ilan_f": lambda a, ci, eol: (
            f"PAZARIX — SISTEM YONETICISI ARANIYOR\n\nBiz kimiz: Turkiye'nin hizla buyuyen e-ticaret sitesi.\n\n"
            f"Sorumluluklar:\n- Magaza altyapisinin (Linux sunucular, yuk dengeleyici) 7/24 ayakta kalmasi\n"
            f"- Kampanya haftalarinda olcekleme\n- {ci} ile surekli entegrasyon (CI/CD) hatlarinin bakimi\n"
            f"- Mevcut {eol} tabanli magaza kodunun yeni surume tasinmasina destek\n\n"
            f"Aradigimiz nitelikler:\n- Linux, Nginx ve MySQL deneyimi\n- Docker bilgisi artidir\n"
            f"- Takim calismasina yatkinlik\n\nBasvuru: ik@{a}\n"),
        "brifing": """
**Pazarix** büyük kampanya haftasına hazırlanıyor ve Selin sana ilk keşif görevini verdi: "Kimseye
tek paket göndermeden, sadece internetteki açık bilgiyle Pazarix hakkında ne öğrenebiliriz?" Elinde
şirketin ana sayfasının bir kopyası, çalışan listesi (<<csv>>), yayınlanmış bir iş ilanı (<<ilan>>) ve
bir sertifika şeffaflık kaydı (<<ct>>) var. Hepsi bu laboratuvara kurgusal olarak kopyalandı; gerçek bir
siteye hiçbir sorgu atılmayacak.

Mert: "Kırmızı takım işe hep buradan başlar. Gürültü yok, iz yok. Ama dikkat: bulduğun her şey gerçek
insanlara ve gerçek sistemlere ait. Sadece okuyacak ve rapora yazacaksın."
""",
    },
    {
        "kod": "kuzgun", "web": "site_arsivi", "csv": "personel_rehberi.csv", "ilan": "kariyer_ilani.txt",
        "ct": "ct_kaydi.json", "bt_unvan": "BT Muduru", "bt_tr": "BT Müdürü", "ci": "GitLab CI",
        "eol": ("Apache Tomcat 7.0", ["apache tomcat 7.0", "tomcat 7.0", "tomcat 7"]),
        "web_adlar": ["takip", "bayi", "kurumsal", "filo", "kariyer", "fatura"],
        "gizli_adlar": ["test-takip", "eski-bayi", "depo-ic"],
        "ilan_f": lambda a, ci, eol: (
            f"KUZGUN LOJISTIK — YAZILIM GELISTIRICI (KARGO TAKIP)\n\nDepo ve filo sistemlerimizi gelistiren "
            f"ekibe katilacak bir arkadas ariyoruz.\n\nIs tanimi:\n- Kargo takip uygulamasinin gelistirilmesi\n"
            f"- Uygulamalarimiz su an {eol} uzerinde calisiyor; gecis planina katki\n"
            f"- {ci} uzerinde otomatik test ve dagitim hatlari\n- Depo el terminalleriyle entegrasyon\n\n"
            f"Nitelikler:\n- Java ve SQL bilgisi\n- Git deneyimi\n- RabbitMQ bilmek artidir\n\n"
            f"CV'ni kariyer@{a} adresine gonder.\n"),
        "brifing": """
**Kuzgun Lojistik**'in filo müdürü Serdar Bey, yeni depo yazılımına geçmeden önce Kalkan'dan "dışarıdan
nasıl görünüyoruz?" raporu istedi. Selin sana şirketin web sayfası kopyasını, personel rehberini
(<<csv>>), bir kariyer ilanını (<<ilan>>) ve sertifika kaydını (<<ct>>) verdi. Hepsi kurgusal ve bu
laboratuvarda.

Selin: "Bu aşamada hedefe dokunmak yok. Pasif keşif: sadece okuyoruz. Her bilgiyi 'saldırgan bundan ne
çıkarır?' gözüyle oku."

Deniz: "Bir de bizim tarafımızdan bak: şirket kendi hakkında bu kadarını açıkta bıraktığını biliyor
mu? Çoğu bilmiyor."
""",
    },
    {
        "kod": "yesiltepe", "web": "sayfa_kopyasi", "csv": "ekip_listesi.csv", "ilan": "ilan_metni.txt",
        "ct": "crt_sonuc.json", "bt_unvan": "Bilgi Islem Muduru", "bt_tr": "Bilgi İşlem Müdürü", "ci": "TeamCity",
        "eol": ("Windows Server 2008 R2", ["windows server 2008 r2", "windows server 2008"]),
        "web_adlar": ["ebelediye", "imar", "duyuru", "ihale", "kent-rehberi", "meclis"],
        "gizli_adlar": ["test-ebys", "eski-portal", "emlak-ic"],
        "ilan_f": lambda a, ci, eol: (
            f"YESILTEPE BELEDIYESI — BILGI ISLEM PERSONELI ALIMI\n\nBilgi Islem Mudurlugu'ne sistem ve ag "
            f"destek personeli alinacaktir.\n\nGorevler:\n- E-belediye portalinin sunucularinin yonetimi "
            f"({eol} uzerindeki dosya ve uygulama sunuculari dahil)\n- Yedekleme ve olay takibi\n"
            f"- Yazilim ekibinin kullandigi {ci} sunucusunun bakimi\n\nAranan nitelikler:\n"
            f"- Active Directory bilgisi\n- Ag cihazlari bilgisi\n- Kamu kurumlarinda calismis olmak tercih sebebi\n\n"
            f"Basvuru: ik@{a}\n"),
        "brifing": """
**Yeşiltepe Belediyesi** e-belediye portalını yeniliyor. Bilgi işlem müdürü Nurcan Hanım: "Vatandaşın
verisi bizde; internette hakkımızda ne bulunuyorsa önce biz bilelim." Selin sana belediyenin web sayfası
kopyasını, ekip listesini (<<csv>>), bir personel alımı ilanını (<<ilan>>) ve sertifika kaydını (<<ct>>)
verdi. Hepsi kurgusal laboratuvar dosyaları.

Selin: "Kamu kurumları iş ilanında bile çok şey söyler. Pasif keşifte dosyaları oku, sonuçları not et;
hiçbir sisteme dokunma."

Mert: "İlanda yazan yazılım sürümüne dikkat et. Saldırgan da okuyor."
""",
    },
]


def _eposta(kalip, a, s, alan):
    return f"{KALIPLAR[kalip](a, s)}@{alan}"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    alan = m["alan"]
    kalip = rng.choice(list(KALIPLAR))
    kisiler = []
    kullanilan = set()
    for _ in range(8):
        while True:
            a, sy = rng.choice(ADLAR), rng.choice(SOYADLAR)
            if (a, sy) not in kullanilan and a not in {x[0] for x in kisiler}:
                kullanilan.add((a, sy))
                break
        kisiler.append((a, sy))
    hedef_a, hedef_s = kisiler[0]
    unvanlar = rng.sample(UNVANLAR, 7)
    satirlar = [(f"{a.capitalize()} {sy.capitalize()}", unvanlar[i - 1], _eposta(kalip, a, sy, alan))
                for i, (a, sy) in enumerate(kisiler[1:], 1)]
    hedef_eposta = _eposta(kalip, hedef_a, hedef_s, alan)
    hedef_ad = f"{hedef_a.capitalize()} {hedef_s.capitalize()}"
    diger_epostalar = [_eposta(k, hedef_a, hedef_s, alan) for k in KALIPLAR if k != kalip]

    web_adlar = rng.sample(v["web_adlar"], 4)
    gizli = rng.choice(v["gizli_adlar"])
    ct_adlar = ["www"] + web_adlar + [gizli]
    sertler = []
    sn = rng.randint(1000, 9000)

    def sert(adlar, bas_ay, cn=None):
        nonlocal sn
        sn += rng.randint(1, 40)
        sertler.append({
            "issuer_ca_id": 7001, "issuer_name": "C=XX, O=Lab Sertifika Otoritesi, CN=Lab Alan Adi CA 1",
            "common_name": cn or adlar[0], "name_value": "\n".join(adlar), "id": 90000000 + sn,
            "not_before": f"2025-{bas_ay:02d}-0{rng.randint(1, 9)}T08:00:00", "not_after": f"2026-{bas_ay:02d}-0{rng.randint(1, 9)}T08:00:00",
        })

    sert([f"www.{alan}", alan], 2)
    sert([f"*.{alan}", alan], 3)
    for ad in web_adlar:
        sert([f"{ad}.{alan}"], rng.randint(1, 9))
    for ad in rng.sample(web_adlar, 2):
        sert([f"{ad}.{alan}"], rng.randint(10, 12))   # yenilenmiş kopya: aynı ad ikinci kez
    sert([f"{gizli}.{alan}"], rng.randint(4, 9))
    rng.shuffle(sertler)
    tum = [n for e in sertler for n in e["name_value"].split("\n")]
    benzersiz = len(set(tum) - {alan} - {f"*.{alan}"})
    hatalar = {
        len(tum): "Aynı adları tekrar tekrar saymışsın: yenilenen sertifikalar aynı adı yeniden içeriyor. Benzersiz say.",
        len(set(tum)): "Ana alan adını ve `*.` jokerini de saymışsın; ikisi de bir alt alan adı değil.",
        len(set(tum) - {alan}): "Joker (`*.`) kaydı bir alt alan adı değil; sayımdan çıkar.",
        len(set(tum) - {f"*.{alan}"}): "Ana alan adının kendisini (alt alan değil) de saymışsın.",
    }
    hatalar.pop(benzersiz, None)

    bayrak = u.bayrak(rng, rng.choice(["unutulan_not", "sessiz_iz", "sakli_bahce"]))
    ci, (eol_ad, eol_kabul) = v["ci"], v["eol"]
    return {
        "vaka": f"{m['ad']} — pasif keşif ({alan})",
        "brifing": v["brifing"],
        "v": v, "m": m, "alan": alan, "kalip": kalip, "satirlar": satirlar, "hedef_ad": hedef_ad,
        "web_adlar": web_adlar, "gizli": gizli, "sertler": sertler, "bayrak_html": bayrak,
        "diger_epostalar": diger_epostalar, "sayi_hatalari": {str(k): t for k, t in hatalar.items()},
        "gun": u.gun(rng),
        "metin": {
            "musteri": m["ad"], "alan": alan, "web": v["web"], "csv": v["csv"], "ilan": v["ilan"],
            "ct": v["ct"], "hedef_ad": hedef_ad, "hedef_unvan": v["bt_tr"],
        },
        "cevaplar": {
            "eposta": hedef_eposta, "ci": ci, "eol": [eol_ad.lower()] + eol_kabul, "sayi": benzersiz,
            "gizli": [f"{gizli}.{alan}"], "bayrak": bayrak,
        },
    }


def _html(s: dict) -> str:
    v, alan, m = s["v"], s["alan"], s["m"]
    baglar = "\n".join(f'    <li><a href="https://{a}.{alan}/">{a}</a></li>' for a in s["web_adlar"])
    return f"""<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <title>{m['ad']} — Ana Sayfa</title>
  <meta name="description" content="{m['ad']} resmi web sitesi">
</head>
<body>
  <h1>{m['ad']}</h1>
  <p>{m['sektor'].capitalize()} alanında yıllardır hizmetinizdeyiz. Sorularınız için bize yazın.</p>
  <ul>
    <li><a href="https://www.{alan}/">Ana sayfa</a></li>
{baglar}
  </ul>
  <h2>İletişim</h2>
  <p>Genel: bilgi@{alan} · Basın: iletisim@{alan} · Telefon: 0850 000 00 00</p>
  <footer>© 2026 {m['ad']}. Teknik sorunlar için BT birimimize ulaşın.</footer>
  <!-- build-kimligi: {s['bayrak_html']} (yayin oncesi silinecek) -->
</body>
</html>
"""


def yaz(lab: Path, s: dict) -> None:
    v, alan, m = s["v"], s["alan"], s["m"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} için toplanmış KURGUSAL açık kaynak çıktıları. Gerçek hiçbir siteye sorgu yapılmaz.\n\n"
          f"  {v['web']}/index.html   şirket ana sayfasının kopyası\n"
          f"  {v['csv']}   herkese açık çalışan listesi (e-posta sütunu eksik olan biri var)\n"
          f"  {v['ilan']}   yayınlanmış iş ilanı\n"
          f"  {v['ct']}   sertifika şeffaflık kaydının (crt.sh benzeri) JSON çıktısı\n")
    u.yaz(lab / v["web"] / "index.html", _html(s))
    satir = ["ad_soyad,unvan,eposta"] + [f"{a},{b},{c}" for a, b, c in s["satirlar"]]
    satir.insert(1, f"{s['hedef_ad']},{v['bt_unvan']},")
    u.yaz(lab / v["csv"], "\n".join(satir) + "\n")
    u.yaz(lab / v["ilan"], v["ilan_f"](alan, v["ci"], v["eol"][0]))
    u.yaz(lab / v["ct"], json.dumps(s["sertler"], indent=2, ensure_ascii=False) + "\n")


def _sayi_hata(g, beklenen, b):
    return b.senaryo["sayi_hatalari"].get(str(g))


def _eposta_hata(g, beklenen, b):
    if g in [x.lower() for x in b.senaryo["diger_epostalar"]]:
        return "E-posta kalıbı bu değil. Listedeki diğer çalışanların adreslerine bak; hepsi aynı kalıbı izliyor."
    if "@" not in g:
        return "Tam e-posta adresini yaz (@alan dahil)."
    return None


def _eol_hata(g, beklenen, b):
    ad = str(beklenen).rsplit(" ", 1)[0]
    if g and g in ad:
        return "Adını doğru buldun ama sürümünü de yaz (örn. 'ad 1.2'): destek ömrü sürüme bağlı."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    v, alan = s["v"], s["alan"]
    eposta = o.sh(
        f"python3 - <<'PY'\nimport csv\nsatirlar = list(csv.DictReader(open('{v['csv']}')))\n"
        "tam = [r for r in satirlar if r['eposta']][0]\n"
        "ad, soy = tam['ad_soyad'].lower().split()\n"
        "yerel = tam['eposta'].split('@')[0]\n"
        "alan = tam['eposta'].split('@')[1]\n"
        "kalip = {f'{ad}.{soy}': lambda a, s: f'{a}.{s}', f'{ad[0]}.{soy}': lambda a, s: f'{a[0]}.{s}',\n"
        "         f'{ad}{soy}': lambda a, s: f'{a}{s}'}[yerel]\n"
        "for r in satirlar:\n"
        "    if not r['eposta']:\n"
        "        a, s = r['ad_soyad'].lower().split()\n"
        "        print(kalip(a, s) + '@' + alan)\nPY", lab)
    ci = o.sh(f"grep -oiE 'jenkins|gitlab ci|teamcity' {v['ilan']} | head -1", lab)
    eol = o.sh(f"grep -oE '(Magento|Apache Tomcat|Windows Server) [0-9][0-9.]*( R2)?' {v['ilan']} | head -1", lab)
    sayi = o.sh(f"python3 -c \"import json;n=set(x for e in json.load(open('{v['ct']}')) for x in e['name_value'].split('\\n'));"
                f"print(len([x for x in n if x!='{alan}' and not x.startswith('*')]))\"", lab)
    gizli = o.sh(f"python3 -c \"import json,re;n=set(x for e in json.load(open('{v['ct']}')) for x in e['name_value'].split('\\n'));"
                 f"h=open('{v['web']}/index.html').read();"
                 f"print(*[x for x in n if not x.startswith('*') and x!='{alan}' and x not in h])\"", lab)
    bayrak = o.sh(f"grep -o 'FLAG{{[^}}]*}}' {v['web']}/index.html", lab)
    return {1: o.secmeli_cevap(SEVIYE, s, lab, 1), 2: eposta, 3: ci, 4: eol, 5: sayi, 6: gizli, 7: bayrak,
            8: o.secmeli_cevap(SEVIYE, s, lab, 8)}


ADIMLAR = [
    Adim("Keşif: pasif ve aktif", """
Bir sızma testinin en uzun ve en belirleyici aşaması **keşiftir** (reconnaissance): hedef hakkında
bilgi toplamak. İki türlüdür:

- **Pasif keşif**: hedefe hiç dokunmadan, herkese açık kaynaklardan (arama motorları, kayıt defterleri,
  arşivler, kamuya açık listeler) bilgi toplamak. Hedef bunu fark etmez, çünkü ona hiçbir paket gitmez.
- **Aktif keşif**: hedefe doğrudan paket göndermek (port taramak, web sitesini kelime listesiyle
  denemek). Hızlı ve kesindir ama hedefin loglarına iz bırakır.

Profesyoneller **her zaman pasifle başlar**: bedavadır, görünmezdir ve sonra aktif aşamada nereye
bakacaklarını daraltır. Bu bölümde yalnızca pasif keşif yapacaksın.

**Hacker gözüyle:** Kırmızı takım (red team) pasif keşfi sever, çünkü savunmacıya hiçbir alarm
düşürmez. Savunma tarafında bunun anlamı: dışarıdan bakan biri senin hakkında ne görüyor, bunu
önce sen bilmelisin.
"""),
    Adim("Saldırı yüzeyi ve OSINT", """
Keşfin amacı **saldırı yüzeyini** haritalamaktır: hedefin dışarıya açık her noktası. Alan adları ve alt
alan adları, IP aralıkları, açık portlar ve servisler, kullanılan yazılımlar ve sürümleri, çalışanların
e-posta adresleri... Her biri potansiyel bir giriş noktasıdır.

**OSINT** (Open Source Intelligence, açık kaynak istihbaratı) bu bilgiyi herkese açık kaynaklardan
toplama işidir:

- Arama motorları ve Google dork'ları (`site:`, `filetype:`, `intitle:index.of` gibi operatörler)
- Meslek ağları (çalışan isimleri, roller, kullanılan teknolojiler)
- Kod depoları (yanlışlıkla yüklenmiş anahtarlar ve ayarlar)
- Sertifika şeffaflık kayıtları, internet arşivleri, Shodan benzeri cihaz arama motorları

Laboratuvardaki kurgusal OSINT dosyalarına bir göz at:
""", komut="ls -R", sonra="""
Gerçek hayatta bu dosyalar internetten gelirdi; burada Selin hazır koydu. Sırayla hepsine bakacağız.
"""),
    Adim("Şirketin kendi web sayfası", """
Şirketin kendi sayfası bile ipucu doludur: iletişim adresleri, başka alt alan adlarına bağlantılar,
teknoloji izleri ve bazen sayfa kaynağında unutulmuş yorum satırları (`<!-- ... -->`). Tarayıcıda
görünmezler ama "sayfa kaynağını göster" ile (ya da `cat` ile) okunurlar.
""", komut="cat <<web>>/index.html", sonra="""
Gördüklerini ayır: hangi adresler **görünür metinde**, hangileri bağlantılarda, hangisi yorum
satırında? Bu sayfa çok yardımsever bir kaynak: hangi alt alan adlarının var olduğunu zaten
söylüyor. Sertifika kaydıyla karşılaştıracağız.
"""),
    Adim("İnsanlar: çalışan listesi", """
Bir kurumun çalışanları ve e-posta kalıbı, hem sosyal mühendisliğin (insanları kandırarak bilgi almanın)
hem de ileride parola denemelerinin hammaddesidir. Meslek ağlarından ve kurumun kendi sayfalarından
derlenen bir liste şöyle görünür:
""", komut="head -n 4 <<csv>>", sonra="""
E-posta adreslerinde bir **kalıp** var: `ad.soyad`, `a.soyad` ya da `adsoyad` gibi. Listede e-postası
eksik biri varsa, kalıbı diğerlerinden çıkararak adresini tahmin edebilirsin. Savunmacı açısından
bakınca: kalıbı bilen biri, bütün kuruma sahte (phishing) e-posta hazırlayabilir.
"""),
    Adim("İş ilanları: kurumun teknoloji itirafı", """
İş ilanları, kurumun hangi teknolojileri kullandığını (ve hangi sürümde kaldığını) isteyerek ele verir.
"Jenkins ile CI/CD", "Windows Server 2008 R2 sunucuları" gibi ifadeler, saldırgana hangi sistemleri ve
hangi zayıflıkları arayacağını söyler. Destek ömrü bitmiş bir sürüm, artık güvenlik yaması almıyor
demektir.
""", komut="cat <<ilan>>", sonra="""
Okurken iki liste tut: **araçlar** (hangi sistemler var?) ve **sürümler** (hangisi eskimiş?). İlk
liste saldırı yüzeyini, ikinci liste en zayıf halkayı gösterir.
"""),
    Adim("Sertifika şeffaflığı", """
Bir web sitesine HTTPS sertifikası verildiğinde, sertifika otoritesi bunu herkese açık **şeffaflık
kayıtlarına** (Certificate Transparency, CT) yazar. Sertifikalar alt alan adlarını içerir; yani bu
kayıtlar bir kurumun alt alan adı listesini DNS'e hiç dokunmadan verir. `crt.sh` bu kayıtları arayan
herkese açık bir sitedir. Siz kurgusal bir çıktıyla çalışıyorsunuz:
""", komut="head -n 22 <<ct>>", sonra="""
`name_value` alanı sertifikadaki bütün adları, satır sonuyla (`\\n`) ayrılmış halde taşır. Aynı ad,
sertifika yenilendikçe tekrar eder; `*.alan` bir **joker** sertifikadır (bütün alt alanlara geçerli)
ve kendisi bir alt alan adı değildir.

**Hacker gözüyle:** Sen hedefe değil kayıt defterine sorarsın; hedef hiçbir paket görmez. Bu yüzden
tamamen pasiftir. Savunma dersi: sertifika alırken adı kayda geçer; "gizli" bir alt alan adı yoktur.
"""),
    Adim("Dork'lar ve sorumlu OSINT", """
Arama motorlarında operatörlerle çok daha hassas arama yapılır (gerçek bir arama yapmayacağız, sadece
formatı tanı):

```
site:ornek.com filetype:pdf          sitedeki PDF dosyaları
site:ornek.com intitle:index.of      açık dizin listeleri
site:ornek.com inurl:admin           adresinde "admin" geçen sayfalar
```

**OSINT, yalnızca açık veriyi okuduğun sürece yasaldır.** Bulduğun bir kimlik bilgisiyle bir hesaba
girmeyi denemek (TCK 243), kişisel veriyi toplayıp saklamak veya yayınlamak (KVKK), bir kişinin ev adresini
bulup yaymak (doxxing) suçtur. Etik hacker bilgiyi yalnızca **yetkilendirilmiş testin kapsamında** ve rapor
için kullanır.
""", calistir=False),
]

GOREVLER = [
    Gorev("Aşağıdakilerden hangisi **aktif** keşiftir (hedefe doğrudan paket gönderir ve iz bırakır)?",
          Secmeli([
              ("Kurumun sertifika kayıtlarını herkese açık bir şeffaflık kaydında aramak",
               "Bu pasiftir: sen üçüncü taraf bir kayda sorarsın, hedefe hiçbir paket gitmez."),
              ("Çalışanların herkese açık meslek ağı profillerini okumak",
               "Pasif: veri zaten herkese açıktır ve hedefin sunucusuna hiçbir bağlantı kurulmaz."),
              ("Hedefin IP aralığına nmap ile port taraması yapmak",
               "Doğru. Port taraması hedefin sunucularına paket gönderir; güvenlik duvarı ve IDS loglarına düşer."),
              ("Bir arşiv sitesinde şirketin eski web sayfası kopyalarını incelemek",
               "Pasif: arşiv sitesine bakarsın, hedefin kendi sunucusuna değil."),
          ], dogru=2),
          ("Ölçüt: hedefin kendi sistemleri bu işlemi görüyor mu?",
           "Dört seçenekten üçü başkasının tuttuğu kayıtları okur; biri hedefin sunucusuna paket yollar.",
           "Port taramak, hedefin cevap verip vermediğini görmek için ona doğrudan bağlanmaktır."),
          puan=20, baslik="Pasif mi aktif mi"),
    Gorev("<<csv>> dosyasında <<hedef_ad>> (<<hedef_unvan>>) için e-posta adresi yazılmamış. "
          "Diğer çalışanların kalıbına göre adresi ne olmalı?",
          Metin("eposta", sik_hatalar=_eposta_hata, bicim="e-posta adresi"),
          ("Listede e-postası dolu olan satırlar var. Adresle ad-soyad arasındaki ilişkiye bak.",
           "`cat <<csv>>` ile diğer satırlara bak: adres, ad ve soyadın hangi biçimle birleştirilmesiyle çıkıyor? "
           "Türkçe karakter yok, hepsi küçük harf.",
           "Kalıbı çıkardıktan sonra aynısını <<hedef_ad>> için uygula ve sonuna @<<alan>> ekle."),
          puan=25, baslik="E-posta kalıbı"),
    Gorev("<<ilan>> içinde, kuruluşun sürekli entegrasyon (CI/CD) hatları için kullandığı aracın adı nedir?",
          Metin("ci", bicim="araç adı"),
          ("İlandaki \"sorumluluklar\" ya da \"iş tanımı\" bölümünü oku.",
           "CI/CD'yi anlatan maddeyi bul: hangi araç \"ile\" ya da \"üzerinde\" kullanılıyor?",
           "`grep -i -E 'ci/cd|entegrasyon|otomatik' <<ilan>>` ilgili satırı getirir."),
          puan=20, baslik="Kullanılan araç"),
    Gorev("<<ilan>> bir yazılımın **sürümünü açıkça** yazıyor ve o sürüm artık güvenlik yaması almıyor "
          "(destek ömrü bitmiş). Yazılımın adını ve sürümünü yaz (örn. `ad 1.2`).",
          Metin("eol", sik_hatalar=_eol_hata, bicim="ad ve sürüm"),
          ("İlanda sürüm numarası içeren bir ifade var; kurumun \"şu an kullandığı\" ya da \"geçmek "
           "istediği\" eski sistemi anlatıyor.",
           "Sayı içeren satırları süz: `grep -n '[0-9]' <<ilan>>`",
           "Sürüm numarası geçen satırda yazılımın adı ve sürümü art arda yazılı."),
          puan=25, baslik="Eskimiş sürüm"),
    Gorev("<<ct>> kaydında, `<<alan>>` altında **kaç farklı alt alan adı** var? "
          "(Ana alan adını ve `*.` jokerini sayma; tekrarları bir kez say.)",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Her sertifikanın `name_value` alanında bir ya da birkaç ad var; aynı ad tekrar edebilir.",
           "Python ile `json.load` yapıp tüm adları bir kümede (set) topla; küme zaten tekrarları atar.",
           "`python3 -c \"import json;n=set(x for e in json.load(open('<<ct>>')) for x in e['name_value'].split('\\n'));"
           "print(sorted(n))\"` ile listele, sonra elle ele."),
          puan=30, baslik="Sertifikadaki alt alan adları"),
    Gorev("<<ct>> kaydında olup <<web>>/index.html sayfasında **hiçbir yerde geçmeyen** alt alan adı hangisi? "
          "(Tam adı yaz.)",
          Metin("gizli", son_ekleri_at=(".",), bicim="tam alt alan adı"),
          ("Sayfa ve kayıt aynı adların çoğunu paylaşıyor; kayıtta fazladan bir ad var.",
           "Kaydın adlarını tek tek çıkar ve sayfada `grep` ile ara; bulunamayan ad aradığındır.",
           "Adlardan `www` ve sayfada bağlantısı olanları ele; ismi `test-`, `eski-` gibi bir şeyle başlayan ad kalır."),
          puan=30, baslik="Sayfada olmayan ad"),
    Gorev("Şirket sayfasının kaynağında, yayın öncesi silinmesi unutulmuş bir yorum satırında bayrak var. Bul.",
          Bayrak("bayrak"),
          ("Tarayıcıda görünmeyen ama sayfa kaynağında duran şeyler: yorum satırları.",
           "HTML yorumları `<!--` ile başlar.",
           "`grep -n '<!--' <<web>>/index.html`"),
          puan=20, baslik="Unutulan yorum"),
    Gorev("Bir OSINT çalışmasında çalışan listesindeki bir kişinin e-posta adresi, internette sızdırılmış bir "
          "parola listesinde de çıkıyor. Etik hacker olarak ne yaparsın?",
          Secmeli([
              ("Raporuna \"çalışan kimlik bilgisi sızıntısı\" olarak yazar, o parolayla hesaba girmeyi denemezsin",
               "Doğru. Bulgu raporlanır; kimlik bilgisini kullanmak yetkisiz erişimdir (TCK 243), test kapsamına girmiyorsa suçtur."),
              ("Hesabın kime ait olduğunu kanıtlamak için parolayı bir kez denersin, sonra çıkarsın",
               "Tek bir deneme bile yetkisiz erişimdir. 'Sadece bir kere' hukuken fark yaratmaz."),
              ("Listeyi çalışanın yöneticisine e-postayla ve ayrıntılarıyla birlikte, yetkin olmasa da iletirsin",
               "Sızıntı verisini yetkisiz kişilere dağıtmak yeni bir veri ihlali oluşturur; kanal Selin ve müşteri güvenlik sorumlusudur."),
              ("Listeyi ileride kullanmak üzere kendi arşivinde saklarsın",
               "Kişisel veriyi gerekçesiz saklamak KVKK'ya aykırıdır; yalnızca kapsam ve rapor için gerekeni tut."),
          ], dogru=0),
          ("Görmek ile kullanmak arasındaki farkı düşün.",
           "Yetkin, test kapsamındaki bir sistem değilse hesabına girmek ne sayılır?",
           "Bilgiyi güvenli kanalla raporla; kullanma ve gereksiz saklama."),
          puan=25, baslik="Sorumlu OSINT"),
]

SEVIYE = Seviye(
    kimlik="c04b01",
    cilt=4,
    bolum=1,
    baslik="Keşif Metodolojisi ve OSINT",
    brifing="""
**<<musteri>>** için pasif keşif yapıyorsun. Selin sana şirketin web sayfası kopyasını, çalışan listesini,
iş ilanını ve sertifika şeffaflık kaydını verdi. Hepsi kurgusal ve bu laboratuvarda. Hedefe tek paket
bile göndermeden ne öğrenebildiğini göstermeni istiyor.
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Pasif keşif bir sızma testinin görünmez yarısıdır: tek paket göndermeden e-posta kalıbı, kullanılan araçlar,
eskimiş sürümler ve unutulmuş alt alan adları ortaya çıktı. Bir saldırgan bunları kimseye fark ettirmeden
toplayabilir. Savunma tarafının dersi: kendi dijital ayak izini düzenli kontrol et, iş ilanlarında sürüm
numarası yazma, yayın öncesi sayfa kaynağını temizle, çalışanları phishing'e karşı eğit ve unutma: sertifika
alınan her ad, kamuya açık kayda düşer.
""",
    gercek_hayat="""
- **Meslek ağı ve iş ilanı bilgisi:** Gerçek sızma testi raporlarında ve kırmızı takım çalışmalarında, çalışan
  listelerinin ve iş ilanlarındaki teknoloji ifadelerinin saldırı hazırlığında kullanıldığı sık görülür. Önleme:
  ilanlarda gereksiz sürüm bilgisi vermemek; tespit: kendi adına yapılan düzenli OSINT taraması ve çalışan
  farkındalığı eğitimi.
- **Kod depolarında unutulan anahtarlar:** Geliştiricilerin API anahtarlarını ve parolaları yanlışlıkla genel
  kod depolarına yüklemesi o kadar yaygındır ki, kod barındırma platformları bu tür gizli bilgileri otomatik
  tarayan özellikler sundu. Önleme: gizli bilgileri koddan ayır, depo taraması kullan; tespit: sızan anahtarı
  hemen iptal edip yenisini üret.
- **Sertifika şeffaflığı iki yönlü çalışır:** Sertifika şeffaflık kayıtları, bir alan adı için izinsiz sertifika
  verilirse alan sahibinin bunu fark edebilmesini sağlamak için kuruldu; aynı kayıtlar saldırganın alt alan adı
  keşfine de yarar. Savunma: kendi alan adlarını bu kayıtlarda izleyen bir uyarı kur.
""",
    sure_hedef_dk=25,
)
