"""Cilt 8 · Bölüm 1 — Metodoloji: İşi Sisteme Bağlamak.

Beceri: bir testin faaliyetlerini pentest aşamalarına (PTES çizgisinde: kapsam, keşif, zafiyet analizi,
istismar, istismar sonrası, raporlama) eşlemek; test günlüğünden kapsam dışına çıkılıp çıkılmadığını
saptamak; günlük ve notlarla "bunu test ettiniz mi?" sorusuna kanıtla cevap vermek; yanlış pozitifi
(doğrulanamayan tarama bulgusunu) ayırt etmek; MITRE ATT&CK ve metodolojinin neden gerekli olduğunu bilmek.

Vakalar: e-ticaret, hastane portalı, banka internet şubesi, lojistik. Her vakada faaliyet metinleri,
host adları, günlük ve tarama özeti farklıdır. Hiçbir saldırı yükü ya da araç kullanımı yoktur.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

ASAMALAR = ["kapsam", "kesif", "zafiyet", "istismar", "sonrasi", "rapor"]
ASAMA_ADI = {"kapsam": "Sözleşme ve kapsam", "kesif": "Keşif", "zafiyet": "Zafiyet analizi", "istismar": "İstismar",
             "sonrasi": "İstismar sonrası", "rapor": "Raporlama"}

VAKALAR = {
    "pazarix": {
        "ad": "Pazarix — e-ticaret sitesi testi", "musteri": "Pazarix", "alan": "pazarix.lab", "panel": "admin",
        "kisi": "Tuncay Bey (sistem yöneticisi)",
        "ic": ["magaza", "api", "admin", "destek"], "dis": ["posta", "muhasebe", "eski"],
        "faaliyet": {
            "kapsam": "Pazarix ile imzalanan kapsam ve kurallar belgesinin madde madde gözden geçirilmesi",
            "kesif": "Mağaza sitesinin alt alan adlarının ve açık servislerinin kamuya açık kaynaklarla haritalanması",
            "zafiyet": "Haritadaki servis sürümlerinden olası zafiyetlerin bir listeye yazılması",
            "istismar": "Listedeki bir sipariş sorgusu açığının test hesabıyla gerçekten çalıştığının kontrollü biçimde doğrulanması",
            "sonrasi": "Test hesabıyla başka müşterilerin hangi sipariş verilerine ulaşılabildiğinin ve bunun iş etkisinin gösterilmesi",
            "rapor": "Bulguların yönetici özeti ve teknik bulgu sayfaları hâlinde raporlanması",
        },
    },
    "medora": {
        "ad": "Medora Sağlık — hasta portalı testi", "musteri": "Medora Sağlık", "alan": "medora.lab", "panel": "portal-yonetim",
        "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
        "ic": ["randevu", "portal-yonetim", "doktor", "sonuclar"], "dis": ["goruntu", "pacs", "personel"],
        "faaliyet": {
            "kapsam": "Medora ile imzalanan kapsam belgesinde hasta verisine dokunulmayacağı maddesinin teyit edilmesi",
            "kesif": "Randevu portalının dışarıdan görünen alan adlarının ve servislerinin haritalanması",
            "zafiyet": "Servis sürümlerinden ve giriş akışından olası zafiyetlerin sıralanması",
            "istismar": "Giriş sayfasındaki bir yetki sorununun yalnızca test kullanıcısıyla çalıştığının doğrulanması",
            "sonrasi": "Test kullanıcısıyla hangi sahte randevu kayıtlarına ulaşıldığının ve bunun etkisinin gösterilmesi",
            "rapor": "Hastane yönetimi için sade bir özet ve BT ekibi için teknik rapor hazırlanması",
        },
    },
    "ferah": {
        "ad": "Ferah Bank — internet şubesi testi", "musteri": "Ferah Bank", "alan": "ferahbank.lab", "panel": "yonetim",
        "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)",
        "ic": ["sube", "api", "yonetim", "kampanya"], "dis": ["swift", "atm", "intranet"],
        "faaliyet": {
            "kapsam": "Ferah Bank ile test penceresinin, kapsam listesinin ve yasaklı tekniklerin yazılı teyidi",
            "kesif": "İnternet şubesinin dışarıdan görünen servislerinin ve uç noktalarının haritalanması",
            "zafiyet": "Uç noktalardaki iş kurallarından olası mantık zafiyetlerinin bir listeye yazılması",
            "istismar": "Listedeki bir limit kontrolünün test hesabıyla gerçekten aşılabildiğinin kontrollü doğrulanması",
            "sonrasi": "Aşılan limitle test hesabında hangi işlemlerin yapılabildiğinin ve iş etkisinin gösterilmesi",
            "rapor": "Bulgu önem dereceleri ve düzeltme önerileriyle bir pentest raporunun yazılması",
        },
    },
    "kuzgun": {
        "ad": "Kuzgun Lojistik — depo ve takip sistemi testi", "musteri": "Kuzgun Lojistik", "alan": "kuzgun.lab", "panel": "depo-panel",
        "kisi": "Serdar Bey (IT sorumlusu)",
        "ic": ["takip", "depo-panel", "bayi", "api"], "dis": ["gps", "muhasebe", "eski-depo"],
        "faaliyet": {
            "kapsam": "Kuzgun ile hangi depoların ve sistemlerin test edileceğini belirleyen kapsam belgesinin imzalanması",
            "kesif": "Kargo takip sitesinin alt alan adlarının ve açık servislerinin haritalanması",
            "zafiyet": "Takip sorgusu ve bayi paneli için olası zafiyetlerin bir listeye yazılması",
            "istismar": "Takip sorgusundaki bir yetki zafiyetinin test kaydıyla çalıştığının kontrollü biçimde doğrulanması",
            "sonrasi": "Bir test kaydıyla başka bayilerin hangi sevkiyat bilgilerine ulaşılabildiğinin ve etkisinin gösterilmesi",
            "rapor": "Yönetici özeti ve teknik ayrıntılarla birlikte bulguların raporlanması",
        },
    },
}
ANAHTAR = [("kapsam", "kapsam"), ("haritalan", "kesif"), ("olası", "zafiyet"), ("doğrulan", "istismar"),
           ("etki", "sonrasi"), ("rapor", "rapor")]


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    sira = list(ASAMALAR)
    rng.shuffle(sira)                                   # faaliyet numaraları karışık gelir
    eslesme = {i + 1: a for i, a in enumerate(sira)}
    ic = [f"{x}.{v['alan']}" for x in v["ic"]]
    dis = [f"{x}.{v['alan']}" for x in rng.sample(v["dis"], rng.randint(1, 2))]
    panel_host = f"{v['panel']}.{v['alan']}"
    log = []
    saatler = set()

    def saat():
        while True:
            t = f"{rng.randint(9, 17):02d}:{rng.randint(0, 59):02d}"
            if t not in saatler:
                saatler.add(t)
                return t
    gun = u.gun(rng)
    notlar = ["port taraması yapıldı", "giriş akışı elle incelendi", "sürüm başlıkları not edildi", "parametre davranışı denendi",
              "hata sayfası incelendi", "oturum süresi kontrol edildi"]
    for h in ic:
        for _ in range(1 if h == panel_host else rng.randint(1, 2)):
            log.append((saat(), h, rng.choice(notlar)))
    for h in dis:
        for _ in range(rng.randint(1, 2)):
            log.append((saat(), h, rng.choice(notlar)))
    log.sort(key=lambda x: x[0])
    panel_saat = next(t for t, h, _ in log if h == panel_host)
    dis_satir = sum(1 for _, h, _ in log if h in dis)
    ozet = []
    yp = rng.randint(2, 4)
    durumlar = ["DOGRULANAMADI"] * yp + ["DOGRULANDI"] * rng.randint(3, 5)
    rng.shuffle(durumlar)
    bulgular = ["sürüm başlığına göre eski bir bileşen olabilir", "dizin listeleme açık görünüyor", "parola sıfırlama süresiz olabilir",
                "yönetim paneli dışarıdan erişilebilir", "hata sayfası ayrıntı veriyor", "yedek dosya adı tahmin edilebilir",
                "çerez bayrakları eksik görünüyor", "başlıklarda güvenlik ayarı eksik"]
    rng.shuffle(bulgular)
    ozet = list(zip(range(1, len(durumlar) + 1), bulgular, durumlar))
    faal = {i: v["faaliyet"][a] for i, a in eslesme.items()}
    return {
        "vaka": v["ad"], "v": v, "faal": faal, "ic": ic, "dis": dis, "log": log, "gun": gun, "ozet": ozet, "panel_host": panel_host,
        "metin": {"musteri": v["musteri"], "kisi": v["kisi"], "panel": panel_host, "alan": v["alan"]},
        "cevaplar": {"eslesme": eslesme, "dis": dis_satir, "panel_saat": panel_saat, "yp": yp},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "proje" / "faaliyetler.csv", "no;faaliyet\n" + "".join(f"{i};{t}\n" for i, t in sorted(s["faal"].items())))
    u.yaz(lab / "proje" / "kapsam.txt",
          f"{v['musteri']} — test kapsamı (imzalı sözleşme eki)\n\nKAPSAM İÇİ:\n" + "".join(f"  - {h}\n" for h in s["ic"])
          + "\nKAPSAM DIŞI: bu listede olmayan her şey. Yasak teknikler: hizmet reddi, sosyal mühendislik, gerçek müşteri verisini indirme.\n")
    u.yaz(lab / "proje" / "kapsam_hostlari.txt", "".join(f"{h}\n" for h in s["ic"]))
    u.yaz(lab / "proje" / "test_gunlugu.log", "".join(
        f"{s['gun']:%Y-%m-%d} {t} {h} {n}\n" for t, h, n in s["log"]))
    u.yaz(lab / "proje" / "tarama_ozeti.txt", "no;bulgu;durum\n" + "".join(f"{i};{b};{d}\n" for i, b, d in s["ozet"]))
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']}\n\nproje/faaliyetler.csv      testte yapılan 6 faaliyet (numaralı)\n"
          "proje/kapsam.txt           imzalı kapsam; proje/kapsam_hostlari.txt aynı listenin düz hâli\n"
          "proje/test_gunlugu.log     test günlüğü (saat, host, not)\n"
          "proje/tarama_ozeti.txt     tarama bulguları ve doğrulama durumları\n"
          "eslesme.txt                SENİN dolduracağın dosya (görev 1)\n")


def _norm_asama(metin: str) -> str | None:
    n = o.ascii_norm(metin)
    for a, anah in (("sonrasi", "sonras"), ("kapsam", "kapsam"), ("kapsam", "sozlesme"), ("kesif", "kesif"),
                    ("zafiyet", "zafiyet"), ("istismar", "istismar"), ("rapor", "rapor")):
        if anah in n:
            return a
    return None


def _eslesme(b) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "eslesme.txt"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `eslesme.txt` yok. Her satıra `<faaliyet no> <aşama>` yaz (aşama: kapsam, kesif, "
                            "zafiyet, istismar, sonrasi, rapor).")
    verilen = {}
    for satir in yol.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\s*(\d+)\s*[:=\-\s]+\s*(.+?)\s*$", satir)
        if m:
            a = _norm_asama(m.group(2))
            if a:
                verilen[int(m.group(1))] = a
    beklenen = s["cevaplar"]["eslesme"]
    if len(verilen) < len(beklenen):
        return Sonuc(False, f"{len(beklenen)} faaliyetin hepsi için satır yazmalısın; şu an {len(verilen)} geçerli satır var. "
                            "Biçim: `1 kesif`.", yakin=len(verilen) > 0)
    dogru = sum(1 for i, a in beklenen.items() if verilen.get(i) == a)
    if dogru == len(beklenen):
        return Sonuc(True, "Faaliyetlerin hepsini doğru aşamaya eşledin.")
    yanlis = [str(i) for i, a in sorted(beklenen.items()) if verilen.get(i) != a]
    return Sonuc(False, f"{dogru}/{len(beklenen)} doğru. Yanlış eşlenen faaliyet numaraları: {', '.join(yanlis)}. "
                        "Aşamaların sırasını düşün: kapsam → keşif → zafiyet analizi → istismar → istismar sonrası → rapor.",
                 yakin=dogru > 0)


def coz(lab: Path, s: dict) -> dict:
    komut = ("awk -F';' 'NR>1{t=$2; a=\"?\"; "
             "if (t ~ /kapsam/) a=\"kapsam\"; else if (t ~ /haritalan/) a=\"kesif\"; else if (t ~ /olası/) a=\"zafiyet\"; "
             "else if (t ~ /doğrulan/) a=\"istismar\"; else if (t ~ /etki/) a=\"sonrasi\"; else if (t ~ /rapor/) a=\"rapor\"; "
             "print $1, a}' proje/faaliyetler.csv > eslesme.txt")
    o.sh(komut, lab)
    dis = o.sh("grep -vFf proje/kapsam_hostlari.txt proje/test_gunlugu.log | wc -l", lab)
    saat = o.sh(f"grep ' {s['panel_host']} ' proje/test_gunlugu.log | cut -d' ' -f2", lab)
    yp = o.sh("grep -c DOGRULANAMADI proje/tarama_ozeti.txt", lab)
    cozum = {1: "", 2: dis, 3: saat, 4: yp}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Amatör ile profesyonel", """
Amatör rastgele dener; profesyonel **tekrarlanabilir bir süreç** izler. Süreç sana iki şey kazandırır:
hiçbir şeyi atlamazsın ve işini **kanıtlayabilirsin**. Bir pentest'in aşamaları, kitabın cilt yapısıyla
aynıdır: **kapsam** (sözleşme, izin) → **keşif** → **zafiyet analizi** → **istismar** (açığı doğrulama)
→ **istismar sonrası** (etkiyi gösterme) → **raporlama**. Sektörün ortak çerçeveleri vardır: **PTES**
(uçtan uca süreç), **OWASP WSTG** (web test kontrol listesi), **OSSTMM** ve **MITRE ATT&CK** (saldırgan
tekniklerinin kataloğu).

Önce bu vakadaki faaliyet listesine bak. Hangi faaliyet hangi aşamada?
""", komut="cat proje/faaliyetler.csv"),
    Adim("Kapsam: izin yalnızca listedeki kadar", """
İlk aşama hep **kapsam ve sözleşme**dir: neyi, ne zaman, hangi tekniklerle test edeceğin yazılı
olmalı. Kapsam dışı bir sisteme dokunmak, genel bir izin olsa bile izinsiz erişimdir. Kapsama bak:
""", komut="cat proje/kapsam.txt"),
    Adim("Günlük tutmak", """
Metodolojinin ikinci faydası **günlük**tür. Test sırasında her faaliyetin saati, hedefi ve notu
kaydedilir. Müşteri "şu alanı test ettiniz mi?" dediğinde cevap günlükte durur. İlk satırlara bak:
""", komut="head -4 proje/test_gunlugu.log"),
    Adim("Kapsam denetimi: kapsam dışına çıktık mı?", """
`grep -F` metni olduğu gibi (desen değil, düz yazı) arar; `-f dosya` aranacakları dosyadan okur;
`-v` eşleşmeyenleri gösterir. Yani şu komut, günlükte **kapsam listesinde olmayan** hostları yazar:
""", komut="grep -vFf proje/kapsam_hostlari.txt proje/test_gunlugu.log", sonra="""
Çıkan her satır, kapsam dışı bir sisteme yapılmış bir dokunuş demek. Gerçek bir testte bu, sözleşme
ihlalidir ve müşteriye hemen bildirilmesi gerekir. Günlük yoksa bunu **göremezsin**.
"""),
    Adim("Zafiyet analizi ≠ istismar", """
Tarama aracı bir açığın **olabileceğini** söyler; istismar aşaması onun **gerçekten** işe yarayıp
yaramadığını kontrollü biçimde doğrular. Bu yüzden iki ayrı aşamadır. Tarama özetinin durum
sütununa bak:
""", komut="head -5 proje/tarama_ozeti.txt", sonra="""
`DOGRULANAMADI`, yanlış pozitif (false positive) demektir: araç bir uyarı verdi ama açık gerçek
çıkmadı. Doğrulanmamış bir uyarıyı rapora "açık" diye yazmak raporunun güvenilirliğini bitirir.

**Hacker gözüyle:** Metodoloji sıkıcı görünür ama seni iki şeyden kurtarır: bir şeyi atlamaktan ve
kanıtsız kalmaktan. MITRE ATT&CK ise saldırı ve savunmayı aynı dilde buluşturur; mor takımın aracıdır.
"""),
]

GOREVLER = [
    Gorev("`proje/faaliyetler.csv` içindeki 6 faaliyeti pentest aşamalarına eşle. Lab klasörüne `eslesme.txt` "
          "dosyası yaz; her satır `<faaliyet no> <aşama>` olsun (aşamalar: `kapsam`, `kesif`, `zafiyet`, `istismar`, "
          "`sonrasi`, `rapor`). Örn. `1 kesif`. Bitince `cevap 1` yaz.",
          Durum(_eslesme, cozum="Her faaliyeti aşamasına eşle: kapsam belgesi → kapsam; haritalama → kesif; olası zafiyet listesi → zafiyet; "
                "doğrulama → istismar; etki gösterme → sonrasi; raporlama → rapor."),
          ("Faaliyetin ne yaptığına bak: izin mi alıyor, haritalıyor mu, açık listeliyor mu, doğruluyor mu, etkisini mi gösteriyor, yoksa yazıyor mu?",
           "Sıra: kapsam → keşif → zafiyet analizi → istismar → istismar sonrası → raporlama. Her satıra `<no> <aşama>` biçiminde yaz; `nano eslesme.txt` ya da `echo` ile.",
           "Örnek dosya içeriği (numaralar sizin vakaya göre değişir):\n`1 kapsam`\n`2 rapor`\n... Hepsi için bir satır. Aşama adları: kapsam, kesif, zafiyet, istismar, sonrasi, rapor."),
          puan=60, baslik="Aşamalara eşle"),
    Gorev("Test günlüğünde (`proje/test_gunlugu.log`), kapsam listesinde **bulunmayan** hostlara yapılmış kaç "
          "satırlık dokunuş var?",
          Sayi("dis", sik_hatalar=lambda g, b, bg: "Sadece kapsam dışı hostların satırlarını say; kapsam içi satırlar dahil değil."
                if g.isdigit() and int(g) > b else None),
          ("Eğitimde kapsam listesiyle günlüğü karşılaştıran bir komut kullandın.",
           "`grep -vFf proje/kapsam_hostlari.txt proje/test_gunlugu.log` kapsam listesinde olmayan satırları gösterir.",
           "Aynı komutu `| wc -l` ile bitir: `grep -vFf proje/kapsam_hostlari.txt proje/test_gunlugu.log | wc -l`"),
          puan=40, baslik="Kapsam dışı dokunuşlar"),
    Gorev("Müşteri sana soruyor: \"<<panel>> yönetim panelini test ettiniz mi?\" Günlüğe göre bu host **hangi saatte** "
          "test edildi? (SS:DD biçiminde)",
          Metin("panel_saat", bicim="SS:DD (örn. 14:35)"),
          ("Cevap günlükte; host adını arat.",
           "`grep '<<panel>>' proje/test_gunlugu.log` ile satırı bul; saat ikinci alan.",
           "`grep ' <<panel>> ' proje/test_gunlugu.log | cut -d' ' -f2`"),
          puan=30, baslik="Günlük kanıttır"),
    Gorev("`proje/tarama_ozeti.txt` içinde **doğrulanamayan** (yanlış pozitif) kaç bulgu var?",
          Sayi("yp", sik_hatalar=lambda g, b, bg: "Başlık satırı (`durum`) sayıma dahil değil; sadece `DOGRULANAMADI` olanları say."
                if g.isdigit() and int(g) == b + 1 else None),
          ("Durum sütunundaki iki farklı değerden hangisini sayıyorsun?",
           "`grep` bir kelimeyi içeren satırları sayabilir: `-c` seçeneği sayıyı verir.",
           "`grep -c DOGRULANAMADI proje/tarama_ozeti.txt`"),
          puan=30, baslik="Yanlış pozitifler"),
    Gorev("Metodolojide zafiyet analizi ile istismar aşamalarının **ayrı** olmasının asıl nedeni nedir?",
          Secmeli([
              ("Zafiyet analizi açığın olabileceğini söyler; istismar gerçek olduğunu kanıtlar", "Doğru: uyarılar yanlış pozitif olabilir; kontrollü doğrulama, rapora yalnızca gerçek açıkları yazmanı sağlar."),
              ("İstismar aşaması her zaman daha uzun sürdüğü için ayrı bir aşamaya bölünmüştür", "Yanlış: süre bir sınıflandırma ölçütü değil; ayrımın nedeni, 'olası' ile 'kanıtlanmış' arasındaki farktır."),
              ("Zafiyet analizi yalnızca müşteri tarafından, istismar yalnızca pentester tarafından yapılır", "Yanlış: iki aşamayı da test ekibi yürütür; ayrım rol dağılımı değil, doğrulama düzeyidir."),
              ("İstismar aşamasına geçilince sözleşmedeki kapsam sınırları artık geçerli olmaz", "Yanlış: istismar da kapsam içinde kalır; kapsam aşılırsa izin biter."),
          ], dogru=0),
          ("Tarama özetinde 'DOGRULANAMADI' ne anlama geliyordu?",
           "Bir uyarının gerçek mi yoksa yanlış mı olduğunu hangi aşama ortaya çıkarır?",
           "Doğru şık, 'olabilir' ile 'kanıtlanmış' ayrımını anlatan şık."),
          puan=30, baslik="Neden iki aşama"),
    Gorev("MITRE ATT&CK nedir ve neden hem saldırı hem savunma tarafı için değerlidir?",
          Secmeli([
              ("Saldırgan teknikleri kataloğudur; saldırı ve savunmayı aynı dilde buluşturur", "Doğru: kırmızı takım teknikleri bu kataloğa göre planlar, mavi takım tespitlerini aynı kataloğa eşler."),
              ("Bir tarama aracıdır; hedefteki açıkları kendiliğinden bulup rapora yazar", "Yanlış: ATT&CK bir araç değil, bir bilgi tabanıdır."),
              ("Sızma testi sertifikalarının sınavlarında kullanılan resmî müfredat listesidir", "Yanlış: bir sınav müfredatı değil; sertifikalardan bağımsız bir teknik kataloğudur."),
              ("Bankaların uyması gereken, kurumun yayımladığı zorunlu bir yönetmeliktir", "Yanlış: ATT&CK bir düzenleme değil, sektörün ortak kullandığı bir çerçevedir."),
          ], dogru=0),
          ("Hem kırmızı hem mavi takım aynı kaynağı kullanırsa ne kazanılır?",
           "ATT&CK bir araç ya da yönetmelik değil; ne olduğunu hatırla: bir ... kataloğu.",
           "Doğru şık, 'saldırı ve savunmayı aynı dilde buluşturan katalog' diyen şık."),
          puan=30, baslik="MITRE ATT&CK"),
    Gorev("Metodoloji, bir müşteriyle çalışırken seni hangi **iki riskten** korur?",
          Secmeli([
              ("Bir şeyi atlamaktan ve yaptığın işi kanıtlayamamaktan", "Doğru: süreç hiçbir adımı atlamamanı, günlük ve notlar da işini kanıtlamanı sağlar."),
              ("Parolaları unutmaktan ve sertifikanın süresinin dolmasından", "Yanlış: bunlar kişisel işleyiş konuları; metodolojinin koruduğu riskler değil."),
              ("Müşterinin fatura ödememesinden ve rakip firmaların teklifinden", "Yanlış: ticari riskler; metodoloji teknik işin eksiksizliğini ve kanıtını korur."),
              ("Araçların eski kalmasından ve internet bağlantısının kesilmesinden", "Yanlış: bunlar altyapı sorunları; metodolojinin amacı bunlar değil."),
          ], dogru=0),
          ("Kitabın metodoloji bölümünün 'Hacker gözüyle' kutusunu hatırla.",
           "Müşteri 'şu alanı test ettiniz mi?' dediğinde elinde ne olmalı?",
           "Doğru şık, 'atlamak' ve 'kanıtsız kalmak' sözcüklerini içeren şık."),
          puan=30, baslik="İki risk"),
]


def _kapanis():
    return """
Metodoloji, teknik beceriyi **mesleğe** çeviren şeydir. Aynı port taraması, kapsam belgesi ve günlükle
yapıldığında bir iş; onlarsız yapıldığında bir risktir. Saldırgan tarafında bakarsan, düzenli bir saldırgan da
aynı aşamaları izler (kesif, açık analizi, doğrulama, kalıcılık, etki): bu yüzden ATT&CK her iki tarafın ortak
dilidir. Savunma tarafı için ders: müşteri günlüğü ve kapsam denetimi, bir testin yasal ve etik sınırını
ayakta tutar; yanlış pozitifleri ayıklamak da raporun güvenilirliğini. Kapsam dışına çıkan tek bir satır, bir
sözleşmeyi ve bir kariyeri bitirebilir.
"""


SEVIYE = Seviye(
    kimlik="c08b01",
    cilt=8,
    bolum=1,
    baslik="Metodoloji: İşi Sisteme Bağlamak",
    brifing="""
<<musteri>> testi bitmek üzere ve <<kisi>> Selin'i arıyor: "Raporu yazmadan önce, testin hangi aşamada ne yaptığını
ve kapsamda kalıp kalmadığımızı bir kez de **siz** doğrulayın." Selin klasörü sana bırakıyor: "Faaliyetleri aşamalara
oturt, günlükten kapsam dışı dokunuş var mı bak, tarama özetinden gerçek ile yanlış pozitifi ayır."

Mert gülümsüyor: "Amatör 'bir şeyler denedim' der. Profesyonel 'şu saatte şu hosta şunu yaptım, işte notum' der."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **PTES ve OWASP WSTG:** Pentest Execution Standard (PTES) bir testi kapsam belirlemeden raporlamaya
  kadar aşamalara böler; OWASP Web Security Testing Guide (WSTG) web testleri için ayrıntılı bir kontrol
  listesidir. Pek çok sızma testi sözleşmesi ve raporu bu çerçevelerden birine atıf yapar.
- **MITRE ATT&CK:** SolarWinds (2020) gibi büyük olaylardan sonra savunma ekipleri, gözlenen saldırı
  tekniklerini ATT&CK terimleriyle eşleyip tespit kurallarını bu çerçeveye göre düzenlemiştir. Mor takım
  çalışmalarında da kırmızı takımın yaptığı her adım bir ATT&CK tekniğine bağlanır.
- **Önleme ve tespit (kapsam disiplini):** Test günlüğü ve imzalı kapsam belgesi, testin yasal sınırını
  korur; kapsam dışına çıkan her adım müşteriye bildirilmelidir. Müşteri tarafında da testin hangi IP'ler
  ve saatlerden geldiğini bilmek, gerçek saldırıları testten ayırmayı sağlar.
""",
    sure_hedef_dk=25,
)
