"""Cilt 8 · Bölüm 5 — Sertifikalar ve Yol Haritası.

Beceri: eJPT, PNPT ve OSCP'yi zorluk/amaç bakımından sıralamak, saldırı ve savunma rotalarını ayırt etmek,
bir kişinin profiline göre doğru ilk sertifikayı seçmek ve 12 aylık kişisel bir yol haritası dosyası yazmak
(yön tutarlı, ilk sertifika kitabın önerisine uygun, aylık adımlar ve bir portföy öğesi içersin).

Vakalar: yazılımcı (saldırı), SOC adayı (savunma), bordro uzmanı (yön seçmeli), öğrenci (yön seçmeli).
Fiyat ve sınav ayrıntıları sık değiştiği için yazılmaz; güncel bilgi sağlayıcının resmî sitesindedir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

PROFILLER = {
    "kerem": {"ad": "Kerem", "gecmis": "4 yıllık yazılımcı", "yon": "saldırı", "saat": 8,
              "not": "Uygulama güvenliği ve araç yazmaya ilgi duyuyor; bütçesi sınırlı.", "musteri": "Pazarix",
              "kisi": "Tuncay Bey (Kerem'in yöneticisi)"},
    "elif": {"ad": "Elif", "gecmis": "2 yıllık BT destek uzmanı", "yon": "savunma", "saat": 6,
             "not": "Bir SOC ekibine geçmek istiyor; vardiyalı çalışıyor.", "musteri": "Medora Sağlık",
             "kisi": "Dr. Aslı Hanım (Elif'in yöneticisi)"},
    "murat": {"ad": "Murat", "gecmis": "6 yıllık bordro ve muhasebe uzmanı", "yon": "açık", "saat": 5,
              "not": "Finansal sistemlerin güvenliğiyle ilgileniyor; saldırı ya da savunma, hangisi olacağına kendisi karar verecek.",
              "musteri": "Ferah Bank", "kisi": "Hande Hanım (Murat'ın yöneticisi)"},
    "deniz": {"ad": "Deniz", "gecmis": "bilgisayar mühendisliği öğrencisi (son sınıf)", "yon": "açık", "saat": 10,
              "not": "Henüz bir yön seçmedi; bu yıl mezun oluyor.", "musteri": "Kuzgun Lojistik",
              "kisi": "Serdar Bey (Deniz'in staj danışmanı)"},
}
SERTIFIKALAR = [  # ad, yön, seviye, kaba zorluk (kitaptaki anlatıma göre), açıklama
    ("eJPT", "saldırı", "giriş", 2, "uygulamalı lab, giriş seviyesi"),
    ("PNPT", "saldırı", "orta", 3, "gerçekçi test ve canlı rapor sunumu, AD odaklı"),
    ("OSCP", "saldırı", "ileri", 5, "24 saatlik uygulamalı sınav ve rapor, sektör standardı"),
    ("Security+", "savunma", "temel", 2, "çoğu giriş seviyesi savunma ilanının istediği temel"),
    ("BTL1", "savunma", "orta", 3, "uygulamalı savunma (mavi takım)"),
]
ILK = {"saldırı": "ejpt", "savunma": "security+"}
ADLAR = {"ejpt": ("ejpt",), "pnpt": ("pnpt",), "oscp": ("oscp",), "security+": ("security+", "security plus", "secplus"), "btl1": ("btl1",)}


def uret(rng):
    kod = rng.choice(list(PROFILLER))
    p = PROFILLER[kod]
    ucu = ["eJPT", "PNPT", "OSCP"]
    rng.shuffle(ucu)
    siralama = "  ".join(f"{i + 1}) {a}" for i, a in enumerate(ucu))
    dogru = [ucu.index(a) + 1 for a in ("eJPT", "PNPT", "OSCP")]
    ilk = ["eJPT", "Security+"] if p["yon"] == "açık" else [ILK[p["yon"]].replace("ejpt", "eJPT").replace("security+", "Security+")]
    return {
        "vaka": f"{p['musteri']} — {p['ad']} için yol haritası", "p": p, "kod": kod,
        "metin": {"ad": p["ad"], "gecmis": p["gecmis"], "yon": p["yon"], "musteri": p["musteri"], "kisi": p["kisi"],
                  "siralama": siralama, "saat": p["saat"]},
        "cevaplar": {"sira": dogru, "ilk": ilk, "savunma": ["Security+", "BTL1"]},
    }


def yaz(lab: Path, s: dict) -> None:
    p = s["p"]
    u.yaz(lab / "profil.txt", f"Ad: {p['ad']}\nGeçmiş: {p['gecmis']}\nHedef yön: {p['yon']}   (saldırı / savunma / açık)\n"
          f"Haftalık çalışma saati: {p['saat']}\nNotlar: {p['not']}\n")
    u.yaz(lab / "sertifikalar.csv", "sertifika;yon;seviye;zorluk_puani;aciklama\n" + "".join(
        f"{a};{b};{c};{d};{e}\n" for a, b, c, d, e in SERTIFIKALAR))
    u.yaz(lab / "plan_sablonu.md",
          "# 12 aylık yol haritası (bunu kopyalayıp doldur: yol_haritam.md)\n"
          "Yön: <saldırı ya da savunma>\n"
          "İlk sertifika: <sertifika adı>\n"
          "Ay 1-3: <ne yapacaksın? hangi platform, hangi proje?>\n"
          "Ay 4-6: <...>\nAy 7-9: <...>\nAy 10-12: <...>\n"
          "Portföy: <writeup blogu, GitHub'da küçük araçlar vb.>\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['vaka']}\n\nprofil.txt         {p['ad']}'in durumu\nsertifikalar.csv   kitapta anlatılan sertifikalar (zorluk puanı: kitabın anlatımına göre kaba değerlendirme)\n"
          "plan_sablonu.md    yol haritası şablonu\nyol_haritam.md     SENİN yazacağın dosya (görev 4)\n\n"
          "Not: Sertifika fiyatları ve sınav ayrıntıları sık değişir; kesin bilgi için sağlayıcının resmî sitesine bak.\n")


def _yol_haritasi(b) -> Sonuc:
    s = b.senaryo
    p = s["p"]
    yol = b.lab / "yol_haritam.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `yol_haritam.md` yok. `cp plan_sablonu.md yol_haritam.md` ile başlayıp doldur.")
    t = yol.read_text(encoding="utf-8", errors="replace")
    alanlar = o.alan_oku(t, ["Yön", "İlk sertifika", "Portföy"])
    yon_ham = o.ascii_norm(alanlar.get("yon", ""))
    yon = "saldırı" if any(x in yon_ham for x in ("saldiri", "kirmizi", "red", "pentest")) else \
          "savunma" if any(x in yon_ham for x in ("savunma", "mavi", "blue", "soc")) else None
    if yon is None:
        return Sonuc(False, "`Yön:` satırı yok ya da anlaşılmıyor. `Yön: saldırı` ya da `Yön: savunma` yaz.", yakin=True)
    if p["yon"] != "açık" and yon != p["yon"]:
        return Sonuc(False, f"{p['ad']}'in hedef yönü `{p['yon']}`; planın yönü `{yon}`. Plan, kişinin hedefiyle tutarlı olmalı.", yakin=True)
    ilk = o.ascii_norm(alanlar.get("ilk sertifika", ""))
    if not ilk:
        return Sonuc(False, "`İlk sertifika:` satırı yok.", yakin=True)
    onerilen = ILK[yon]
    if not any(a in ilk for a in ADLAR[onerilen]):
        return Sonuc(False, f"Seçtiğin yön `{yon}` için kitabın önerdiği ilk sertifika `{'eJPT' if yon == 'saldırı' else 'Security+'}`. "
                            "Zorlu bir sertifikayla (OSCP gibi) başlamak yerine önce giriş seviyesini hedefle.", yakin=True)
    aylar = re.findall(r"(?mi)^\s*[-*]?\s*Ay\s*(\d+)(?:\s*[-–]\s*(\d+))?\s*:\s*(\S.+)$", t)
    gecerli = [(int(a), int(b or a), m) for a, b, m in aylar if not m.strip().startswith("<") and len(m.split()) >= 3]
    if len(gecerli) < 4:
        return Sonuc(False, f"Aylık adımlar yetersiz: en az 4 dolu satır (`Ay 1-3: ...` biçiminde) gerekir, {len(gecerli)} var. "
                            "Her satır en az 3 kelimelik somut bir adım içersin.", yakin=True)
    if max(b for _, b, _ in gecerli) < 9:
        return Sonuc(False, "Plan 12 aylık olmalı; son aylar da (en az 9. aya kadar) planlanmalı.", yakin=True)
    portfoy = alanlar.get("portfoy", "")
    if not (len(portfoy.split()) >= 2 and not portfoy.startswith("<")) and not re.search(r"(?i)portf|writeup|blog|github", t.replace(alanlar.get("portfoy", ""), "")):
        return Sonuc(False, "Planda bir portföy öğesi yok (writeup blogu, GitHub'da küçük araçlar...). "
                            "Portföy, tek başına pahalı bir sertifikadan daha ikna edici olabilir.", yakin=True)
    return Sonuc(True, "Yol haritan tutarlı: yön hedefle uyumlu, ilk sertifika kitabın önerisine uygun, 12 aya yayılmış ve bir portföy öğesi içeriyor.")


def coz(lab: Path, s: dict) -> dict:
    sira_komut = ("awk -F';' 'NR>1 && ($1==\"eJPT\"||$1==\"PNPT\"||$1==\"OSCP\"){print $4, $1}' sertifikalar.csv | sort -n | cut -d' ' -f2")
    sirali = o.sh(sira_komut, lab).split()
    metin = s["metin"]["siralama"]
    sira = []
    for ad in sirali:
        m = re.search(rf"(\d)\) {ad}", metin)
        sira.append(m.group(1))
    yon = o.sh("grep '^Hedef yön' profil.txt | sed 's/Hedef yön: *//' | cut -d' ' -f1", lab)
    yon = "savunma" if yon == "savunma" else "saldırı"          # "açık" ise saldırıyı seç
    ilk = "Security+" if yon == "savunma" else "eJPT"
    savunma = o.sh("awk -F';' 'NR>1 && $2==\"savunma\"{print $1}' sertifikalar.csv", lab).replace("\n", " ")
    (lab / "yol_haritam.md").write_text(
        f"Yön: {yon}\nİlk sertifika: {ilk}\nAy 1-3: Kitabı bitir ve kendi lab'ında pratik yap.\nAy 4-6: {ilk} sınavına hazırlan ve sınava gir.\n"
        "Ay 7-9: Her çözdüğüm makine için bir writeup yaz.\nAy 10-12: Bir sonraki sertifikayı seç ve GitHub'a küçük bir araç koy.\n"
        "Portföy: writeup blogu ve GitHub'da küçük araçlar.\n", encoding="utf-8")
    cozum = {1: " ".join(sira), 2: ilk, 3: savunma, 4: "", 5: "", 6: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Sertifika ne işe yarar?", """
Sertifikalar iki işe yarar: **İK filtrelerini geçmek** ve **öğrenmeni yapılandırmak**. Hiçbiri tek başına seni
hacker yapmaz; beceri yapar. Ama doğru seçilmiş sertifikalar kapıları açar. Bu bölümdeki bilgiler kitabın
yazıldığı döneme göre; **fiyat ve sınav ayrıntıları sık değişir**, güncel bilgi için sağlayıcının sitesine bak.

Önce bugünkü vakadaki kişinin profiline bak:
""", komut="cat profil.txt"),
    Adim("Kitaptaki sertifikalar", """
Kitapta iki rota var: **saldırı** (pentest/kırmızı takım) için eJPT → PNPT → OSCP; **savunma** (SOC/GRC) için
Security+ → BTL1. Hepsinin özelliklerini ve kaba zorluk puanlarını (kitabın anlatımına göre) gör:
""", komut="cat sertifikalar.csv"),
    Adim("Zorluğa göre sırala", """
`awk` ile bir yön süzüp `sort -n` ile zorluğa göre sıralayabilirsin. Saldırı rotasını kolaydan zora diz:
""", komut="awk -F';' 'NR>1 && $2==\"saldırı\"{print $4, $1}' sertifikalar.csv | sort -n", sonra="""
Sıra: **eJPT** (giriş, ilk sertifikan) < **PNPT** (orta, canlı rapor sunumu) < **OSCP** (ileri, sektör standardı).
Savunma rotasında başlangıç **Security+**, ardından **BTL1**'dir.

**Hacker gözüyle:** Sertifika toplamaya değil beceri biriktirmeye odaklan. "Sertifika avcısı" olmak bir tuzaktır;
işverenler mülakatta gerçekte ne yapabildiğini anlar. Çoğu işveren için **portföy + giriş sertifikası**, tek başına
pahalı bir sertifikadan daha ikna edicidir.
"""),
    Adim("Plan şablonu", """
Bir yol haritası somut olmalıdır: yön, ilk sertifika, aylık adımlar ve bir portföy öğesi. Şablona bak:
""", komut="cat plan_sablonu.md"),
    Adim("Planı yazarken", """
Üç kural: **tutarlı ol** (kişinin hedef yönüyle uyumlu), **kademeli ol** (zor bir sertifikayla değil, giriş
seviyesiyle başla), **kanıt üret** (her ay somut bir çıktı: bir lab, bir writeup, bir küçük araç). Planı
`cp plan_sablonu.md yol_haritam.md` ile kopyalayıp `nano` ile dolduracaksın. `<...>` yer tutucularını kendi
cümlelerinle değiştir.
""", komut=None),
]

GOREVLER = [
    Gorev("Aşağıdaki üç sertifikayı **en kolaydan en zora** sırala (sertifika dosyasındaki zorluk puanına göre): "
          "<<siralama>>. Cevabı numaralarla yaz (örn. `2 1 3`).",
          o.Sira("sira", sik_hatalar=lambda v, b, bg: "Ters sırayı yazmış olabilirsin: en kolaydan en zora (eJPT en başta)." if v == b[::-1] else None),
          ("Sertifika dosyasında her birinin kaba zorluk puanı var.",
           "`awk` ile üçünü süzüp `sort -n` ile zorluğa göre diz.",
           "`awk -F';' 'NR>1{print $4, $1}' sertifikalar.csv | sort -n` — eJPT en kolay; sonra numaraları soruda bul."),
          puan=30, baslik="Zorluk sırası"),
    Gorev("<<ad>> (`<<gecmis>>`, hedef yön: `<<yon>>`) için kitabın önerdiği **ilk sertifika** hangisidir? "
          "(Hedef yön `açık` ise iki yönden birini seçip o yönün ilk sertifikasını yaz.)",
          Metin("ilk", kabul=["security plus", "secplus"], bicim="sertifika adı"),
          ("Kitap iki rota veriyor: saldırı ve savunma. Her rotanın giriş seviyesi sertifikası var.",
           "Saldırı rotasının ilk adımı giriş seviyesi uygulamalı bir sertifika; savunma rotasında temel bir sertifika.",
           "Saldırı için **eJPT**, savunma için **Security+**."),
          puan=30, baslik="İlk sertifika"),
    Gorev("Kitaba göre **savunma** (SOC/GRC) rotasında hangi iki sertifika yer alır? (adları virgülle ya da boşlukla ayır)",
          Kume("savunma", bicim="iki sertifika adı"),
          ("Sertifika dosyasında yön sütunu var.",
           "`awk -F';' '$2==\"savunma\"{print $1}' sertifikalar.csv` yön sütununa göre süzer.",
           "Çıktıdaki iki ad: temel bir sertifika ve uygulamalı bir mavi takım sertifikası."),
          puan=30, baslik="Savunma rotası"),
    Gorev("**Yol haritanı yaz:** `yol_haritam.md` dosyasına <<ad>> için (ya da kendi durumun için) 12 aylık bir plan "
          "yaz: `Yön:`, `İlk sertifika:` (kitabın önerdiği), en az 4 satır `Ay 1-3: ...` biçiminde somut adım ve bir "
          "`Portföy:` satırı. Yön, kişinin hedefiyle uyumlu olsun. Bitince `cevap 4` yaz.",
          Durum(_yol_haritasi, cozum="`cp plan_sablonu.md yol_haritam.md` ve doldur: Yön, İlk sertifika (eJPT ya da Security+), Ay 1-3 / 4-6 / 7-9 / 10-12 satırları, Portföy."),
          ("Şablonu kopyala. Hedef yön `açık` ise sen birini seç; değilse profildeki yönü yaz.",
           "İlk sertifika giriş seviyesi olmalı (eJPT ya da Security+). Her `Ay` satırına en az üç kelimelik somut bir adım yaz.",
           "`cp plan_sablonu.md yol_haritam.md && nano yol_haritam.md`; `<...>` yerlerini doldur; son satırda bir portföy öğesi (writeup blogu, GitHub aracı) belirt."),
          puan=70, baslik="12 aylık plan"),
    Gorev("Çoğu işveren için **portföy + giriş seviyesi sertifika**, neden tek başına pahalı bir sertifikadan daha "
          "ikna edici olabilir?",
          Secmeli([
              ("Portföy gösterilebilir beceri kanıtıdır; işveren gerçekte ne yapabildiğini görmek ister", "Doğru: pahalı bir sertifika tek başına bu kanıtı vermez; yazdığın writeup'lar ve araçlar işveren için somut kanıttır."),
              ("Sertifikalar yalnızca belirli ülkelerde geçerli olduğu için portföy her yerde kabul edilir", "Yanlış: sertifikaların geçerliliği ülkeye göre değişmez; asıl fark kanıtın niteliğidir."),
              ("İşverenler portföy ile sertifikayı karşılaştırmaz, yalnızca ücret beklentisine bakar", "Yanlış: işe alımda ücret önemli ama beceri kanıtı en az onun kadar belirleyicidir."),
              ("Giriş seviyesi sertifikalar bütün işverenlerin zorunlu tuttuğu tek şeydir, portföy gereksizdir", "Yanlış: zorunlu bir tek şey yoktur; ilanlar değişir, ama kanıtlanmış beceri her yerde değerlidir."),
          ], dogru=0),
          ("İşveren mülakatta neyi anlamak ister?",
           "Kitabın sertifika bölümündeki 'Hacker gözüyle' kutusunu hatırla.",
           "Doğru şık 'gerçek, gösterilebilir beceri kanıtı' diyen şık."),
          puan=20, baslik="Portföy"),
    Gorev("\"Sertifika avcısı\" olmak neden bir **tuzaktır**?",
          Secmeli([
              ("Sertifika toplamak beceri yerine geçmez; işveren ne yapabildiğini anlar", "Doğru: sertifikayı bir öğrenme yapısı olarak kullan; sınavı geçmek için değil, alanı gerçekten öğrenmek için."),
              ("Her sertifikanın süresi dolduğu için toplu sertifika almak yasak sayılır", "Yanlış: sertifikalar yenilenebilir ve toplamak yasak değildir; sorun, becerinin yerine geçmesidir."),
              ("Sertifika sayısı arttıkça işverenin vereceği maaş otomatik olarak düşer", "Yanlış: böyle bir kural yok; sorun, sayıya odaklanıp beceriyi ihmal etmektir."),
              ("Yalnızca pahalı sertifikalar işe yaradığı için ucuz olanları toplamak boşunadır", "Yanlış: bedel değil içerik ve uygulama kanıtı önemlidir; giriş sertifikaları da değerlidir."),
          ], dogru=0),
          ("Mülakatta sertifikanın ötesinde ne sorulur?",
           "Kitabın 'İPUCU' kutusu: sertifika toplamaya mı beceri biriktirmeye mi odaklanılır?",
           "Doğru şık, sertifikanın becerinin yerine geçmediğini söyleyen şık."),
          puan=20, baslik="Sertifika avcılığı"),
]


def _kapanis():
    return """
Bir yol haritası, çaba ile sonuç arasındaki köprüdür: yön seçmeden toplanan sertifikalar bir çanta dolusu kâğıt
olur, yönü olan küçük adımlar bir kariyer olur. Bu bölümde iki ilkeyi uyguladın: **kademeli git** (giriş seviyesinden başla) ve
**kanıt üret** (portföy). Saldırı mı savunma mı sorusu aslında "hangi sorun beni daha çok çekiyor?" sorusudur; ikisinde
de aynı temel bilgi (Cilt 1-7) kullanılır. Savunma bakışıyla ders: şirketler çalışanlarının yetkinliğini ölçmek için
sertifikaları kullanır ama gerçek güvenlik, sertifikalı kişilerin sürekli pratik yapmasından gelir. Senin finans ve
yazılım geçmişin, hangi rotayı seçersen seç, nadir bir farktır.
"""


SEVIYE = Seviye(
    kimlik="c08b05",
    cilt=8,
    bolum=5,
    baslik="Sertifikalar ve Yol Haritası",
    brifing="""
<<musteri>>'de <<kisi>> bir iş arkadaşından bahsediyor: "<<ad>> (<<gecmis>>) güvenliğe geçmek istiyor ama hangi
sertifikayla başlayacağını bilmiyor." Selin bu konuyu sana devrediyor: "Önce kitaptaki sertifikaları zorluğa göre
sırala, sonra <<ad>>'in profiline uygun **ilk** sertifikayı seç. En sonunda 12 aylık gerçekçi bir yol haritası yaz."

Mert ekliyor: "Sertifika toplamak seni hacker yapmaz. Beceri yapar. Haritaya mutlaka bir **portföy** öğesi koy; benim de
ilk işim blog yazılarımdan çıktı."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Rol ve beceri çerçeveleri:** ABD'nin NIST kurumu, NICE Siber Güvenlik İşgücü Çerçevesi (NIST SP 800-181)
  ile güvenlik işlerini görev ve yetkinlik bazında tanımlar; birçok kurum işe alım ve eğitim planlarını
  bu çerçeveyle hizalar. Bu, sertifikanın tek ölçü olmadığını, yetkinliğin tanımlı olduğunu gösterir.
- **İlanlarda sertifika:** Pek çok güvenlik iş ilanı Security+, eJPT ya da OSCP gibi sertifikaları ister;
  ama aynı ilanların çoğu "uygulamalı deneyim" ve "portföy"ü de arar. Bu yüzden iyi bir profil, birkaç
  uygulamalı sertifika ile güçlü bir portföyü ve sürekli öğrenme kanıtını birleştirir.
- **Önleme ve tespit (yanlış yatırım riski):** Sertifika seçerken sağlayıcının resmî sitesinden güncel
  ücret, sınav biçimi ve geçerlilik süresi doğrulanmalı; üçüncü kişilerin "garanti iş" vaatleri
  şüpheyle karşılanmalıdır.
""",
    sure_hedef_dk=25,
)
