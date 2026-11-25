"""Cilt 10 · Bölüm 8 — Kapanış Görevi: Bir Finansal Akışı Uçtan Uca Test Et.

Beceri: bir finansal uygulamanın dört akışını (transfer, hesap özeti, profil, kupon) bir test planına
göre sınamak, hangilerinin savunmasız olduğunu kanıtlamak, bulguları önem sırasına koymak, bütün
açıkları kodda kapatmak ve finans sektörüne uygun (etki, çözüm, uyum bağlantılı) bir rapor yazmak.

Her tohumda dört akıştan 2 ya da 3 tanesi savunmasızdır; hangileri olduğu oyuncunun testine kalır.
Vakalar: banka, dijital cüzdan, ödeme altyapısı, lojistik tahsilat, hastane fatura.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

AKISLAR = ["transfer", "ozet", "profil", "kupon"]
ETKI = {"transfer": 9, "profil": 8, "ozet": 7, "kupon": 6}
ETKI_ACIKLAMA = {"transfer": "doğrudan para kaybı", "profil": "yetki ve limit yükseltme",
                 "ozet": "müşteri verisi ifşası", "kupon": "kampanya bütçesi kaybı"}
ANAHTAR = {  # rapordaki bulgu tanıma sözcükleri
    "transfer": ("negatif",), "ozet": ("bola", "idor", "yetkilendirme", "sahiplik", "başka hesap", "baska hesap"),
    "profil": ("kütle", "kutle", "mass assignment", "allow-list", "izin listesi"),
    "kupon": ("kupon", "yarış", "yaris", "race", "atomik"),
}
FONK = {"transfer": "transfer", "ozet": "hesap_ozet", "profil": "profil_guncelle", "kupon": "kupon_kullan"}


def uret(rng):
    kod, v = o.vaka_sec(rng, o.VAKALAR)
    s = o.taban(rng, kod)
    for m in s["musteriler"]:
        m["bakiye_kurus"] = rng.randrange(900000, 4000000, 25)
    acik = sorted(rng.sample(AKISLAR, rng.randint(2, 3)), key=AKISLAR.index)
    onek = {"ferah": "FERAH", "paramix": "HEDIYE", "pazarix": "KAMPANYA", "kuzgun": "BAYI", "medora": "CEK"}[kod]
    kodlar = u.benzersiz(rng, lambda r: f"{onek}-{r.randint(1000, 9999)}", 2)
    degerler = [rng.choice([50, 75, 100, 125]) for _ in kodlar]
    s["kuponlar"] = [{"kod": k, "indirim_kurus": d * 100} for k, d in zip(kodlar, degerler)]
    ms = s["musteriler"]
    s.update({"acik": acik, "kupon0": kodlar[0], "kupon_tl": degerler[0]})
    s["metin"].update({"komsu": ms[1]["hesap_id"], "kupon": kodlar[0], "limit_tl": ms[0]["islem_limiti_kurus"] // 100})
    en_agir = max(acik, key=lambda a: ETKI[a])
    s["cevaplar"] = {"acik": acik, "en_agir": en_agir}
    return s


def _mantik(acik: list) -> str:
    return (o.KOD_SAGLIK + o.KOMISYON_DOGRU
            + (o.TRANSFER_ACIK if "transfer" in acik else o.TRANSFER_GUVENLI)
            + (o.OZET_ACIK if "ozet" in acik else o.OZET_GUVENLI)
            + (o.PROFIL_ACIK if "profil" in acik else o.PROFIL_GUVENLI)
            + (o.KUPON_ACIK if "kupon" in acik else o.KUPON_GUVENLI))


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    komsu = s["musteriler"][1]["hesap_id"]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — uçtan uca test\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Test hesabın          : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}\n"
          f"Komşu test hesabı     : {komsu}\n"
          f"Test kuponun          : {s['kupon0']}  ({s['kupon_tl']} TL)\n\n"
          "test_plani.md        test planı ve kontrol soruları\n"
          "siddet_cetveli.csv   akış başına etki puanları\n"
          "uygulama/mantik.py   uygulamanın kodu\n\n"
          "Kurallar: yalnızca bu lab'daki test hesabı, komşu test hesabı ve test kuponu. Bulgu yazmadan önce kanıtla.\n")
    u.yaz(lab / "siddet_cetveli.csv", "akis;etki_puani;etki\n" + "".join(
        f"{a};{ETKI[a]};{ETKI_ACIKLAMA[a]}\n" for a in AKISLAR))
    ornek = (f"curl -s -X POST -H 'X-Oturum: {ben['token']}' -H 'Content-Type: application/json' "
             f"-d '<gövde>' http://{s['host']}:{s['port']}")
    u.yaz(lab / "test_plani.md",
          f"# Test planı — {s['v']['ad']}\n\n"
          "Her akış için kendine \"kötüye kullanım\" sorularını sor: negatif olabilir mi? sıfır? çok büyük? "
          "bu adımı atlayabilir miyim? aynı anda iki kez yapabilir miyim? başkasının nesnesi mi?\n\n"
          f"Örnek istek kalıbı:\n    {ornek}/<uç nokta>\n\n"
          "## transfer\nPOST /transfer  gövde: {\"kime\": <hesap_no>, \"tutar\": <TL>}\n"
          f"Soru: Tutar negatif ya da sıfır olursa ne oluyor? (alıcı olarak komşu test hesabını kullan: {komsu})\n\n"
          "## ozet\nGET /hesap/<hesap_no>/ozet\nSoru: Başka hesabın numarasını yazarsam ne oluyor?\n\n"
          "## profil\nPOST /profil/guncelle  gövde: {\"telefon\": \"...\"}\n"
          "Soru: Gövdeye normalde değiştirememem gereken bir alan (rol, islem_limiti_kurus) eklersem?\n\n"
          f"## kupon\nPOST /kupon/kullan  gövde: {{\"kod\": \"{s['kupon0']}\"}}\n"
          "Soru: Aynı kuponu ikinci kez bozdurursam?\n")
    o.uygulama_yaz(lab, s, _mantik(s["acik"]))


def _hepsi(ns, s) -> Sonuc:
    for ad, f in (("transfer: negatif/sıfır/geçersiz tutar", o.test_negatif), ("transfer: komisyon", o.test_komisyon),
                  ("hesap özeti: başkasının hesabı", o.test_bola), ("profil: kütle atama", o.test_kutle),
                  ("kupon: tekrar kullanım", o.test_kupon_tekrar), ("kupon: yarış durumu", o.test_kupon_yaris)):
        r = f(ns, s)
        if not r.dogru:
            return Sonuc(False, f"Hâlâ açık ya da bozuk: [{ad}] {r.mesaj}", yakin=True)
    return Sonuc(True, "Dört akışın hepsi güvenli ve normal kullanım çalışıyor: uçtan uca test temiz.")


def _rapor(b) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "rapor.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `rapor.md` dosyası yok. Raporunu bu adla yaz (`nano rapor.md`).")
    t = yol.read_text(encoding="utf-8", errors="replace")
    k = t.casefold()
    if len(t.split()) < 45:
        return Sonuc(False, "Rapor çok kısa. Her bulgu için açıklama, kanıt, etki, çözüm ve önem derecesi yaz (en az ~45 kelime).")
    eksik = [a for a in s["acik"] if not any(x in k for x in ANAHTAR[a])]
    if eksik:
        return Sonuc(False, "Raporda bulduğun açıkların hepsi yok. Şu akış(lar)ın bulgusunu eklemeyi unutma: "
                            + ", ".join(eksik) + ".", yakin=True)
    kontrol = [("önem derecesi (Kritik/Yüksek/Orta/Düşük)", any(x in k for x in ("kritik", "yüksek", "yuksek", "orta", "düşük", "dusuk"))),
               ("etki", "etki" in k), ("çözüm/öneri", any(x in k for x in ("çözüm", "cozum", "öneri", "oneri"))),
               ("kanıt", any(x in k for x in ("kanıt", "kanit"))),
               ("uyum bağlantısı (KVKK ya da PCI-DSS)", "kvkk" in k or "pci" in k)]
    yok = [ad for ad, ok in kontrol if not ok]
    if yok:
        return Sonuc(False, "Raporda şu unsurlar eksik: " + ", ".join(yok) + ".", yakin=True)
    return Sonuc(True, "Rapor, bulgu yapısı ve uyum bağlantısıyla eksiksiz görünüyor.")


def coz(lab: Path, s: dict) -> dict:
    ben, komsu = s["musteriler"][0], s["musteriler"][1]
    bulunan = []
    _, y = o.curl(s, lab, "POST", "/transfer", {"kime": komsu["hesap_id"], "tutar": -5})
    if y and y.get("durum") == "tamam":
        bulunan.append("transfer")
    _, y = o.curl(s, lab, "GET", f"/hesap/{komsu['hesap_id']}/ozet")
    if y and "bakiye_kurus" in y:
        bulunan.append("ozet")
    _, y = o.curl(s, lab, "POST", "/profil/guncelle", {"islem_limiti_kurus": 99999999})
    if y and y.get("profil", {}).get("islem_limiti_kurus") == 99999999:
        bulunan.append("profil")
    o.curl(s, lab, "POST", "/kupon/kullan", {"kod": s["kupon0"]})
    _, y = o.curl(s, lab, "POST", "/kupon/kullan", {"kod": s["kupon0"]})
    if y and y.get("durum") == "kupon uygulandi":
        bulunan.append("kupon")
    alt = "|".join(bulunan)
    en_agir = o.sh(f"grep -E '^({alt});' siddet_cetveli.csv | sort -t';' -k2 -nr | head -1 | cut -d';' -f1", lab)
    o.duzelt(lab, "transfer", "hesap_ozet", "profil_guncelle", "kupon_kullan")
    govde = ["# Pentest raporu", "", "Yönetici özeti: uçtan uca testte aşağıdaki bulgular kanıtlandı ve kodda düzeltildi; müşteri parası ve verisi risk altındaydı, düzeltme sonrası yeniden test temiz.", ""]
    ornek = {
        "transfer": "Negatif tutarlı transfer: Yüksek/Kritik. Kanıt: curl ile -5 TL gönderildi, bakiye arttı. "
                    "Etki: doğrudan para kaybı. Çözüm: tutar sıfırdan büyük olmalı. Uyum: PCI-DSS ve BDDK.",
        "ozet": "BOLA, başka hesabın özeti: Yüksek. Kanıt: komşu hesabın bakiyesi görüldü. Etki: müşteri verisi ifşası. "
                "Çözüm: sunucuda sahiplik kontrolü. Uyum: KVKK.",
        "profil": "Kütle atama: Yüksek. Kanıt: islem_limiti_kurus değiştirildi. Etki: limit yükseltme. "
                  "Çözüm: izin listesi (allow-list). Uyum: KVKK.",
        "kupon": "Kupon tekrar kullanımı ve yarış durumu: Orta. Kanıt: aynı kupon iki kez bozduruldu. Etki: bütçe kaybı. "
                 "Çözüm: atomik güncelleme. Uyum: finansal kontrol.",
    }
    for a in bulunan:
        govde += [ornek[a], ""]
    (lab / "rapor.md").write_text("\n".join(govde), encoding="utf-8")
    cozum = {1: " ".join(bulunan), 2: en_agir, 3: "", 4: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Test planını oku", """
Profesyonel bir test **plansız** yapılmaz. Plan, her akış için "kötüye kullanım sorularını" ve
isteğin kalıbını verir. Dört akış var: `transfer`, `ozet`, `profil`, `kupon`. Planı oku:
""", komut="cat test_plani.md"),
    Adim("Şiddet cetveli", """
Bulgular aynı ağırlıkta değildir. Ürün ekibi her akış için bir **etki puanı** belirlemiş (parasal ya da
veri etkisi). Rapor yazarken önem derecesini bu cetvele göre koyacaksın:
""", komut="cat siddet_cetveli.csv", sonra="""
Etki puanı yüksek olan, kontrol edilmezse **daha çok para ya da veri** kaybettirendir. Bir pentester'ın
işi yalnızca açığı bulmak değil, önceliklendirmektir: tek bir kritik bulgu, on düşük bulgudan değerlidir.
"""),
    Adim("Normal akış çalışıyor mu?", """
Test etmeden önce **normal** davranışı bil: yanlışlıkla açık gibi görünen bir şey aslında tasarımdır.
Kendi hesabının özetini iste:
""", komut="curl -s -H 'X-Oturum: <<token>>' http://<<adres>>/hesabim"),
    Adim("Uç noktaları kodda tanı", """
Kod elinde olduğu için (beyaz kutu test) hangi fonksiyonların hangi akışlara karşılık geldiğini
görebilirsin. Bütün fonksiyon tanımlarını listele:
""", komut="grep -n '^def ' uygulama/mantik.py", sonra="""
Altı fonksiyon göreceksin: `hesabim`, `komisyon_kurus`, `transfer`, `hesap_ozet`, `profil_guncelle`,
`kupon_kullan`. Her akışın testi, öğrendiğin bir açık sınıfına karşılık gelir: **negatif tutar**,
**BOLA**, **kütle atama**, **kupon tekrarı/yarış**. Hangilerinin bu uygulamada **gerçekten** açık
olduğunu testlerle bulacaksın; hepsi açık olmayabilir.
"""),
    Adim("Raporun iskeleti", """
Rapor, bu işin tek somut ürünüdür. Her bulgu şu unsurları taşır:

- **Başlık ve önem derecesi** (Kritik / Yüksek / Orta / Düşük)
- **Açıklama:** açık nedir, nerede
- **Kanıt:** nasıl doğrulandı (istek, yanıt)
- **Etki:** parasal ya da veri etkisi
- **Çözüm:** somut düzeltme
- **Uyum bağlantısı:** hangi standardı ilgilendiriyor (**PCI-DSS** kart verisi, **KVKK** kişisel veri,
  bankalar için **BDDK** düzenlemeleri)

Yönetici özeti de unutulmaz: teknik olmayan, risk odaklı birkaç cümle.

**Hacker gözüyle:** Finansal sektörde "bu açık şu gereksinimi ihlal ediyor" cümlesi bulgunun ağırlığını
artırır. Aynı bulguyu yöneticiye parasal etkiyle, mühendise tam konum ve düzeltmeyle anlat.
""", komut=None),
]

GOREVLER = [
    Gorev("Test planına göre dört akışı sına. Bu uygulamada **savunmasız** olan akışlar hangileridir? "
          "(`transfer`, `ozet`, `profil`, `kupon` adlarından, virgülle ya da boşlukla ayırarak yaz)",
          Kume("acik", bicim="akış adları (örn. transfer ozet)",
               sik_hatalar=lambda g, b, bg: "Akış adlarını tam olarak `transfer`, `ozet`, `profil`, `kupon` biçiminde yaz."
               if any(x in g for x in ("hesap_ozet", "profil_guncelle", "kupon_kullan")) else None),
          ("Her akış için test planındaki soruyu kendi test hesabınla dene; yalnızca test hesabı, komşu hesap ve test kuponu.",
           "Negatif tutar (`transfer`), komşunun özeti (`ozet`), gövdeye `islem_limiti_kurus` ekleme (`profil`), kuponu iki kez bozdurma (`kupon`). Kabul edilen her saldırı biçimi o akışın açık olduğunu gösterir.",
           "`transfer`: tutar -5 gönder, `tamam` yanıtı açık demektir. `ozet`: komşu numarasıyla bakiye dönüyorsa açık. `profil`: yanıtta limit değişmişse açık. `kupon`: ikinci bozdurma `kupon uygulandi` derse açık."),
          puan=80, baslik="Hangileri açık"),
    Gorev("Açık bulduğun akışlar arasında, `siddet_cetveli.csv`'ye göre **etki puanı en yüksek** olan hangisidir?",
          Metin("en_agir", bicim="akış adı"),
          ("Cetvelde her akışın puanı var; yalnızca açık olanları karşılaştır.",
           "Açık bulduğun akışların satırlarını `grep` ile süz ve `sort -t';' -k2 -nr` ile en yükseğe göre sırala.",
           "`grep -E '^(<akış1>|<akış2>);' siddet_cetveli.csv | sort -t';' -k2 -nr | head -1`"),
          puan=40, baslik="En ağır bulgu"),
    Gorev("**Düzelt:** `uygulama/mantik.py` içinde bulduğun **bütün** açıkları kapat (öğrendiklerini uygula: tutar "
          "doğrulama, sahiplik kontrolü, izin listesi, atomik kupon). Normal kullanım bozulmasın; oyun dört akışı da "
          "sınayacak. Bitince `cevap 3` yaz.",
          Durum(o.durum_testi(_hepsi), cozum="Açık akışların fonksiyonlarını önceki bölümlerdeki gibi düzelt (transfer: `tutar <= 0` reddi; "
                "hesap_ozet: sahiplik; profil_guncelle: allow-list; kupon_kullan: atomik UPDATE)."),
          ("Hangi akış açıksa onu önceki bölümlerde düzelttiğin gibi düzelt. Açık olmayan akışlara dokunma ya da dokunursan bozma.",
           "Her akışın düzeltmesi: negatif tutar → tutar doğrulama (400); BOLA → `musteri_id` kontrolü (403); kütle atama → izinli alanlar; kupon → `UPDATE ... WHERE kullanildi = 0` + `rowcount`.",
           "`transfer`: `if tutar <= 0: return 400`; `hesap_ozet`: `if h[\"musteri_id\"] != kul[\"id\"]: return 403`; `profil_guncelle`: yalnızca `(\"telefon\", \"eposta\")`; `kupon_kullan`: koşullu `UPDATE` ve `rowcount == 0` ise 409."),
          puan=100, baslik="Düzelt: bütün açıkları kapat"),
    Gorev("**Raporla:** `rapor.md` dosyasına, bulduğun **her açık** için bir bulgu yaz: başlık ve önem derecesi, kanıt, "
          "etki, çözüm ve uyum bağlantısı (KVKK ya da PCI-DSS). Bitince `cevap 4` yaz.",
          Durum(_rapor, cozum="rapor.md içinde her açık akış için: başlık + önem, kanıt, etki, çözüm ve uyum (KVKK/PCI-DSS) yaz."),
          ("Bulgunun anatomisini eğitimde okudun: başlık+önem, açıklama, kanıt, etki, çözüm, uyum.",
           "Her açık için kısa bir paragraf yaz: nasıl kanıtladın (hangi istek), parasal ya da veri etkisi, ve çözüm. KVKK kişisel veriyle, PCI-DSS kart verisiyle ilgili.",
           "`nano rapor.md` ile aç. Örnek bir bulgu: \"Negatif tutarlı transfer — Kritik. Kanıt: -5 TL gönderildi, bakiye arttı. Etki: doğrudan para kaybı. Çözüm: tutar > 0 doğrulaması. Uyum: BDDK/PCI-DSS.\""),
          puan=80, baslik="Raporla"),
    Gorev("Bir **BOLA** (başkasının hesabını görme) bulgusu raporda en çok hangi çerçeveyle ilişkilendirilir?",
          Secmeli([
              ("KVKK: kişisel verilerin yetkisiz kişilere açılması bir veri ihlalidir", "Doğru: başka müşterilerin bakiye, IBAN ve ad bilgisi kişisel veridir; yetkisiz erişim KVKK kapsamında bir ihlaldir."),
              ("PCI-DSS: yalnızca kart numarası saklanıyorsa geçerlidir ve bu uygulamada kart verisi yoktur", "Yanlış: bu uygulamada kart verisi yok; BOLA açığının asıl ilişkili olduğu çerçeve kişisel verinin korunmasıdır."),
              ("MASAK: bakiye ifşası kara para aklama sayılır", "Yanlış: MASAK kara para ve mali suçlarla mücadele eder; bakiye ifşası bunu doğrudan ilgilendirmez."),
              ("GİB: e-fatura entegrasyonunda otomatik bildirim gerektirir", "Yanlış: GİB vergi ve e-dönüşümü düzenler; bu açığın ilişkili olduğu kurum değildir."),
          ], dogru=0),
          ("BOLA'da ne sızar: bir ödeme kartı mı, kişisel veri mi?",
           "Başka müşterinin ad, IBAN ve bakiyesi hangi tür veridir?",
           "Doğru şık KVKK'yı ve kişisel verinin yetkisiz açılmasını anlatan şık."),
          puan=30, baslik="Uyum eşlemesi"),
    Gorev("Dört açık sınıfını doğru savunma kontrolüyle eşleyen satır hangisidir?",
          Secmeli([
              ("Negatif tutar: girdi doğrulaması · BOLA: sahiplik kontrolü · Kütle atama: izin listesi · Kupon yarışı: atomik işlem", "Doğru: her açık sınıfı kendi doğal çözümüyle eşleşmiş."),
              ("Negatif tutar: izin listesi · BOLA: atomik işlem · Kütle atama: sunucuda sahiplik kontrolü · Kupon yarışı: girdi doğrulaması", "Yanlış: çözümler birbirine karışmış; örneğin yarış durumunu girdi doğrulaması çözmez."),
              ("Negatif tutar: atomik işlem · BOLA: girdi doğrulaması · Kütle atama: atomik işlem · Kupon yarışı: sahiplik kontrolü", "Yanlış: negatif tutar atomiklikle değil iş kuralı doğrulamasıyla engellenir."),
              ("Negatif tutar: sahiplik kontrolü · BOLA: izin listesi · Kütle atama: girdi doğrulaması · Kupon yarışı: izin listesi", "Yanlış: izin listesi kabul edilen alanları sınırlar (kütle atama), BOLA'yı çözmez."),
          ], dogru=0),
          ("Her açığın kökünü düşün: değer mi, sahiplik mi, alan listesi mi, zamanlama mı?",
           "Cilt 10'un ilk bölümlerinde her açığı nasıl düzelttin?",
           "Doğru şıkta 'negatif tutar → girdi doğrulaması' ve 'kupon yarışı → atomik işlem' var."),
          puan=30, baslik="Açık → kontrol"),
]


def _kapanis():
    return """
Bu son görevde bir finansal akışı bir saldırgan gibi sınadın, bir mühendis gibi onardın ve bir danışman gibi
raporladın. Gördüğün dört açığın hiçbiri karmaşık değil, ve hepsi gerçek sistemlerde hâlâ çıkıyor: bir değer
doğrulanmamış, bir sahiplik sorulmamış, bir alan listesi unutulmuş, bir kontrol atomik değil. Saldırgan bunları
arar çünkü ödül para ya da müşteri verisidir; otomatik tarayıcı bulamaz çünkü ortada hata yoktur. Savunmada
ilke tek: **sunucuda, her istekte, kimliği, yetkiyi ve iş kuralını doğrula.** Senin avantajın, bu akışların
nasıl çalışması gerektiğini finans ve bordro tecrübenden bilmen; açığı kodu okumadan önce sezebilirsin. Bu
raporu portföyünün en değerli parçası olarak sakla.
"""


SEVIYE = Seviye(
    kimlik="c10b08",
    cilt=10,
    bolum=8,
    baslik="Kapanış Görevi: Bir Finansal Akışı Test Et",
    brifing="""
<<sahne>> <<kisi>> toplantı odasında: "Uygulamamızın dört temel akışını yayına almadan önce baştan sona test
etmenizi istiyoruz. Hangisi açık, ne kadar ciddi, nasıl kapanır?" Selin sana test planını veriyor.

"Bu, cildin kapanış görevi," diyor Selin. "Önce **test et**: hangi akışlar savunmasız? Sonra **önceliklendir**.
Sonra **düzelt** ve en sonunda bir **rapor** yaz: etki, çözüm ve uyum bağlantısıyla. Raporu bir müşteriye
gönderecek gibi yaz; bu senin portföyün olabilir."

Mert kapıdan sesleniyor: "Hepsi açık olmayabilir. Açık olmayanı açık diye yazarsan raporun güvenilirliği biter."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Raporlarda sık görülen sınıflar:** OWASP API Güvenliği Top 10 listesinde nesne düzeyinde yetki
  eksikliği (BOLA) birinci sıradadır; kütle atama ve kaynak kötüye kullanımı da listede yer alır.
  Finansal uygulamaların sızma testi raporlarında negatif/aşırı tutar, kupon ve bakiye yarış
  durumları, BOLA ve istemci tarafı kontroller çok sık geçen bulgulardır.
- **Uyum ve test zorunluluğu:** PCI-DSS gibi çerçeveler düzenli sızma testini zorunlu kılar; Türkiye'de
  bankalar için de BDDK düzenlemeleri sızma testi yaptırmayı gerektirir. Bulguları bu çerçevelere
  göre raporlamak, bulgunun ağırlığını ve düzeltilme önceliğini artırır.
- **Tespit ve önleme:** Tespit için işlem tutarı ve hesap kimliği anormallikleri, aynı kimlikten
  ardışık nesne istekleri, kupon kullanım yığılması ve her para hareketi için değiştirilemez
  denetim izi izlenir. Önlemek için sunucu tarafında doğrulama, sahiplik kontrolü, izin listeleri
  ve atomik işlemler tasarım gereği uygulanır; geliştirme sürecine iş mantığı testleri eklenir.
""",
    sure_hedef_dk=45,
)
