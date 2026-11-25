"""Cilt 8 · Bölüm 2 — Rapor Yazımı: Asıl Ürün.

Beceri: kurgusal bulguları bir şiddet cetveline göre doğru önem derecesine koymak, iyi ve kötü
bulgu yazımını ayırt etmek (eksik unsuru bulmak), belirli bir şablonda tutarlı bir bulgu yazmak ve
aynı açığı yöneticiye ayrı bir dille anlatmak.

Vakalar: e-ticaret sitesi, hastane portalı, banka internet şubesi. Her vakada bulgular, hostlar,
özellikler ve taslaklar farklıdır. Bütün açıklamalar kurgusaldır, saldırı yükü içermez.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c08_meslek import ortak as o

VAKALAR = {
    "pazarix": {
        "ad": "Pazarix — e-ticaret sitesi raporu", "musteri": "Pazarix", "alan": "pazarix.lab",
        "kisi": "Tuncay Bey (sistem yöneticisi)",
        "bulgular": [
            ("Sipariş sorgusunda başka müşterinin siparişi görünüyor", "siparis", "sipariş numarasının sahibi sunucuda kontrol edilmeli"),
            ("Yönetim paneli varsayılan parolayı kabul ediyor", "admin", "varsayılan parola değiştirilmeli ve çok faktörlü doğrulama zorunlu olmalı"),
            ("Sunucu sürüm bilgisini yanıt başlığında veriyor", "www", "sürüm bilgisi yanıt başlıklarından kaldırılmalı"),
            ("Yedek dosyası web kökünde indirilebiliyor", "yedek", "yedekler web kökünden kaldırılıp erişimi kapalı bir alana taşınmalı"),
            ("Parola sıfırlama bağlantısı süresiz geçerli", "hesap", "sıfırlama bağlantıları kısa ömürlü ve tek kullanımlık olmalı"),
            ("Ürün yorumu alanı girdiyi süzmeden sayfada gösteriyor", "magaza", "çıktı kodlanmalı ve girdi doğrulanmalı"),
        ],
        "sahne": "Pazarix'in kampanya haftası öncesi testi bitti; Selin raporun bulgu sayfalarını senin yazmanı istiyor.",
    },
    "medora": {
        "ad": "Medora Sağlık — hasta portalı raporu", "musteri": "Medora Sağlık", "alan": "medora.lab",
        "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)",
        "bulgular": [
            ("Randevu numarası değiştirilince başka hastanın randevusu görünüyor", "randevu", "randevu sahibi her istekte sunucuda doğrulanmalı"),
            ("Doktor paneli zayıf parola politikasına izin veriyor", "doktor", "güçlü parola politikası ve çok faktörlü doğrulama uygulanmalı"),
            ("Hata sayfası veritabanı adını gösteriyor", "portal", "hata ayrıntıları kullanıcıya gösterilmemeli, yalnızca loglanmalı"),
            ("Tahlil sonucu PDF bağlantıları kimlik sormadan açılıyor", "sonuclar", "bağlantılar kimlik doğrulaması ve kısa ömürlü imza ile korunmalı"),
            ("Oturum süresi gün boyu uzamıyor ama çıkışta sonlanmıyor", "giris", "çıkışta oturum sunucuda geçersiz kılınmalı"),
            ("Misafir Wi-Fi ile klinik ağı arasında ağ ayrımı yok", "wifi", "misafir ağı klinik ağdan ayrılmalı ve güvenlik duvarıyla kısıtlanmalı"),
        ],
        "sahne": "Medora'nın portal testi sona erdi; yönetim kurulu için hem özet hem teknik bulgular isteniyor.",
    },
    "ferah": {
        "ad": "Ferah Bank — internet şubesi raporu", "musteri": "Ferah Bank", "alan": "ferahbank.lab",
        "kisi": "Hande Hanım (dijital bankacılık ürün sahibi)",
        "bulgular": [
            ("Transfer isteğinde negatif tutar kabul ediliyor", "transfer", "tutar sunucuda sıfırdan büyük olacak şekilde doğrulanmalı"),
            ("İşlem limiti yalnızca mobil istemcide kontrol ediliyor", "mobil", "limit kontrolü sunucuda yapılmalı"),
            ("Hesap özeti uç noktası başka müşterinin hesabını döndürüyor", "ozet", "hesap sahibi her istekte sunucuda doğrulanmalı"),
            ("Giriş sayfasında hız sınırı yok", "giris", "başarısız girişler için hız sınırı ve geçici kilit uygulanmalı"),
            ("Kampanya sayfası eski bir bileşen sürümü kullanıyor", "kampanya", "bileşen güncellenmeli ve envanter takibi yapılmalı"),
            ("Hata ayrıntıları kullanıcıya gösteriliyor", "sube", "hata ayrıntıları gizlenip loglanmalı"),
        ],
        "sahne": "Ferah Bank'ın internet şubesi testi tamamlandı; denetim ekibi bulguların yazılı raporunu bekliyor.",
    },
}
ONEMLER = ["Düşük", "Orta", "Yüksek", "Kritik"]
ETKI_CUMLESI = {
    "Kritik": "müşteri verisine ya da paraya doğrudan ulaşabilir; parasal kayıp, yasal sorumluluk ve itibar kaybı doğabilir",
    "Yüksek": "önemli miktarda veriye ya da yetkiye ulaşabilir; kısa sürede ciddi bir olaya dönüşebilir",
    "Orta": "sınırlı veriye ya da yetkiye ulaşabilir; başka bir açıkla birleştirilirse etkisi artabilir",
    "Düşük": "doğrudan zarar veremez ama saldırgana sistem hakkında ipucu verir",
}


def siddet(etki: int, kolay: int, internet: bool, kimlik: bool) -> tuple:
    skor = etki * kolay + (2 if internet else 0) - (1 if kimlik else 0)
    sev = "Kritik" if skor >= 10 else "Yüksek" if skor >= 7 else "Orta" if skor >= 4 else "Düşük"
    return skor, sev


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    for _ in range(500):
        kartlar = []
        for i, (baslik, sub, cozum) in enumerate(v["bulgular"], 1):
            etki, kolay = rng.randint(1, 3), rng.randint(1, 3)
            internet, kimlik = rng.random() < 0.6, rng.random() < 0.4
            skor, sev = siddet(etki, kolay, internet, kimlik)
            kartlar.append({"id": f"B{i}", "baslik": baslik, "varlik": f"{sub}.{v['alan']}", "cozum": cozum,
                            "internet": internet, "kimlik": kimlik, "etki": etki, "kolay": kolay, "skor": skor, "sev": sev})
        skorlar = sorted(k["skor"] for k in kartlar)
        sevler = [k["sev"] for k in kartlar]
        if ("Kritik" in sevler and "Düşük" in sevler and skorlar[0] != skorlar[1] and skorlar[-1] != skorlar[-2]
                and sevler.count("Kritik") <= 3):
            break
    else:
        raise RuntimeError("Uygun bulgu seti üretilemedi")
    f = max(kartlar, key=lambda k: k["skor"])
    dusuk = min(kartlar, key=lambda k: k["skor"])
    eksik = rng.choice(["kanıt", "etki", "çözüm"])
    harfler = ["a", "b", "c"]
    rng.shuffle(harfler)
    iyi_harf, eksik_harf, belirsiz_harf = harfler
    s = {
        "vaka": v["ad"], "v": v, "kartlar": kartlar, "f": f, "eksik": eksik, "harf": {"iyi": iyi_harf, "eksik": eksik_harf, "belirsiz": belirsiz_harf},
        "metin": {"musteri": v["musteri"], "kisi": v["kisi"], "sahne": v["sahne"], "f_id": f["id"], "f_baslik": f["baslik"],
                  "f_varlik": f["varlik"], "f_sev": f["sev"]},
        "cevaplar": {
            "kritik": [k["id"] for k in kartlar if k["sev"] == "Kritik"],
            "en_dusuk": dusuk["id"],
            "iyi": [iyi_harf, f"taslak_{iyi_harf}"],
            "eksik": [eksik, o.ascii_norm(eksik), {"kanıt": "kanit", "etki": "etki", "çözüm": "cozum"}[eksik]],
        },
    }
    return s


def _taslak(f: dict, eksik: str | None, belirsiz: bool = False) -> str:
    if belirsiz:
        return "Bulgu: sistemde bir güvenlik sorunu var.\nAcilen düzeltilmesi gerekiyor. Ayrıntıları sonra yazarız.\n"
    satir = {
        "baslik": f"Başlık: {f['baslik']} ({f['varlik']})",
        "onem": f"Önem: {f['sev']}",
        "aciklama": f"Açıklama: {f['varlik']} adresinde şu sorun saptandı: {f['baslik'][0].lower() + f['baslik'][1:]}.",
        "kanit": f"Kanıt: Test hesabıyla {f['varlik']} üzerine yapılan istek ve alınan yanıt kaydedildi; "
                 f"ekran görüntüsü ve istek/yanıt çifti ekte ({f['id']}_kanit.txt).",
        "etki": f"Etki: Saldırgan bu açığı kullanarak {ETKI_CUMLESI[f['sev']]}.",
        "cozum": f"Çözüm: {f['cozum'][0].upper() + f['cozum'][1:]}.",
    }
    anahtar = {"kanıt": "kanit", "etki": "etki", "çözüm": "cozum"}
    return "\n".join(v for k, v in satir.items() if k != anahtar.get(eksik)) + "\n"


SABLON = """# Bulgu raporu şablonu — bunu kopyalayıp doldur: bulgu_raporu.md
Başlık: <bulgunun adı ve etkilenen varlık>
Önem: <Kritik | Yüksek | Orta | Düşük>
Açıklama: <açık nedir, nerede bulundu>
Kanıt: <nasıl doğrulandı: istek/yanıt, adımlar>
Etki: <istismar edilirse ne olur>
Çözüm: <somut düzeltme adımları>
"""


def yaz(lab: Path, s: dict) -> None:
    f = s["f"]
    u.yaz(lab / "bulgu_kartlari.csv", "id;baslik;varlik;internete_acik;kimlik_gerekir;etki;kolaylik\n" + "".join(
        f"{k['id']};{k['baslik']};{k['varlik']};{'evet' if k['internet'] else 'hayir'};{'evet' if k['kimlik'] else 'hayir'};"
        f"{k['etki']};{k['kolay']}\n" for k in s["kartlar"]))
    u.yaz(lab / "siddet_cetveli.txt",
          "ŞİDDET CETVELİ (ekibin ortak kuralı)\n\n"
          "etki      : 1 sınırlı, 2 orta, 3 ağır   (veri/para kaybı büyüklüğü)\n"
          "kolaylik  : 1 zor, 2 orta, 3 kolay      (istismar kolaylığı)\n\n"
          "skor = etki x kolaylik\n"
          "       + 2  (internete açıksa)\n"
          "       - 1  (kimlik doğrulaması gerekiyorsa)\n\n"
          "Kritik: skor 10 ve üstü\nYüksek: 7 - 9\nOrta  : 4 - 6\nDüşük : 3 ve altı\n")
    u.yaz(lab / "taslaklar" / f"taslak_{s['harf']['iyi']}.txt", _taslak(f, None))
    u.yaz(lab / "taslaklar" / f"taslak_{s['harf']['eksik']}.txt", _taslak(f, s["eksik"]))
    u.yaz(lab / "taslaklar" / f"taslak_{s['harf']['belirsiz']}.txt", _taslak(f, None, belirsiz=True))
    u.yaz(lab / "sablon.md", SABLON)
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']}\n\nbulgu_kartlari.csv   6 bulgunun ham özellikleri\nsiddet_cetveli.txt   önem derecesi kuralı\n"
          f"taslaklar/            {f['id']} için üç farklı kişinin yazdığı taslak\nsablon.md            bulgu şablonu\n"
          "bulgu_raporu.md      SENİN yazacağın dosya (görev 5)\n")


KANITSIZ = ("<", ">", "…")


def _bulgu_yazildi(b) -> Sonuc:
    s = b.senaryo
    f = s["f"]
    yol = b.lab / "bulgu_raporu.md"
    if not yol.exists():
        return Sonuc(False, "Lab klasöründe `bulgu_raporu.md` yok. `sablon.md`'yi kopyalayıp doldur: `cp sablon.md bulgu_raporu.md`.")
    alanlar = o.alan_oku(yol.read_text(encoding="utf-8", errors="replace"), ["Başlık", "Önem", "Açıklama", "Kanıt", "Etki", "Çözüm"])
    eksik = [a for a in ("baslik", "onem", "aciklama", "kanit", "etki", "cozum") if a not in alanlar]
    if eksik:
        return Sonuc(False, "Şablondaki şu alanlar eksik: " + ", ".join(eksik) + ". Her alan `Alan: değer` biçiminde olmalı.", yakin=True)
    for ad, deger in alanlar.items():
        if (ad != "onem" and len(deger) < 15) or deger.startswith("<") or not deger:
            return Sonuc(False, f"`{ad}` alanı boş ya da şablon metni gibi duruyor. Kendi cümlelerinle doldur (en az bir cümle).", yakin=True)
    onem = o.ascii_norm(alanlar["onem"])
    if o.ascii_norm(f["sev"]) not in onem or any(o.ascii_norm(x) in onem for x in ONEMLER if x != f["sev"]):
        return Sonuc(False, f"Önem derecesi şiddet cetveline göre hesaplanandan farklı. {f['id']} için skoru yeniden hesapla ve "
                            "tek bir önem derecesi yaz.", yakin=True)
    metin = " ".join(alanlar[k] for k in ("baslik", "aciklama", "kanit")).casefold()
    if f["varlik"].casefold() not in metin:
        return Sonuc(False, f"Rapor tutarsız: etkilenen varlık (`{f['varlik']}`) başlıkta, açıklamada ya da kanıtta geçmiyor. "
                            "Bir bulgu, hangi sistemde bulunduğunu açıkça söylemeli.", yakin=True)
    if len(alanlar["cozum"].split()) < 4:
        return Sonuc(False, "Çözüm alanı çok kısa; mühendisin uygulayabileceği somut bir adım yaz (en az 4 kelime).", yakin=True)
    return Sonuc(True, "Bulgun şablona uygun, önem derecesi doğru ve varlıkla tutarlı. Böyle bir bulgu mühendisin elinde işe yarar.")


def coz(lab: Path, s: dict) -> dict:
    ks = ("awk -F';' 'NR>1{s=$6*$7+($4==\"evet\"?2:0)-($5==\"evet\"?1:0); print $1, s}' bulgu_kartlari.csv")
    kritik = o.sh(f"{ks} | awk '$2>=10{{print $1}}'", lab)
    dusuk = o.sh(f"{ks} | sort -k2 -n | head -1 | cut -d' ' -f1", lab)
    iyi = o.sh("for f in taslaklar/*; do [ $(grep -c -E '^(Başlık|Önem|Açıklama|Kanıt|Etki|Çözüm):' $f) -eq 6 ] && basename $f .txt | cut -d_ -f2; done", lab)
    en_yuksek = o.sh(f"{ks} | sort -k2 -nr | head -1 | cut -d' ' -f1", lab)
    # eksik unsur: iki unsuru olan ama 5 alanlı taslak
    eksik_dosya = o.sh("for f in taslaklar/*; do [ $(grep -c -E '^(Başlık|Önem|Açıklama|Kanıt|Etki|Çözüm):' $f) -eq 5 ] && echo $f; done", lab)
    eksik = o.sh(f"for a in Kanıt Etki Çözüm; do grep -q \"^$a:\" {eksik_dosya} || echo $a; done", lab)
    f = s["f"]
    o.sh(f"cp sablon.md bulgu_raporu.md", lab)
    (lab / "bulgu_raporu.md").write_text(
        f"Başlık: {f['baslik']} ({f['varlik']})\nÖnem: {f['sev']}\n"
        f"Açıklama: {f['varlik']} adresinde şu sorun saptandı: {f['baslik'].lower()}.\n"
        f"Kanıt: Test hesabıyla {f['varlik']} üzerine istek yapıldı ve yanıt kaydedildi (ekran görüntüsü ekte).\n"
        f"Etki: Saldırgan bu açığı kullanarak {ETKI_CUMLESI[f['sev']]}.\nÇözüm: {f['cozum']}.\n", encoding="utf-8")
    assert en_yuksek == f["id"]
    cozum = {1: kritik, 2: dusuk, 3: iyi, 4: eksik, 5: "", 6: "Müşteri verisi saldırganlara açık durumda; kısa sürede para ve itibar kaybı yaşanabilir, acil düzeltme önerilir."}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Rapor: tek somut ürün", """
Bir pentester'ın müşteriye teslim ettiği **tek somut ürün rapordur**. En iyi hack'i yapmış olabilirsin;
iyi anlatamazsan müşteri için o hack hiç olmamıştır. Rapor iki kitleye yazılır: **yönetici özeti**
(teknik olmayan, risk odaklı) yöneticiler içindir, **teknik bulgular** açığı düzeltecek mühendis içindir.

Her bulgu aynı **anatomiyi** taşır: başlık ve **önem derecesi**, **açıklama**, **kanıt**, **etki**,
**çözüm**. Önce bulguların ham kartlarına bak:
""", komut="head -4 bulgu_kartlari.csv"),
    Adim("Önem derecesi keyfî olamaz", """
"Bence kritik" bir ölçü değildir. Ekipler bir **şiddet cetveli** kullanır: etki, istismar kolaylığı,
dışarıdan erişilebilirlik gibi nesnel özellikleri bir skora, skoru da önem derecesine çevirir:
""", komut="cat siddet_cetveli.txt"),
    Adim("Cetveli veriye uygula", """
`awk` bir satırdaki alanlardan hesap yapabilir. Alanlar: `$4` internete açık, `$5` kimlik gerekir, `$6`
etki, `$7` kolaylık. Şu komut her bulgunun skorunu hesaplar ve en yüksek üçünü gösterir
(`?:` kısa bir "eğer-ise-değilse"dir):
""", komut="awk -F';' 'NR>1{s=$6*$7+($4==\"evet\"?2:0)-($5==\"evet\"?1:0); print $1, s}' bulgu_kartlari.csv | sort -k2 -nr | head -3",
         sonra="""
Cetvelin eşiklerine göre skoru önem derecesine çevirirsin (10+ kritik, 7-9 yüksek, 4-6 orta, 3 ve altı
düşük). Aynı kural herkes için aynı sonucu verir: **tutarlılık**, raporun güvenilirliğidir.
"""),
    Adim("Üç taslak: hangisi iyi?", """
Aynı bulgu için üç kişi üç taslak yazmış. İyi bir bulgu **eksiksiz** (altı alan), **somut** (hangi varlık,
hangi adım) ve **eyleme dönüktür** (çözümü uygulanabilir). Taslaklardan birine bak:
""", komut="cat taslaklar/taslak_a.txt", sonra="""
Diğer iki taslağı da `cat` ile kendin oku. Biri tek cümlelik belirsiz bir uyarı; biri neredeyse iyi ama
bir unsuru eksik. **Bulgu yazarken en sık düşülen hata**: kanıt ya da çözüm cümlesini atlamaktır; kanıtsız bulguya
inanılmaz, çözümsüz bulgu düzeltilemez.
"""),
    Adim("Şablon", """
Ekipler bulguları ortak bir şablona yazar; böylece raporlar tutarlı ve taranabilir olur. Şablonu gör:
""", komut="cat sablon.md", sonra="""
Alanlar `Alan: değer` biçimindedir. Şablonu `cp sablon.md bulgu_raporu.md` ile kopyalayıp `nano` ile
dolduracaksın. Yazarken üç kural: **tutarlı ol** (önem derecesi cetvelden gelsin, varlık adı başlıkta ve
kanıtta aynı olsun), **somut ol** (kanıtta ne yaptığını, çözümde ne yapılacağını yaz), **iki kitleyi
unutma** (etki cümlesini yönetici de anlamalı).

**Hacker gözüyle:** İşverenler iyi yazılmış writeup'ları bir sertifikadan bile değerli bulabilir.
Çözdüğün her makine için kısa bir bulgu raporu yazmak, hem pekiştirir hem portföyün olur.
"""),
]

GOREVLER = [
    Gorev("`bulgu_kartlari.csv` içindeki bulgulardan şiddet cetveline göre **Kritik** olanların kimlikleri nelerdir? "
          "(örn. `B1 B4`)",
          Kume("kritik", bicim="bulgu kimlikleri (örn. B1 B4)",
               sik_hatalar=lambda g, b, bg: "Kritik için skor 10 ve üstü gerekir; eşiği (Yüksek: 7-9) karıştırmış olabilirsin."),
          ("Her bulgunun skorunu hesaplamalısın: etki × kolaylık, internete açıksa +2, kimlik gerekiyorsa −1.",
           "Eğitimdeki `awk` komutu her bulgunun skorunu verir. Skoru 10 ve üstü olanlar Kritik.",
           "`awk -F';' 'NR>1{s=$6*$7+($4==\"evet\"?2:0)-($5==\"evet\"?1:0); print $1, s}' bulgu_kartlari.csv | awk '$2>=10{print $1}'`"),
          puan=40, baslik="Kritik bulgular"),
    Gorev("En **düşük skorlu** (en az önemli) bulgunun kimliği nedir?",
          Metin("en_dusuk", bicim="bulgu kimliği (örn. B3)"),
          ("Aynı skor hesabını kullan, bu sefer en küçüğü ara.",
           "Skorları hesaplayıp `sort -k2 -n` ile artan sıralarsan en üstte en düşük gelir.",
           "`awk -F';' 'NR>1{s=$6*$7+($4==\"evet\"?2:0)-($5==\"evet\"?1:0); print $1, s}' bulgu_kartlari.csv | sort -k2 -n | head -1`"),
          puan=30, baslik="En düşük skor"),
    Gorev("`taslaklar/` klasöründe <<f_id>> bulgusu için üç taslak var. **Hangisi iyi yazılmış** (eksiksiz, somut, "
          "eyleme dönük)? Harfini yaz (a, b ya da c).",
          Metin("iyi", on_ekleri_at=("taslak_", "taslak "), bicim="harf (a, b veya c)"),
          ("Üç taslağı da `cat` ile oku. İyi bulguda altı alanın hepsi var.",
           "Alan adlarını sayabilirsin: `grep -c -E '^(Başlık|Önem|Açıklama|Kanıt|Etki|Çözüm):' taslaklar/*` her dosyada kaç alan olduğunu gösterir.",
           "Altı alanın hepsi olan dosya iyi olandır; dosya adındaki harf cevap."),
          puan=30, baslik="İyi taslak"),
    Gorev("Üç taslaktan biri neredeyse iyi ama bir unsur eksik. Eksik olan **unsur** hangisi? (`kanıt`, `etki` ya da `çözüm`)",
          Metin("eksik", bicim="kanıt, etki ya da çözüm"),
          ("Beş alanlı taslağı bul; hangi alan başlığı eksik?",
           "Altı alandan hangisinin satırı o dosyada yok? `grep -c`'u 5 veren dosyayı okuyup kontrol et.",
           "Taslağı `cat` ile oku; Başlık, Önem, Açıklama, Kanıt, Etki, Çözüm satırlarından hangisinin olmadığını bul."),
          puan=30, baslik="Eksik unsur"),
    Gorev("**Yaz:** <<f_id>> bulgusunu (en yüksek skorlu, `<<f_varlik>>` varlığındaki) `sablon.md` biçiminde "
          "`bulgu_raporu.md` dosyasına yaz: önem derecesi cetvelden doğru çıkmalı, varlık adı tutarlı olmalı, her alan "
          "kendi cümlelerinle dolu olmalı. Bitince `cevap 5` yaz.",
          Durum(_bulgu_yazildi, cozum="`cp sablon.md bulgu_raporu.md` yapıp altı alanı doldur; <<f_id>> için önem derecesi <<f_sev>> olmalı."),
          ("Şablonu kopyala, sonra her satırı kendi cümlelerinle doldur. Önem derecesi için skoru kendin hesapla.",
           "Başlık ve açıklamada ya da kanıtta varlık adını (`<<f_varlik>>`) aynen geçir. Çözümde mühendisin yapabileceği somut bir adım yaz.",
           "`cp sablon.md bulgu_raporu.md && nano bulgu_raporu.md`; `Önem:` satırına <<f_sev>> yaz; Kanıt'ta hangi hesapla ne yaptığını anlat."),
          puan=70, baslik="Bulguyu yaz"),
    Gorev("**Yönetici özeti:** <<f_id>> bulgusunu (`<<f_baslik>>`) **teknik olmayan** bir yöneticiye, risk odaklı, "
          "bir-iki cümleyle anlat. Cevabını tırnak içinde yaz.",
          Serbest("Müşteri/hasta/hesap verisi dışarıdan, kimlik doğrulaması olmadan okunabilir durumda; kısa sürede para, veri ve itibar "
                  "kaybı yaşanabilir. Düzeltme acil önceliktir.", min_kelime=10),
          ("Yönetici parametre, sunucu ya da HTTP başlığı bilmez. O neyi anlamak ister?",
           "Ne oluyor? Kime zarar veriyor? Ne kadar acil? Bu üç soruya teknik terimsiz cevap ver.",
           "Örnek yapı: \"[Varlık/veri] [kim tarafından] [nasıl] görülebilir; bu [parasal/itibar] zarar doğurabilir; düzeltme [acil/önemli].\""),
          puan=30, baslik="İki kitle: yönetici özeti"),
    Gorev("Neden \"açığı bulmak\" değil de **\"çözümü anlatmak\"** bir pentester'ı değerli yapar?",
          Secmeli([
              ("Müşteri açığı değil çözümü satın alır; çözümsüz bulgu değer üretmez", "Doğru: bulgunun değeri, onu düzeltmeye yol göstermesindedir; çözümsüz bulgu yalnızca bir kaygı listesidir."),
              ("Çözüm yazmak raporu uzattığı için müşteri daha çok ücret öder", "Yanlış: rapor uzunluğu değer ölçüsü değil; müşteri değeri, işin düzeltmeyi kolaylaştırmasından alır."),
              ("Çözüm kısmını yazmak, bulgunun önem derecesini otomatik olarak düşürür", "Yanlış: çözüm önem derecesini değiştirmez; önem etkiye ve istismar kolaylığına bağlıdır."),
              ("Sızma testi sözleşmeleri çözüm yazmayı yasaklar, o yüzden bu bir ayrıcalıktır", "Yanlış: çözüm önerisi rapor yapısının doğal parçasıdır; yasak değil beklentidir."),
          ], dogru=0),
          ("Müşteri raporu aldıktan sonra ne yapmak ister: açığı bilmek mi, kapatmak mı?",
           "Bulgunun anatomisindeki son unsuru hatırla.",
           "Doğru şık, 'müşteri çözümü satın alır' diyen şık."),
          puan=20, baslik="Çözümün değeri"),
]


def _kapanis():
    return """
Rapor, yaptığın işin **ürünüdür**: aynı açık iyi yazılmadığında "yok" gibi, iyi yazıldığında bir bütçeye ve bir
düzeltmeye dönüşür. Önem derecesi kişisel görüş değil, ekibin cetveline göre hesaplanır; böylece iki
pentester aynı bulguya aynı derecesi verir. Kötü bulgu yazımının üç klasik biçimi: **belirsiz** ("güvenlik
sorunu var"), **eksik** (kanıtsız ya da çözümsüz) ve **tutarsız** (başlıkta bir varlık, kanıtta başkası). Saldırgan
bakışıyla düşünürsen: iyi rapor, saldırganın gelecekte hangi kapıyı kullanacağını müşteriye gösterip o kapıyı
kapattırır. Aynı bulguyu yöneticiye parayla, mühendise adımla anlat.
"""


SEVIYE = Seviye(
    kimlik="c08b02",
    cilt=8,
    bolum=2,
    baslik="Rapor Yazımı: Asıl Ürün",
    brifing="""
<<sahne>> <<kisi>> raporun yönetici özetini ve kritik bulguları özellikle okuyacak. Selin sana üç şey bırakıyor:
bulgu kartları, ekibin şiddet cetveli ve üç farklı kişinin yazdığı taslaklar.

"Önce önem derecelerini **cetvelden** çıkar, keyfî yazma," diyor Selin. "Sonra taslaklara bak: hangisi iyi,
hangisinde ne eksik? En sonunda en yüksek skorlu bulguyu şablona kendin yaz ve bir de yönetici özeti ekle."

Mert not ekliyor: "İyi bulgu, mühendisin ertesi sabah düzeltmeye başlayabileceği bulgudur."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Önceliklendirme olayların kaderini belirler:** Equifax (2017) olayında, bilinen bir web çerçevesi
  açığının yamasının uygulanmaması veri ihlaline yol açtı. İyi bir raporda bu tür bulgu, "yüksek/kritik"
  olarak ve yamalama süresiyle birlikte yazılır; önem derecesinin nedeni (etki, kolaylık, internete açıklık)
  açıkça belirtilir.
- **Rapor yapısı pratikte:** Sızma testi raporlarının neredeyse hepsi yönetici özeti, kapsam ve metodoloji,
  bulgular (başlık, önem, kanıt, etki, çözüm) ve öneriler bölümlerinden oluşur. Önem derecesi için
  CVSS gibi ortak puanlama sistemleri de kullanılır; ekipler kendi cetvellerini bunlarla tutarlı kılar.
- **Tespit ve önleme (rapor kalitesi):** Raporun kalitesini ölçmek için çapraz inceleme (ikinci bir
  uzmanın okuması), şablon zorunluluğu ve önem derecesinin hesaplanabilir olması, tutarsız ve belirsiz
  bulguların müşteriye ulaşmasını önler.
""",
    sure_hedef_dk=30,
)
