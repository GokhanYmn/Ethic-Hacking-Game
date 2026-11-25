"""Cilt 10 · Bölüm 3 — İş Mantığı Açıkları II: Tek Kullanımlık Kupon ve Yarış Durumu.

Beceri: aynı kuponun birden çok bozdurulduğunu loglardan okumak (milisaniyelik zaman damgalarıyla
"aynı anda gelen istekleri" fark etmek), kendi test kuponunda kanıtlamak, etkisini hesaplamak ve
`kupon_kullan` kodunu önce ardışık tekrara, sonra eşzamanlı isteğe karşı düzeltmek (atomik işlem).

Vakalar: e-ticaret indirim kuponu, cüzdan hediye kodu, hastane indirim çeki, banka kampanya kodu.
Yarış testi, bir SELECT'ten sonra bekleyen bağlantı sarmalayıcısıyla iki isteği gerçekten iç içe sokar.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

VAKA = {  # kod: (kupon adı, önek, log klasörü)
    "pazarix": ("indirim kuponu", "KAMPANYA", "odeme_loglari"),
    "paramix": ("hediye kodu", "HEDIYE", "cuzdan_loglari"),
    "medora": ("indirim çeki", "CEK", "fatura_loglari"),
    "ferah": ("kampanya kodu", "FERAH", "sube_loglari"),
}


def uret(rng):
    kod, v = o.vaka_sec(rng, VAKA)
    ad, onek, log_k = VAKA[kod]
    s = o.taban(rng, kod)
    for m in s["musteriler"]:
        m["bakiye_kurus"] = rng.randrange(300000, 2000000, 25)
    kodlar = u.benzersiz(rng, lambda r: f"{onek}-{r.randint(1000, 9999)}", 6)
    degerler = [rng.choice([50, 75, 100, 125, 150, 200]) for _ in kodlar]
    s["kuponlar"] = [{"kod": k, "indirim_kurus": d * 100} for k, d in zip(kodlar, degerler)]
    ms = s["musteriler"]
    saldirgan = rng.choice(ms[2:])
    hedef = rng.randint(2, 5)                            # saldırganın hedef kupon indeksi (oyuncunun 0 ve 1'inden farklı)
    hedef = 2 + hedef % 4
    n = rng.randint(4, 7)
    gun = u.gun(rng)
    satirlar = []
    t = gun + timedelta(hours=10)
    for _ in range(rng.randint(14, 20)):                 # sıradan kullanım: herkes kendi kuponunu bir kez bozdurur
        t += timedelta(seconds=rng.randint(60, 1500))
        m = rng.choice([x for x in ms[1:] if x is not saldirgan])
        k = rng.choice([x for i, x in enumerate(kodlar) if i != hedef])
        satirlar.append((t, o.log_satiri(t, o.ascii_ad(m["ad"]), "POST", "/kupon/kullan", {"kod": k}, 200)))
        if rng.random() < 0.4:
            t += timedelta(seconds=rng.randint(2, 20))
            satirlar.append((t, o.log_satiri(t, o.ascii_ad(m["ad"]), "GET", "/hesabim", None, 200)))
    tb = gun + timedelta(hours=rng.choice([13, 14, 15]), minutes=rng.randint(0, 50), seconds=rng.randint(0, 59))
    for _ in range(n):                                   # aynı saniye içinde art arda gelen istekler
        tb += timedelta(milliseconds=rng.randint(3, 40))
        satirlar.append((tb, o.log_satiri(tb, o.ascii_ad(saldirgan["ad"]), "POST", "/kupon/kullan",
                                          {"kod": kodlar[hedef]}, 200)))
    satirlar.sort(key=lambda x: x[0])
    s.update({"log_satirlari": [x[1] for x in satirlar], "log_k": log_k, "kupon_adi": ad,
              "kodlar": kodlar, "degerler": degerler, "saldirgan": saldirgan})
    s["metin"].update({"log_k": log_k, "kupon_adi": ad, "kupon": kodlar[0], "kupon_tl": degerler[0]})
    s["cevaplar"] = {
        "saldirgan": [saldirgan["ad"], o.ascii_ad(saldirgan["ad"]), saldirgan["ad"].replace(" ", ".").lower()],
        "adet": n,
        "kayip_tl": (n - 1) * degerler[hedef],
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — {s['kupon_adi']} denetimi\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Test hesabın          : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}\n"
          f"Test {s['kupon_adi']}n    : {s['kodlar'][0]}  ({s['degerler'][0]} TL)\n\n"
          f"kupon_tanimlari.csv         bütün {s['kupon_adi']} tanımları\n"
          f"{s['log_k']}/kupon_erisim.log  geçen haftaki kupon isteklerinin logu\n"
          "uygulama/mantik.py          düzelteceğin kod\n")
    u.yaz(lab / "kupon_tanimlari.csv", "kod;deger_tl;kullanim_hakki\n" + "".join(
        f"{k};{d};1\n" for k, d in zip(s["kodlar"], s["degerler"])))
    u.yaz(lab / s["log_k"] / "kupon_erisim.log", "\n".join(s["log_satirlari"]) + "\n")
    o.uygulama_yaz(lab, s, o.KOD_SAGLIK + o.KUPON_ACIK)


def _kanit(b) -> Sonuc:
    kod = b.senaryo["kuponlar"][0]["kod"]
    n = o.db_oku(b.lab, "SELECT kullanildi FROM kuponlar WHERE kod = ?", (kod,))[0][0]
    if n >= 2:
        return Sonuc(True, f"Tek kullanımlık kuponu {n} kez bozdurdun: kanıt tamam.")
    return Sonuc(False, f"`{kod}` kuponunu henüz en az iki kez bozdurmadın (şu an {n} kez). "
                        "Aynı `curl` komutunu iki kez çalıştır.")


def coz(lab: Path, s: dict) -> dict:
    k = s["log_k"]
    ad = o.ascii_ad(s["saldirgan"]["ad"])
    kullanici = o.sh(f"sn=$(cut -d' ' -f1 {k}/kupon_erisim.log | cut -c1-19 | uniq -c | sort -rn | head -1 | "
                     f"awk '{{print $2}}'); grep \"$sn\" {k}/kupon_erisim.log | cut -d' ' -f2 | sort -u", lab)
    adet = o.sh(f"grep '{ad} POST /kupon/kullan' {k}/kupon_erisim.log | grep -c ' 200$'", lab)
    kayip = o.sh(f"kod=$(grep '{ad} POST /kupon/kullan' {k}/kupon_erisim.log | head -1 | grep -o '\"kod\":\"[^\"]*\"' "
                 "| cut -d'\"' -f4); d=$(grep \"^$kod;\" kupon_tanimlari.csv | cut -d';' -f2); "
                 f"echo $(( ({adet} - 1) * d ))", lab)
    kod0 = s["kuponlar"][0]["kod"]
    for _ in range(2):
        o.curl(s, lab, "POST", "/kupon/kullan", {"kod": kod0})
    o.duzelt(lab, "kupon_kullan")
    cozum = {1: kullanici, 2: adet, 3: kayip, 4: "", 5: "", 6: "", 7: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Kural: tek kullanımlık", """
Kupon, hediye kodu ya da indirim çeki aslında **para gibidir**: bozdurulunca hesaba değer ekler.
Bu yüzden her kuponun bir **kullanım hakkı** vardır. Tanımlara bak, hepsinin hakkı 1:
""", komut="cat kupon_tanimlari.csv"),
    Adim("Test kuponunu bir kez bozdur", """
Önce normal davranış. Test hesabın için verilen kuponu bozdur; yanıtta eklenen tutarı göreceksin:
""", komut="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"kod\": \"<<kupon>>\"}' http://<<adres>>/kupon/kullan",
         sonra="""
Kupon artık **kullanılmış** sayılmalı. İkinci kez bozdurmayı **sonraki görevde** deneyeceksin;
şimdilik loglara bakalım.
"""),
    Adim("Logun zaman damgası", """
Geçen haftanın kupon logunda zaman damgaları **milisaniyeye** kadar gidiyor
(`2026-03-02T14:05:31.412`). Bu, "iki şey aynı anda oldu mu?" sorusunu cevaplayabilmen için
önemli. İlk üç satıra bak:
""", komut="head -3 <<log_k>>/kupon_erisim.log"),
    Adim("Aynı saniyedeki kümeleri bul", """
Log zamana göre sıralı olduğundan aynı saniyedeki istekler yan yana durur. `cut -c1-19` zaman
damgasını saniyeye kadar keser, `uniq -c` yan yana tekrarları sayar, `sort -rn` en kalabalığı
üste koyar:
""", komut="cut -d' ' -f1 <<log_k>>/kupon_erisim.log | cut -c1-19 | uniq -c | sort -rn | head -3",
         sonra="""
Normal kullanıcı bir saniyede bir kupon bozdurur. Aynı saniyede **birden çok** istek varsa biri
bir şeyi hızla tekrarlıyor demektir. Bu istekler çoğu zaman sırayla değil **aynı anda** işlenir;
buna **yarış durumu** (race condition) denir.
"""),
    Adim("Kodda kontrolü ara", """
Kuponun kullanılıp kullanılmadığı kodda kontrol ediliyor mu? `kullanildi` kelimesini ara:
""", komut="grep -n 'kullanildi' uygulama/mantik.py", sonra="""
Kod kuponu okuyor, değeri hesaba ekliyor, sonra sayacı artırıyor; ama **araya hiçbir "zaten
kullanılmış mı?" kontrolü girmemiş**. Bu en basit hâli: art arda iki istek de kabul edilir.

Kontrolü eklesen bile bir tuzak var: *önce oku, sonra yaz* iki ayrı adımdır. İki istek aynı
anda "kullanılmamış" okuyup ikisi de yazabilir. Gerçek çözüm, kontrolü ve işaretlemeyi tek
bir **atomik** (bölünmez) veritabanı işlemine sığdırmaktır.
"""),
    Adim("Atomik güncelleme", """
SQL'de `UPDATE ... WHERE kullanildi = 0` ifadesi tek bir bölünmez işlemdir: koşulu veritabanı
**satırı kilitleyerek** kontrol eder. Kaç satırın değiştiğini `imlec.rowcount` söyler: 0 ise
başkası seni geçmiş demektir. Bu kalıbı unutma:

```
islendi = db.execute("UPDATE kuponlar SET kullanildi = 1 WHERE kod = ? AND kullanildi = 0", (kod,))
if islendi.rowcount == 0:
    return 409, {"hata": "kupon daha önce kullanılmış"}
```

**Hacker gözüyle:** Yarış durumu açıkları, bir saldırganın aynı anda çok istek göndermesiyle
sömürülür; bu yüzden iş mantığında "kontrol et, sonra yap" kalıbı finansal kodda kırmızı bayraktır.
""", komut=None),
]

GOREVLER = [
    Gorev("`<<log_k>>/kupon_erisim.log` içinde aynı saniye içinde art arda kupon bozduran **kullanıcı** kim? "
          "(log'daki adıyla yaz)",
          Metin("saldirgan", bicim="kullanıcı adı (örn. ad.soyad)"),
          ("Eğitimde aynı saniyedeki istek kümelerini bulmuştun; en kalabalık saniyeye bak.",
           "En kalabalık saniyenin zaman damgasını (ilk 19 karakter) `grep` ile aratırsan o saniyedeki satırları görürsün; kullanıcı adı ikinci alan.",
           "`cut -d' ' -f1 <<log_k>>/kupon_erisim.log | cut -c1-19 | uniq -c | sort -rn | head -1` saniyeyi verir; "
           "sonra `grep '<saniye>' <<log_k>>/kupon_erisim.log | cut -d' ' -f2 | sort -u`."),
          puan=30, baslik="Kim"),
    Gorev("Bu kullanıcı aynı kuponu toplam **kaç kez** başarıyla (HTTP 200) bozdurdu?",
          Sayi("adet", sik_hatalar=lambda g, b, bg: "Sadece o kullanıcının kupon isteklerini say; `GET /hesabim` "
                "gibi satırlar kupon değil." if g.isdigit() and int(g) == b + 1 else None),
          ("Kullanıcı adıyla ve `POST /kupon/kullan` ile süzüp 200 olanları say.",
           "`grep '<kullanıcı> POST /kupon/kullan' ... | grep -c ' 200$'` kalıbı.",
           "Önce kullanıcı adını bul (1. görev), sonra o adla `grep`, sonra `grep -c ' 200$'` ya da `wc -l`."),
          puan=30, baslik="Kaç kez"),
    Gorev("`kupon_tanimlari.csv` içindeki değeri kullan: bu kullanıcı kuponun hakkından fazla bozdurarak "
          "**kaç TL fazladan** değer elde etti? (tam sayı)",
          Sayi("kayip_tl", sik_hatalar=lambda g, b, bg: "Hakkı olan ilk kullanım zarar sayılmaz; yalnızca fazladan "
                "bozdurulanlar." if g.isdigit() and b > 0 and int(g) > b else None),
          ("Kupon bir kez geçerliydi. Fazladan kaç kez bozdurulmuş?",
           "Fazla sayısı = bozdurma adedi − 1. Kuponun TL değeri CSV'de, kod logda.",
           "(adet − 1) × kuponun değeri. Değeri `grep '<kod>' kupon_tanimlari.csv` ile bul."),
          puan=40, baslik="Etki: fazladan değer"),
    Gorev("Aynı kullanıcının istekleri milisaniye aralıklarla art arda, **yanıtlar beklenmeden** gelmiş. "
          "Bu desen neyi gösterir?",
          Secmeli([
              ("Birden çok istek aynı anda işlendi ve her biri kuponu \"kullanılmamış\" gördü", "Doğru: bu yarış durumudur (race condition). Kontrol ile işaretleme arasındaki boşlukta istekler birbirinin sonucunu görmeden işlenir."),
              ("Kullanıcının internet bağlantısı koptu ve tarayıcı isteği otomatik tekrarladı", "Olası ama bu deseni açıklamaz: tekrar eden istek ayrı ayrı gelir, milisaniyeler içinde birkaç tane ve hepsinin 200 dönmesi başka bir şeye işaret eder."),
              ("Sunucunun saati yanlıştı ve zaman damgaları bozuk yazıldı", "Yanlış: zaman damgaları diğer kullanıcılarda tutarlı; bu kullanıcıya özgü bir yığılma var."),
              ("Kupon veritabanında birden çok kez tanımlanmıştı", "Yanlış: `kupon_tanimlari.csv`'de her kod bir kez geçiyor ve hakkı 1."),
          ], dogru=0),
          ("Tek bir kullanıcı bir saniyede kaç kez kupon bozdurabilir? İnsan eliyle mümkün mü?",
           "Aynı anda gelen iki istek, birbirinin veritabanına yazdığını görmeden kontrolden geçebilir.",
           "Doğru şık, 'aynı anda işlenen istekler kuponu kullanılmamış gördü' diyen şık."),
          puan=30, baslik="Yarış durumunu tanı"),
    Gorev("**Kanıtla:** Test kuponunu (`<<kupon>>`) kendi test hesabından **en az iki kez** bozdur (`curl` ile). "
          "Sadece kendi test hesabın ve test kuponun. Bitince `cevap 5` yaz.",
          Durum(_kanit, cozum="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
                              "-d '{\"kod\": \"<<kupon>>\"}' http://<<adres>>/kupon/kullan   (iki kez)"),
          ("Eğitimde kuponu bir kez bozdurmuştun. Aynı komutu bir daha çalıştır.",
           "Komutu yukarı ok ile geri çağırıp tekrar çalıştır; yanıtta her seferinde eklenen tutarı gör.",
           "`curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"kod\": \"<<kupon>>\"}' http://<<adres>>/kupon/kullan` komutunu iki kez çalıştır; ikisi de eklesin."),
          puan=40, baslik="Kanıtla"),
    Gorev("`kupon_kullan` fonksiyonunu **düzelt**: kullanılmış kupon ikinci kez kabul edilmesin (4xx dönsün), "
          "ilk kullanım çalışmaya devam etsin. Bitince `cevap 6` yaz.",
          Durum(o.durum_testi(o.test_kupon_tekrar), cozum="Kuponu işaretlemeden önce kullanılıp kullanılmadığına bak; "
                "kullanılmışsa `return 409, {...}` dön."),
          ("Kod kuponu okuyor ama kullanılmış mı diye bakmıyor.",
           "Okuduğun satırda `kullanildi` sütunu zaten var. Sıfırdan farklıysa isteği reddet.",
           "Kuponu bulduktan sonra: `if k[\"kullanildi\"]: return 409, {\"hata\": \"kupon daha önce kullanılmış\"}`."),
          puan=40, baslik="Düzelt: tekrar kullanım"),
    Gorev("Şimdi **yarış durumunu** da kapat: aynı anda gelen iki isteğin yalnızca biri kuponu bozdurabilsin. "
          "Oyun iki isteği gerçekten iç içe çalıştırıp deneyecek. Bitince `cevap 7` yaz.",
          Durum(o.durum_testi(o.test_kupon_yaris), cozum="`UPDATE kuponlar SET kullanildi = 1 WHERE kod = ? AND kullanildi = 0` "
                "çalıştır ve `rowcount == 0` ise 409 dön; hesabı yalnızca bundan sonra güncelle."),
          ("Önce-oku-sonra-yaz iki ayrı adım. İkisini tek bir SQL ifadesine sığdırmanın yolu var.",
           "UPDATE'in `WHERE` kısmına `AND kullanildi = 0` ekle ve `imlec.rowcount` ile kaç satırın değiştiğine bak.",
           "`islendi = db.execute(\"UPDATE kuponlar SET kullanildi = 1 WHERE kod = ? AND kullanildi = 0\", (kod,))` "
           "ardından `if islendi.rowcount == 0: return 409, {...}`; hesaba para eklemeyi bu kontrolden SONRA yap."),
          puan=60, baslik="Düzelt: atomik işlem"),
]


def _kapanis():
    return """
Kupon açığı, finansal iş mantığının iki derin dersini taşır. Birincisi: **kuralı kodda gerçekten
uygula** ("tek kullanımlık" yalnızca bir belge cümlesi değildir). İkincisi: **kontrol ile eylem
arasındaki boşluk** saldırgan için bir kapıdır; kontrol et-sonra-yap yerine atomik işlem kullan.
Saldırgan tarafında bu açık çok az sinyal bırakır; yalnızca milisaniyelik zaman damgalarında görünür.
Savunma için: veritabanı kısıtları (benzersizlik, koşullu güncelleme), her işlem için tekrar
güvenliği (idempotency) ve loglarda aynı kimlikten gelen istek yığılması alarmı. Muhasebe gözüyle:
bir kuponun iki kez bozdurulması, aynı faturanın iki kez ödenmesinin kuzenidir.
"""


SEVIYE = Seviye(
    kimlik="c10b03",
    cilt=10,
    bolum=3,
    baslik="İş Mantığı Açıkları II: Kupon ve Yarış Durumu",
    brifing="""
<<sahne>> Bu sefer konu **<<kupon_adi>>**: <<kisi>> kampanya bütçesinin beklenenden hızlı eridiğini söylüyor.
Selin logu sana uzatıyor: "Her kodun kullanım hakkı bir. Biri bu hakkı aşmış gibi görünüyor. Loglardan kim
olduğunu ve ne kadar fazladan değer çıkardığını bul; test hesabında kendin de yeniden üret. Sonra kodu düzelt."

Mert kahvesini bırakıyor: "Zaman damgalarına milisaniye diye bakma, **eşzamanlılık** diye bak. Kontrol ile
yazma arasındaki boşluk, saldırganın bütün zamanıdır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Yarış durumu açıkları:** Hediye kartı, kupon ve bakiye aktarımı gibi "kontrol et, sonra
  değiştir" akışlarında yarış durumu bulguları, bug bounty raporlarında ve güvenlik
  araştırmacılarının yazılarında defalarca kamuya açık biçimde anlatılmıştır; en bilinen
  örneklerden biri, büyük bir kahve zincirinin hediye kartı bakiyesiyle ilgili 2015'te
  yayımlanan araştırmadır. Güvenlik araştırmacıları sonraki yıllarda yarış durumlarını daha
  güvenilir tetikleyen teknikler de yayımlamıştır; yani bu açık "şansa kalan" bir açık değil.
- **Tespit:** Aynı kimlikten milisaniyeler içinde gelen çok sayıda istek, aynı kupon kodunun
  birden çok başarılı kullanımı ve beklenenden hızlı eriyen kampanya bütçesi güçlü işaretlerdir.
- **Önleme:** Kontrolü ve değişikliği tek atomik işlemde yap (koşullu `UPDATE`, benzersizlik
  kısıtı, kilit ya da işlem izolasyonu), ödeme isteklerine benzersiz kimlik ver (idempotency) ve
  kupon kullanımını ayrı bir tabloda kayıt altına al.
""",
    sure_hedef_dk=30,
)
