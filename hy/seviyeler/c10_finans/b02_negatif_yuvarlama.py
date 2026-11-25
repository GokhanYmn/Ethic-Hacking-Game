"""Cilt 10 · Bölüm 2 — İş Mantığı Açıkları I: Negatif Tutar ve Yuvarlama.

Beceri: negatif tutarlı transferi loglardan tanımak, kendi test hesabında kanıtlamak, etkisini
hesaplamak ve `transfer` kodunu düzeltmek; komisyon yuvarlamasının (kesme) bıraktığı kuruş
farkını hesaplayıp tam sayı aritmetiğiyle düzeltmek.

Vakalar: banka, dijital cüzdan, ödeme altyapısı. Aynı açık farklı müşteri hikâyesi, log ve klasör
adlarıyla sorulur. Düzeltme canlı sunucuda değil, bellekteki bir kopyada test edilir.
"""
from __future__ import annotations

import json
import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

KLASORLER = {"ferah": ("sube_loglari", "muhasebe"), "paramix": ("api_loglari", "cuzdan_defteri"),
             "pazarix": ("odeme_loglari", "mutabakat")}


def uret(rng):
    kod, v = o.vaka_sec(rng, KLASORLER)
    s = o.taban(rng, kod)
    for m in s["musteriler"]:
        m["bakiye_kurus"] = rng.randrange(900000, 4000000, 25)
    ms = s["musteriler"]
    saldirgan = rng.choice(ms[2:])
    gun = u.gun(rng)
    satirlar = []                                       # (zaman, metin)
    t = gun + timedelta(hours=9)
    for _ in range(rng.randint(26, 34)):                # sıradan trafik
        t += timedelta(seconds=rng.randint(40, 900))
        m = rng.choice([x for x in ms if x is not saldirgan])
        if rng.random() < 0.35:
            satirlar.append((t, o.log_satiri(t, o.ascii_ad(m["ad"]), "GET", "/hesabim", None, 200)))
        else:
            hedef = rng.choice([x for x in ms if x is not m])
            tutar = rng.choice([50, 75, 120, 250, 400, 1200, 15.5, 89.9, 310.25])
            satirlar.append((t, o.log_satiri(t, o.ascii_ad(m["ad"]), "POST", "/transfer",
                                             {"kime": hedef["hesap_id"], "tutar": tutar}, 200)))
    tn = gun + timedelta(hours=rng.choice([2, 3, 4]), minutes=rng.randint(0, 40))
    negatifler = []
    for _ in range(rng.randint(3, 4)):                  # saldırganın negatif transferleri (gece)
        tn += timedelta(seconds=rng.randint(20, 240))
        kurban = rng.choice([x for x in ms if x is not saldirgan])
        tutar = -rng.choice([500, 750, 1000, 1500, 2000, 2500, 3000])
        negatifler.append(-tutar)
        satirlar.append((tn, o.log_satiri(tn, o.ascii_ad(saldirgan["ad"]), "POST", "/transfer",
                                          {"kime": kurban["hesap_id"], "tutar": tutar}, 200)))
        if rng.random() < 0.5:
            tn += timedelta(seconds=rng.randint(5, 30))
            satirlar.append((tn, o.log_satiri(tn, o.ascii_ad(saldirgan["ad"]), "GET", "/hesabim", None, 200)))
    satirlar.sort(key=lambda x: x[0])
    # Komisyon geçmişi: eski kod kesiyordu; doğru kural en yakın kuruşa yuvarlar
    kayitlar = []
    for i in range(1, rng.randint(110, 140) + 1):
        tutar = rng.randrange(1000, 250000, 5) if rng.random() < 0.7 else rng.randint(1000, 250000)
        kayitlar.append((i, tutar, tutar * 125 // 10000))
    fark = sum((tutar * 125 + 5000) // 10000 - kom for _, tutar, kom in kayitlar)
    s.update({"log_satirlari": [x[1] for x in satirlar], "kayitlar": kayitlar, "log_k": KLASORLER[kod][0],
              "defter_k": KLASORLER[kod][1], "saldirgan": saldirgan})
    s["metin"].update({"log_k": KLASORLER[kod][0], "defter_k": KLASORLER[kod][1], "komsu": ms[1]["hesap_id"]})
    s["cevaplar"] = {
        "saldirgan": [saldirgan["ad"], o.ascii_ad(saldirgan["ad"]), saldirgan["ad"].replace(" ", ".").lower()],
        "calinan": sum(negatifler),
        "yuvarlama": fark,
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — iş mantığı denetimi\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Test hesabın          : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}\n"
          f"Komşu test hesabı     : {s['musteriler'][1]['hesap_id']}\n\n"
          f"{s['log_k']}/erisim.log      geçen haftaki uygulama erişim logu\n"
          f"{s['defter_k']}/islemler.csv  geçmiş transferlerin komisyon kayıtları\n"
          "kural_belgesi.txt           ürün ekibinin yazdığı iş kuralları\n"
          "uygulama/mantik.py          düzelteceğin kod\n")
    u.yaz(lab / "kural_belgesi.txt",
          f"{s['v']['musteri']} — transfer iş kuralları\n"
          "1. Transfer tutarı sıfırdan büyük olmalıdır.\n"
          "2. Gönderen, tutar ve komisyonu ödeyebilmelidir.\n"
          "3. Komisyon tutarın %1,25'idir; en yakın kuruşa yuvarlanır, yarımlar yukarı.\n"
          "4. Transfer alıcıya tutarın tamamını ulaştırır; komisyon yalnızca göndereni etkiler.\n")
    u.yaz(lab / s["log_k"] / "erisim.log", "\n".join(s["log_satirlari"]) + "\n")
    u.yaz(lab / s["defter_k"] / "islemler.csv", "no;tutar_kurus;komisyon_kurus\n" + "".join(
        f"{n};{t};{k}\n" for n, t, k in s["kayitlar"]))
    o.uygulama_yaz(lab, s, o.KOD_SAGLIK + o.KOMISYON_HATALI + o.TRANSFER_ACIK)


def _kanit(b) -> Sonuc:
    ben = b.senaryo["musteriler"][0]
    n = o.db_oku(b.lab, "SELECT COUNT(*) FROM islemler WHERE kimden = ? AND tutar_kurus < 0", (ben["hesap_id"],))[0][0]
    if n:
        return Sonuc(True, "Kendi test hesabında negatif transferin çalıştığını kanıtladın: işlem veritabanına yazılmış.")
    return Sonuc(False, "Veritabanında senin hesabından yapılmış negatif tutarlı bir işlem yok. `curl` ile komşu "
                        "hesaba **negatif** bir tutar göndermeyi dene (kendi test hesabınla!).")


def coz(lab: Path, s: dict) -> dict:
    cozum = {}
    cozum[1] = o.sh(f"grep '\"tutar\":-' {s['log_k']}/erisim.log | awk '{{print $2}}' | sort -u", lab)
    cozum[2] = o.sh("grep -o '\"tutar\":-[0-9.]*' " + s["log_k"] + "/erisim.log | cut -d- -f2 | awk '{s+=$1} END{print s}'", lab)
    o.curl(s, lab, "POST", "/transfer", {"kime": s["musteriler"][1]["hesap_id"], "tutar": -40})
    cozum[3] = ""
    cozum[4] = o.sh(f"awk -F';' 'NR>1{{s+=int(($2*125+5000)/10000)-$3}} END{{print s}}' {s['defter_k']}/islemler.csv", lab)
    o.duzelt(lab, "transfer")
    cozum[5] = ""
    o.duzelt(lab, "komisyon_kurus")
    cozum[6] = ""
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Kuralları oku", """
Bir iş mantığı açığını bulmanın ilk adımı, **uygulamanın ne yapması gerektiğini** bilmektir.
Ürün ekibinin yazdığı kurallara bak; açık, bu kurallarla kodun uyuşmadığı yerde olacak:
""", komut="cat kural_belgesi.txt"),
    Adim("Normal bir transfer", """
Önce uygulamanın normal davranışını gör. Test hesabından komşu test hesabına 10 TL gönder.
`-X POST` bir veri gönderdiğimizi, `-d` gövdeyi, `-H` başlıkları belirtir:
""", komut="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"kime\": <<komsu>>, \"tutar\": 10}' http://<<adres>>/transfer",
         sonra="""
Yanıttaki `komisyon_kurus` ve `yeni_bakiye_kurus` alanlarına bak. Para **kuruş** cinsinden tam
sayıdır; gönderdiğin 10 TL, `1000` kuruş eder.
"""),
    Adim("Geçmiş log: izleri oku", """
`<<log_k>>/erisim.log` geçen haftanın erişim kaydı. Her satır: zaman, **kullanıcı**, yöntem, adres,
**gövde** ve HTTP kodu. Gövdede transferin tutarı açıkça görünür. İlk satırlara bak:
""", komut="head -5 <<log_k>>/erisim.log"),
    Adim("Şüpheli deseni ara", """
İş mantığı açıkları saldırı imzası bırakmaz; ama **mantıksız bir değer** bırakır. Bir transfer
tutarının eksi olması mantıksızdır. `grep -c` eşleşen satırları sayar:
""", komut="grep -c '\"tutar\":-' <<log_k>>/erisim.log", sonra="""
Hepsi `200` yani **başarılı** döndü. Uygulama bu istekleri kabul etmiş. Satırları `grep` ile
çıkarıp kimin gönderdiğine ve tutarlarına bak: kullanıcı adı ikinci alan.

**Hacker gözüyle:** Her işlem için şunu sor: "Bu değer negatif olabilir mi? Sıfır olabilir mi?
Çok büyük olabilir mi?" Otomatik tarayıcılar bunu sormaz; sen sorarsın.
"""),
    Adim("Komisyon kayıtlarına bak", """
`<<defter_k>>/islemler.csv` geçmiş transferlerin tutarını ve **kesilen komisyonu** gösteriyor. Kural:
%1,25, en yakın kuruşa yuvarla. İlk üç kaydı gör ve kafanda kontrol et:
""", komut="awk -F';' 'NR>1{print $2, $3}' <<defter_k>>/islemler.csv | head -3", sonra="""
Örnek: 1000 kuruşun %1,25'i 12,5 kuruş. "Yarımlar yukarı" kuralıyla 13 olmalı. Kod ise 12'ye
**kesiyor** olabilir. Tek işlemde fark yarım kuruş; yüz binlerce işlemde bu bir **para**dır.
"""),
    Adim("Kodu bul", """
Düzelteceğin yer `uygulama/mantik.py`. Önce `transfer` ve `komisyon_kurus` fonksiyonlarının
nerede olduğuna bak. `-n` satır numarası gösterir:
""", komut="grep -n 'def \\|tutar' uygulama/mantik.py | head -20", sonra="""
Dosyayı `nano uygulama/mantik.py` ile aç, değiştir, kaydet (Ctrl+O, Enter, Ctrl+X). Sunucu her
istekte dosyayı yeniden okur; yeniden başlatmaya gerek yok. Düzeltmeyi oyun kendi test verisiyle
dener, bu yüzden canlı veritabanını bozmandan korkma.
"""),
]

GOREVLER = [
    Gorev("`<<log_k>>/erisim.log` içinde negatif tutarlı transferleri gönderen **kullanıcı** kim? (log'daki adıyla yaz)",
          Metin("saldirgan", bicim="kullanıcı adı (örn. ad.soyad)"),
          ("Negatif tutar gövdede `\"tutar\":-` biçiminde görünür.",
           "`grep '\"tutar\":-' <<log_k>>/erisim.log` ile satırları çıkar; kullanıcı ikinci alan.",
           "`grep '\"tutar\":-' <<log_k>>/erisim.log | awk '{print $2}' | sort -u`"),
          puan=30, baslik="Kim gönderdi"),
    Gorev("Bu kullanıcının negatif transferleriyle toplam **kaç TL** (tam sayı) çekilmiş? "
          "(Eksi işaretini atıp tutarları topla)",
          Sayi("calinan", sik_hatalar=lambda g, b, bg: "Eksi işaretli toplamı mı yazdın? Çekilen tutar pozitif bir "
                "sayı olarak sorulur." if g.lstrip("-").isdigit() and int(g) == -b else None),
          ("Her negatif satırdaki tutarı çıkarıp toplamak gerekiyor; `awk` ya da elle toplayabilirsin.",
           "`grep -o` yalnızca eşleşen kısmı basar; `cut -d- -f2` eksiyi atar; `awk '{s+=$1} END{print s}'` toplar.",
           "`grep -o '\"tutar\":-[0-9.]*' <<log_k>>/erisim.log | cut -d- -f2 | awk '{s+=$1} END{print s}'`"),
          puan=40, baslik="Etki: çekilen tutar"),
    Gorev("**Kanıtla:** Kendi test hesabından komşu hesaba (`<<komsu>>`) **negatif** tutarlı bir transfer gönder "
          "(`curl` ile). Sadece kendi test hesabını kullan. Bitince `cevap 3` yaz.",
          Durum(_kanit, cozum="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
                              "-d '{\"kime\": <<komsu>>, \"tutar\": -40}' http://<<adres>>/transfer"),
          ("Normal transferi eğitimde yaptın; aynı isteği, tutarı eksi yaparak gönder.",
           "`-d '{\"kime\": <<komsu>>, \"tutar\": -40}'` gövdesiyle `/transfer` ucuna POST at.",
           "`curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"kime\": <<komsu>>, \"tutar\": -40}' http://<<adres>>/transfer` — bakiyenin ARTTIĞINI gör."),
          puan=40, baslik="Kanıtla"),
    Gorev("`<<defter_k>>/islemler.csv` içindeki komisyonlar kesilerek hesaplanmış. Doğru kural "
          "(en yakın kuruşa, yarımlar yukarı) uygulansaydı **toplam komisyon kaç kuruş daha fazla** olurdu?",
          Sayi("yuvarlama", sik_hatalar=lambda g, b, bg: "Çok yaklaştın ama küçük bir sapma var; bu kuruş cinsinden "
                "toplamdır ve yarımlar yukarı yuvarlanmalı." if g.lstrip("-").isdigit() and 0 < abs(int(g) - b) <= 3 else None),
          ("Her satır için doğru komisyon ile kayıtlı komisyonu karşılaştırıp farkları toplayacaksın.",
           "Doğru komisyon: `(tutar*125 + 5000) / 10000` tam sayı bölmesi. Kayıtlı komisyon üçüncü sütun.",
           "`awk -F';' 'NR>1{s+=int(($2*125+5000)/10000)-$3} END{print s}' <<defter_k>>/islemler.csv`"),
          puan=40, baslik="Etki: yuvarlama farkı"),
    Gorev("`uygulama/mantik.py` içindeki `transfer` fonksiyonunu **düzelt**: sıfır, negatif ve sayı olmayan tutarları "
          "400 koduyla reddetsin; normal transfer çalışmaya devam etsin. Bitince `cevap 5` yaz.",
          Durum(o.durum_testi(o.test_negatif), cozum="`transfer` içinde tutarı sayıya çevirdikten sonra "
                "`if tutar <= 0: return 400, {...}` ekle; sayıya çevirme hatasını `try/except` ile yakalayıp 400 dön."),
          ("Kuralın birinci maddesi: tutar sıfırdan büyük olmalı. Kod bunu kontrol ediyor mu?",
           "Tutarı kuruşa çevirdikten hemen sonra bir `if` koy. Ayrıca `float(...)` sayı olmayan metinde hata fırlatır; "
           "bunu `try/except` ile 400'e çevir.",
           "`if tutar <= 0: return 400, {\"hata\": \"tutar sıfırdan büyük olmalı\"}` satırını bakiye kontrolünden ÖNCE ekle."),
          puan=60, baslik="Düzelt: negatif tutar"),
    Gorev("`komisyon_kurus` fonksiyonunu kurala uydur: %1,25, en yakın kuruşa, yarımlar yukarı; **tam sayı** "
          "aritmetiğiyle. Bitince `cevap 6` yaz.",
          Durum(o.durum_testi(o.test_komisyon), cozum="return (tutar_kurus * 125 + 5000) // 10000"),
          ("`int(x * 0.0125)` ondalıklı sayı kullanıyor ve kesiyor. İkisi de sorun.",
           "Ondalık yerine tam sayıyla çalış: önce 125 ile çarp, yarım birimi ekle, sonra `//` ile böl.",
           "%1,25 = 125/10000. Yarımları yukarı yuvarlamak için bölmeden önce 5000 ekle: `(tutar_kurus * 125 + 5000) // 10000`."),
          puan=50, baslik="Düzelt: yuvarlama"),
    Gorev("Mobil uygulama negatif tutar girmenize izin vermiyor. Sunucuda yine de kontrol gerekir mi?",
          Secmeli([
              ("Evet, çünkü istemci kontrolü atlanabilir: saldırgan doğrudan API'yi çağırır", "Doğru: arayüzdeki kontrol yalnızca kullanıcı rahatlığıdır. Güvenlik kontrolü her zaman sunucuda olmalıdır (istemciye asla güvenme)."),
              ("Hayır, arayüz zaten engelliyorsa sunucuda ikinci kez kontrol etmek gereksiz yük getirir", "Yanlış: arayüz saldırganın kontrolündeki bir bileşendir; `curl` ile onu hiç kullanmadan istek atılabilir, nitekim az önce yaptın."),
              ("Hayır, mobil uygulama imzalıysa gönderdiği tutarlara her zaman güvenilebilir", "Yanlış: imza uygulamanın kendisini korur, arkasındaki API'ye elle yapılan isteği değil."),
              ("Evet, ama yalnızca uygulama eski bir sürümdeyse gerekir", "Yanlış: kontrolün gerekliliği sürümle ilgili değildir; her sürümde API doğrudan çağrılabilir."),
          ], dogru=0),
          ("Bu görevin 3. adımında arayüzü hiç kullanmadan ne yaptığını hatırla.",
           "Saldırgan hangi bileşeni kontrol eder: telefondaki uygulamayı mı, sunucuyu mu?",
           "Doğru şık, istemci kontrolünün atlanabildiğini ve API'nin doğrudan çağrılabildiğini söyleyen şık."),
          puan=20, baslik="İstemciye güvenme"),
]


def _kapanis():
    return """
Negatif tutar açığı ders kitabı kadar basit ve hâlâ gerçek sistemlerde çıkar: kod "doğru" çalışır,
çünkü eksi bir sayıyı da toplayıp çıkarabilir; eksik olan, "bu değer ne olamaz?" sorusunun kurala
dönüşmemiş olmasıdır. Yuvarlama ise sessiz tarafı: tek işlemde görünmez, milyonlarcasında bir hesap
kalemi olur. Saldırgan her ikisini de arar: biri hızlı para, öteki fark edilmeyen para. Savunma
dersi: her girdiyi **iş kurallarına** göre doğrula (sıfır, negatif, aşırı büyük), parayı tam sayı
kuruşla tut, yuvarlamayı kurala bağla ve geçmiş kayıtları mutabakatla karşılaştır. Senin muhasebe
bilgin burada bir silah: "Bu kuruş kimin?" diye sorabilen kişi, açığı koddan önce görür.
"""


SEVIYE = Seviye(
    kimlik="c10b02",
    cilt=10,
    bolum=2,
    baslik="İş Mantığı Açıkları I: Negatif Tutar ve Yuvarlama",
    brifing="""
<<sahne>> Ürün sahibi <<kisi>>, geçen hafta bir hesapta açıklanamayan bir artış fark ettiklerini
söylüyor. Selin dosyayı sana uzatıyor: "Önce loglardan olayı yeniden kur: kim, ne yaptı, kaç
lira? Sonra kendi test hesabında aynısını yapıp **kanıtla**. En sonunda kodu düzelt. Rapora
kanıtsız bir cümle yazmıyoruz."

Mert ekliyor: "Bir de komisyon kayıtlarına bak. Orada başka bir şey kokuyor; para yoktan var
olmuyor ama kuruş kuruş yok olabiliyor."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **İş mantığı açıkları ve OWASP:** OWASP Top 10'un 2021 sürümünde "Güvensiz Tasarım" (Insecure
  Design) kategorisi, tam bu tür kural eksiklerini kapsar: kod hatasız çalışır ama kural eksiktir.
  Pek çok sızma testi raporunda "negatif ya da aşırı büyük tutar kabul ediliyor" bulgusu sık
  görülür; bug bounty programlarında da klasik bir iş mantığı bulgusudur.
- **Yuvarlama ve kesme hataları:** Finans tarihinin bilinen örneklerinden biri, 1980'lerin başında
  bir borsa endeksinin her güncellemede yuvarlama yerine kesme yapması yüzünden zamanla gerçek
  değerinin çok altına düşmesi, düzeltildiğinde değerin kabaca ikiye katlanmasıdır. Ders: küçük
  bir yuvarlama kuralı, yeterli sayıda işlemde büyük bir farka dönüşür.
- **Tespit ve önleme:** Tespit için tutar dağılımı alarmları (negatif ya da olağandışı tutar),
  günlük mutabakat ve aynı kullanıcıdan art arda gelen işlemlere uyarı kullanılır. Önlemek için
  girdi doğrulama sunucuda yapılır, para tam sayı kuruş ya da `Decimal` ile tutulur ve yuvarlama
  kuralı belgelenip testlenir.
""",
    sure_hedef_dk=30,
)
