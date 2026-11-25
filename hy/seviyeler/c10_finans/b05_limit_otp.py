"""Cilt 10 · Bölüm 5 — İşlem Güvenliği: İstemci Tarafı Limit ve OTP/İşlem Onayı Atlama.

Beceri: istemcide (mobil uygulama kodu) yapılan kontrolün sunucuda yapılmadığını görmek, kendi
test hesabında kanıtlamak; işlem onayında OTP'nin (tek seferlik kod) sunucuya "doğrulandı"
beyanıyla atlanabildiğini kanıtlamak; ikisini de düzeltmek (sunucu tarafı limit, sunucu tarafı
OTP doğrulaması, sahiplik ve tekrar güvenliği).

Vakalar: banka EFT onayı, dijital cüzdan transferi, lojistik bayi ödemesi, ödeme altyapısı hakediş
onayı. Servis her istekte mantik.py'yi yeniden okur; düzeltme testleri bellek veritabanında çalışır.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

VAKA = {  # kod: (akış adı, istemci adı)
    "ferah": ("EFT onayı", "Ferah Mobil"),
    "paramix": ("cüzdan transfer onayı", "Paramix Mobil"),
    "kuzgun": ("bayi ödeme onayı", "Kuzgun Bayi Uygulaması"),
    "pazarix": ("hakediş ödemesi onayı", "Pazarix Satıcı Uygulaması"),
}


def uret(rng):
    kod, v = o.vaka_sec(rng, VAKA)
    akis, istemci = VAKA[kod]
    s = o.taban(rng, kod)
    for m in s["musteriler"]:
        m["bakiye_kurus"] = rng.randrange(1500000, 4000000, 25)
    ms = s["musteriler"]
    otp1 = "%06d" % rng.randint(100000, 999999)
    tutar1 = rng.randrange(15000, 90000, 50)
    s["bekleyen"] = [
        {"id": 1, "kimden": ms[0]["hesap_id"], "kime": ms[1]["hesap_id"], "tutar_kurus": tutar1, "otp": otp1},
        {"id": 2, "kimden": ms[0]["hesap_id"], "kime": ms[2]["hesap_id"], "tutar_kurus": rng.randrange(10000, 40000, 50),
         "otp": "%06d" % rng.randint(100000, 999999)},
        {"id": 3, "kimden": ms[3]["hesap_id"], "kime": ms[0]["hesap_id"], "tutar_kurus": rng.randrange(10000, 40000, 50),
         "otp": "%06d" % rng.randint(100000, 999999)},
    ]
    gun = u.gun(rng)
    s.update({"akis": akis, "istemci": istemci, "gun": gun})
    s["metin"].update({"akis": akis, "istemci": istemci, "limit_tl": ms[0]["islem_limiti_kurus"] // 100,
                       "bekleyen_id": 2, "komsu_h": ms[1]["hesap_id"],
                       "buyuk_tl": ms[0]["islem_limiti_kurus"] // 100 + 100})
    s["cevaplar"] = {"istemci_limit": ms[0]["islem_limiti_kurus"] // 100, "otp": otp1}
    s["sms_baslangic"] = [f"{gun + timedelta(hours=9, minutes=3):%Y-%m-%dT%H:%M:%S} SMS: Ferah Mini onay kodunuz "
                          f"{otp1} (işlem #1, {tutar1 / 100:.2f} TL)\n"]
    return s


ISTEMCI = '''# {istemci} — kurgusal mobil uygulama istemci kodu (SADECE OKUMA AMAÇLI).
# Bu dosya telefondaki uygulamanın mantığını gösterir; sunucu değildir.

ISLEM_LIMITI_TL = {limit}          # kullanıcı başına işlem limiti


def transfer_gonder(kime, tutar_tl):
    if tutar_tl > ISLEM_LIMITI_TL:
        ekranda_goster("İşlem limitinizi aşıyorsunuz")      # kontrol YALNIZCA burada
        return
    yanit = post("/transfer/baslat", {{"kime": kime, "tutar": tutar_tl}})
    ekranda_goster("SMS ile gelen onay kodunu girin")
    return yanit["id"]


def onayla(bekleyen_id, girilen_kod):
    # Kod telefonda kontrol edilir; sunucuya yalnızca sonuç bildirilir.
    dogru_mu = girilen_kod == sms_kutusundaki_kod(bekleyen_id)
    post("/transfer/onayla", {{"id": bekleyen_id, "dogrulandi": dogru_mu, "otp": girilen_kod}})
'''


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — {s['akis']} güvenliği\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Test hesabın          : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}\n"
          f"Komşu test hesabı     : {s['musteriler'][1]['hesap_id']}\n\n"
          "Akış: POST /transfer/baslat  ->  SMS ile onay kodu (uygulama/sms.log)  ->  POST /transfer/onayla\n"
          f"Bekleyen işlemler (test): #1 ve #{s['metin']['bekleyen_id']} senin hesabından başlatılmış, onay bekliyor.\n"
          "istemci/mobil_uygulama.py   telefondaki uygulamanın (kurgusal) kodu\n"
          "uygulama/mantik.py          sunucunun kodu; düzelteceğin yer burası\n")
    u.yaz(lab / "istemci" / "mobil_uygulama.py",
          ISTEMCI.format(istemci=s["istemci"], limit=s["musteriler"][0]["islem_limiti_kurus"] // 100))
    o.uygulama_yaz(lab, s, o.KOD_SAGLIK + o.BASLAT_ACIK + o.ONAYLA_ACIK, sms_baslangic=s["sms_baslangic"])


def _kanit_limit(b) -> Sonuc:
    ben = b.senaryo["musteriler"][0]
    n = o.db_oku(b.lab, "SELECT COUNT(*) FROM bekleyen WHERE kimden = ? AND tutar_kurus > ?",
                 (ben["hesap_id"], ben["islem_limiti_kurus"]))[0][0]
    if n:
        return Sonuc(True, "Limit üstü bir işlemi sunucuya başlatabildin: limit yalnızca istemcideymiş.")
    return Sonuc(False, "Limitin üstünde bir tutarla başlatılmış bir işlem yok. İstemci kodunu hiç kullanmadan "
                        "`/transfer/baslat` ucuna doğrudan limitten büyük bir tutar gönder.")


def _kanit_otp(b) -> Sonuc:
    bid = b.senaryo["metin"]["bekleyen_id"]
    r = o.db_oku(b.lab, "SELECT durum FROM bekleyen WHERE id = ?", (bid,))
    if r and r[0][0] == "tamam":
        return Sonuc(True, f"#{bid} işlemini onay kodunu bilmeden tamamladın: sunucu kodu hiç doğrulamamış.")
    return Sonuc(False, f"#{bid} numaralı bekleyen işlem hâlâ onay bekliyor. Onay kodunu bilmeden, istemcinin "
                        "gönderdiği gibi bir `\"dogrulandi\"` alanıyla onaylamayı dene.")


def coz(lab: Path, s: dict) -> dict:
    ben, komsu = s["musteriler"][0], s["musteriler"][1]
    limit = o.sh("grep -o 'ISLEM_LIMITI_TL = [0-9]*' istemci/mobil_uygulama.py | grep -o '[0-9]*$'", lab)
    o.curl(s, lab, "POST", "/transfer/baslat", {"kime": komsu["hesap_id"], "tutar": int(limit) + 100})
    otp = o.sh("grep '#1,' uygulama/sms.log | grep -o '[0-9]\\{6\\}' | head -1", lab)
    o.curl(s, lab, "POST", "/transfer/onayla", {"id": s["metin"]["bekleyen_id"], "dogrulandi": True})
    o.duzelt(lab, "transfer_baslat", "transfer_onayla")
    cozum = {1: limit, 2: "", 3: otp, 4: "", 5: "", 6: "", 7: "", 8: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("İstemci kodunu oku", """
Mobil uygulamanın arayüzü ve kodu **senin telefonunda** (yani saldırganın kontrolünde) çalışır.
Burada kurgusal bir istemci kodu var. Limit ve onay mantığı nerede yapılıyor?
""", komut="cat istemci/mobil_uygulama.py", sonra="""
İki şeye dikkat: limit kontrolü `if tutar_tl > ISLEM_LIMITI_TL` ile **yalnızca istemcide**,
OTP kontrolü de yine telefonda yapılıp sunucuya sadece `"dogrulandi": true/false` olarak
bildiriliyor. Bu iki karar da güvenlik açısından yanlış yerde verilmiş.
"""),
    Adim("Normal akış: işlemi başlat", """
Normal akışta işlem iki adımlıdır: önce **başlat** (bekleyen işlem oluşur, telefona SMS ile kod
gider), sonra **onayla** (kodu gönder). Limit altında bir işlem başlat:
""", komut="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"kime\": <<komsu_h>>, \"tutar\": 10}' http://<<adres>>/transfer/baslat",
         sonra="""
(Bu komut komşu test hesabına 10 TL'lik bir bekleyen işlem açtı; para henüz gitmedi.) Yanıtta
`onay_bekliyor` ve işlemin `id` değeri var. Sunucu bu işlem için bir onay kodu üretip SMS gönderdi.
"""),
    Adim("SMS kutusu", """
Gerçekte kod telefonuna gelirdi. Lab'da SMS'ler `uygulama/sms.log` dosyasına düşer:
""", komut="cat uygulama/sms.log", sonra="""
Her satır bir SMS: `onay kodunuz <6 hane> (işlem #<no>, <tutar>)`. Hangi kodun hangi işleme
ait olduğunu satırın sonundaki `#<no>` söyler.
"""),
    Adim("Sunucu kodunu oku: limit", """
Sunucuda `transfer_baslat` fonksiyonuna bak. Limiti kontrol eden bir satır var mı? (`sed` ile
fonksiyonu `return 200` satırına kadar göster)
""", komut="sed -n '/def transfer_baslat/,/return 200/p' uygulama/mantik.py", sonra="""
Fonksiyon tutarın sıfırdan büyük olduğuna bakıyor ama **limite bakmıyor**. Kullanıcının limiti
`kul["islem_limiti_kurus"]` ile elinin altında; sadece kullanılmamış.
"""),
    Adim("Sunucu kodunu oku: onay", """
Şimdi onay tarafı. `transfer_onayla` kodu OTP'yi nasıl doğruluyor?
""", komut="sed -n '/def transfer_onayla/,/return 200/p' uygulama/mantik.py", sonra="""
`if not g.get("dogrulandi"):` satırı, istemcinin söylediği **"dogrulandi": true** beyanına güvenip
OTP karşılaştırmasını tamamen atlıyor. Saldırgan kodu bilmeden bu alanı isteğe ekleyebilir.
Oysa OTP'nin tüm anlamı, işlemi gerçekten **telefonu elinde tutanın** yapmasıdır.

**Hacker gözüyle:** Bir isteği kullanıcı arayüzü olmadan elle gönderebildiğin için, istemcinin
yaptığını sandığın her kontrolü deneyebilirsin: "bu alanı değiştirsem sunucu fark eder mi?"
Fark etmiyorsa kontrol yoktur. Savunma tarafında ders sade: karar sunucuda verilir, istemci yalnızca
sorar.
"""),
]

GOREVLER = [
    Gorev("`istemci/mobil_uygulama.py` dosyasında işlem limiti kaç **TL**? (sabitin değeri)",
          Sayi("istemci_limit"),
          ("Dosyada büyük harfle yazılmış bir sabit var, adında LIMIT geçiyor.",
           "`grep LIMIT istemci/mobil_uygulama.py` ile sabiti bul.",
           "`ISLEM_LIMITI_TL = <sayı>` satırındaki sayıyı yaz."),
          puan=20, baslik="İstemcideki limit"),
    Gorev("**Kanıtla:** İstemci kodunu hiç kullanmadan, `/transfer/baslat` ucuna **limitin üstünde** bir tutar "
          "(örneğin <<buyuk_tl>> TL) gönder. Alıcı komşu test hesabı (`<<komsu_h>>`) olsun. "
          "Sadece test hesabın. Bitince `cevap 2` yaz.",
          Durum(_kanit_limit, cozum="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
                                    "-d '{\"kime\": <<komsu_h>>, \"tutar\": <<buyuk_tl>>}' http://<<adres>>/transfer/baslat"),
          ("Eğitimdeki başlatma isteğini kullan; tutarı limitten büyük yap.",
           "Limit <<limit_tl>> TL. Gövdeye `\"tutar\": <<buyuk_tl>>` yaz; `kime` olarak <<komsu_h>> ver.",
           "Aynı `curl` komutu; yanıtta `onay_bekliyor` görmelisin. Limit uygulansaydı 403 görürdün."),
          puan=40, baslik="Kanıtla: limit"),
    Gorev("`uygulama/sms.log` içinde **#1 numaralı** bekleyen işlemin onay kodu nedir?",
          Metin("otp", bicim="6 haneli kod"),
          ("SMS'ler `uygulama/sms.log` dosyasında; satır sonundaki `#<no>` işleme ait.",
           "`grep '#1,' uygulama/sms.log` ile #1 numaralı işlemin satırını bul.",
           "Satırdaki 6 haneli sayı koddur; `grep -o '[0-9]\\{6\\}'` onu ayıklar."),
          puan=30, baslik="OTP'yi oku"),
    Gorev("**Kanıtla:** Onay kodunu **bilmeden**, #<<bekleyen_id>> numaralı bekleyen işlemi (test hesabından) "
          "onaylat: istemcinin gönderdiği `\"dogrulandi\"` alanına güvenen sunucuyu dene. Bitince `cevap 4` yaz.",
          Durum(_kanit_otp, cozum="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
                                  "-d '{\"id\": <<bekleyen_id>>, \"dogrulandi\": true}' http://<<adres>>/transfer/onayla"),
          ("İstemci kodu sunucuya hangi alanı gönderiyor? O alanı sen gönder, kodu verme.",
           "`/transfer/onayla` ucuna `{\"id\": <<bekleyen_id>>, \"dogrulandi\": true}` gövdesini yolla.",
           "`curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"id\": <<bekleyen_id>>, \"dogrulandi\": true}' http://<<adres>>/transfer/onayla` — yanıt `tamam` olmalı."),
          puan=40, baslik="Kanıtla: OTP atlama"),
    Gorev("İşlem onayında OTP'nin (tek seferlik kod) asıl amacı nedir?",
          Secmeli([
              ("Oturum çalınsa bile kodu bilmeyen birinin para hareketi yapamamasını sağlamak", "Doğru: OTP, 'bu işlemi gerçekten telefonu elinde tutan kişi onayladı' kanıtıdır; oturum anahtarı tek başına yetmemelidir."),
              ("Parolanın yerine geçip kullanıcıyı sisteme tek başına giriş yaptırmak ve oturumu başlatmak", "Yanlış: giriş doğrulaması ayrı bir adım; burada OTP, giriş yapılmış bir oturumdaki riskli işlemi ayrıca onaylatır."),
              ("İşlem verisini ağda şifreleyerek dinleyen birinin görmesini engellemek ve veriyi gizlemek", "Yanlış: ağdaki gizliliği TLS sağlar; OTP şifreleme değil, onay mekanizmasıdır."),
              ("Bakiye yetersiz olduğunda işlemi otomatik olarak sunucuda reddedip kullanıcıyı uyarmak", "Yanlış: bakiye kontrolü iş kuralıdır, OTP'nin işi değil."),
          ], dogru=0),
          ("Bir saldırgan yalnızca senin oturum anahtarını ele geçirmiş olsa ne yapabilmesini istemezsin?",
           "OTP, kimliğe ek bir 'ikinci faktör'dür: bildiğin bir şeye (oturum) ek olarak sahip olduğun bir şey (telefon).",
           "Doğru şık, çalınmış oturumla bile işlemin yapılamamasından söz eden şık."),
          puan=20, baslik="OTP ne işe yarar"),
    Gorev("`transfer_baslat` fonksiyonunu **düzelt**: tutar kullanıcının `islem_limiti_kurus` değerini aşıyorsa 403 "
          "dönsün; limit tutarına eşit işlem serbest kalsın. Bitince `cevap 6` yaz.",
          Durum(o.durum_testi(o.test_limit), cozum="`if tutar > kul[\"islem_limiti_kurus\"]: return 403, {...}`"),
          ("Kullanıcının limiti sunucuda zaten elinde: `kul` sözlüğüne bak.",
           "Tutarı kuruşa çevirdikten sonra, bekleyen kaydı oluşturmadan ÖNCE limitle karşılaştır.",
           "`if tutar > kul[\"islem_limiti_kurus\"]: return 403, {\"hata\": \"işlem limitini aşıyor\"}`"),
          puan=50, baslik="Düzelt: sunucu tarafı limit"),
    Gorev("`transfer_onayla` fonksiyonunu **düzelt**: OTP'yi sunucu bekleyen kayıttaki kodla karşılaştırsın "
          "(`dogrulandi` beyanına güvenilmesin); işlemi yalnızca sahibi, doğru kodla ve **bir kez** onaylayabilsin. "
          "Bitince `cevap 7` yaz.",
          Durum(o.durum_testi(o.test_otp), cozum="`dogrulandi` kontrolünü kaldır; `str(g.get(\"otp\")) != b[\"otp\"]` ise 403 dön; "
                "`b[\"kimden\"] != kul[\"hesap_id\"]` ise 404; `b[\"durum\"] != \"bekliyor\"` ise 409."),
          ("Bir kodu kimin karşılaştırması gerekir: istemci mi sunucu mu? Üç ek kural da var: sahip, tekrar.",
           "`if not g.get(\"dogrulandi\"):` bloğunu kaldır, yerine sunucuda `otp` karşılaştır. Sahiplik için `kimden` ile `kul[\"hesap_id\"]`'i, tekrar için `durum`'u kontrol et.",
           "`if str(g.get(\"otp\")) != b[\"otp\"]: return 403`; `if b[\"kimden\"] != kul[\"hesap_id\"]: return 404`; `if b[\"durum\"] != \"bekliyor\": return 409`."),
          puan=70, baslik="Düzelt: sunucu tarafı OTP"),
    Gorev("Aynı onay isteği ağ hatası yüzünden iki kez gönderilse bile paranın yalnızca bir kez gitmesini "
          "sağlayan güvence hangi kavramdır?",
          Secmeli([
              ("Tekrar güvenliği (idempotency)", "Doğru: aynı işlem kimliğiyle gelen ikinci istek yeni bir işlem yaratmaz, yok sayılır. Ödeme sistemlerinde şarttır."),
              ("Çift onay (maker-checker)", "Yanlış: maker-checker, bir işlemi başlatan ile onaylayan kişilerin farklı olmasıdır; aynı isteğin tekrarını önlemez."),
              ("Yetki ayrımı (separation of duties)", "Yanlış: kimin hangi adımı yapabileceğini ayırır; tekrarlanan isteği önlemez."),
              ("Hız sınırı (rate limiting)", "Yanlış: birim zamanda istek sayısını kısar; tek bir tekrarı ayırt etmez."),
          ], dogru=0),
          ("Test (7) 'aynı işlem ikinci kez onaylanamamalı' diyordu. Bunun finansal adı ne?",
           "Ödeme isteği iki kez ulaşırsa ne olmasını istersin: iki ödeme mi, bir ödeme mi?",
           "Doğru şık 'tekrar güvenliği' diyen şık."),
          puan=20, baslik="İki kez gelirse"),
]


def _kapanis():
    return """
İki açık, aynı yanlış varsayımdan doğdu: **"istemci doğru davranır."** Limit telefondaki uygulamada
vardı ama sunucuda yoktu; OTP telefonda doğrulanıyordu ama sunucu sonucu kimden duyduğunu sorgulamadı.
Saldırgan için bu, hiçbir şeyi kırmadan, yalnızca isteği elle yazarak para hareketi başlatmak demek.
Savunma için kural net: **güvenlik kararı sunucuda, işlem başına, her istekte verilir.** Limit
sunucuda uygulanır, OTP sunucuda doğrulanır, onay yalnızca işlemin sahibine ve yalnızca bir kez
açıktır. Daha kritik işlemlerde ek olarak maker-checker (çift onay) ve yetki ayrımı katman ekler;
çünkü hiçbir tek kontrol, tek başına "tek nokta" olmamalıdır.
"""


SEVIYE = Seviye(
    kimlik="c10b05",
    cilt=10,
    bolum=5,
    baslik="İşlem Güvenliği: İstemci Limiti ve OTP Atlama",
    brifing="""
<<sahne>> <<kisi>>: "Mobil uygulamamız **<<akis>>** için limit uyguluyor ve SMS kodu soruyor; güvenli
olduğunu düşünüyoruz." Selin sana <<istemci>> uygulamasının kodunu ve sunucunun kodunu veriyor: "Güvenlik
kontrollerinin **nerede** yapıldığına bak: telefonda mı, sunucuda mı? Telefondakini saldırgan zaten
kontrol eder."

Mert uyarıyor: "Sadece kendi test hesabında dene; hiçbir gerçek müşteriye dokunma. İşin bir pentester'ın
kanıtlama işi; sonra düzeltmesi de sende."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Uber, Eylül 2022:** Saldırgan, bir yüklenici çalışanın kimlik bilgilerini edinip tekrar tekrar
  çok faktörlü doğrulama onayı bildirimi gönderdi (MFA yorgunluğu) ve BT personeli gibi davranarak
  onay aldı. Ders: ikinci faktör de kötüye kullanılabilir; onay mekanizmasının tasarımı (sayı
  eşleştirme, işlem özetini gösterme, kimlik avına dirençli yöntemler) en az kodu kadar önemlidir.
- **İstemci tarafı kontroller:** Pek çok mobil uygulama sızma testi raporunda "limit ve doğrulama
  yalnızca istemcide yapılıyor" bulgusu sık görülür. Bunu test etmek için uygulamayı değil
  doğrudan API'yi çağırmak yeterlidir.
- **Tespit ve önleme:** Tespit için limit aşımı denemeleri, kısa sürede çok sayıda başarısız OTP
  ve olağandışı bekleyen işlem yığılması izlenir. Önlemek için limit ve OTP sunucuda doğrulanır,
  OTP kısa ömürlü ve tek kullanımlık olur, deneme sayısı sınırlanır ve yüksek tutarlı işlemlerde
  ikinci bir kişinin onayı (maker-checker) istenir.
""",
    sure_hedef_dk=35,
)
