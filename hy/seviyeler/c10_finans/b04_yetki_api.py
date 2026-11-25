"""Cilt 10 · Bölüm 4 — Kimlik, Yetki ve API: Finansal IDOR (BOLA) ve Kütle Atama.

Beceri: başka hesabın özetini görme açığını (BOLA/IDOR) loglardan tanımak ve kendi isteğinle
kanıtlamak; profil güncellemede kütle atama (mass assignment) ile kendi limitini/rolünü değiştirmenin
kanıtını görmek; ikisini de sunucuda düzeltmek (sahiplik kontrolü, allow-list).

Vakalar: dijital cüzdan, satıcı hesabı (ödeme), lojistik cari hesap ekstresi, hastane cari hesabı.
Düzeltmeler canlı sunucuda değil, bellekteki bir kopyada test edilir.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

VAKA = {  # kod: (log klasörü, ozet adı)
    "paramix": ("api_loglari", "cüzdan özeti"),
    "pazarix": ("odeme_loglari", "satıcı hesap özeti"),
    "kuzgun": ("tahsilat_loglari", "cari hesap ekstresi"),
    "medora": ("fatura_loglari", "hasta cari özeti"),
}


def uret(rng):
    kod, v = o.vaka_sec(rng, VAKA)
    log_k, ozet_adi = VAKA[kod]
    s = o.taban(rng, kod, musteri_sayisi=8)
    ms = s["musteriler"]
    saldirgan = rng.choice(ms[2:])
    gun = u.gun(rng)
    satirlar = []
    t = gun + timedelta(hours=9)
    for _ in range(rng.randint(10, 16)):                # herkes kendi hesabını görüntüler
        t += timedelta(seconds=rng.randint(30, 700))
        m = rng.choice([x for x in ms if x is not saldirgan])
        satirlar.append((t, o.log_satiri(t, o.ascii_ad(m["ad"]), "GET", f"/hesap/{m['hesap_id']}/ozet", None, 200)))
    tb = gun + timedelta(hours=rng.choice([1, 2, 3]), minutes=rng.randint(0, 50))
    ilk = ms[0]["hesap_id"] - rng.randint(1, 3)
    son = ms[-1]["hesap_id"] + rng.randint(1, 3)
    var = {m["hesap_id"] for m in ms}
    for hid in range(ilk, son + 1):                     # ardışık hesap numaralarını tarar
        tb += timedelta(seconds=rng.randint(1, 4), milliseconds=rng.randint(0, 900))
        satirlar.append((tb, o.log_satiri(tb, o.ascii_ad(saldirgan["ad"]), "GET", f"/hesap/{hid}/ozet", None,
                                          200 if hid in var else 404)))
    satirlar.sort(key=lambda x: x[0])
    s.update({"log_satirlari": [x[1] for x in satirlar], "log_k": log_k, "ozet_adi": ozet_adi, "saldirgan": saldirgan})
    s["metin"].update({"log_k": log_k, "ozet_adi": ozet_adi, "komsu": ms[1]["hesap_id"],
                       "limit_tl": ms[0]["islem_limiti_kurus"] // 100})
    s["cevaplar"] = {
        "saldirgan": [saldirgan["ad"], o.ascii_ad(saldirgan["ad"]), saldirgan["ad"].replace(" ", ".").lower()],
        "baskasi": len(var) - 1,
        "komsu_bakiye": ms[1]["bakiye_kurus"],
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    ben = s["musteriler"][0]
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']} — kimlik ve yetki denetimi\n\n"
          f"Canlı test uygulaması : http://{s['host']}:{s['port']}\n"
          f"Test hesabın          : {ben['ad']} ({s['v']['terim']} no {ben['hesap_id']})\n"
          f"Oturum anahtarın      : {ben['token']}\n"
          f"Komşu test hesabı     : {s['musteriler'][1]['hesap_id']}  (sadece sahibini görmesi gerekir!)\n\n"
          f"Uç noktalar: GET /hesap/<hesap_no>/ozet   POST /profil/guncelle\n"
          f"{s['log_k']}/api_erisim.log  geçen haftanın API erişim logu\n"
          "uygulama/mantik.py          düzelteceğin kod\n")
    u.yaz(lab / s["log_k"] / "api_erisim.log", "\n".join(s["log_satirlari"]) + "\n")
    o.uygulama_yaz(lab, s, o.KOD_SAGLIK + o.OZET_ACIK + o.PROFIL_ACIK)


def _kanit_kutle(b) -> Sonuc:
    ben = b.senaryo["musteriler"][0]
    r = o.db_oku(b.lab, "SELECT rol, islem_limiti_kurus FROM musteriler WHERE id = ?", (ben["id"],))[0]
    if r[0] != ben["rol"] or r[1] != ben["islem_limiti_kurus"]:
        return Sonuc(True, f"Kendi profilinde rol/limit değiştirilebildi (rol={r[0]}, limit={r[1]} kuruş): "
                           "kütle atama kanıtlandı.")
    return Sonuc(False, "Profilindeki `islem_limiti_kurus` (ya da `rol`) hâlâ ilk değerinde. `/profil/guncelle` ucuna, "
                        "normalde değiştiremeyeceğin bir alanı da ekleyip gönder.")


def coz(lab: Path, s: dict) -> dict:
    k = s["log_k"]
    ben, komsu = s["musteriler"][0], s["musteriler"][1]
    kullanici = o.sh(f"grep '/ozet' {k}/api_erisim.log | cut -d' ' -f2 | sort | uniq -c | sort -rn | head -1 | "
                     "awk '{print $2}'", lab)
    baskasi = o.sh(f"grep '/ozet' {k}/api_erisim.log | grep '{o.ascii_ad(s['saldirgan']['ad'])} GET' | grep ' 200$' | "
                   f"cut -d' ' -f4 | sort -u | grep -v '/hesap/{s['saldirgan']['hesap_id']}/' | wc -l", lab)
    _, yanit = o.curl(s, lab, "GET", f"/hesap/{komsu['hesap_id']}/ozet")
    o.curl(s, lab, "POST", "/profil/guncelle", {"islem_limiti_kurus": 99999999})
    o.duzelt(lab, "hesap_ozet", "profil_guncelle")
    cozum = {1: kullanici, 2: baskasi, 3: str(yanit["bakiye_kurus"]), 4: "", 5: "", 6: "", 7: "", 8: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Kendi özetin", """
Finansal sistemde en önemli soru şudur: **"Bu işlemi kim yapabilir? Bu veriyi kim görebilir?"**
Uygulamanın `<<ozet_adi>>` ucu, adresteki hesap numarasına göre bilgi döndürür. Kendi hesabınla dene:
""", komut="curl -s -H 'X-Oturum: <<token>>' http://<<adres>>/hesap/<<hesap_id>>/ozet",
         sonra="""
Adresteki `<<hesap_id>>` sayısı senin hesabının numarası. Hesap numaraları **ardışık** sayılar;
bir numaranın ötesini tahmin etmek zor değil. Güvenlik ise tahmin edilemezliğe değil
**kontrole** dayanır.
"""),
    Adim("API logunu oku", """
`<<log_k>>/api_erisim.log` geçen haftanın API trafiği. Her satırda kullanıcı, uç nokta ve HTTP
kodu var. İlk satırlara bak:
""", komut="head -4 <<log_k>>/api_erisim.log"),
    Adim("Kim çok soruyor?", """
Normal bir müşteri yalnızca **kendi** hesabının özetini görüntüler; bir hafta içinde birkaç kez.
`cut` ile kullanıcıyı ayıklayıp `uniq -c` ile sayabilirsin. `-f2` ikinci alanı seçer:
""", komut="grep '/ozet' <<log_k>>/api_erisim.log | cut -d' ' -f2 | sort | uniq -c | sort -rn | head -3",
         sonra="""
Biri diğerlerinden çok fazla istek yapmış. Onun satırlarına bakarsan hesap numaralarının
**art arda gittiğini** ve çoğunun `200` döndüğünü görürsün: başka insanların hesaplarını
sırayla açmış. Buna **BOLA** (nesne seviyesinde yetki ihlali, IDOR'un API'deki adı) denir.
"""),
    Adim("Kodu oku: özet", """
`sed -n '/baş/,/son/p'` komutu iki desen arasındaki satırları basar. `hesap_ozet` fonksiyonunu
`return 200` satırına kadar göster:
""", komut="sed -n '/def hesap_ozet/,/return 200/p' uygulama/mantik.py", sonra="""
Kod hesabı numarasından bulup **doğrudan döndürüyor**; hesabın isteği yapan kullanıcıya ait olup
olmadığına bakan bir satır yok. Kimlik doğrulama var (oturum anahtarı), **yetkilendirme** yok.
Bu ikisi farklı şeylerdir: biri "sen kimsin", öteki "bunu yapmaya hakkın var mı".
"""),
    Adim("Profil güncelleme", """
Bir müşteri profilini güncelleyebiliyor: telefon ve e-posta. Normal kullanımı gör:
""", komut="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"telefon\": \"0555 000 11 22\"}' http://<<adres>>/profil/guncelle",
         sonra="""
Yanıtta profilin tamamı dönüyor: telefon, eposta, **rol** ve **islem_limiti_kurus** da var. Bu
ikisinin müşteri tarafından değişmemesi gerekir; ama kodun bunu engelleyip engellemediğine bakalım.
"""),
    Adim("Kodu oku: profil", """
Aynı komutu `profil_guncelle` için çalıştır:
""", komut="sed -n '/def profil_guncelle/,/return 200/p' uygulama/mantik.py", sonra="""
Döngü, profil modelinin **bütün** sütunlarını (rol ve limit dahil) isteğe açık bırakıyor: gelen
alan neyse olduğu gibi yazılır. Buna **kütle atama** (mass assignment) denir. Çözüm, değişebilecek
alanların bir **izin listesi**ni (allow-list) yazmaktır.

**Hacker gözüyle:** Yanıtı okumak bir saldırgan için ipucudur: dönen her alan, "gönderebileceğim
olası bir alan"dır. Savunma tarafında ders: API'ler yalnızca gerektiği kadar alan döndürmeli ve
yalnızca gerektiği kadar alan kabul etmelidir.
"""),
]

GOREVLER = [
    Gorev("`<<log_k>>/api_erisim.log` içinde, çok sayıda farklı hesabın `<<ozet_adi>>` bilgisini isteyen "
          "**kullanıcı** kim? (log'daki adıyla yaz)",
          Metin("saldirgan", bicim="kullanıcı adı (örn. ad.soyad)"),
          ("Normal bir kullanıcı çok az özet isteği yapar. En çok isteği yapan kim?",
           "`grep '/ozet'` ile süz, kullanıcı alanını (`cut -d' ' -f2`) ayıkla, `uniq -c` ile say.",
           "`grep '/ozet' <<log_k>>/api_erisim.log | cut -d' ' -f2 | sort | uniq -c | sort -rn | head -1`"),
          puan=30, baslik="Kim tarıyor"),
    Gorev("Bu kullanıcı **başkalarına ait kaç farklı hesabın** özetini başarıyla (HTTP 200) görüntüledi? "
          "(Kendi hesabı hariç)",
          Sayi("baskasi", sik_hatalar=lambda g, b, bg: "Kendi hesabını da saymış olabilirsin ya da 404 dönen "
                "(var olmayan) numaraları. Sadece 200 alan, kendisine ait olmayanlar." if g.isdigit() and abs(int(g) - b) <= 3 and int(g) != b else None),
          ("`200` dönenleri say; `404` hesap bulunamadı demek, veri sızmamış. Kendi hesabı da hariç.",
           "Kullanıcının satırlarını süz, 200 olanların adresini (4. alan) `sort -u` ile benzersizleştir, say.",
           "Kullanıcı adını 1. görevden bil; `grep '<kullanıcı> GET'` ... `grep ' 200$'` ... `cut -d' ' -f4 | sort -u | wc -l`; sonra kendi hesabını çıkar."),
          puan=40, baslik="Etki: kaç hesap"),
    Gorev("**Kanıtla:** Kendi oturum anahtarınla **komşu test hesabının** (`<<komsu>>`) özetini iste. Komşunun "
          "bakiyesi **kaç kuruş**? (Sadece oyunun test hesabı)",
          Sayi("komsu_bakiye"),
          ("Eğitimdeki özet isteğinde hesap numarasını değiştir.",
           "`curl -s -H 'X-Oturum: <<token>>' http://<<adres>>/hesap/<<komsu>>/ozet`",
           "Aynı komut; yanıttaki `bakiye_kurus` alanını `cevap 3 <sayı>` olarak yaz. Kendi anahtarınla başkasının verisini gördün: BOLA kanıtlandı."),
          puan=40, baslik="Kanıtla: BOLA"),
    Gorev("**Kanıtla:** `/profil/guncelle` ucunu kullanarak **kendi test hesabının** `islem_limiti_kurus` değerini "
          "değiştir (şu an <<limit_tl>> TL; çok yüksek bir değer ver). Sadece kendi test hesabın. Bitince `cevap 4` yaz.",
          Durum(_kanit_kutle, cozum="curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
                                    "-d '{\"islem_limiti_kurus\": 99999999}' http://<<adres>>/profil/guncelle"),
          ("Normal profil güncellemesini eğitimde yaptın. Gövdeye başka bir alan koy.",
           "Gövde `{\"islem_limiti_kurus\": 99999999}` olsun; yanıtta profilinin değiştiğini gör.",
           "`curl -s -X POST -H 'X-Oturum: <<token>>' -H 'Content-Type: application/json' "
           "-d '{\"islem_limiti_kurus\": 99999999}' http://<<adres>>/profil/guncelle`"),
          puan=40, baslik="Kanıtla: kütle atama"),
    Gorev("Özet ucu, kimlik doğruluyor ama istenen hesabın isteği yapana ait olup olmadığını kontrol etmiyor. "
          "Bu açık sınıfının adı nedir?",
          Secmeli([
              ("BOLA: nesne seviyesinde yetkilendirme eksikliği (API'nin IDOR'u)", "Doğru: kullanıcı kimliği doğrulanmış, ama istediği NESNE (hesap) için yetkisi kontrol edilmemiş."),
              ("Fonksiyon seviyesinde yetki eksikliği: yetkisiz biri yönetici işlevi çağırıyor", "Yanlış: burada çağrılan işlev (özet görüntüleme) herkese açık bir işlev; sorun hangi hesap için çağrıldığıdır."),
              ("Kaynak tüketimi açığı: istek sayısı sınırlanmamış", "Yanlış: bu başka bir sınıf. Hız sınırı eksikliği de olabilir ama burada verinin sahibi kontrol edilmiyor."),
              ("Aşırı veri ifşası: yanıt gerekenden fazla alan döndürüyor", "Yanlış: başka bir sınıf. Asıl sorun, yanıtın hiç görmemesi gereken birine dönmesi."),
          ], dogru=0),
          ("Kimlik doğrulama ile yetkilendirmeyi karıştırma: hangisi eksik?",
           "OWASP API Top 10'un birinci sırasındaki açık, nesne düzeyinde yetki kontrolü eksikliğidir.",
           "Doğru şık 'BOLA' ile başlayan şık."),
          puan=20, baslik="Açığın adı"),
    Gorev("`hesap_ozet` fonksiyonunu **düzelt**: hesap isteği yapan kullanıcıya ait değilse 403 dönsün; kendi hesabı "
          "çalışmaya devam etsin. Bitince `cevap 6` yaz.",
          Durum(o.durum_testi(o.test_bola), cozum="Hesabı okuduktan sonra `if h[\"musteri_id\"] != kul[\"id\"]: "
                "return 403, {\"hata\": ...}` ekle."),
          ("Kodda hesabın sahibi (`musteri_id`) zaten okunuyor. İstek yapan kullanıcının kimliği `kul[\"id\"]`.",
           "İkisini karşılaştır: eşit değilse isteği reddet. Sorgudan SONRA, yanıt döndürmeden ÖNCE.",
           "`if h[\"musteri_id\"] != kul[\"id\"]: return 403, {\"hata\": \"bu hesap size ait değil\"}`"),
          puan=60, baslik="Düzelt: BOLA"),
    Gorev("`profil_guncelle` fonksiyonunu **düzelt**: yalnızca `telefon` ve `eposta` değişebilsin; `rol` ve "
          "`islem_limiti_kurus` istekle değiştirilemesin. Bitince `cevap 7` yaz.",
          Durum(o.durum_testi(o.test_kutle), cozum="Döngüyü `(\"telefon\", \"eposta\")` ile sınırla (allow-list)."),
          ("Kod hangi alanlar üzerinde dönüyor? O listeyi küçült.",
           "İzin verilen alanların bir demetini (`(\"telefon\", \"eposta\")`) yaz ve döngüyü yalnızca onların üzerinde çalıştır.",
           "Döngüdeki demeti `(\"telefon\", \"eposta\")` yap. İsteğe bağlı: izinli olmayan alan gelirse 400 dön."),
          puan=60, baslik="Düzelt: allow-list"),
    Gorev("Kütle atamayı düzeltirken neden `rol` ve `islem_limiti_kurus` alanlarını yasak listesine (block-list) "
          "yazmak yerine `telefon` ve `eposta` için **izin listesi** yazdık?",
          Secmeli([
              ("Yeni eklenecek hassas bir alan, izin listesinde olmadığı için kendiliğinden korunur", "Doğru: izin listesi 'varsayılan olarak kapalı' çalışır; yasak listesi ise unutulan her yeni alanı açık bırakır."),
              ("İzin listesi kodu daha kısa yazdırdığı için geliştiricinin hata yapma ihtimali azalır", "Yanlış: kodun kısalığı bir güvenlik gerekçesi değil; asıl neden, unutulan alanın nasıl davrandığıdır."),
              ("Yasak listeleri veritabanı katmanında çalışmaz, yalnızca izin listeleri çalışabilir", "Yanlış: teknik bir kısıt yok; yasak listesi de çalışır ama eksik kalmaya yatkındır."),
              ("İzin listesi kullanınca kimlik doğrulamasına artık gerek kalmaz", "Yanlış: izin listesi hangi alanların değişebileceğini sınırlar; kimin değiştirebileceği ayrı bir kontroldür."),
          ], dogru=0),
          ("Bir geliştirici yarın `hesap_durumu` adında yeni bir sütun eklerse hangi liste onu korur?",
           "'Varsayılan olarak kapalı' ile 'varsayılan olarak açık' yaklaşımlarını karşılaştır.",
           "Doğru şık, yeni alanın kendiliğinden korunduğunu söyleyen şık."),
          puan=20, baslik="İzin listesi neden"),
]


def _kapanis():
    return """
Bu bölümde kodun iki ayrı yerinde aynı sorunun iki yüzünü gördün: **sunucu, istemcinin söylediğine
fazla güveniyor**. Birinde istemci "şu hesabı göster" diyor ve sunucu sahiplik sormuyor (BOLA);
ötesinde istemci "şu alanı da değiştir" diyor ve sunucu yetki sormuyor (kütle atama). Saldırgan için
bu açıklar neredeyse hiç iz bırakmaz: istekler geçerli, yanıtlar 200, kimlik doğru. Savunma için
her uç noktada hem **kimliği** hem **yetkiyi** hem **iş kuralını** sunucuda doğrula; yalnızca
gerekeni döndür, yalnızca gerekeni kabul et. Finansta bunun sonucu doğrudan para ve müşteri sırrıdır.
"""


SEVIYE = Seviye(
    kimlik="c10b04",
    cilt=10,
    bolum=4,
    baslik="Kimlik, Yetki ve API: BOLA ve Kütle Atama",
    brifing="""
<<sahne>> <<kisi>> bir şikâyetten söz ediyor: bir müşteri, kendisine ait olmayan **<<ozet_adi>>** bilgilerini
görebildiğini yazmış. Selin: "API'nin erişim loguna bak: biri bu uç noktayı tarıyor olabilir. Sonra
kendi test hesabında hem başkasının verisini görmeyi hem de profilinde olmaması gereken bir alanı
değiştirmeyi **kanıtla**. İkisini de sonra sen düzelteceksin."

Mert ekliyor: "API'ler çoğu zaman 'arka plan' olduğu için test edilmez. Ama arayüzün arkasında hep
konuşabileceğin bir kapı vardır."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=o.banka_servis,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **BOLA gerçek hayatta:** OWASP API Güvenliği Top 10 listesinde nesne düzeyinde yetki eksikliği
  (BOLA) birinci sıradadır. Kamuya yansımış olaylardan biri, ABD posta idaresinin 2018'de
  duyurulan bir API açığıdır: giriş yapmış herhangi bir kullanıcı, başka hesapların bilgilerini
  sorgulayabiliyordu. Olay, kimlik doğrulama ile yetkilendirmenin aynı şey olmadığını gösterir.
- **Kütle atama:** 2012'de bir araştırmacı, popüler bir kod barındırma sitesindeki kütle atama
  açığını kamuya göstermişti (hesabına olmaması gereken bir yetki ekleyerek). Açık, çatıların
  "modelin bütün alanlarını isteğe aç" varsayılanından kaynaklanıyordu.
- **Tespit ve önleme:** Tespit için tek kullanıcıdan gelen ardışık nesne kimliği istekleri, çok
  sayıda 403/404 ve beklenmeyen alan içeren gövdeler alarma bağlanır. Önlemek için her uç noktada
  sahiplik kontrolü yapılır, kimlikler tahmin edilmesi zor (UUID gibi) seçilebilir (ek önlem; tek
  başına yetmez), yanıt ve istek alanları izin listesiyle sınırlanır.
""",
    sure_hedef_dk=35,
)
