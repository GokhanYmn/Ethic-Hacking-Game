"""Cilt 5 · Bölüm 2 — Burp Suite ile Trafiği Görmek.

Beceri: araya giren vekil (proxy) kavramı, HTTP geçmişi okumak, Repeater mantığı (bir isteği
değiştirip yeniden göndermek), Intruder'ın ne olduğu; Burp olmadan aynı işi `curl -v`, `curl -x` ve
dosyadan istek göndermekle yapmak; "istemci kısıtlaması sunucuyu bağlamaz" dersi.

Laboratuvar: küçük bir mağaza uygulaması (fiyatı gizli alanda istemciden alıyor) ve Burp'un
"HTTP geçmişi"ni taklit eden küçük bir vekil. Vekil yalnızca 127.x adreslerine iletir.
Burp Suite'in kendisi Raspberry Pi'de ağır olabilir; kullanımı isteğe bağlı anlatılır.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.motor.servis import http_sunucu
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c05_web import ortak as o

VAKALAR = [
    {"kod": "pazarix", "liste": "/urunler", "fiyat": "birim_fiyat", "etiket": "ürün",
     "urunler": [("Kablosuz kulaklık", 899), ("Akıllı saat", 1499), ("Powerbank 20.000 mAh", 649), ("Oyuncu faresi", 399)],
     "olay": "Pazarix kampanya öncesi sepet akışını yeniledi. Tuncay Bey, müşterilerin sepetteki fiyatla oynayıp "
             "oynayamayacağını ve bunu Burp ile nasıl göreceğimizi sormak istiyor."},
    {"kod": "medora", "liste": "/paketler", "fiyat": "tutar", "etiket": "sağlık paketi",
     "urunler": [("Genel check-up", 2450), ("Kardiyoloji paketi", 3100), ("Göz muayenesi", 950), ("Diş temizliği", 700)],
     "olay": "Medora Sağlık, online check-up paketi satışına başladı. Dr. Aslı Hanım, ödeme öncesi sepet isteğinin "
             "güvenilir olup olmadığını öğrenmek istiyor; paket fiyatı tarayıcıdan geliyor gibi görünüyor."},
    {"kod": "paramix", "liste": "/katalog", "fiyat": "fiyat_tl", "etiket": "cihaz",
     "urunler": [("Mini POS", 1250), ("Masaüstü POS", 2890), ("QR ödeme standı", 340), ("Yazıcı rulosu (50'li)", 210)],
     "olay": "Paramix, üye işyerlerine POS cihazı satan yeni bir mağaza açtı. Ece Hanım, sepete ekleme isteğinin "
             "içindeki alanlara sunucunun ne kadar güvendiğini görmemizi istiyor."},
    {"kod": "atolye", "liste": "/menu", "fiyat": "ucret", "etiket": "ürün",
     "urunler": [("Filtre kahve 250 g", 280), ("Çekirdek kahve 1 kg", 960), ("Soğuk demleme şişesi", 190), ("Seramik fincan", 150)],
     "olay": "Atölye Kahve'nin sahibi Berk, çekirdek kahve siparişi için kendi yaptığı sipariş formunun \"fiyat\" "
             "kutusuyla bir müşterinin oynayabileceğinden endişeleniyor."},
]

SEMA = """
CREATE TABLE urunler (id INTEGER PRIMARY KEY, ad TEXT, fiyat INTEGER);
CREATE TABLE ayarlar (ad TEXT PRIMARY KEY, deger TEXT);
"""

KAYNAK = '''# uygulama.py — @@AD@@ sepet uygulaması (laboratuvar kopyası)
def sayfa(baslik, govde):
    return ("<html><head><title>%s</title></head><body><h1>%s</h1>%s</body></html>\\n"
            % (baslik, baslik, govde))


def isle(istek, db):
    if istek.path == "/":
        return 200, {}, sayfa("@@AD@@", "<p><a href='@@LISTE@@'>@@ETIKET@@ listesi</a></p>")
    if istek.path == "@@LISTE@@":
        satirlar = ""
        for u in db.execute("SELECT id, ad, fiyat FROM urunler ORDER BY id"):
            satirlar += ("<li>%s — %d TL <form method='post' action='/sepet/ekle'>"
                         "<input type='hidden' name='urun' value='%d'>"
                         "<input type='hidden' name='@@FIYAT@@' value='%d'>"
                         "<input name='adet' value='1' maxlength='2' size='2'> <button>Sepete ekle</button>"
                         "</form></li>" % (u["ad"], u["fiyat"], u["id"], u["fiyat"]))
        return 200, {}, sayfa("@@ETIKET@@ listesi", "<ul>" + satirlar + "</ul>")
    if istek.path == "/sepet/ekle" and istek.method == "POST":
        urun = db.execute("SELECT ad, fiyat FROM urunler WHERE id = ?",
                          (istek.form.get("urun", ""),)).fetchone()
        if urun is None:
            return 404, {}, sayfa("Hata", "<p>Böyle bir ürün yok.</p>")
@@FIYAT_ADET@@
        toplam = fiyat * adet
        denetim = ""
        if fiyat != urun["fiyat"]:
            kayit = db.execute("SELECT deger FROM ayarlar WHERE ad = 'denetim'").fetchone()
            denetim = "<!-- denetim kaydı: fiyat uyuşmazlığı kabul edildi %s -->" % kayit["deger"]
        return 200, {}, sayfa("Sepet", "<p>Sepete eklendi: %s x%d</p><p>Toplam: %d TL</p>%s"
                              % (urun["ad"], adet, toplam, denetim))
    return 404, {}, sayfa("404", "<p>Sayfa bulunamadı.</p>")
'''

FIYAT_ADET_ACIK = '''        fiyat = int(istek.form.get("@@FIYAT@@", "0"))      # fiyatı istemci söylüyor
        adet = int(istek.form.get("adet", "1"))'''

FIYAT_ADET_GUVENLI = '''        fiyat = urun["fiyat"]                              # fiyat her zaman sunucudaki kayıttan gelir
        try:
            adet = int(istek.form.get("adet", "1"))
        except ValueError:
            return 400, {}, sayfa("Hata", "<p>Geçersiz adet.</p>")
        if not 1 <= adet <= 10:                            # maxlength istemcidedir; sunucu da denetler
            return 400, {}, sayfa("Hata", "<p>Adet 1 ile 10 arasında olmalı.</p>")'''

SIFIR_YOLLARI = ["/ara", "/odeme/onay", "/profil/duzenle", "/api/stok"]


def kaynak(s: dict, guvenli: bool = False) -> str:
    v = s["v"]
    blok = FIYAT_ADET_GUVENLI if guvenli else FIYAT_ADET_ACIK
    return o.kaynak_doldur(KAYNAK, {"FIYAT_ADET": blok, "AD": s["musteri"]["ad"], "LISTE": v["liste"],
                                    "FIYAT": v["fiyat"], "ETIKET": v["etiket"].capitalize()})


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    port = rng.randint(20000, 45000)
    vekil_port = rng.randint(20000, 45000)
    while vekil_port == port:
        vekil_port = rng.randint(20000, 45000)
    ornek = rng.randrange(len(v["urunler"]))
    hatali = rng.choice(SIFIR_YOLLARI)
    return {
        "vaka": f"{m['ad']} — {v['etiket']} sepeti",
        "musteri": m, "v": v, "port": port, "vekil_port": vekil_port, "ornek": ornek, "hatali": hatali,
        "metin": {
            "musteri": m["ad"], "olay": v["olay"], "url": f"http://127.0.0.1:{port}",
            "vekil": f"http://127.0.0.1:{vekil_port}", "vekil_port": vekil_port,
            "liste": v["liste"], "fiyat": v["fiyat"], "ornek_urun": ornek + 1,
            "ornek_ad": v["urunler"][ornek][0], "ornek_fiyat": v["urunler"][ornek][1],
        },
        "cevaplar": {
            "gizli": v["fiyat"],
            "hatali": [hatali, hatali.lstrip("/"), f"http://127.0.0.1:{port}{hatali}"],
            "bayrak": u.bayrak(rng, "istemciye_guvenme"),
        },
    }


def trafik_satirlari(s: dict, rng) -> list:
    """Burp "HTTP geçmişi"ne benzeyen sahte kayıt: tek bir istek 500 döndürür."""
    v = s["v"]
    liste = v["liste"]
    kayitlar = [
        ("GET", "/", 200, 612), ("GET", liste, 200, 1840), ("GET", "/static/site.css", 200, 3320),
        ("POST", "/sepet/ekle", 200, 540), ("GET", "/giris", 200, 705), ("POST", "/giris/dogrula", 302, 0),
        ("GET", "/hesabim", 200, 1190), ("GET", "/favicon.ico", 404, 310), ("GET", "/eski-sayfa", 301, 0),
        ("GET", "/yonetim", 403, 280), ("GET", "/kampanya", 200, 2210),
    ]
    rng.shuffle(kayitlar)
    kayitlar.insert(rng.randint(2, len(kayitlar) - 2), ("POST", s["hatali"], 500, 2113))
    return kayitlar


def yaz(lab: Path, s: dict) -> None:
    import random
    rng = random.Random(f"{s['port']}-{s['vekil_port']}")
    v = s["v"]
    o.db_olustur(lab / "uygulama.db", SEMA, {
        "urunler": [(i + 1, ad, fiyat) for i, (ad, fiyat) in enumerate(v["urunler"])],
        "ayarlar": [("denetim", s["cevaplar"]["bayrak"])],
    })
    u.yaz(lab / "uygulama.py", kaynak(s))
    satirlar = [f"#{i:02d}  {m:<5} {yol:<20} -> {kod}   ({boyut} bayt)"
                for i, (m, yol, kod, boyut) in enumerate(trafik_satirlari(s, rng), 1)]
    u.yaz(lab / "trafik.txt",
          f"# {s['musteri']['ad']} — Burp \"HTTP history\" dışa aktarımı (kısaltılmış)\n"
          "# sıra  yöntem yol                  -> durum   (yanıt boyutu)\n" + "\n".join(satirlar) + "\n")
    ornek = v["urunler"][s["ornek"]]
    govde = f"urun={s['ornek'] + 1}&{v['fiyat']}={ornek[1]}&adet=1"
    u.yaz(lab / "govde.txt", govde + "\n")
    u.yaz(lab / "istek_sepet.txt",
          "POST /sepet/ekle HTTP/1.1\n"
          f"Host: 127.0.0.1:{s['port']}\n"
          "User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:128.0) Gecko/20100101 Firefox/128.0\n"
          "Content-Type: application/x-www-form-urlencoded\n"
          f"Content-Length: {len(govde)}\n\n{govde}\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — sepet uygulaması laboratuvar kopyası\n\n"
          f"Uygulama : http://127.0.0.1:{s['port']}\n"
          f"Vekil    : http://127.0.0.1:{s['vekil_port']}   (Burp Proxy'nin minik taklidi)\n\n"
          "trafik.txt       Burp 'HTTP history' gibi: yakalanmış isteklerin listesi\n"
          "istek_sepet.txt  yakalanmış bir isteğin tamamı (Repeater'a gönderdiğin istek)\n"
          "govde.txt        aynı isteğin gövdesi; curl -d @govde.txt ile tekrar gönderilebilir\n"
          "vekil_gecmis.log vekilden geçen isteklerin kaydı (vekil çalışınca oluşur)\n"
          "uygulama.py      kaynak kod; 6. görevde düzeltilecek (sunucu dosyayı kendisi yeniden yükler)\n")


def servis(s: dict, lab: Path, dur) -> None:
    vekil = http_sunucu("127.0.0.1", s["vekil_port"], o.vekil_isleyici(lab / "vekil_gecmis.log"))
    o.servis_calis(s["port"], lab, dur, ek_sunucular=[vekil])


# ---------------------------------------------------------------- kontroller

def _vekil_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    log = Path(b.lab) / "vekil_gecmis.log"
    if not log.is_file():
        return Sonuc(False, "`vekil_gecmis.log` yok: vekilden hiç istek geçmemiş. İsteği vekile ver: "
                            "`curl -s -x <<vekil>> <<url>><<liste>>`.")
    metin = log.read_text(encoding="utf-8", errors="replace")
    hedef = f"127.0.0.1:{s['port']}{s['v']['liste']}"
    if hedef in metin:
        return Sonuc(True, "İstek vekilden geçti ve geçmişe düştü: Burp'un Proxy > HTTP history sekmesinin yaptığı tam olarak bu.")
    if "GET http" in metin:
        return Sonuc(False, f"Vekilden bir istek geçmiş ama `{hedef}` adresine değil. Adres tam olarak "
                            f"`<<url>><<liste>>` olmalı.", yakin=True)
    return Sonuc(False, "Log var ama içinde vekilden geçmiş bir GET isteği yok. `-x` (vekil) seçeneğini kullandın mı?", yakin=True)


def _duzeltme_denetle(b: Baglam) -> Sonuc:
    s = b.senaryo
    v = s["v"]
    ornek = v["urunler"][s["ornek"]]
    urun_no, fiyat = s["ornek"] + 1, ornek[1]

    def f(d):
        def sepet(adet, gonderilen):
            return d.post("/sepet/ekle", {"urun": str(urun_no), v["fiyat"]: str(gonderilen), "adet": str(adet)})

        y = sepet(2, fiyat)
        hata = o.cokme_sonucu(y, "normal sepet")
        if hata:
            return hata
        if y.kod != 200 or f"Toplam: {fiyat * 2} TL" not in y.govde:
            return Sonuc(False, f"Normal bir sipariş artık çalışmıyor: {ornek[0]} x2 için `Toplam: {fiyat * 2} TL` "
                                f"bekliyordum (durum {y.kod}). Düzeltirken uygulamayı bozmuşsun.", yakin=True)
        y = sepet(1, 1)
        hata = o.cokme_sonucu(y, "sahte fiyatlı")
        if hata:
            return hata
        if "FLAG{" in y.govde or f"Toplam: {fiyat} TL" not in y.govde:
            return Sonuc(False, f"İstemcinin gönderdiği fiyat (`{v['fiyat']}=1`) hâlâ hesaba giriyor. Fiyat, ürün "
                                "kaydından (`urun[\"fiyat\"]`) alınmalı; istekteki fiyat alanı yok sayılmalı.", yakin=True)
        for adet, ne in ((-3, "negatif"), (500, "çok büyük"), ("abc", "sayı olmayan")):
            y = sepet(adet, fiyat)
            if y.hata and "ValueError" not in y.hata:
                return o.cokme_sonucu(y, f"{ne} adet")
            if not 400 <= y.kod < 500:
                return Sonuc(False, f"`adet={adet}` ({ne}) sunucuya ulaştığında 4xx hata beklerdim, durum {y.kod} geldi. "
                                    "Tarayıcıdaki `maxlength` bunu engellemez; sunucu adedi 1-10 aralığında denetlemeli.",
                             yakin=True)
        return Sonuc(True, "Fiyat artık sunucudan geliyor ve adet sunucuda denetleniyor. İstemciden gelen hiçbir şeye "
                           "güvenmedin; Burp ile ya da curl ile oynanan alanlar artık işe yaramaz.")

    return o.deneme_calistir(b, f)


def _gizli_hata(g, beklenen, b):
    if g == "urun":
        return "`urun` da gizli bir alan ama o ürünün numarasını taşıyor. Soru PARAYI taşıyan alanı soruyor."
    if g == "adet":
        return "`adet` görünür bir kutu (maxlength'li). Gizli olan ve fiyatı taşıyan alanı ara."
    return None


def _hatali_hata(g, beklenen, b):
    if g.strip("/") in ("sepet/ekle", "giris", "giris/dogrula"):
        return "O satır başarılı bir yanıt vermiş. `trafik.txt`'de durumu 500 olan satırı ara."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    url, vk, v = s["metin"]["url"], s["metin"]["vekil"], s["v"]
    o.hazir_bekle(url + "/")
    satir = o.sh("grep -- '-> 500' trafik.txt", lab)
    hatali = re.search(r"\s(/\S*)\s+->", satir).group(1)
    o.sh(f"curl -s -x {vk} -o /dev/null {url}{v['liste']}", lab)
    sayfa = o.sh(f"curl -s {url}{v['liste']}", lab)
    gizli = [a for a in re.findall(r"type='hidden' name='(\w+)'", sayfa) if a != "urun"][0]
    govde = f"urun={s['ornek'] + 1}&{gizli}=1&adet=1"
    cevap = o.sh(f"curl -s -d '{govde}' {url}/sepet/ekle", lab)
    bayrak = re.search(r"FLAG\{[^}]+\}", cevap).group(0)
    (lab / "uygulama.py").write_text(kaynak(s, guvenli=True), encoding="utf-8")
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(Baglam(s, lab, no))[0] for no in (1, 7, 8)}
    return {1: secmeli[1], 2: hatali, 3: "", 4: gizli, 5: bayrak, 6: "", 7: secmeli[7], 8: secmeli[8]}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Araya giren vekil: Burp Suite", """
Web pentestinin vazgeçilmez aracı **Burp Suite**'tir. Temelde bir **vekil** (proxy) olarak çalışır:
tarayıcın ile sunucu arasına girer. Normalde `tarayıcı → sunucu` olan yol, `tarayıcı → Burp → sunucu`
olur; böylece her isteği görür, durdurur, değiştirir ve yeniden gönderirsin.

Ana bileşenler:

- **Proxy:** istekleri yakalar; "HTTP history" geçmişi tutar.
- **Repeater:** bir isteği değiştirip tekrar tekrar gönderir (en çok kullanacağın bileşen).
- **Intruder:** bir isteği çok sayıda varyasyonla otomatik gönderir (fuzzing).
- **Decoder:** URL/Base64 gibi kodlamaları çevirir.

**Önemli not:** Burp Suite Raspberry Pi'de (özellikle Java ile) ağır olabilir; bu bölümü onsuz da bitirebilirsin.
Burp'u kurmak ve denemek **isteğe bağlıdır**. Asıl ders aracın değil, **mantığın**: tarayıcı sadece bir
arayüz, gerçek konuşma HTTP isteği. O yüzden aynı işi curl ile yapacağız.
"""),
    Adim("curl -v: isteği ve yanıtı çıplak gör", """
`-v` (verbose) seçeneği hem gönderdiğin isteği (`>` ile başlayan satırlar) hem sunucunun
yanıtını (`<` ile başlayanlar) gösterir; Burp'un Proxy sekmesindeki iki panelin metin hali:
""", komut="curl -v -s -o /dev/null <<url>><<liste>>", sonra="""
`> GET <<liste>> HTTP/1.0` bir **istek satırı**, ardından `Host`, `User-Agent` gibi istek başlıkları. `<` ile
başlayan satırlar sunucunun cevabı. Burp'ta gördüğün her şey bu iki bloktur.
"""),
    Adim("HTTP geçmişi", """
Burp'un Proxy sekmesinde her istek bir satır olarak birikir: sıra, yöntem, yol, durum kodu,
boyut. Laboratuvarda böyle bir dışa aktarma var; ilk satırlara bak:
""", komut="head -8 trafik.txt", sonra="""
Gerçek işte yüzlerce satır olur ve ilginç olanı (500 hata, 403, beklenmedik bir POST) süzmek
gerekir. `grep` burada Burp'un filtresi gibi çalışır. Durum kodu **500** sunucunun bir şeyin
ters gittiğini söylemesidir; saldırgan için bu bir ipucudur, savunmacı için bir uyarı.
"""),
    Adim("Vekilden geçir", """
Laboratuvarda Burp'un minik bir taklidi `<<vekil>>` adresinde çalışıyor. curl'e `-x` (proxy)
verirsen isteği vekile yollar; vekil kaydedip uygulamaya iletir (sadece 127.x adreslerine):
""", komut="curl -s -x <<vekil>> -o /dev/null <<url>><<liste>>", sonra="""
Cevap `/dev/null`'a gitti ama vekil isteği not etti. Kaydına bir sonraki adımda bakacağız.
"""),
    Adim("Vekil geçmişine bak", """
Vekilin kaydı lab'daki `vekil_gecmis.log` dosyasında:
""", komut="cat vekil_gecmis.log", sonra="""
Gerçek Burp'ta bu kayıt Proxy > HTTP history sekmesidir. Tarayıcıyı `127.0.0.1:8080` gibi bir vekile
yönlendirmek de aynı mantıktır (curl'deki `-x` bunun komut satırı karşılığı). HTTPS için Burp'un
sertifikasını tarayıcıya tanıtmak gerekir; bu bölümde HTTP kullanıyoruz.
"""),
    Adim("Repeater: yakalanmış isteği oku", """
Yakalanan bir istek bütün halinde böyle görünür. Bu, Burp'ta bir isteği sağ tıklayıp "Send to
Repeater" dediğinde önüne gelen metindir:
""", komut="cat istek_sepet.txt", sonra="""
Bir `POST`: gövdede üç alan var. İçlerinden biri **fiyat**. Sunucu fiyatı kendi veritabanından
bilmesine rağmen **istemciden alıyor olabilir**; bunu anlamanın yolu isteği değiştirip
tekrar göndermektir. Repeater'ın yaptığı budur.
"""),
    Adim("Aynen tekrar gönder", """
Gövdeyi `govde.txt`'ye koymuştuk. `-d @dosya` curl'e gövdeyi dosyadan okutur; isteği olduğu gibi
yeniden gönder:
""", komut="curl -s -d @govde.txt <<url>>/sepet/ekle", sonra="""
Cevap: sepete eklendi, toplam tutar. Repeater'da "Send" tuşuna basmak tam olarak budur.
"""),
    Adim("Değiştir ve tekrar gönder", """
Repeater'ın asıl gücü, göndermeden önce **bir değeri değiştirmendir**. Aynı gövdede `<<fiyat>>`
değerini başka bir sayıyla değiştirip (ekrana bastırarak) ne olacağını görelim:
""", komut="sed 's/<<fiyat>>=[0-9]*/<<fiyat>>=777/' govde.txt", sonra="""
Gövde değişti. Bunu `curl -d @-` ile (standart girdiden okuyarak) ya da kendin yazdığın `-d '...'` ile
gönderebilirsin. Hangi alanı değiştirirsen değiştir, sunucu bunu fark edecek mi? Görevlerde
bakacaksın.

**Hacker gözüyle:** `maxlength="2"` bir tarayıcı kısıtıdır; Burp ya da curl isteği tarayıcıdan
sonra yakalar, yani kısıt hiç devreye girmez. **Güvenlik denetimleri sunucuda yapılmalıdır.**
Intruder bu fikrin otomatik halidir: aynı isteği yüzlerce değerle gönderir. Çok gürültülüdür;
yalnızca izinli hedeflerde.
"""),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Bir isteği yakaladın ve tek bir parametresini değiştirip, cevabı inceleyerek, tekrar tekrar göndermek "
          "istiyorsun. Burp Suite'in hangi bileşeni bunun içindir?",
          Secmeli([
              ("Repeater: isteği düzenleyip yeniden gönderir ve her cevabı yan yana gösterir",
               "Doğru. Manuel web testlerinin döngüsü Repeater'dadır: değiştir, gönder, cevabı oku."),
              ("Proxy: tarayıcı ile sunucu arasına girip trafiği sadece kaydeder",
               "Proxy isteği yakalar ve geçmişe koyar; ama düzenleyip defalarca göndermek Repeater'ın işidir."),
              ("Decoder: veriyi URL veya Base64 gibi biçimlere çevirir",
               "Decoder kodlama çevirir; istek göndermez."),
              ("Intruder: tek isteği otomatik olarak çok sayıda değerle bombalar",
               "Intruder otomatik ve çok sayıda istek içindir; sen tek tek, elle düzenlemek istiyorsun."),
          ]),
          ("Bölüm metnindeki bileşen tablosuna bak.",
           "\"Düzenle ve tekrar gönder\" hangi bileşenin tanımı?",
           "Manuel döngü: yakala, Repeater'a gönder, değiştir, gönder, incele."),
          puan=15, baslik="Burp bileşenleri"),
    Gorev("`trafik.txt` dosyası, Burp'un HTTP geçmişi gibi bir kayıt. Bu kayıtta **500** (sunucu hatası) dönen isteğin "
          "yolu hangisi?",
          Metin("hatali", sik_hatalar=_hatali_hata, bicim="yol (örn. /a/b)"),
          ("Durum kodları okun ucundan sonra yazılı.",
           "`grep -- '-> 500' trafik.txt`",
           "Çıktıdaki satırda yöntemden sonra gelen yolu yaz."),
          puan=20, baslik="Geçmişte 500"),
    Gorev("Vekili kullan: `<<liste>>` sayfasını `curl -x <<vekil>> <<url>><<liste>>` ile vekilden geçirerek iste. "
          "Vekilin kaydına düştüğünde `cevap 3` yaz.",
          Durum(_vekil_denetle, "```\ncurl -s -x <<vekil>> -o /dev/null <<url>><<liste>>\n```"),
          ("İsteğin vekile gitmesi için curl'e vekilin adresini söylemelisin.",
           "`-x` seçeneği vekil adresini alır. Adres: <<vekil>>",
           "`curl -s -x <<vekil>> -o /dev/null <<url>><<liste>>`"),
          puan=25, baslik="Vekilden geç"),
    Gorev("`<<liste>>` sayfasındaki sepete ekle formlarında, ekranda görünmeyen ve **fiyatı taşıyan** gizli alanın adı nedir? "
          "(`urun` değil.)",
          Metin("gizli", sik_hatalar=_gizli_hata, bicim="alan adı"),
          ("Formda iki gizli alan var; biri ürünü, diğeri parayı taşıyor.",
           "`curl -s <<url>><<liste>>` ve `type='hidden'` olan `input`ların `name=` değerleri.",
           "Ürün numarası `urun`; diğer gizli alan fiyattır. Aynı adı `istek_sepet.txt` içinde de görürsün."),
          puan=25, baslik="Gizli fiyat"),
    Gorev("Repeater'daki gibi isteği değiştir: fiyat alanını gerçek fiyattan **farklı** bir sayıyla gönder "
          "(`curl -s -d 'urun=<<ornek_urun>>&<<fiyat>>=1&adet=1' <<url>>/sepet/ekle`). Sunucu kabul ederse sayfa "
          "bir denetim kaydı bırakıyor. Kayıttaki bayrağı bul.",
          Bayrak("bayrak"),
          ("Sunucu, istemcinin söylediği fiyatı kabul ediyor mu?",
           "Gövdedeki `<<fiyat>>` değerini 1 yap; `curl -s -d '...' <<url>>/sepet/ekle` ve çıktıyı `grep FLAG` ile süz.",
           "`curl -s -d 'urun=<<ornek_urun>>&<<fiyat>>=1&adet=1' <<url>>/sepet/ekle | grep -o 'FLAG{[^}]*}'`"),
          puan=35, baslik="Fiyatı oyna"),
    Gorev("Az önce fiyatı istemcinin söylediği gibi kabul eden uygulamayı düzelt. `uygulama.py` içinde fiyatı **sunucudaki "
          "ürün kaydından** al, ve adedi (1-10 arası bir tam sayı olmalı) sunucuda denetle. Kaydet ve `cevap 6` yaz. "
          "Normal siparişler çalışmaya devam etmeli.",
          Durum(_duzeltme_denetle, "```\nfiyat = urun[\"fiyat\"]\ntry:\n    adet = int(istek.form.get(\"adet\", \"1\"))\n"
                "except ValueError:\n    return 400, {}, sayfa(\"Hata\", \"<p>Geçersiz adet.</p>\")\n"
                "if not 1 <= adet <= 10:\n    return 400, {}, sayfa(\"Hata\", \"<p>Adet 1 ile 10 arasında olmalı.</p>\")\n```"),
          ("Hangi değerin kaynağı güvenilir: istekteki fiyat mı, veritabanındaki fiyat mı?",
           "`uygulama.py`'de `fiyat = int(istek.form.get(...))` satırını `urun[\"fiyat\"]` ile değiştir; adet için `try/except` ve aralık denetimi ekle.",
           "`fiyat = urun[\"fiyat\"]`; adedi `int()`'e çevir (`ValueError` olursa 400) ve `1 <= adet <= 10` değilse `return 400, {}, ...`."),
          puan=45, baslik="Sunucuda düzelt"),
    Gorev("Tarayıcıdaki `<input name='adet' maxlength='2'>` kutusu neden adedi **güvenli biçimde** sınırlamaz?",
          Secmeli([
              ("Burp ve curl isteği tarayıcıdan sonra yakalar/gönderir; `maxlength` hiç devreye girmez",
               "Doğru. İstemci kısıtlaması sadece kullanıcıya yardımcıdır; sunucu her değeri yeniden denetlemelidir."),
              ("`maxlength` yalnızca rakam girilen alanlarda çalışmadığı için etkisizdir",
               "`maxlength` metin ve rakam alanlarında çalışır; sorun, tarayıcıyı hiç kullanmayan bir istemcinin onu atlamasıdır."),
              ("Sunucu zaten adedi kendiliğinden 2 haneye kırpar, bu yüzden yalnızca fazladan bir önlemdir",
               "Hiçbir sunucu bunu otomatik yapmaz; uygulama kodu denetlemezse 500 ya da -3 adet gibi değerler içeri girer."),
              ("Tarayıcı eklentileri bu kısıtlamayı genellikle kaldırdığı için güvenilmezdir",
               "Eklenti gerekmez; istek tarayıcı olmadan da gönderilebilir. Sorun eklentiler değil, istemcinin kontrol dışı olmasıdır."),
          ]),
          ("Bu bölümde isteği hangi araçlarla gönderdin?",
           "Bu araçlar HTML formunu çalıştırıyor mu?",
           "Form sadece bir arayüzdür; maxlength tarayıcıda kalır."),
          puan=20, baslik="maxlength"),
    Gorev("Raspberry Pi'de Burp Suite çok yavaş çalışıyor. Aynı öğrenme hedefine (isteği görmek, değiştirip tekrar "
          "göndermek) ulaşmak için en uygun yol hangisi?",
          Secmeli([
              ("`curl -v` ile istek/yanıtı görmek, `curl -x` ile vekilden geçirmek, isteği `-d @dosya` ile düzenleyip göndermek",
               "Doğru. Mantık aynı: istek bir metindir; görürsün, değiştirirsin, gönderirsin. Burp bunun kolay arayüzüdür."),
              ("Web testini tamamen bırakmak, çünkü Burp olmadan hiçbir isteği değiştirmek mümkün değildir",
               "HTTP isteği düz metindir; curl, nc ve betiklerle de aynı iş yapılır."),
              ("Tarayıcının adres çubuğuna isteği elle yazmak, çünkü POST istekleri de orada gönderilir",
               "Adres çubuğu yalnızca GET gönderir; gövdeli POST için curl gibi bir araç ya da vekil gerekir."),
              ("Hedef siteye tarama yapan bir araç çalıştırıp bulguları beklemek",
               "Öğrenme hedefi isteği kendin görmek ve değiştirmek; ayrıca izinsiz tarama yapmak etik ve yasal sorun yaratır."),
          ]),
          ("Bu bölümün adımlarında Burp kullandın mı?",
           "`curl -v`, `-x` ve `-d @dosya` hangi Burp bileşenlerinin karşılığı?",
           "Görmek için `-v`, geçmiş için vekil, Repeater için dosyadan gönderme."),
          puan=15, baslik="Burp'suz yol"),
]


SEVIYE = Seviye(
    kimlik="c05b02",
    cilt=5,
    bolum=2,
    baslik="Burp Suite ile Trafiği Görmek",
    brifing="""
Mert, ekranında bir istek gösteriyor: "Tarayıcı bir arayüz; gerçek iş bu metinde. Burp'un
bütün sırrı, bu metni görüp değiştirebilmen."

Selin dosyayı açıyor: "**<<musteri>>**. <<olay>> Uygulamanın laboratuvar kopyası `<<url>>`
adresinde, yanında Burp'un minik bir taklidi olan vekil `<<vekil>>` adresinde. Raspberry Pi'de
Burp ağır çalışabilir; o yüzden aynı mantığı curl ile uygulayacaksın."

"Kuralı unutma: yalnızca laboratuvar. Bir isteği değiştirip tekrar göndermek, izinsiz bir
siteye yapıldığında saldırıdır. Burada ise amacın açığı **görmek** ve **kodda kapatmak**."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    servis=servis,
    coz=coz,
    kapanis="""
Burp Suite'in asıl dersi şu: tarayıcı yalnızca bir arayüz, gerçek iletişim HTTP istekleridir ve
saldırgan o istekleri istediği gibi şekillendirebilir. `maxlength`, gizli alan, "devre dışı" bir buton:
hepsi istemcidedir ve tek hamlede aşılır. Savunma tarafında anlamı net: **her denetim sunucuda
yapılmalı**; fiyat, yetki, adet gibi değerlerin kaynağı istek değil, sunucudaki kayıt olmalı.
Ayrıca loglarında normalde görünmeyen bir 500 ya da alışılmadık parametre, birinin bir isteği
elle kurcaladığının işaretidir.
""",
    gercek_hayat="""
- **Fiyatı istemciden almak klasik bir iş mantığı hatasıdır:** Pek çok sızma testi raporunda
  ve bug bounty bildiriminde, fiyatın, indirim oranının ya da adedin istek içinden alınıp
  doğrulanmadığı bulgularına rastlanır. Test yöntemi bu bölümdeki gibi isteği yakalayıp değeri
  değiştirmektir; önleme sunucuda değerleri kendi kaydından türetmektir.
- **Burp Suite** PortSwigger firmasının ürünüdür; ücretsiz Community sürümü bu bölümdeki
  vekil ve Repeater kullanımı için yeterlidir, bazı gelişmiş özellikleri ücretli sürümdedir. Sertifika
  tanıtmak ve tarayıcıyı vekile yönlendirmek HTTPS trafiği için gerekir.
- **Tespit:** Savunma tarafında uygulama günlüklerinde alışılmadık değerlerin (negatif adet,
  fiyatla eşleşmeyen tutarlar) ya da kısa sürede tekrarlanan isteklerin izlenmesi, bu tür kurcalamayı
  yakalar. Sunucuda hesaplamak ve tutarsızlıkları loglamak ikisini birden yapar.
""",
    sure_hedef_dk=35,
)
