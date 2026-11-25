"""Cilt 20 · Bölüm 3 — Tokenizasyon ve Savunma (günlüklerde kart verisi).

Beceri: kurgusal uygulama günlüklerinde maskesiz PAN izlerini bulmak (ardışık ve boşluklu yazımlar), PAN'ın
hangi alanda sızdığını saptamak, günlük yapılandırmasını düzeltmek (maskeleme, ham gövde günlüğünü kapatmak,
desen) ve mevcut günlükleri `sed` ile temizlemek. `cevap <no>` komutu dosyaların son halini kontrol eder.

Kart numaraları YALNIZCA herkesçe bilinen test kartı numaralarıdır. Maskeleme/temizleme, savunma amaçlıdır;
görevlerde kart numarası doğrulaması ya da toplama yapılmaz.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c20_pci.ortak import TEST_PAN, maske, sec_doldur, sh, token

PAN_RE = re.compile(r"[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}")

VAKALAR = [
    {"vaka": "Pazarix — ödeme servisi günlükleri", "musteri": "Pazarix", "log_k": "uygulama_loglari",
     "ayar_k": "log_ayar", "alan": "kart_no", "dosyalar": ["odeme-servisi.log", "hata.log", "debug.log", "entegrasyon.log"],
     "kisi": "Tuncay Bey (sistem yöneticisi)",
     "sahne": "Pazarix'in PCI-DSS ön denetiminde, denetçi uygulama günlüklerinden örnek istedi. Tuncay Bey: \"Günlüğe kart "
              "numarası yazıyor muyuz, bilmiyorum; yazıyorsak nerede? Bulalım ve ayarı düzeltelim, yoksa ilk bulgu "
              "bu olacak.\""},
    {"vaka": "Paramix — ödeme geçidi günlükleri", "musteri": "Paramix", "log_k": "loglar",
     "ayar_k": "yapilandirma", "alan": "pan", "dosyalar": ["gateway.log", "retry.log", "audit.log", "debug_trace.log"],
     "kisi": "Ece Hanım (CTO)",
     "sahne": "Paramix'in ödeme geçidinde, bir geliştirici hata ayıklama sırasında ham istek gövdelerini günlüğe açmış. "
              "Ece Hanım: \"Bunu kimin ne zaman açtığını bilmiyorum; ama denetçi görürse ağır bir bulgu. Günlüklerde "
              "ne kadar kart verisi var, bulalım ve temizleyelim.\""},
    {"vaka": "Ferah Bank — sanal POS günlükleri", "musteri": "Ferah Bank", "log_k": "kayitlar",
     "ayar_k": "ayarlar", "alan": "card_number", "dosyalar": ["sanalpos.log", "iade.log", "hatalar.log", "izleme.log"],
     "kisi": "Kaan Bey (bilgi güvenliği müdürü)",
     "sahne": "Ferah Bank'ın sanal POS uygulamasında iç denetim, günlüklerde kart verisi izleri olduğundan şüpheleniyor. "
              "Kaan Bey: \"Günlükleri yazan uygulamanın ayarını ve mevcut kayıtları düzeltmemiz gerek; acil, çünkü "
              "günlükler merkezi bir sunucuya da kopyalanıyor.\""},
]


def _satir(rng, t, v, tur: str, pan: str) -> str:
    isl = f"ISL-{rng.randint(10000, 99999)}"
    ts = f"2026-03-{rng.randint(1, 28):02d} {rng.randint(8, 22):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}"
    tutar = f"{rng.randint(20, 3500)}.{rng.randint(0, 99):02d}"
    k = v["alan"]
    if tur == "normal":
        return f"{ts} INFO odeme_tamamlandi islem={isl} tutar={tutar} sonuc=onay"
    if tur == "token":
        return f"{ts} INFO kart_kaydedildi islem={isl} kart={token(rng)} sonuc=ok"
    if tur == "maske":
        return f"{ts} INFO odeme_istegi islem={isl} {k}={maske(pan)} tutar={tutar}"
    if tur == "json":
        return f'{ts} DEBUG istek_govdesi islem={isl} {{"{k}":"{pan}","tutar":{tutar}}}'
    # bosluklu
    p = " ".join(pan[i:i + 4] for i in range(0, 16, 4))
    return f"{ts} ERROR kart_reddedildi islem={isl} {k}={p} kod=05"


def uret(rng):
    v = rng.choice(VAKALAR)
    dosyalar = v["dosya_listesi"] if "dosya_listesi" in v else list(v["dosyalar"])
    sizan = sorted(rng.sample(range(4), rng.randint(2, 3)))
    icerik = {}
    toplam = 0
    bosluklu = 0
    tokenler = 0
    for i, ad in enumerate(dosyalar):
        satirlar = []
        for _ in range(rng.randint(6, 9)):
            satirlar.append(_satir(rng, None, v, rng.choice(["normal", "normal", "token", "maske"]), rng.choice(TEST_PAN)))
        if i in sizan:
            for _ in range(rng.randint(2, 4)):
                tur = rng.choice(["json", "bosluklu"])
                bosluklu += tur == "bosluklu"
                satirlar.append(_satir(rng, None, v, tur, rng.choice(TEST_PAN)))
                toplam += 1
            rng.shuffle(satirlar)
        icerik[ad] = satirlar
    # yedek: token satırları belirli sayıda ve PAN desenine uymayan token'lar olsun
    for ad, satirlar in icerik.items():
        for sat in satirlar:
            if "tok_" in sat and PAN_RE.search(sat.split("kart=")[1]):
                raise RuntimeError("token PAN desenine uydu")
        tokenler += sum("tok_" in x for x in satirlar)
    if tokenler < 3:
        icerik[dosyalar[0]].append(_satir(rng, None, v, "token", ""))
        icerik[dosyalar[0]].append(_satir(rng, None, v, "token", ""))
        icerik[dosyalar[0]].append(_satir(rng, None, v, "token", ""))
    sizan_dosyalar = sorted(ad for ad, sl in icerik.items() if any(PAN_RE.search(x) for x in sl))
    ornek_log = sizan_dosyalar[0]
    satir_sayilari = {ad: len(sl) for ad, sl in icerik.items()}
    islem_sayisi = sum(x.count("islem=") for sl in icerik.values() for x in sl)
    return {
        "vaka": v["vaka"], "v": v, "icerik": icerik, "satir_sayilari": satir_sayilari, "islem_sayisi": islem_sayisi,
        "bosluklu": bosluklu, "pan_ornekleri": rng.sample(TEST_PAN, 3),
        "metin": {"musteri": v["musteri"], "sahne": v["sahne"], "kisi": v["kisi"], "log_k": v["log_k"],
                  "ayar_k": v["ayar_k"], "ornek_log": ornek_log, "alan": v["alan"]},
        "cevaplar": {
            "dosyalar": sizan_dosyalar,
            "satir_sayisi": sum(1 for sl in icerik.values() for x in sl if PAN_RE.search(x)),
            "alan": v["alan"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt", f"{v['musteri']} uygulama günlükleri (kurgusal).\n"
          "Kart numaraları herkesçe bilinen TEST numaralarıdır; gerçek kimseye ait değildir.\n"
          f"{v['log_k']}/ : günlükler · {v['ayar_k']}/ : günlük yapılandırması · ornekler/ : desen sınama dosyaları\n")
    for ad, sl in s["icerik"].items():
        u.yaz(lab / v["log_k"] / ad, "\n".join(sl) + "\n")
    u.yaz(lab / v["ayar_k"] / "maskeleme.conf",
          "# Günlüğe yazılan satırlardaki kart numarası bu ayarlara göre maskelenir.\n"
          "# maskeleme=acik|kapali    maske_bicim=yok|ilk6_son4|son4\n"
          "# debug_govde_logla=evet|hayir (ham istek/yanıt gövdesini yazar)\n"
          "# desen=<Python düzenli ifadesi> (eşleşen metin maskelenir)\n"
          "maskeleme=kapali\nmaske_bicim=yok\ndebug_govde_logla=evet\ndesen=\n")
    pan_ornek = []
    for p in s["pan_ornekleri"]:
        pan_ornek += [p, " ".join(p[i:i + 4] for i in range(0, 16, 4))]
    pan_ornek.append("-".join(s["pan_ornekleri"][0][i:i + 4] for i in range(0, 16, 4)))
    u.yaz(lab / "ornekler" / "pan_ornekleri.txt", "\n".join(pan_ornek) + "\n")
    u.yaz(lab / "ornekler" / "zararsiz_ornekler.txt",
          "tutar=1250.50\nislem=ISL-48213\n2026-03-12 10:14:01\ntel=05325550102\nkod=0005\nmaskeli=411111******1111\n"
          "sonuc=onay referans=R20260312\n")


# ----------------------------------------------------------------------------- kontroller


def _ayar(lab: Path, ayar_k: str) -> dict:
    d = {}
    try:
        for satir in (lab / ayar_k / "maskeleme.conf").read_text(encoding="utf-8").splitlines():
            satir = satir.strip()
            if satir and not satir.startswith("#") and "=" in satir:
                a, de = satir.split("=", 1)
                d[a.strip()] = de.strip()
    except OSError:
        pass
    return d


def _ayar_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    a = _ayar(b.lab, v["ayar_k"])
    if a.get("maskeleme") != "acik":
        return Sonuc(False, "Maskeleme hâlâ kapalı (`maskeleme=acik` olmalı).")
    if a.get("maske_bicim") not in ("ilk6_son4", "son4"):
        return Sonuc(False, "`maske_bicim` `ilk6_son4` ya da `son4` olmalı; `yok` maskeleme yapmaz.", yakin=True)
    if a.get("debug_govde_logla") != "hayir":
        return Sonuc(False, "Ham istek gövdesi hâlâ günlüğe yazılıyor (`debug_govde_logla=hayir`). Gövdede kart numarası olur.",
                     yakin=True)
    desen = a.get("desen", "")
    if not desen:
        return Sonuc(False, "`desen=` boş; kart numarasını tanıyacak bir düzenli ifade yaz (ardışık, boşluklu ve tireli biçimleri yakalasın).",
                     yakin=True)
    try:
        r = re.compile(desen)
    except re.error:
        return Sonuc(False, "Desen geçerli bir düzenli ifade değil.")
    for satir in (b.lab / "ornekler" / "pan_ornekleri.txt").read_text(encoding="utf-8").splitlines():
        if not r.search(satir):
            return Sonuc(False, f"Desen şu kart yazımını yakalamıyor: {satir}", yakin=True)
    for satir in (b.lab / "ornekler" / "zararsiz_ornekler.txt").read_text(encoding="utf-8").splitlines():
        if r.search(satir):
            return Sonuc(False, f"Desen fazla geniş: zararsız bir satırı da yakalıyor ({satir}).", yakin=True)
    return Sonuc(True, "Maskeleme açık, ham gövde günlüğü kapalı ve desen tüm kart yazımlarını (yalnızca onları) yakalıyor.")


def _temizlik_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    kalan = 0
    toplam_islem = 0
    for ad, n in b.senaryo["satir_sayilari"].items():
        yol = b.lab / v["log_k"] / ad
        try:
            satirlar = yol.read_text(encoding="utf-8").splitlines()
        except OSError:
            return Sonuc(False, f"{ad} dosyası yok; günlüğü silme, içindeki kart numaralarını maskele.")
        if len(satirlar) != n:
            return Sonuc(False, f"{ad} dosyasının satır sayısı değişmiş ({n} -> {len(satirlar)}). Satırı silme; yalnızca kart numarasını maskele.")
        kalan += sum(1 for x in satirlar if PAN_RE.search(x))
        toplam_islem += sum(x.count("islem=") for x in satirlar)
    if kalan:
        return Sonuc(False, f"Hâlâ {kalan} satırda maskesiz kart numarası var (boşluklu yazımları da unutma).", yakin=True)
    if toplam_islem != b.senaryo["islem_sayisi"]:
        return Sonuc(False, "İşlem kimlikleri bozulmuş; yalnızca kart numarası kısmını maskelemelisin, satırın kalanı yerinde kalmalı.")
    return Sonuc(True, "Günlüklerde maskesiz kart numarası kalmadı; satırların geri kalanı yerinde.")


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen - b.senaryo["bosluklu"] and b.senaryo["bosluklu"]:
        return "Boşluklu yazılmış kart numaralarını (`4111 1111 1111 1111`) da say; yalnızca ardışık 16 rakamı aramak onları kaçırır."
    return None


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    k, ak = v["log_k"], v["ayar_k"]
    desen = "[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}"
    dosyalar = sh(f"grep -l -E '{desen}' {k}/*.log | xargs -n1 basename", lab).replace("\n", " ")
    sayi = sh(f"cat {k}/*.log | grep -c -E '{desen}'", lab)
    alan = sh(f"grep -h -E '{desen}' {k}/*.log | grep -o '[a-z_]*=[0-9]' | head -1 | cut -d= -f1", lab)
    sh(f"sed -i -e 's/^maskeleme=.*/maskeleme=acik/' -e 's/^maske_bicim=.*/maske_bicim=ilk6_son4/' "
       f"-e 's/^debug_govde_logla=.*/debug_govde_logla=hayir/' -e 's|^desen=.*|desen={desen}|' {ak}/maskeleme.conf", lab)
    sh("sed -i -E 's/[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?([0-9]{4})/************\\1/g' " + f"{k}/*.log", lab)
    return sec_doldur({2: dosyalar, 3: sayi, 4: alan, 5: "", 6: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Günlük dosyalarına bakmak", """
Uygulamalar her işlem hakkında günlük (log) yazar. Hata ayıklamak için yazılan bu satırlara kart numarası
**kazara** düşebilir ve günlükler çoğu zaman en az korunan dosyalardır. Önce dosyalara ve boyutlarına bak:
""", komut="wc -l <<log_k>>/*.log", sonra="""
`wc -l` satır sayar. Birkaç dosya, her birinde birkaç on satır. Gerçek sistemde bu sayılar milyonlarca olur ve
elle okumak imkânsızdır; bu yüzden **desenle arama** şart.
"""),
    Adim("Normal bir satır nasıl görünür?", """
Önce sağlıklı bir satırı tanı. Bir günlük dosyasının ilk satırları:
""", komut="head -4 <<log_k>>/<<ornek_log>>", sonra="""
Zaman, seviye (INFO/DEBUG/ERROR), olay, `islem=` kimliği ve alanlar. Kart bilgisi şu üç biçimden birinde
görünebilir: **açık** numara, **maskeli** (`411111******1111`) ya da **token** (`tok_...`).
"""),
    Adim("Ardışık 16 rakam", """
`grep -E '[0-9]{16}'` ardışık 16 rakam geçen satırları bulur; `-c` bunları dosya başına sayar:
""", komut="grep -c -E '[0-9]{16}' <<log_k>>/*.log", sonra="""
Sayılar çıktı ama **eksik** olabilir: kart numaraları günlüklerde boşlukla (`4111 1111 1111 1111`) ya da tireyle de
yazılır. Ardışık desen onları kaçırır. Bir sonraki adımda bunu düzelt.
"""),
    Adim("Boşluklu ve tireli yazımlar", """
Desene, her dört hane arasında isteğe bağlı boşluk ya da tire ekle: `[ -]?` "boşluk ya da tire, olabilir de
olmayabilir de" demektir:
""", komut="grep -c -E '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}' <<log_k>>/*.log", sonra="""
Sayılar arttı: artık boşluklu yazımlar da yakalanıyor. **Hacker gözüyle:** Saldırgan günlükten kart toplarken
tam da böyle bir desen kullanır; savunmacı bu desenle **önce** kendi günlüklerini tarar.
"""),
    Adim("Hangi alanda sızıyor?", """
Bir satırda kart numarasının **hangi alana** yazıldığı kök nedeni gösterir (ham istek gövdesi mi, hata
mesajı mı?). Eşleşen satırlara göz at:
""", komut="grep -h -E '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}' <<log_k>>/<<ornek_log>>", sonra="""
Aynı alan adı hem JSON gövdesinde hem hata satırında geçiyor: uygulama kartı bir **değişken** olarak yazıyor ve
yazmadan önce maskelemiyor. Çözüm, yazılan değeri **günlüğe girmeden önce** maskelemektir.
"""),
    Adim("Günlük yapılandırması", """
Maskeleme, günlük kütüphanesinin yapılandırmasıyla açılır. Ayar dosyası:
""", komut="cat <<ayar_k>>/maskeleme.conf", sonra="""
Dört ayar: maskeleme açık/kapalı, biçim (`ilk6_son4`: ilk 6 ve son 4 hane görünür, ortası gizli; `son4`: yalnızca
son 4), ham gövde günlüğü ve bir **desen**. En güvenlisi, ham gövdeyi hiç yazmamak ve kalan satırları desenle
maskelemektir.
"""),
    Adim("Mevcut günlükleri temizlemek: sed", """
Yapılandırmayı düzeltmek **yeni** satırları korur; eski günlükler hâlâ açık numara taşıyor. `sed -E` ile
düzenli ifadeyi değiştirebilirsin: parantez içindeki parça `\\1` ile geri çağrılır. Önce yalnızca **ne
değişecek** diye bak (`-n` ve `p` değişen satırları yazdırır, dosyaya dokunmaz):
""", komut="sed -n -E 's/[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?([0-9]{4})/************\\1/p' <<log_k>>/<<ornek_log>>",
          sonra="""
Gördüğün gibi her kart numarası yalnızca **son 4 hane** kalacak biçimde dönüşüyor. `-i` ekleyip `p` yerine `g`
kullanırsan dosya yerinde değişir; ama önce hep dene, sonra uygula. Silme: **tokenizasyon** burada devreye girer
(aşağıda).
"""),
]

GOREVLER = [
    Gorev("Tokenizasyon bir sistemi PCI-DSS kapsamından büyük ölçüde nasıl çıkarır?",
          Secmeli([
              ("Gerçek numara kasada kalır, sistem yalnızca token'ı görür; kapsam küçülür",
               "Doğru. Token çalınsa bile gerçek numaraya dönüştürülemez; sistem kart verisi tutmaz."),
              ("Kart numarası güçlü bir şifreyle her sistemde saklanır ve anahtarı yönetici tutar",
               "Yanlış. Şifrelenmiş PAN hâlâ kart verisidir ve sistemi kapsamda tutar; tokenizasyon farklıdır."),
              ("Kart numarasının son dört hanesi dışındaki bütün hanelerini rastgele sayılarla değiştirir",
               "Yanlış. Bu maskelemedir ve kısmi veri bırakır; tokenizasyon anlamsız, ilişkisiz bir değer üretir."),
              ("Kart verisi bir kez silindiğinde sistem otomatik olarak denetimden bağımsız hale gelir",
               "Yanlış. Silmek tek başına yetmez; veri başka yerde (günlük, yedek) kalmış olabilir ve kayıtlar denetlenir."),
          ], dogru=0),
          ("Tokenizasyonda sistem neyi görür, kasa neyi saklar?",
           "Sistem kart verisi görmüyorsa PCI-DSS neyi denetler?",
           "Cevap: token görür, gerçek numara ayrı kasada; kapsam küçülür."),
          puan=20, baslik="Tokenizasyon"),
    Gorev("`<<log_k>>` içinde **maskesiz kart numarası** (ardışık ya da boşluklu/tireli yazım) bulunan günlük dosyaları "
          "hangileri? Adları boşlukla yaz.",
          Kume("dosyalar", tur="metin", bicim="dosya adları, boşlukla ayrılmış"),
          ("Hem ardışık hem boşluklu/tireli yazımı yakalayan bir desen gerekli.",
           "`grep -l -E` eşleşen dosyaların adını verir; deseni `[0-9]{4}[ -]?` dört kez tekrarla.",
           "`grep -l -E '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}' <<log_k>>/*.log`"),
          puan=40, baslik="Sızıntılı günlükler"),
    Gorev("Bu günlüklerde toplam **kaç satırda** maskesiz kart numarası var?",
          Sayi("satir_sayisi", sik_hatalar=_sayi_hata),
          ("Boşluklu yazımlar sayıyı etkiler.",
           "Dosyaları birleştirip (`cat`) sonra `grep -c -E` ile sayabilirsin; çünkü `grep -c` birden çok dosyada dosya başına sayar.",
           "`cat <<log_k>>/*.log | grep -c -E '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}'`"),
          puan=40, baslik="Sızıntılı satır sayısı"),
    Gorev("Uygulama kart numarasını günlüğe hangi **alan adıyla** yazıyor? (Örneğin `xyz=4111...` biçimindeki `xyz`.)",
          Metin("alan", bicim="alan adı"),
          ("Eşleşen satırlarda `=` işaretinden önce gelen kelimeye bak.",
           "`grep -h -E` ile açık numaralı satırları göster; alan adı hem JSON'da hem hata satırında aynı.",
           "`grep -h -E '[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}' <<log_k>>/<<ornek_log>>`"),
          puan=30, baslik="Sızan alan"),
    Gorev("Günlük yapılandırmasını (`<<ayar_k>>/maskeleme.conf`) düzelt: maskeleme açık, maske biçimi `ilk6_son4` ya "
          "da `son4`, ham gövde günlüğü kapalı ve kart numarasını yakalayan bir `desen=` (ardışık, boşluklu ve tireli "
          "yazımları yakalasın; `ornekler/` içindeki zararsız satırlara dokunmasın). Sonra `cevap 5`.",
          Durum(_ayar_kontrol, "maskeleme=acik, maske_bicim=ilk6_son4, debug_govde_logla=hayir, "
                               "desen=[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}"),
          ("Dört ayar var: üçü basit değer, biri düzenli ifade. Sınama dosyaları `ornekler/` altında.",
           "Desen: dört hane, isteğe bağlı boşluk/tire, bu dört kez. `ornekler/pan_ornekleri.txt` yakalanmalı, `zararsiz_ornekler.txt` yakalanmamalı.",
           "`sed -i -e 's/^maskeleme=.*/maskeleme=acik/' -e 's/^maske_bicim=.*/maske_bicim=ilk6_son4/' -e 's/^debug_govde_logla=.*/debug_govde_logla=hayir/' -e 's|^desen=.*|desen=[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}|' <<ayar_k>>/maskeleme.conf`"),
          puan=50, baslik="Yapılandırmayı düzelt"),
    Gorev("Mevcut günlük dosyalarındaki kart numaralarını **maskele**: her numara yalnızca son 4 hanesi kalacak biçimde "
          "dönüşsün. Satırları silme, geri kalan alanlara (`islem=`, tutar...) dokunma; boşluklu yazımları da unutma. "
          "Sonra `cevap 6`.",
          Durum(_temizlik_kontrol, "sed -i -E 's/[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?([0-9]{4})/************\\1/g' <<log_k>>/*.log"),
          ("`sed -E` ile bir düzenli ifadeyi bir metinle değiştirebilirsin; son dört haneyi parantezle yakalayıp geri çağırabilirsin.",
           "Desen adım 7'de gösterildiği gibi; `p` yerine `g` yaz, `-n`'yi bırak ve `-i` ekle. Önce `sed -n ... p` ile dene.",
           "`sed -i -E 's/[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?([0-9]{4})/************\\1/g' <<log_k>>/*.log`"),
          puan=50, baslik="Günlükleri temizle"),
    Gorev("Uçtan uca şifreleme (P2PE) ne sağlar?",
          Secmeli([
              ("Kart verisi okunduğu anda şifrelenir, ara sistemlerde hiç açık görünmez",
               "Doğru. Ara sistemler ele geçirilse bile kart verisi okunamaz."),
              ("Kart verisi yalnızca saklandığı veritabanında şifrelenir; ağ üzerinden açık dolaşır",
               "Yanlış. Bu, dururken şifrelemedir; P2PE okuma anından itibaren korur."),
              ("Kart numarası günlüklere yazılmadan önce son dört hanesi dışında maskelenir",
               "Yanlış. Bu, maskelemedir; P2PE veriyi daha en baştan şifreler."),
              ("Kart sahibinin kimliği ikinci bir faktörle doğrulanır ve işlem onaylanır",
               "Yanlış. Bu, güçlü müşteri doğrulamasıdır; P2PE veri gizliliğiyle ilgilidir."),
          ], dogru=0),
          ("P2PE'deki 'P' kelimesini düşün: nokta-nokta (uçtan uca).",
           "Veri POS cihazında okunduğu anda ne olur?",
           "Cevap: okunduğu anda şifrelenir, ara sistemler açık hâlini hiç görmez."),
          puan=20, baslik="P2PE"),
]


def _kapanis():
    return """
Günlükler, kart verisinin en sinsi sızdığı yerdir: kimse oraya kart yazmak istemez ama hata ayıklama gövdesi
her şeyi ham yazar, günlükler çoğaltılır, yedeklenir ve geniş kitlece okunur. Saldırgan gözüyle günlük bir altın
madenidir: tek bir desenle yüzlerce kart toplanır. Savunma gözüyle üç katman var: kartı **hiç almamak** (token),
günlüğe yazmadan **maskelemek**, ve mevcut dosyaları düzenli **taramak** ve temizlemek.
"""


SEVIYE = Seviye(
    kimlik="c20b03", cilt=20, bolum=3, baslik="Tokenizasyon ve Savunma: Günlüklerdeki Kart Verisi",
    brifing="""
<<sahne>>

Selin: "Günlükler `<<log_k>>/`, ayarlar `<<ayar_k>>/` klasöründe. Hepsi test kartlarıyla dolu; gerçek veri yok, ama
müşterinin sistemi gerçek olsaydı bu bir ihlal olurdu. Önce **ne kadar** sızmış, sonra **nasıl** düzeltiriz."

Deniz: "Kural basit: yeni sızıntıyı ayarla kapat, eski sızıntıyı sed ile temizle. İkisini birden yapmazsan
yarım iş yapmış olursun."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Günlüklerde kart verisi:** PCI-DSS, kart numarasının (PAN) saklanan her yerde (günlükler dahil) okunamaz
  hâle getirilmesini ister. Pek çok uyum denetiminde bulgu, hata ayıklama için açılmış ham istek günlüğünün
  üretimde unutulması ve içinde kart numaraları taşımasıdır.
- **Tespit:** Kart verisi keşif araçları günlükleri, yedekleri ve paylaşılan klasörleri düzenli tarar. Tarama desenleri
  ardışık, boşluklu ve tireli yazımları kapsamalı; eşleşmeler ayrıca doğrulanarak yanlış alarmlar elenir.
- **Önleme:** Mümkünse kart numarasını hiç almamak (ödeme sayfasını sağlayıcıya yaptırmak, token kullanmak), günlük
  kütüphanesinde maskeleme açmak ve üretimde ham gövde günlüğünü kapatmak. Tokenizasyon ve P2PE, kart verisinin
  ara sistemlerde hiç görünmemesini sağlayarak hem ihlal riskini hem denetim kapsamını azaltır.
""",
    sure_hedef_dk=40,
)
