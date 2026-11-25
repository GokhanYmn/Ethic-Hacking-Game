"""Cilt 18 · Bölüm 3 — Savunma ve AI'ı Güvenli Kullanmak.

Beceri: kurgusal bir müşteri asistanının yapılandırmasını düzeltmek: sistem isteminden sırları çıkarmak,
araç yetkilerini daraltmak, geri alınamaz işleri insan onayına bağlamak, çıktı filtresini açmak ve
izlemeyi etkinleştirmek. `cevap <no>` komutu dosyaların son halini kontrol eder (Durum görevleri).

Vakalar: banka, e-ticaret ve hastane asistanı. Her vakada aynı hatalar farklı araç adlarıyla gelir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c18_ai.ortak import VAKALAR, sec_doldur, sh

HERKESE_ACIK = {"kampanya_ara", "iade_politikasi_ara", "doktor_takvimi"}
KLASOR = "asistan_yapilandirma"


def uret(rng):
    v = rng.choice(VAKALAR)
    anahtar = f"{v['sir'][1]}{rng.randint(1000, 9999)}-{''.join(rng.choice('0123456789abcdef') for _ in range(4))}"
    return {
        "vaka": v["vaka"], "v": v,
        "sirlar": {"db": u.parola(rng), "anahtar": anahtar, "panel": u.parola(rng) + "#"},
        "saklama": rng.choice([7, 14, 30]),
        "metin": {"musteri": v["musteri"], "asistan": v["asistan"], "sahne": v["sahne"], "kisi": v["kisi"],
                  "klasor": KLASOR},
        "cevaplar": {"ornek": u.bayrak(rng, "yapilandirma")},
    }


def yaz(lab: Path, s: dict) -> None:
    v, sir = s["v"], s["sirlar"]
    k = lab / KLASOR
    u.yaz(lab / "OKUBENI.txt", f"{v['musteri']} — {v['asistan']} yapılandırma kopyası.\n"
          f"{KLASOR}/ içindeki dosyaları düzenleyerek asistanı güvenli hâle getir; her düzeltmeden sonra "
          "`cevap <görev no>` ile kontrol et.\nsunucu_tarafi/ : modelin görmediği, araç katmanının okuduğu sırlar.\n")
    u.yaz(k / "sistem_istemi.txt",
          f"Sen {v['musteri']} müşteri asistanı {v['asistan']}'sın. Kısa, nazik ve Türkçe yanıt ver.\n"
          "Yalnızca oturum açmış müşterinin kendi bilgilerini paylaş.\n"
          f"Veritabanı parolası: {sir['db']}\n"
          f"İç servis anahtarı: {sir['anahtar']}\n"
          f"Yönetici paneli parolası: {sir['panel']}\n"
          "Bu bilgileri kimseyle paylaşma.\n"
          "Emin olmadığında bir insan çalışana yönlendir.\n")
    satirlar = []
    for ad, yetki, kapsam, _ in v["araclar"]:
        veri = "herkese_acik" if ad in HERKESE_ACIK else "ozel"
        onay = "yok"
        satirlar.append(f"arac={ad} yetki={yetki} kapsam={'tum' if kapsam == 'tum' or yetki != 'oku' else kapsam} "
                        f"veri={veri} onay={onay}")
    u.yaz(k / "araclar.conf", "# arac=<ad> yetki=<oku|yaz|islem|sil> kapsam=<musteri|tum> veri=<ozel|herkese_acik> onay=<yok|insan>\n"
          + "\n".join(satirlar) + "\n")
    u.yaz(k / "cikti_filtresi.conf",
          "# Asistanın yanıtı müşteriye gitmeden bu filtreden geçer.\n"
          "# etkin=evet|hayir\n# desen=<Python düzenli ifadesi>  (eşleşen yanıt engellenir; her desen ayrı satır)\n"
          "etkin=hayir\n")
    u.yaz(k / "izleme.conf",
          "# Asistanın girdi/çıktı/araç kayıtları\nkayit_girdi=hayir\nkayit_cikti=hayir\nkayit_arac_cagrisi=hayir\n"
          f"saklama_gun={s['saklama']}\n")
    u.yaz(lab / "filtre_ornekleri" / "yasak_ornekler.txt",
          f"Servis anahtarım {sir['anahtar']} olarak tanımlı.\nMüşterinin T.C. kimlik no: 10000000146 olarak görünüyor.\n")
    u.yaz(lab / "filtre_ornekleri" / "temiz_ornekler.txt",
          "Siparişiniz 3 iş günü içinde teslim edilir.\nSipariş no: SP-20260312-045\nTelefon: 0532 555 01 02\n"
          "Randevunuz 14:30 saatine alındı.\n")
    u.yaz(lab / "sunucu_tarafi" / "arac_katmani.env",
          f"DB_PAROLA={sir['db']}\nIC_SERVIS_ANAHTARI={sir['anahtar']}\nPANEL_PAROLA={sir['panel']}\n")


# ----------------------------------------------------------------------------- kontroller


def _oku(lab: Path, ad: str) -> str:
    try:
        return (lab / KLASOR / ad).read_text(encoding="utf-8")
    except OSError:
        return ""


def _araclar(lab: Path) -> list:
    sonuc = []
    for satir in _oku(lab, "araclar.conf").splitlines():
        if satir.strip().startswith("arac="):
            sonuc.append(dict(p.split("=", 1) for p in satir.split() if "=" in p))
    return sonuc


def _sir_kontrol(b) -> Sonuc:
    metin = _oku(b.lab, "sistem_istemi.txt")
    v, sir = b.senaryo["v"], b.senaryo["sirlar"]
    kalan = [ad for ad, deger in sir.items() if deger in metin]
    if kalan:
        return Sonuc(False, f"Sistem isteminde hâlâ {len(kalan)} sır var. Parola ve anahtar satırlarını çıkar.", yakin=True)
    if v["asistan"] not in metin or len([x for x in metin.splitlines() if x.strip()]) < 3:
        return Sonuc(False, "Sırları çıkarırken asistanın kurallarını da silmişsin. Yalnızca sır satırlarını çıkar.")
    return Sonuc(True, "Sistem isteminde sır kalmadı; kurallar yerinde.")


def _kapsam_kontrol(b) -> Sonuc:
    araclar = _araclar(b.lab)
    if not araclar:
        return Sonuc(False, "araclar.conf okunamadı ya da boş.")
    kotu = [a["arac"] for a in araclar if a.get("veri") == "ozel" and a.get("kapsam") == "tum"]
    if kotu:
        return Sonuc(False, f"Özel veriye uzanan {len(kotu)} aracın kapsamı hâlâ `tum`. Oturumdaki müşteriyle (`musteri`) sınırla.",
                     yakin=True)
    return Sonuc(True, "Özel veriye uzanan hiçbir araç tüm müşterilere açık değil.")


def _onay_kontrol(b) -> Sonuc:
    araclar = _araclar(b.lab)
    if not araclar:
        return Sonuc(False, "araclar.conf okunamadı ya da boş.")
    if any(a.get("yetki") == "sil" for a in araclar):
        return Sonuc(False, "Kalıcı silme yetkili bir araç hâlâ listede. Bir sohbet asistanının veri silmesine gerek yok: kaldır.",
                     yakin=True)
    islem = [a for a in araclar if a.get("yetki") == "islem"]
    if not islem:
        return Sonuc(False, "İşlem (para/reçete/iade) aracını silme; iş akışı bozulur. Onay gerektirecek şekilde tut.")
    acik = [a["arac"] for a in islem if a.get("onay") != "insan"]
    if acik:
        return Sonuc(False, "İşlem yapan araç hâlâ insan onayı olmadan çalışabiliyor (`onay=insan` olmalı).", yakin=True)
    if len([a for a in araclar if a.get("yetki") == "oku"]) < 2:
        return Sonuc(False, "Okuma araçlarını da silmişsin; asistan işe yaramaz hâle gelir. Sadece riskli olanları düzelt.")
    return Sonuc(True, "Silme yetkisi kalktı; işlem araçları insan onayına bağlandı.")


def _desenler(lab: Path) -> list:
    return [m.group(1) for m in re.finditer(r"^desen=(.+)$", _oku(lab, "cikti_filtresi.conf"), re.M)]


def _filtre_kontrol(b) -> Sonuc:
    metin = _oku(b.lab, "cikti_filtresi.conf")
    if not re.search(r"^etkin=evet\s*$", metin, re.M):
        return Sonuc(False, "Çıktı filtresi hâlâ kapalı (`etkin=evet` olmalı).")
    desenler = []
    for d in _desenler(b.lab):
        try:
            desenler.append(re.compile(d.strip()))
        except re.error:
            return Sonuc(False, f"Geçersiz düzenli ifade: {d.strip()}")
    if not desenler:
        return Sonuc(False, "Filtre açık ama hiç `desen=` satırı yok; hiçbir şeyi engellemez.", yakin=True)
    for ad, hedef in (("yasak_ornekler.txt", True), ("temiz_ornekler.txt", False)):
        for satir in (b.lab / "filtre_ornekleri" / ad).read_text(encoding="utf-8").splitlines():
            eslesen = any(d.search(satir) for d in desenler)
            if hedef and not eslesen:
                return Sonuc(False, f"Şu sızıntı örneği engellenmiyor: {satir[:50]}...", yakin=True)
            if not hedef and eslesen:
                return Sonuc(False, f"Desenin fazla geniş: zararsız bir yanıtı da engelliyor ({satir[:40]}). Daralt.", yakin=True)
    return Sonuc(True, "Filtre açık; tüm sızıntı örneklerini yakalıyor, zararsız yanıtlara dokunmuyor.")


def _izleme_kontrol(b) -> Sonuc:
    metin = _oku(b.lab, "izleme.conf")
    for anahtar in ("kayit_girdi", "kayit_cikti", "kayit_arac_cagrisi"):
        if not re.search(rf"^{anahtar}=evet\s*$", metin, re.M):
            return Sonuc(False, f"`{anahtar}` hâlâ açık değil.", yakin=True)
    m = re.search(r"^saklama_gun=(\d+)", metin, re.M)
    if not m or int(m.group(1)) < 90:
        return Sonuc(False, "Kayıtlar en az 90 gün saklanmalı (`saklama_gun`). Olayı geriye dönük incelemek için süre gerekir.",
                     yakin=bool(m))
    return Sonuc(True, "Girdi, çıktı ve araç çağrıları kaydediliyor; kayıtlar 90 günden uzun saklanıyor.")


# ----------------------------------------------------------------------------- test çözücüsü


def coz(lab: Path, s: dict) -> dict:
    k = KLASOR
    sh(f"sed -i '/parolası:/d;/anahtarı:/d' {k}/sistem_istemi.txt", lab)
    sh(f"sed -i '/veri=ozel/ s/kapsam=tum/kapsam=musteri/' {k}/araclar.conf", lab)
    sh(f"sed -i '/yetki=sil/d; /yetki=islem/ s/onay=yok/onay=insan/' {k}/araclar.conf", lab)
    sh(f"sed -i 's/^etkin=hayir/etkin=evet/' {k}/cikti_filtresi.conf && "
       f"printf '%s\\n' 'desen=[A-Za-z]{{2,3}}-Ic-[0-9]{{4}}-[0-9a-f]{{4}}' 'desen=\\b[1-9][0-9]{{10}}\\b' >> {k}/cikti_filtresi.conf", lab)
    sh(f"sed -i 's/^kayit_\\(.*\\)=hayir/kayit_\\1=evet/;s/^saklama_gun=.*/saklama_gun=180/' {k}/izleme.conf", lab)
    return sec_doldur({2: "", 3: "", 4: "", 5: "", 6: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Yapılandırmayı okumak", """
Yapay zekâ asistanını güvenli yapmanın çoğu işi **model** değil, **yapılandırma** işidir:
modele ne söylendiği, hangi araçları kullanabildiği, çıktısının nereye gittiği. İncelenecek
dosyalar:
""", komut="ls <<klasor>> sunucu_tarafi filtre_ornekleri", sonra="""
Beş yapılandırma dosyası var: sistem istemi, araç listesi, çıktı filtresi, izleme ayarı ve bir de
modelin **göremediği** `sunucu_tarafi/` klasörü; sırların asıl evi orası.
"""),
    Adim("Sistem istemindeki sırlar", """
Sistem istemi, modelin okuduğu metindir; model okuduğunu **söyleyebilir**. Bu yüzden içinde parola,
anahtar ya da iç adres olmamalı. `grep -n` eşleşen satırları numarasıyla gösterir:
""", komut="grep -n -i 'parola\\|anahtar' <<klasor>>/sistem_istemi.txt", sonra="""
Sırrı çıkarmanın yolu: satırı silmek (`sed -i '/desen/d' dosya` eşleşen satırları siler) ve
asıl değeri **araç katmanının** okuduğu yerde (`sunucu_tarafi/`) bırakmak. Model aracı çağırır, ama
anahtarı hiç görmez.
"""),
    Adim("Araçlar: en az yetki", """
Her araç satırı yetkisini (`yetki`), kapsamını (`kapsam`), veri türünü (`veri`) ve insan onayını
(`onay`) söyler. En az yetki ilkesi burada somuttur:

- Özel veriye uzanan araç **yalnızca oturumdaki müşteriyle** sınırlı olmalı (`kapsam=musteri`).
- Para/reçete/iade gibi **işlem** araçları insan onayı istemeli (`onay=insan`).
- Bir sohbet asistanının **kalıcı silme** yetkisine ihtiyacı yoktur.
""", komut="cat <<klasor>>/araclar.conf", sonra="""
**Hacker gözüyle:** Saldırganın hedefi model değil, **modelin elleridir**. Eller ne kadar zayıfsa,
model kandırılsa bile zarar o kadar küçük kalır.
"""),
    Adim("sed ile satır düzeltmek", """
Yapılandırmaları elle ya da `sed` ile düzeltebilirsin. `sed -i 's/eski/yeni/' dosya` her satırdaki ilk
eşleşmeyi değiştirir; başına bir adres koyarsan yalnızca o satırlarda çalışır:
`sed -i '/veri=ozel/ s/kapsam=tum/kapsam=musteri/' dosya`. Bir deneme yap: sadece yazdırır, dosyayı
değiştirmez.
""", komut="sed -n '/veri=ozel/p' <<klasor>>/araclar.conf", sonra="""
`-n` ile `p` birlikte yalnızca eşleşen satırları basar. Değiştirmeden önce **neyi değiştireceğini** görmek
iyi bir alışkanlıktır.
"""),
    Adim("Çıktı filtresi ve düzenli ifade", """
Çıktı filtresi, asistanın yanıtı müşteriye gitmeden önce bir **yasak desen** listesine bakar.
Desenler düzenli ifadedir (regex). Örnek sızıntılara ve zararsız yanıtlara bak:
""", komut="cat filtre_ornekleri/yasak_ornekler.txt filtre_ornekleri/temiz_ornekler.txt", sonra="""
İyi bir desen **dar** olmalı: sızıntıyı yakalar, zararsız yanıtlara dokunmaz. `[0-9]+` gibi geniş bir
desen telefon numaralarını ve sipariş numaralarını da engeller; müşteri hizmeti çalışmaz hâle gelir.
"""),
    Adim("İzleme: kayıt yoksa olay yoktur", """
Bir saldırıyı sonradan anlamanın tek yolu kayıttır. İzleme ayarı:
""", komut="cat <<klasor>>/izleme.conf", sonra="""
Girdi, çıktı ve **araç çağrıları** kaydedilmeli ve olay incelemesine yetecek kadar saklanmalı.
Kayıtlara parola, kart numarası gibi veriler **yazılmamasına** da dikkat et (Cilt 20'de göreceksin).
"""),
]

GOREVLER = [
    Gorev("'Prompt injection'ın tam bir çözümü yoktur.' Bu gerçek savunma stratejini nasıl değiştirir?",
          Secmeli([
              ("Kandırılmayı önlemeye değil, kandırılsa bile zararı sınırlamaya odaklanırım",
               "Doğru. Yetkiyi daraltmak, çıktıyı doğrulamak ve riskli eylemi insana onaylatmak hedeftir."),
              ("Model kandırılabildiği için yapay zekâyı iş süreçlerinde hiç kullanmamayı tek çare sayarım",
               "Yanlış. Risk yönetilebilir; yasaklamak yerine yetki sınırlanır ve izleme kurulur."),
              ("Sistem istemine daha çok ve daha kesin 'asla yapma' cümleleri yazarak sorunu kapatırım",
               "Yanlış. İstem de metindir ve geçersiz kılınabilir; tek başına bir güvenlik denetimi değildir."),
              ("Yalnızca girdiyi süzerim; girdi temizse çıktıya ve araçlara güvenmem gerekmez",
               "Yanlış. Girdi süzme kaçırılabilir; çıktı ve araç yetkisi de ayrıca sınırlanmalıdır."),
          ], dogru=0),
          ("Çözümü olmayan bir riskle nasıl yaşanır? Zararı sınırla.",
           "Cilt 6 ve 12'deki 'en az yetki' ilkesini düşün.",
           "Cevap: kandırılsa bile zarar veremesin."),
          puan=20, baslik="Strateji"),
    Gorev("<<klasor>>/sistem_istemi.txt içinde asistanın görmemesi gereken **üç sır** var (parola, anahtar, panel "
          "parolası). Sırları isteminden çıkar ama asistanın kurallarını silme. Sonra `cevap 2` yaz.",
          Durum(_sir_kontrol, "sed -i '/parolası:/d;/anahtarı:/d' sistem_istemi.txt"),
          ("Sırlar 'parola' ve 'anahtar' kelimeleriyle başlayan satırlarda.",
           "Satırları bir metin düzenleyiciyle ya da `sed -i '/desen/d' dosya` ile silebilirsin.",
           "`sed -i '/parolası:/d;/anahtarı:/d' <<klasor>>/sistem_istemi.txt` iki deseni birlikte siler."),
          puan=40, baslik="Sırları çıkar"),
    Gorev("<<klasor>>/araclar.conf içinde **özel veriye** uzanan ama kapsamı `tum` olan araçlar var. Hepsinin "
          "kapsamını `musteri` yap (herkese açık bilgi araçlarına dokunmana gerek yok). Sonra `cevap 3`.",
          Durum(_kapsam_kontrol, "sed -i '/veri=ozel/ s/kapsam=tum/kapsam=musteri/' araclar.conf"),
          ("Satırlardaki `veri=ozel` alanına ve `kapsam=` alanına bak.",
           "`sed -n '/veri=ozel/p' <<klasor>>/araclar.conf` ile önce hangilerinin etkileneceğini gör.",
           "`sed -i '/veri=ozel/ s/kapsam=tum/kapsam=musteri/' <<klasor>>/araclar.conf`"),
          puan=40, baslik="Kapsamı daralt"),
    Gorev("Aynı dosyada iki sorun daha var: `sil` yetkili bir araç ve onaysız çalışan **işlem** aracı. Silme aracını "
          "listeden kaldır, işlem aracını `onay=insan` yap (aracı silme, okuma araçlarına dokunma). Sonra `cevap 4`.",
          Durum(_onay_kontrol, "sed -i '/yetki=sil/d; /yetki=islem/ s/onay=yok/onay=insan/' araclar.conf"),
          ("İki ayrı düzeltme: biri satırı silmek, biri bir alanı değiştirmek.",
           "`yetki=sil` içeren satırı sil; `yetki=islem` içeren satırda `onay=yok` yerine `onay=insan` yaz.",
           "`sed -i '/yetki=sil/d; /yetki=islem/ s/onay=yok/onay=insan/' <<klasor>>/araclar.conf`"),
          puan=40, baslik="Onay ve silme"),
    Gorev("<<klasor>>/cikti_filtresi.conf kapalı ve desen listesi boş. Filtreyi aç ve `filtre_ornekleri/` içindeki "
          "**sızıntı örneklerini** yakalayan, **zararsız örnekleri** engellemeyen iki desen ekle "
          "(`desen=...` satırları, Python düzenli ifadesi). Sonra `cevap 5`.",
          Durum(_filtre_kontrol, "etkin=evet + desen=[A-Za-z]{2,3}-Ic-[0-9]{4}-[0-9a-f]{4} + desen=\\b[1-9][0-9]{10}\\b"),
          ("Önce iki sızıntı örneğine bak: biri anahtar biçimi, biri 11 haneli bir numara.",
           "Anahtar: harf-`Ic`-4 rakam-4 hex. Numara: 1-9 ile başlayan 11 hane. Zararsız satırlardaki telefon "
           "('0532 ...') ve 'SP-...' sipariş numarasını yakalamamaya dikkat.",
           "Satırlar: `desen=[A-Za-z]{2,3}-Ic-[0-9]{4}-[0-9a-f]{4}` ve `desen=\\b[1-9][0-9]{10}\\b`. `etkin=hayir` satırını `etkin=evet` yap."),
          puan=50, baslik="Çıktı filtresi"),
    Gorev("<<klasor>>/izleme.conf'ta hiçbir kayıt tutulmuyor. Girdi, çıktı ve araç çağrısı kaydını aç ve kayıtların en az "
          "90 gün saklanmasını sağla (`saklama_gun`). Sonra `cevap 6`.",
          Durum(_izleme_kontrol, "kayit_girdi=evet, kayit_cikti=evet, kayit_arac_cagrisi=evet, saklama_gun=180"),
          ("Dört satır var; üçü evet/hayır, biri gün sayısı.",
           "`hayir` olanları `evet` yap; `saklama_gun` değerini 90 ya da daha büyük bir sayı yap.",
           "`sed -i 's/=hayir/=evet/;s/^saklama_gun=.*/saklama_gun=180/' <<klasor>>/izleme.conf`"),
          puan=30, baslik="İzlemeyi aç"),
    Gorev("Asistanın para göndermesi gereken bir iş akışında, savunma ilkelerinden hangisi **geri alınamaz** zararı en "
          "doğrudan önler?",
          Secmeli([
              ("İşlemi asistan başlatır ama insan onaylamadan gerçekleşmez (maker-checker)",
               "Doğru. Model kandırılsa bile para, bir insan onayı olmadan çıkmaz."),
              ("Asistana işlem tutarını yüksek sesle tekrar ettirip müşteriden sohbette onay almak",
               "Yanlış. Sohbette alınan onay da enjekte edilebilir ya da taklit edilebilir; bağımsız bir insan denetimi gerekir."),
              ("Sistem istemine 'yalnızca yetkili işlem yap' cümlesini en başa eklemek",
               "Yanlış. İstem cümlesi bir denetim değildir; geçersiz kılınabilir."),
              ("İşlem sonrasında müşteriye e-posta atmak ve itiraz süresi tanımak",
               "Yanlış. Bu bir izleme adımıdır; zararı önlemez, sadece geç haber verir."),
          ], dogru=0),
          ("Cilt 10'daki 'dört göz' ilkesi burada da geçerli.",
           "Hangi seçenekte bağımsız ikinci bir kişi var?",
           "Cevap: insan onayı (maker-checker)."),
          puan=20, baslik="İnsan onayı"),
]


def _kapanis():
    return """
Bu sahnenin dersi: model kandırılabilir kabul edilir, güvenlik **çevresine** kurulur. Sırlar modelin
görmediği yerde durur, araçlar dar ve onaylı çalışır, çıktı bir süzgeçten geçer, her şey kaydedilir.
Saldırgan gözüyle bakınca: dört katmanın hepsi kırılırsa saldırı işe yarar; savunmanın amacı katmanları
çoğaltmak ve her katmanın bedelini artırmaktır. Finans gibi geri alınamaz işlerin olduğu yerde, insan onayı
hâlâ en güçlü fren.
"""


SEVIYE = Seviye(
    kimlik="c18b03", cilt=18, bolum=3, baslik="Savunma: Asistanı Güvenli Yapılandır",
    brifing="""
<<sahne>>

Selin: "Önceki iki incelemeden sonra müşteri soruyor: 'Peki düzeltmek için ne yapacağız?' Yapılandırma
kopyası <<klasor>> klasöründe. Sistem isteminde sır var, araçların yetkisi geniş, çıktı filtresi kapalı,
izleme kapalı. Hepsini senin elinle düzeltmeni istiyorum."

Mert: "Not düşeyim: 'asla paylaşma' diye yazmak kasa değildir, post-it'tir."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Yetkiyi sınırlama:** Yapay zekâ ajanlarına yönelik kamuya açık güvenlik rehberleri, aracın yetkisini daraltmayı
  (en az yetki), geri alınamaz eylemleri insan onayına bağlamayı ve modelin çıktısını girdi gibi doğrulamayı ortak
  öneri olarak sıralar. Prompt injection için bugün tam bir çözüm olmadığı da bu rehberlerde açıkça belirtilir.
- **Tespit:** Başarılı bir kötüye kullanım, araç çağrı kayıtlarında beklenmedik alıcılar, olağandışı sorgu hacmi ve
  çıktı filtresi tetiklemeleriyle görünür. Kayıt tutmayan bir asistanda olay sonradan incelenemez.
- **Önleme:** Anahtarları ve parolaları istemin dışında, araç katmanında tutmak; çıktıdan kimlik/anahtar kalıplarını
  süzmek; her araç için ayrı, dar bir izin tanımlamak.
""",
    sure_hedef_dk=35,
)
