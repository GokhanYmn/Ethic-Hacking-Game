"""Cilt 17 · Bölüm 1 — Neden ve Nasıl Güvenle Analiz Edilir?

Beceri: izole analiz ortamının kurallarını bilmek; lab'daki ZARARSIZ örnek dosyaların sha256 özetini hesaplayıp
kurgusal bir tehdit istihbaratı listesiyle karşılaştırmak; "listede yok = temiz" yanılgısını görmek.

Vakalar: Ferah Bank, Kuzgun Lojistik, Medora Sağlık, Paramix. Lab'daki "örnekler" yalnızca "ZARARSIZ EGITIM ORNEGI"
yazan düz metin dosyalarıdır; gerçek zararlı, EICAR dizgisi ya da çalıştırılabilir içerik yoktur. Tehdit istihbaratı
listesindeki aile adları kurguseldır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c17_zararli.ortak import KURGUSAL_AILELER, hex_, sec_doldur, sh, sha256, vaka_sec


def uret(rng):
    v = vaka_sec(rng)
    adlar = rng.sample(v["dosyalar"], 6)
    icerik = {a: (f"ZARARSIZ EGITIM ORNEGI\nKalkan Guvenlik analiz laboratuvari\n"
                  f"ornek-no: {hex_(rng, 8)}\nrastgele: {hex_(rng, 32)}\n") for a in adlar}
    hashler = {a: sha256(icerik[a].encode("utf-8")) for a in adlar}
    m = rng.choice([2, 3])
    eslesen = rng.sample(adlar, m)
    etiketler = dict(zip(eslesen, rng.sample(KURGUSAL_AILELER, m)))
    yok = [a for a in adlar if a not in eslesen]
    kayitlar = [(hashler[a], etiketler[a]) for a in eslesen]
    for _ in range(5):
        kayitlar.append((hex_(rng, 64), rng.choice(KURGUSAL_AILELER)))
    yakin = hashler[rng.choice(yok)]      # bir karakteri farklı, yani eşleşmeyen "yakın" kayıt
    degisik = yakin[:-1] + ("0" if yakin[-1] != "0" else "1")
    kayitlar.append((degisik, rng.choice(KURGUSAL_AILELER)))
    rng.shuffle(kayitlar)
    tarihler = [f"2026-{rng.randint(1, 3):02d}-{rng.randint(1, 28):02d}" for _ in kayitlar]
    hedef = rng.choice(adlar)
    etiket_dosya = rng.choice(eslesen)
    return {
        "vaka": f"{v['ad']} — şüpheli dosyaların özet (hash) karşılaştırması",
        "v": v, "adlar": adlar, "icerik": icerik, "kayitlar": kayitlar, "tarihler": tarihler,
        "metin": {"musteri": v["ad"], "pc": v["pc"], "hikaye": v["hikaye"], "hedef": hedef,
                  "etiket_dosya": etiket_dosya},
        "cevaplar": {"hash": hashler[hedef], "eslesen": sorted(eslesen), "etiket": etiketler[etiket_dosya],
                     "yok_sayisi": len(yok)},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['pc']} bilgisayarından toplanan 6 dosya. HEPSİ ZARARSIZ EĞİTİM ÖRNEĞİDİR (düz metin).\n"
          "Selin'den not: gerçek analizde bu dosyalar izole bir VM'de dururdu. Burada yalnızca hash hesaplayacaksın, hiçbir dosyayı çalıştırmayacaksın.\n")
    for a in s["adlar"]:
        u.yaz(lab / "ornekler" / a, s["icerik"][a])
    u.yaz(lab / "istihbarat" / "bilinen_hashler.txt",
          "# sha256 | etiket | ilk_gorulme   (KURGUSAL tehdit istihbaratı listesi; aile adları kurgusaldır)\n" +
          "".join(f"{h} | {e} | {t}\n" for (h, e), t in zip(s["kayitlar"], s["tarihler"])))
    u.yaz(lab / "analiz_ortami_kurallari.txt",
          "Güvenli analiz ortamının kuralları\n"
          "  1. İnternetten yalıtım   : zararlı dışarıya yayılmasın, komuta sunucusuna ulaşmasın\n"
          "  2. Ayrı VM + snapshot    : analizden sonra temiz duruma dönülür\n"
          "  3. Ana sistemle paylaşım yok : bulaşma ana makineye geçmesin\n")


def coz(lab: Path, s: dict) -> dict:
    hedef = s["metin"]["hedef"]
    e = s["metin"]["etiket_dosya"]
    h = sh(f"sha256sum ornekler/{hedef} | cut -d' ' -f1", lab)
    eslesen = sh("sha256sum ornekler/* | while read h f; do grep -q \"$h\" istihbarat/bilinen_hashler.txt "
                 "&& basename $f; done | tr '\\n' ' '", lab)
    etiket = sh(f"grep \"$(sha256sum ornekler/{e} | cut -d' ' -f1)\" istihbarat/bilinen_hashler.txt | cut -d'|' -f2 | tr -d ' '", lab)
    yok = sh("sha256sum ornekler/* | awk '{print $1}' | while read h; do grep -q \"$h\" istihbarat/bilinen_hashler.txt "
             "|| echo $h; done | wc -l", lab)
    return sec_doldur({2: h, 3: eslesen, 4: etiket, 5: yok}, GOREVLER, lab, s)


def _hash_hata(g, beklenen, b):
    if beklenen in g.replace(" ", ""):
        return "Doğru hash, ama yalnızca 64 karakterlik özeti yaz; dosya adını yazma."
    if len(g) == 64:
        return "64 karakter ama yanlış dosyanın hash'i olabilir; soruda hangi dosya olduğuna bak."
    return None


def _kume_hata(g, beklenen, b):
    if "/" in g:
        return "Sadece dosya adlarını yaz (`ornekler/` klasör adı olmadan)."
    return None


def _yok_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == 6 - beklenen:
        return "Bu, listeyle **eşleşen** örneklerin sayısı. Soru eşleşmeyenleri soruyor."
    return None


ADIMLAR = [
    Adim("Düşmanı tanı, ama güvenle", """
Zararlı yazılım analizi, bir olay müdahalesinde (Cilt 7) "bu dosya ne yaptı?" sorusunu cevaplar: ne yaptığını (hangi veriyi
çaldı, nereye bağlandı), nasıl tespit edileceğini ve nasıl temizleneceğini. Ama zararlı canlı bir tehdittir; yanlışlıkla
çalıştırıp yaymak felaket olur. Bu yüzden analiz **izole bir ortamda** yapılır. Kuralları oku:
""", komut="cat analiz_ortami_kurallari.txt", sonra="""
Bu cilt zararlı yazılım **yazmayı öğretmez**. Lab'daki "örnekler" yalnızca "ZARARSIZ EGITIM ORNEGI" yazan metin dosyalarıdır:
bunları çalıştırmayacak, sadece inceleyeceğiz. Gerçek hayatta bu kurallar mutlaktır: ayrı VM, internet yok, snapshot, paylaşım yok.
"""),
    Adim("Elimizde ne var?", """
Müşterinin bilgisayarından toplanan altı dosya `ornekler/` klasöründe. İsimleri birbirine benziyor ama içerikleri farklı:
""", komut="ls -l ornekler"),
    Adim("Hash: dosyanın parmak izi", """
`sha256sum`, bir dosyanın **sha256 özetini** (hash) hesaplar: 64 karakterlik, içeriğe bağlı bir parmak izi. İçerik bir bayt
değişse hash tamamen değişir; dosyanın adı değişse hash değişmez. Bu yüzden zararlıları adlarıyla değil hash'leriyle tanırız.
""", komut="sha256sum ornekler/*"),
    Adim("Çığ etkisi", """
Girdi bir harf değişince hash nasıl tamamen değişiyor, gör:
""", komut="echo kalkan | sha256sum && echo kalkaN | sha256sum"),
    Adim("Tehdit istihbaratı listesi", """
Güvenlik şirketleri ve kurumlar, bilinen zararlıların hash'lerini listeler. Lab'da kurgusal bir liste var (aile adları da kurgusal):
""", komut="cat istihbarat/bilinen_hashler.txt"),
    Adim("Eşleştirmek: grep -F -f", """
Önce kendi örneklerinin hash'lerini bir dosyaya yaz; sonra `grep -F -f` ile listede **hangilerinin geçtiğini** bul. `-F` metni olduğu
gibi (düzenli ifade olmadan), `-f` kalıpları dosyadan okur:
""", komut="sha256sum ornekler/* | awk '{print $1}' > benim_hashlerim.txt && grep -F -f benim_hashlerim.txt istihbarat/bilinen_hashler.txt",
         sonra="""
Listede görünen satırlar **bilinen** zararlılardır: etiketi (ailesi) de oradan okursun. Dikkat: listedeki bir hash örneklerinden
birine **neredeyse** benzese de (bir karakter farkla) eşleşmez; hash'te "neredeyse aynı" diye bir şey yoktur.

**Hacker gözüyle:** Saldırgan zararlısını her yeni kampanyada küçük bir değişiklikle yeniden derler ve hash'i değişir. Bu yüzden
hash eşleşmesi hızlıdır ama yalnızca **bilineni** yakalar (sonraki bölümlerde davranışa bakacağız).
"""),
]

GOREVLER = [
    Gorev("Zararlı yazılım analizi için **en güvenli ortam** hangisidir?",
          Secmeli([
              ("Ayrı bir VM: internetten yalıtılmış (Host-Only), snapshot'lı, paylaşım yok",
               "Doğru. Yalıtım, yayılmayı ve komuta sunucusuyla iletişimi engeller; snapshot temiz sıfırlama sağlar."),
              ("Kendi iş bilgisayarın, ama internet bağlantısı açık ki güncellemeleri alsın",
               "Yanlış. İnternet açıksa zararlı komuta sunucusuna ulaşabilir; ana sistem de risktedir."),
              ("Ayrı bir VM, ama dosya aktarmak kolay olsun diye paylaşılan klasörle ana bilgisayara bağlı",
               "Yanlış. Paylaşılan klasör, bulaşmanın ana sisteme geçme yoludur."),
              ("Şirket ağındaki ortak bir sunucu; antivirüs açık olduğu sürece sorun olmaz",
               "Yanlış. Antivirüs yalnızca bilineni yakalar; canlı ağ ve ortak sunucu analiz için uygun değildir."),
          ], dogru=0),
          ("Üç kural: dışarıyla bağlantı, temiz sıfırlama, ana sistem.",
           "İnternetten yalıtım, ayrı VM + snapshot ve paylaşım yok: bu üçünü birlikte sağlayan şık hangisi?",
           "Doğru şık 'Host-Only, snapshot, paylaşım yok' bileşimini anlatan şık."),
          puan=25, baslik="Güvenli ortam"),
    Gorev("`ornekler/<<hedef>>` dosyasının **sha256 özetini** (64 karakter) yaz.",
          Metin("hash", bicim="64 karakterlik sha256", sik_hatalar=_hash_hata),
          ("Dosyaların parmak izini hesaplayan komut `sha256sum`.",
           "`sha256sum ornekler/<<hedef>>` çıktıda önce hash, sonra dosya adı verir.",
           "`sha256sum ornekler/<<hedef>> | cut -d' ' -f1` yalnızca hash'i verir."),
          puan=30, baslik="Hash hesapla"),
    Gorev("`ornekler/` içindeki hangi dosyalar `istihbarat/bilinen_hashler.txt` listesindeki hash'lerle **eşleşiyor**? "
          "Dosya adlarını yaz (virgülle ayır).",
          Kume("eslesen", bicim="dosya adları, virgülle ayrılmış", sik_hatalar=_kume_hata),
          ("Önce her dosyanın hash'ini çıkar, sonra listede ara.",
           "`sha256sum ornekler/* | awk '{print $1}' > benim_hashlerim.txt`, sonra `grep -F -f benim_hashlerim.txt istihbarat/bilinen_hashler.txt`: eşleşen hash'ler.",
           "Her eşleşen hash'in hangi dosyaya ait olduğunu `sha256sum ornekler/*` çıktısından oku; bir hash'e neredeyse benzeyen satır eşleşmez."),
          puan=40, baslik="Bilinenleri bul"),
    Gorev("`ornekler/<<etiket_dosya>>` listede bulunuyor. Kurgusal tehdit istihbaratı listesi bu dosyayı **hangi etiketle** (aile adıyla) "
          "kaydetmiş?",
          Metin("etiket", bicim="etiket (örn. Ad.X)"),
          ("Önce bu dosyanın hash'ini hesapla.",
           "Hash'i listede ara: `grep <hash> istihbarat/bilinen_hashler.txt`.",
           "Satırdaki ikinci sütun (`|` ile ayrılan) etikettir."),
          puan=30, baslik="Etiket"),
    Gorev("`ornekler/` içindeki dosyalardan **kaçı listede yok**?",
          Sayi("yok_sayisi", sik_hatalar=_yok_hata),
          ("Toplam 6 dosya var; kaçı eşleşti, kaçı eşleşmedi?",
           "Eşleşenleri bir önceki görevde buldun; kalanı say.",
           "Eşleşmeyenleri doğrudan görmek için: her hash için `grep -q hash liste || echo hash`."),
          puan=25, baslik="Listede olmayanlar"),
    Gorev("Bir örnek **listede çıkmadı**. Bu, dosyanın **temiz** olduğu anlamına gelir mi?",
          Secmeli([
              ("Hayır: yalnızca bilinmiyor demektir; yeni ya da değiştirilmiş olabilir",
               "Doğru. Hash listesi yalnızca bilinenleri tanır; 'listede yok' ≠ 'temiz'."),
              ("Evet: bilinen listede yer almayan her dosya güvenlidir ve temiz kabul edilebilir",
               "Yanlış. Yeni çıkan ya da bir bayt değiştirilmiş zararlılar da listede olmaz."),
              ("Evet, ama yalnızca dosya adı sıradan ve zararsız görünüyorsa temiz kabul edilir",
               "Yanlış. Dosya adı güvenlik kanıtı değildir; saldırganlar adları kolayca taklit eder."),
              ("Hayır: listede olmayan her dosya kesin olarak zararlıdır ve hemen silinmelidir",
               "Yanlış. Listede olmamak zararlı olduğunu da kanıtlamaz; yalnızca bilinmediğini gösterir."),
          ], dogru=0),
          ("Listenin kapsamı neye bağlı: bilinen mi, bilinmeyen mi?",
           "Saldırgan zararlısını her kampanyada yeniden derlerse hash'e ne olur?",
           "Doğru şık 'bilinmiyor, ek analiz gerekir' diyen şık."),
          puan=30, baslik="Listede yok = temiz mi?"),
    Gorev("Bir zararlının **dosya adı değiştirilmiş** ama içeriği aynı. Hash eşleşmesi onu yine yakalar mı?",
          Secmeli([
              ("Evet: hash dosya içeriğinden hesaplanır, adından değil",
               "Doğru. Ad değişse de içerik aynıysa hash aynıdır."),
              ("Hayır: hash dosya adından hesaplandığı için ad değişince farklı çıkar",
               "Yanlış. Hash içeriğe bağlıdır; dosya adı hesaba girmez."),
              ("Evet, ama yalnızca dosya uzantısı da aynıysa",
               "Yanlış. Uzantı da hash'e girmez; yalnızca içerik önemlidir."),
              ("Hayır: ad değişiklikleri antivirüsü şaşırtır ama hash'i değil, bu yüzden eşleşmez",
               "Yanlış. Hash eşleşir; sorun hash'in adla ilgisi olmamasıdır."),
          ], dogru=0),
          ("Hash neyin üzerinden hesaplanıyor: ad mı, bayt dizisi mi?",
           "Aynı içeriğe iki farklı ad ver; `sha256sum` çıktıları nasıl olur?",
           "Doğru şık, hash'in içerikten hesaplandığını söyleyen şık."),
          puan=25, baslik="Ad değişirse"),
]

SEVIYE = Seviye(
    kimlik="c17b01",
    cilt=17,
    bolum=1,
    baslik="Güvenle Analiz ve Hash",
    brifing="""
**<<musteri>>** olay müdahale ekibi, **<<pc>>** bilgisayarından altı şüpheli dosya topladı. <<hikaye>>

Deniz: "Dosyaları açmayacağız. Önce hepsinin **parmak izini** (hash) çıkarıp bilinen listelerle karşılaştırıyoruz. Bir eşleşme
bize yarım saat kazandırır." Selin ekliyor: "Burada her şey ZARARSIZ eğitim örneği ve analiz izole varsayılıyor; ama alışkanlık
şimdiden oturmalı: şüpheli dosyayı **asla** çift tıklamayız." Mert: "Hash eşleşmedi diye rahatlama. Listede olmamak temiz demek değil."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Zararlı analizinin ilk kuralı güvenliktir: yalıtılmış VM, internet yok, snapshot, paylaşım yok. İlk teknik adım ise hash'tir:
dosyanın parmak izi, onu çalıştırmadan bilinen listelerle karşılaştırmanı sağlar. Saldırgan açısından ise hash'i değiştirmek
çok kolaydır (küçük bir değişiklik yeter); bu yüzden hash eşleşmesi hızlı ama sınırlı bir kontroldür. Savunma dersi: hash
listesini kullan, ama "listede yok"u "temiz" sayma; davranışa ve diğer göstergelere de bak.
""",
    gercek_hayat="""
- **Hash ile tanıma:** Olay müdahalesinde şüpheli dosyaların sha256 özetini çıkarıp VirusTotal gibi herkese açık tehdit
  istihbaratı servislerinde aramak yaygın bir ilk adımdır; çoğu kurum bilinen hash'leri kendi güvenlik araçlarına da ekler.
  Dosyanın kendisini değil yalnızca hash'ini aramak, hassas bir dosyanın dışarı yüklenmesini önler.
- **Önleme / tespit:** Antivirüs ve EDR araçları da bilinen hash'leri engeller; yeni varyantlar için davranış tabanlı tespit
  gerekir (Bölüm 3). Analiz için yalıtılmış VM (Cilt 9 ilkeleri), anlık görüntüden temiz sıfırlama ve ağ yalıtımı zorunludur.
""",
    sure_hedef_dk=25,
)
