"""Cilt 10 · Bölüm 6 — Bordro ve HR Sistemlerinin Güvenliği: Dosya Bütünlüğü.

Beceri: onaylanmış bir maaş dosyasının sonradan değiştirildiğini SHA-256 özetiyle kanıtlamak,
değişikliği (değiştirilmiş IBAN, "hayalet çalışan") İK sicili ve denetim izi (audit trail) ile
karşılaştırarak bulmak, finansal etkisini hesaplamak ve dosyayı onaylı hâline geri getirmek.

Vakalar: lojistik şirketi, hastane, belediye, e-ticaret şirketi. Her vakada klasör/dosya adları,
çalışanlar, IBAN'lar ve değiştirilen satırlar farklıdır. Bütün IBAN'lar kurgusaldır.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c10_finans import ortak as o

AYLAR = ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim", "Kasım", "Aralık"]

VAKALAR = {
    "kuzgun": {"ad": "Kuzgun Lojistik — depo ve şoför bordrosu", "musteri": "Kuzgun Lojistik", "klasor": "bordro",
               "kisi": "Serdar Bey (IT sorumlusu)", "deps": ["depo", "sevkiyat", "şoför", "muhasebe", "ofis"],
               "sahne": "Kuzgun Lojistik'in muhasebesi, maaş ödemesi öncesi toplam tutarın onay kaydıyla tutmadığını fark etti."},
    "medora": {"ad": "Medora Sağlık — hastane maaş ödemeleri", "musteri": "Medora Sağlık", "klasor": "maas_odemeleri",
               "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)", "deps": ["hemşirelik", "poliklinik", "laboratuvar", "idari", "temizlik"],
               "sahne": "Medora'nın İK müdürü, maaş dosyası bankaya gitmeden önce bir kontrol istedi çünkü dosyanın saati garip."},
    "yesiltepe": {"ad": "Yeşiltepe Belediyesi — personel maaşları", "musteri": "Yeşiltepe Belediyesi", "klasor": "personel_odeme",
                  "kisi": "Nurcan Hanım (bilgi işlem müdürü)", "deps": ["fen işleri", "zabıta", "yazı işleri", "park bahçeler", "mali hizmetler"],
                  "sahne": "Belediyenin mali hizmetler müdürü, bu ayki maaş listesinin sayısının bir fazla göründüğünü söylüyor."},
    "pazarix": {"ad": "Pazarix — İK ve maaş sistemi", "musteri": "Pazarix", "klasor": "ik_odeme",
                "kisi": "Tuncay Bey (sistem yöneticisi)", "deps": ["yazılım", "depo", "müşteri hizmetleri", "pazarlama", "finans"],
                "sahne": "Pazarix'in finans ekibi, maaş dosyasının onaydan sonra değiştirilmiş olabileceğinden şüpheleniyor."},
}
KULLANICILAR = ["ik.uzmani1", "ik.uzmani2", "bordro.uzmani", "muhasebe.sefi", "sistem.yoneticisi", "destek.uzmani"]


def _icerik(satirlar: list) -> str:
    return "sicil;ad_soyad;iban;net_kurus\n" + "".join(f"{a};{b};{c};{d}\n" for a, b, c, d in satirlar)


def uret(rng):
    kod = rng.choice(list(VAKALAR))
    v = VAKALAR[kod]
    n = rng.randint(14, 18)
    adlar = o.kisi_adlari(rng, n)
    sicil0 = rng.randint(1000, 4000)
    sicil_listesi = sorted(rng.sample(range(sicil0, sicil0 + 300), n))
    kayit = [(str(sc), ad, o.sahte_iban(rng), rng.randrange(1500000, 6500000, 50)) for sc, ad in zip(sicil_listesi, adlar)]
    # Onaylı dosya = bu liste. Sonradan: bir IBAN değişir, bir hayalet satır eklenir.
    degisen = rng.randrange(2, n - 2)
    hayalet_sicil = str(rng.randint(9000, 9899))
    hayalet = (hayalet_sicil, o.kisi_adlari(rng, 1)[0], o.sahte_iban(rng), rng.randrange(1500000, 5000000, 50))
    onayli = list(kayit)
    kirli = list(kayit)
    saldirgan_iban = o.sahte_iban(rng)
    kirli[degisen] = (kayit[degisen][0], kayit[degisen][1], saldirgan_iban, kayit[degisen][3])
    kirli.insert(rng.randrange(3, n - 1), hayalet)
    onayli_metin, kirli_metin = _icerik(onayli), _icerik(kirli)
    hash_onayli = hashlib.sha256(onayli_metin.encode("utf-8")).hexdigest()
    hash_kirli = hashlib.sha256(kirli_metin.encode("utf-8")).hexdigest()
    gun = u.gun(rng)
    ay, yil = gun.month, gun.year
    dosya = f"maas_{yil}_{ay:02d}.csv"
    onay_t = gun + timedelta(hours=17, minutes=rng.choice([0, 15, 30, 45]))
    saldirgan = rng.choice(KULLANICILAR[2:])
    hazirlayan = "bordro.uzmani"
    log = []
    t = onay_t - timedelta(days=rng.randint(3, 6), hours=rng.randint(0, 2))
    for _ in range(rng.randint(5, 7)):                  # onaydan önce meşru değişiklikler
        t += timedelta(hours=rng.randint(2, 20), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        if t >= onay_t - timedelta(minutes=30):
            t = onay_t - timedelta(minutes=rng.randint(31, 90))
        kul = rng.choice(["ik.uzmani1", "ik.uzmani2", "ik.muduru"])
        sc = rng.choice(sicil_listesi)
        islem = rng.choice(["ADRES_GUNCELLENDI", "DEPARTMAN_DEGISTI", "IBAN_DEGISTI", "IZIN_KAYDI"])
        log.append((t, f"{t:%Y-%m-%d %H:%M:%S} {kul} {islem} sicil={sc} onay=ik.muduru"))
    log.append((onay_t, f"{onay_t:%Y-%m-%d %H:%M:%S} ik.muduru BORDRO_ONAYLANDI donem={yil}-{ay:02d} dosya={dosya}"))
    ta = onay_t + timedelta(hours=1, minutes=rng.randint(5, 50), seconds=rng.randint(0, 59))
    log.append((ta, f"{ta:%Y-%m-%d %H:%M:%S} {saldirgan} IBAN_DEGISTI sicil={kayit[degisen][0]} onay=-"))
    ta2 = ta + timedelta(minutes=rng.randint(2, 9), seconds=rng.randint(0, 59))
    log.append((ta2, f"{ta2:%Y-%m-%d %H:%M:%S} {saldirgan} CALISAN_EKLENDI sicil={hayalet_sicil} onay=-"))
    log.sort(key=lambda x: x[0])
    hr = [(sc, ad, iban, rng.choice(v["deps"])) for sc, ad, iban, _ in kayit]
    toplam = sum(r[3] for r in onayli)
    s = {
        "vaka": v["ad"], "v": v, "kod": kod, "dosya": dosya, "onayli": onayli_metin, "kirli": kirli_metin,
        "hash_onayli": hash_onayli, "hash_kirli": hash_kirli, "hr": hr, "log": [x[1] for x in log],
        "onay_t": onay_t, "saldirgan": saldirgan, "hazirlayan": hazirlayan, "n": n, "toplam": toplam,
        "donem": f"{yil} {AYLAR[ay - 1]}",
        "metin": {"musteri": v["musteri"], "klasor": v["klasor"], "dosya": dosya, "kisi": v["kisi"], "sahne": v["sahne"],
                  "onay_zamani": f"{onay_t:%Y-%m-%d %H:%M:%S}", "onay_hash": hash_onayli},
        "cevaplar": {
            "sha8": hash_kirli[:8], "iban_sicil": kayit[degisen][0], "hayalet": hayalet_sicil, "kullanici": saldirgan,
            "risk": kayit[degisen][3] + hayalet[3],
        },
    }
    return s


def yaz(lab: Path, s: dict) -> None:
    k = s["v"]["klasor"]
    u.yaz(lab / k / s["dosya"], s["kirli"])
    u.yaz(lab / k / "ik_sicil.csv", "sicil;ad_soyad;iban;departman\n" + "".join(
        f"{a};{b};{c};{d}\n" for a, b, c, d in s["hr"]))
    u.yaz(lab / k / "degisiklik.log", "\n".join(s["log"]) + "\n")
    u.yaz(lab / k / "onay_kaydi.txt",
          f"BORDRO ONAY KAYDI — {s['v']['musteri']}\n"
          f"Dönem: {s['donem']}\n"
          f"Dosya: {k}/{s['dosya']}\n"
          f"Hazırlayan: {s['hazirlayan']}\n"
          f"Onaylayan: ik.muduru\n"
          f"Onay zamanı: {s['onay_t']:%Y-%m-%d %H:%M:%S}\n"
          f"Satır sayısı (başlık hariç): {s['n']}\n"
          f"Toplam net (kuruş): {s['toplam']}\n"
          f"SHA-256: {s['hash_onayli']}\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{s['v']['ad']}\n\n"
          f"{k}/{s['dosya']:<24} bankaya gönderilecek maaş dosyası\n"
          f"{k}/onay_kaydi.txt        onay sırasında alınan kayıt (özet dahil)\n"
          f"{k}/ik_sicil.csv          İK'nın ana kaydı (kaynak doğru bilgi)\n"
          f"{k}/degisiklik.log        maaş sisteminin denetim izi\n\n"
          "Selin'den not: Dosya bankaya gitmeden bütünlüğünü kanıtla.\n")


def _geri_yukle(b) -> Sonuc:
    s = b.senaryo
    yol = b.lab / s["v"]["klasor"] / s["dosya"]
    if not yol.exists():
        return Sonuc(False, f"`{s['v']['klasor']}/{s['dosya']}` dosyası yok; silmişsin. Dosyayı onaylı hâline getirmelisin.")
    veri = yol.read_bytes()
    if hashlib.sha256(veri).hexdigest() == s["hash_onayli"]:
        return Sonuc(True, "Dosyanın SHA-256 özeti onay kaydındakiyle birebir aynı: dosya onaylı hâline döndü.")
    satirlar = [l for l in veri.decode("utf-8", "replace").splitlines()[1:] if l.strip()]
    hr = {h[0]: h[2] for h in s["hr"]}
    ipucu = []
    for l in satirlar:
        p = l.split(";")
        if len(p) < 4:
            continue
        if p[0] not in hr:
            ipucu.append("İK sicilinde olmayan bir satır duruyor")
        elif hr[p[0]] != p[2]:
            ipucu.append("bir satırın IBAN'ı İK sicilindekiyle uyuşmuyor")
    if len(satirlar) != s["n"] and not ipucu:
        ipucu.append(f"satır sayısı {s['n']} olmalı, şu an {len(satirlar)}")
    if ipucu:
        return Sonuc(False, "Hâlâ onaylı dosya değil: " + "; ".join(sorted(set(ipucu))) + ".", yakin=True)
    return Sonuc(False, "İçerik doğru görünüyor ama özet tutmuyor: satır sırası, boşluk ya da sondaki satır sonu "
                        "farklı olabilir. Dosyanın onaydaki hâliyle BİREBİR aynı olması gerekir.", yakin=True)


def coz(lab: Path, s: dict) -> dict:
    k, d = s["v"]["klasor"], s["dosya"]
    sha8 = o.sh(f"sha256sum {k}/{d} | cut -c1-8", lab)
    karsi = f"awk -F';' 'NR==FNR{{h[$1]=$3; next}} FNR>1 && %s {{print $1}}' {k}/ik_sicil.csv {k}/{d}"
    iban_sicil = o.sh(karsi % "($1 in h) && h[$1]!=$3", lab)
    hayalet = o.sh(karsi % "!($1 in h)", lab)
    kullanici = o.sh(f"awk '$1\" \"$2 > \"{s['onay_t']:%Y-%m-%d %H:%M:%S}\"' {k}/degisiklik.log | cut -d' ' -f3 | sort -u", lab)
    risk = o.sh(f"awk -F';' -v a={iban_sicil} -v g={hayalet} 'NR>1 && ($1==a||$1==g){{s+=$4}} END{{print s}}' {k}/{d}", lab)
    o.sh(f"eski=$(grep '^{iban_sicil};' {k}/ik_sicil.csv | cut -d';' -f3); "
         f"sed -i '/^{hayalet};/d' {k}/{d}; "
         f"sed -i \"s|^\\({iban_sicil};[^;]*;\\)[^;]*|\\1$eski|\" {k}/{d}", lab)
    cozum = {1: sha8, 2: iban_sicil, 3: hayalet, 4: kullanici, 5: risk, 6: ""}
    return o.sec_doldur(cozum, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Onay kaydı: bütünlüğün mührü", """
Bordro dosyası onaylandığı anda bir **kayıt** alınır: kim hazırladı, kim onayladı, kaç satır, toplam
tutar ve en önemlisi dosyanın **SHA-256 özeti** (hash). Özet, dosyanın parmak izidir: tek bir karakter
değişse bambaşka bir özet çıkar. Onay kaydına bak:
""", komut="cat <<klasor>>/onay_kaydi.txt"),
    Adim("Şu anki özeti hesapla", """
`sha256sum` bir dosyanın özetini hesaplar. Bankaya gidecek dosyanın **şu anki** özetini al ve onay
kaydındakiyle karşılaştır:
""", komut="sha256sum <<klasor>>/<<dosya>>", sonra="""
İki özet **aynı olmalıydı**. Farklıysa dosya, onaydan sonra bir şekilde değişmiştir. Özet neyin
değiştiğini söylemez, yalnızca **değiştiğini** kanıtlar. Neyin değiştiğini bulmak için başka
kaynaklarla karşılaştırmak gerekir.
"""),
    Adim("Doğrulamayı otomatiğe bağla", """
`sha256sum -c` özeti bir dosyadaki beklenenle karşılaştırır ve `OK` ya da `FAILED` yazar. Beklenen
özeti standart girdiyle verelim (iki boşluk ve dosya adı biçimi önemli):
""", komut="echo \"<<onay_hash>>  <<klasor>>/<<dosya>>\" | sha256sum -c -", sonra="""
`FAILED` gördün. Finans sistemlerinde bu kontrol **ödeme gitmeden hemen önce** otomatik yapılmalı;
onay anında alınan özet, değişikliği aynı gün yakalar.
"""),
    Adim("İK ana kaydıyla karşılaştır", """
Maaş dosyasındaki IBAN'lar İK'nın ana kaydındakilerle **aynı olmalı**. `awk` iki dosyayı birlikte
okur: ilk dosyayı (`NR==FNR`) belleğe alır, ikincide karşılaştırır. Şu komut, dosyadaki her satır için
İK'daki IBAN ile uyuşmayanları ya da İK'da hiç olmayan sicilleri yazar:
""", komut="awk -F';' 'NR==FNR{h[$1]=$3; next} FNR>1 && h[$1]!=$3 {print $1, $2}' <<klasor>>/ik_sicil.csv <<klasor>>/<<dosya>>",
         sonra="""
İki sicil çıktı. İkisi de sorunlu ama **farklı nedenlerle**: biri İK'da var ama IBAN'ı değişmiş,
öteki İK'da hiç yok (**hayalet çalışan**). `($1 in h)` ile varlığı ayırabilirsin.

**Hacker gözüyle:** Bordro saldırısının en sessiz yolu, toplamı hiç değiştirmeden **bir IBAN'ı
değiştirmektir**: ödeme gider, kimse şikâyet etmez, ta ki asıl çalışan maaşının yatmadığını söyleyene
kadar. Hayalet çalışan ise toplamı değiştirir ama listeye "normal" görünür.
"""),
    Adim("Denetim izini zamana göre süz", """
`degisiklik.log` maaş sisteminin **denetim izi**: kim, ne zaman, neyi değiştirdi. Onay zamanından
**sonraki** satırlar şüphelidir. Tarih biçimi (`YYYY-AA-GG SS:DD:SS`) alfabetik karşılaştırmayla
zaman sırasını da verir:
""", komut="awk '$1\" \"$2 > \"<<onay_zamani>>\"' <<klasor>>/degisiklik.log", sonra="""
Onaydan sonra yapılan değişikliklerin `onay=-` olduğuna dikkat: **kimse onaylamamış**. Meşru
değişiklikler (`onay=ik.muduru`) ise onaydan önce yapılmıştı. Denetim izi olmasaydı bu iki
satırı kimin yaptığını bilemezdik.
"""),
]

GOREVLER = [
    Gorev("Bankaya gidecek `<<klasor>>/<<dosya>>` dosyasının **şu anki** SHA-256 özetinin ilk **8 karakteri** nedir?",
          Metin("sha8", bicim="8 karakter (0-9, a-f)"),
          ("Özeti hesaplayan komutu eğitimde kullandın.",
           "`sha256sum <<klasor>>/<<dosya>>` çıktısının başındaki uzun harf-rakam dizisine bak.",
           "`sha256sum <<klasor>>/<<dosya>> | cut -c1-8` ilk sekiz karakteri verir."),
          puan=20, baslik="Özet"),
    Gorev("Maaş dosyasında IBAN'ı **İK kaydındakiyle uyuşmayan** çalışanın sicil numarası nedir? (İK'da var olan biri)",
          Metin("iban_sicil", bicim="sicil numarası"),
          ("İK sicili doğru bilgidir; maaş dosyasındaki IBAN'larla karşılaştır.",
           "Eğitimdeki `awk` komutu iki sorunlu satır verir; birinin İK'da kaydı var, diğerinin yok.",
           "`awk -F';' 'NR==FNR{h[$1]=$3; next} FNR>1 && ($1 in h) && h[$1]!=$3 {print $1}' <<klasor>>/ik_sicil.csv <<klasor>>/<<dosya>>`"),
          puan=40, baslik="Değiştirilen IBAN"),
    Gorev("Maaş dosyasında **İK sicilinde hiç bulunmayan** (hayalet) çalışanın sicil numarası nedir?",
          Metin("hayalet", bicim="sicil numarası"),
          ("İK sicilinde karşılığı olmayan bir satır arıyorsun.",
           "Aynı `awk` karşılaştırmasında `($1 in h)` yerine `!($1 in h)` koşulunu kullan.",
           "`awk -F';' 'NR==FNR{h[$1]=$3; next} FNR>1 && !($1 in h) {print $1}' <<klasor>>/ik_sicil.csv <<klasor>>/<<dosya>>`"),
          puan=40, baslik="Hayalet çalışan"),
    Gorev("Onay zamanından (`<<onay_zamani>>`) **sonra** ve onaysız (`onay=-`) değişiklikleri yapan sistem kullanıcısı kim?",
          Metin("kullanici", bicim="kullanıcı adı"),
          ("Denetim izinde onay zamanından sonraki satırlara bak.",
           "Zaman damgası olan ilk iki alanı birleştirip onay zamanıyla karşılaştıran `awk` kalıbını eğitimde gördün.",
           "`awk '$1\" \"$2 > \"<<onay_zamani>>\"' <<klasor>>/degisiklik.log | cut -d' ' -f3 | sort -u`"),
          puan=40, baslik="Kim yaptı"),
    Gorev("Bu iki yetkisiz değişiklik yüzünden yanlış yere gidecek (saldırganın IBAN'ına ve hayalet çalışana yazılan) "
          "**toplam net maaş tutarı kaç kuruş**? (İki satırın `net_kurus` toplamı)",
          Sayi("risk", sik_hatalar=lambda g, b, bg: "Tek satırı mı topladın? İki satırın net tutarları toplanmalı: "
                "değiştirilen IBAN'lı satır ve hayalet satır." if g.isdigit() and 0 < int(g) < b else None),
          ("İki sorunlu satırın tutarları dördüncü sütunda.",
           "İki sicili (2. ve 3. görevlerin cevapları) seçip `net_kurus` değerlerini topla.",
           "`awk -F';' -v a=<sicil1> -v g=<sicil2> 'NR>1 && ($1==a||$1==g){s+=$4} END{print s}' <<klasor>>/<<dosya>>`"),
          puan=40, baslik="Etki: tutar"),
    Gorev("**Düzelt:** `<<klasor>>/<<dosya>>` dosyasını onaylı hâline getir: hayalet satırı sil, değiştirilen IBAN'ı "
          "İK sicilindeki doğru değere çevir. Dosyanın özeti onay kaydıyla birebir aynı olmalı. "
          "Bitince `cevap 6` yaz.",
          Durum(_geri_yukle, cozum="Hayalet satırı sil (`sed -i '/^<sicil>;/d' ...`), IBAN'ı İK sicilinden kopyalayıp yerine yaz; "
                "`echo \"<özet>  dosya\" | sha256sum -c -` komutu OK vermeli."),
          ("Dosya onaydan önce ne durumdaydı? İK sicili sana doğru IBAN'ı veriyor; hayalet satırı kaldırman gerekiyor.",
           "Bir editörle (`nano`) ya da `sed -i` ile iki değişikliği yap. Satır sırasına ve sondaki satır sonuna dokunma.",
           "`sed -i '/^<hayalet sicil>;/d' dosya` hayaleti siler; `nano` ile değiştirilen satırın IBAN'ını İK'dakiyle değiştir; "
           "sonra `sha256sum -c` doğrulamasını çalıştır."),
          puan=60, baslik="Düzelt: onaylı hâle döndür"),
    Gorev("Bu olayın **tekrarını** en etkili önleyen kontrol hangisidir?",
          Secmeli([
              ("Onayda dosya özetini kaydedip ödemeden önce yeniden hesaplamak, farklıysa durdurmak", "Doğru: bütünlük kontrolü, onaydan sonraki her değişikliği ödeme gitmeden yakalar. Yetki ayrımı ve denetim izi onu tamamlar."),
              ("Maaş dosyasının adını her ay değiştirip saldırganın dosyayı bulmasını zorlaştırmak", "Yanlış: gizlilik yoluyla güvenlik kalıcı çözüm değildir; sistem kullanıcıları dosyayı zaten bilir."),
              ("Dosyayı yalnızca mesai saatleri içinde açılabilir hâle getirmek ve diğer saatlerde kilitlemek", "Yanlış: değişiklik mesai içinde de yapılabilir; saat kısıtı değişikliği tespit ya da önlemez."),
              ("Toplam tutarı ödemeden önce iki farklı kişiye elle hesaplatmak ve karşılaştırmak", "Yanlış: toplam değişmeyebilir (yalnızca IBAN değişti) ve hayalet satır da toplamı gözle ayırt edilemeyecek kadar küçük etkiler."),
          ], dogru=0),
          ("Dosya onaylandıktan sonra değiştiğini hangi teknik, hangi tutarda olursa olsun yakalar?",
           "Bu bölümde başta kullandığın araç: parmak izi.",
           "Doğru şık, 'özeti kaydet, ödemeden önce yeniden hesapla' diyen şık."),
          puan=20, baslik="Önleme"),
    Gorev("Hayalet çalışan dolandırıcılığını yapısal olarak en çok zorlaştıran kontrol hangisidir?",
          Secmeli([
              ("Ekleyen ile onaylayanın ayrı olması ve İK sicilinin düzenli mutabakatı", "Doğru: yetki ayrımı tek kişinin hem ekleyip hem ödemeyi çıkarmasını engeller; sicil mutabakatı ise listedeki fazlalığı yakalar."),
              ("Bordro yazılımının arayüzüne daha güçlü bir tema ve daha okunaklı yazı tipi koymak", "Yanlış: arayüzün görünüşü hiçbir kontrol sağlamaz."),
              ("Maaşları banka kanalından çıkarıp yalnızca nakit olarak ve elden ödemeye geçmek", "Yanlış: izlenebilirliği tamamen kaldırır ve riski artırır."),
              ("Bordro dosyasına parola koymak ve parolayı yalnızca tek bir kişinin bilmesini sağlamak", "Yanlış: tek kişiye bağımlılık tam olarak 'tek nokta' sorunudur; parolayı bilen kişi içeriden saldırgan olabilir."),
          ], dogru=0),
          ("Bölüm 3'ten yetki ayrımı ilkesini hatırla: bir işlemi baştan sona tek kişi yapabilmeli mi?",
           "Ekleyen ile onaylayan aynı kişiyse kimin kontrol edeceği kalmaz.",
           "Doğru şık, 'ekleyen ile onaylayan ayrı' diyen şık."),
          puan=20, baslik="Hayalet çalışan önlemi"),
]


def _kapanis():
    return """
Bordro, "iş mantığı + hassas veri + para" üçlüsünün en yoğun olduğu yerdir ve en büyük risk çoğu zaman
içeridedir. Bu bölümde saldırı **hiçbir teknik açık gerektirmedi**: yetkili bir kullanıcı, onaydan sonra
bir dosyada iki satırı değiştirdi. Saldırgan için hedef toplamı hiç değiştirmeden tek bir IBAN'ı
yönlendirmek ya da "normal görünen" bir hayalet satır eklemektir. Savunmanın üç ayağı: **bütünlük**
(onay anında özet, ödemeden önce doğrulama), **yetki ayrımı** (hazırlayan ≠ onaylayan ≠ ödemeyi
serbest bırakan) ve **denetim izi** (kim, ne zaman, neyi değiştirdi, kim onayladı). Senin bordro
deneyimin burada tam bir avantaj: sürecin normal hâlini bilen kişi, sapmayı ilk görür.
"""


SEVIYE = Seviye(
    kimlik="c10b06",
    cilt=10,
    bolum=6,
    baslik="Bordro ve HR Sistemleri: Dosya Bütünlüğü",
    brifing="""
<<sahne>> <<musteri>>'nin bordro dosyası bankaya gönderilmeden önce son bir kontrolden geçecek. <<kisi>>
Selin'i arıyor ve "dosyaya bir göz atar mısınız?" diyor. Selin sana dönüyor: "Onay kaydında bir
**parmak izi** var. Dosya onaydan beri değişmiş mi, değiştiyse **neyi, kim, ne kadar para**
için? Sonra dosyayı onaylı hâline getir ve tekrarını önleyecek kontrolü anlat."

Mert ekliyor: "Burada exploit yok. Yetkili biri, yetkili olduğu yerde hile yapıyor. İçeriden tehdit
böyle görünür."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Maaş yönlendirme dolandırıcılığı:** ABD'de FBI'ın internet suç şikâyet merkezi (IC3) gibi
  kurumlar, saldırganların çalışan gibi davranıp maaş banka hesabını değiştirttiği "maaş
  yönlendirme" (payroll diversion) dolandırıcılığına karşı kamuya açık uyarılar yayımlamıştır.
  Pek çok iş e-postası ele geçirme (BEC) olayında da ödeme IBAN'ının son anda değiştirilmesi ana
  yöntemdir. Bu bölümdeki IBAN değişikliği deseni aynı mantığın dosya sürümüdür.
- **Tespit:** Onay anında alınan özet ile ödeme öncesi özetin karşılaştırılması, İK sicili ile
  maaş listesinin mutabakatı ve onaysız değişiklik içeren denetim izi satırları (örneğin
  `onay=-`) için alarm, bu tür olayları ödeme gitmeden yakalar.
- **Önleme:** Banka hesabı değişikliklerinde ek doğrulama ve çift onay (maker-checker), hazırlayan
  ile onaylayanın ayrı kişiler olması, maaş dosyasının salt okunur ve imzalı/özetli tutulması ve
  değişikliklerin değiştirilemez bir denetim iziyle kaydedilmesi.
""",
    sure_hedef_dk=30,
)
