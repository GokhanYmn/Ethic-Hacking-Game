"""Cilt 16 · Bölüm 3 — Savunma ve Yetkili Simülasyon.

Beceri: sosyal mühendisliğe karşı katmanlı savunmayı (teknik, süreçsel, insani) kurmak: bildirim sürecini doğru
sıraya koymak, MFA'sı olmayan sistemleri bulmak, farkındalık programı verisini okumak ve bir yetkili phishing
simülasyonu talebini etik kurallara göre değerlendirip DÜZELTMEK.

Vakalar: Ferah Bank, Paramix, Kuzgun Lojistik, Yeşiltepe Belediyesi, Medora Sağlık. Bu seviye YALNIZCA kavramsaldır:
simülasyon e-postası, şablonu, sayfası ya da aracı yazılmaz; yalnızca talep formlarının etik uygunluğu ele alınır.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c16_sosyal.ortak import Sira, sec_doldur, sh, vaka_sec

SURECLER = [  # (sıralı adım, ayırt edici anahtar)
    ("Mesajdaki bağlantıya tıklama, ek dosyayı açma: dur ve incele", "dur ve incele"),
    ("Gönderen alan adı, Reply-To ve bağlantının gerçek hedefi gibi ipuçlarına bak", "ipuçlarına bak"),
    ("Mesajı 'phishing bildir' düğmesiyle ya da güvenlik kutusuna ilet", "güvenlik kutusuna"),
    ("SOC mesajı inceler ve aynı mesajı tüm posta kutularında arar", "tüm posta kutularında"),
    ("Doğrulanırsa gönderen alan adı ve bağlantı engellenir, mesaj kutulardan silinir", "alan adı ve bağlantı engellenir"),
    ("Bildirene teşekkür edilir ve sonuç bilgisi verilir", "teşekkür"),
]
SISTEMLER = ["e-posta", "vpn", "muhasebe-paneli", "ik-portali", "odeme-paneli", "uzak-masaustu"]
BIRIMLER = ["muhasebe", "satis", "ik", "lojistik", "pazarlama", "hukuk", "operasyon", "destek"]
IHLALLER = ["onay", "icerik", "kimlik", "sonuc"]


def _talep_metni(no, birim, onay, icerik, kimlik, sonuc):
    return (f"TALEP_NO: {no}\nBIRIM: {birim}\nYAZILI_ONAY: {onay}\nICERIK: {icerik}\n"
            f"KIMLIK_BILGISI_TOPLANIR: {kimlik}\nSONUC_KULLANIMI: {sonuc}\n")


def uret(rng):
    v = vaka_sec(rng)
    # --- simülasyon talepleri: 2 uygun, 2 uygunsuz
    uygun_idx = set(rng.sample(range(4), 2))
    birimler = rng.sample(BIRIMLER, 4)
    talepler, uygunlar, uygunsuzlar = [], [], []
    for i in range(4):
        no = i + 1
        if i in uygun_idx:
            talepler.append((no, birimler[i], "var", "zararsiz", "hayir", "egitim"))
            uygunlar.append(no)
        else:
            ihlal = set(rng.sample(IHLALLER, rng.choice([1, 2, 3])))
            talepler.append((no, birimler[i], "yok" if "onay" in ihlal else "var",
                             "zararli_ek" if "icerik" in ihlal else "zararsiz",
                             "evet" if "kimlik" in ihlal else "hayir",
                             "bireysel_disiplin" if "sonuc" in ihlal else "egitim"))
            uygunsuzlar.append(no)
    hedef = min(uygunsuzlar)
    # --- farkındalık planı: en yüksek tıklama ORANI, en yüksek tıklama SAYISINDAN farklı bölümde
    while True:
        dept = rng.sample(BIRIMLER, 6)
        satirlar = []
        for d in dept:
            cal = rng.randint(30, 140)
            satirlar.append((d, cal, rng.randint(2, max(3, cal // 3)), rng.randint(0, cal // 6)))
        oran = sorted(((t / c, d) for d, c, t, _ in satirlar), reverse=True)
        sayi = sorted(((t, d) for d, c, t, _ in satirlar), reverse=True)
        if oran[0][0] - oran[1][0] >= 0.04 and oran[0][1] != sayi[0][1] and sayi[0][0] > sayi[1][0]:
            break
    en_yuksek = oran[0][1]
    # --- önlemler
    mfasiz = rng.sample(SISTEMLER, rng.choice([2, 3]))
    sistemler = list(SISTEMLER)
    rng.shuffle(sistemler)
    # --- bildirim süreci (karışık)
    sira = list(range(6))
    rng.shuffle(sira)       # ekranda i. satırda gösterilen adım numarası (0 tabanlı)
    dogru_sira = [sira.index(k) + 1 for k in range(6)]
    return {
        "vaka": f"{v['ad']} — farkındalık programı ve simülasyon planı",
        "v": v, "talepler": talepler, "hedef": hedef, "plan": satirlar, "mfasiz": mfasiz, "sistemler": sistemler,
        "sira": sira,
        "metin": {"musteri": v["ad"], "birim": v["birim"], "hikaye": v["hikaye"], "hedef": str(hedef),
                  "hedef_birim": talepler[hedef - 1][1]},
        "cevaplar": {"sira": dogru_sira, "uygun": uygunlar, "en_yuksek": en_yuksek, "mfasiz": mfasiz},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} farkındalık ve simülasyon dosyası (politika/). KURGUSAL. Bu dosyalarda e-posta şablonu YOKTUR;\n"
          "yalnızca talep formları, plan ve süreç bilgisi var. Selin: 'Simülasyon yazmıyoruz, yönetiyoruz.'\n")
    satirlar = [f"{k + 1}) {SURECLER[k][0]}" for k in s["sira"]]
    # ekranda i. satırda hangi adım gösteriliyor: sira[i]
    u.yaz(lab / "politika" / "bildirim_sureci.txt",
          "Şüpheli mesaj bildirim süreci — adımlar KARIŞIK sırada. Doğru sıraya diz.\n\n" +
          "\n".join(f"{i}) {SURECLER[k][0]}" for i, k in enumerate(s["sira"], 1)) + "\n")
    u.yaz(lab / "politika" / "etik_kurallari.txt",
          "Yetkili phishing simülasyonu etik kuralları\n"
          "  1. Yazılı yönetim onayı olmadan simülasyon yapılmaz (YAZILI_ONAY: var).\n"
          "  2. İçerik zararsız olur; gerçek zararlı ek ya da bağlantı kullanılmaz (ICERIK: zararsiz).\n"
          "  3. Gerçek kimlik bilgisi (parola, kod) toplanmaz (KIMLIK_BILGISI_TOPLANIR: hayir).\n"
          "  4. Sonuç eğitim içindir; çalışanı küçük düşürmek ya da cezalandırmak için kullanılmaz (SONUC_KULLANIMI: egitim).\n")
    for no, birim, onay, icerik, kimlik, sonuc in s["talepler"]:
        u.yaz(lab / "politika" / "talepler" / f"talep_{no}.txt", _talep_metni(no, birim, onay, icerik, kimlik, sonuc))
    u.yaz(lab / "politika" / "farkindalik_plani.csv",
          "departman,calisan,tiklayan,bildiren\n" + "".join(f"{d},{c},{t},{b}\n" for d, c, t, b in s["plan"]))
    u.yaz(lab / "politika" / "onlemler.txt",
          "# sistem | MFA durumu   (teknik savunma envanteri)\n" +
          "".join(f"{x} | {'MFA yok' if x in s['mfasiz'] else 'MFA var'}\n" for x in s["sistemler"]))


def coz(lab: Path, s: dict) -> dict:
    sira = []
    for _, kw in SURECLER:
        sira.append(sh(f"grep -m1 '{kw}' politika/bildirim_sureci.txt | cut -d')' -f1", lab))
    uygun = sh("grep -l 'YAZILI_ONAY: var' politika/talepler/*.txt | xargs grep -l 'ICERIK: zararsiz' | "
               "xargs grep -l 'KIMLIK_BILGISI_TOPLANIR: hayir' | xargs grep -l 'SONUC_KULLANIMI: egitim' | "
               "grep -o '[0-9]' | tr '\\n' ' '", lab)
    en = sh("awk -F, 'NR>1 {printf \"%.3f %s\\n\", $3/$2, $1}' politika/farkindalik_plani.csv | sort -rn | head -1 | cut -d' ' -f2", lab)
    mfasiz = sh("grep 'MFA yok' politika/onlemler.txt | cut -d' ' -f1 | tr '\\n' ' '", lab)
    h = s["hedef"]
    sh(f"sed -i 's/^YAZILI_ONAY:.*/YAZILI_ONAY: var/; s/^ICERIK:.*/ICERIK: zararsiz/; "
       f"s/^KIMLIK_BILGISI_TOPLANIR:.*/KIMLIK_BILGISI_TOPLANIR: hayir/; "
       f"s/^SONUC_KULLANIMI:.*/SONUC_KULLANIMI: egitim/' politika/talepler/talep_{h}.txt", lab)
    return sec_doldur({1: " ".join(sira), 2: uygun, 4: en, 5: mfasiz}, GOREVLER, lab, s)


def _talep_oku(yol: Path) -> dict:
    d = {}
    for satir in yol.read_text(encoding="utf-8").splitlines():
        if ":" in satir:
            k, _, v = satir.partition(":")
            d[k.strip().upper()] = v.strip().lower()
    return d


def _talep_duzelt(b) -> Sonuc:
    h = b.senaryo["hedef"]
    yol = b.lab / "politika" / "talepler" / f"talep_{h}.txt"
    try:
        d = _talep_oku(yol)
    except OSError:
        return Sonuc(False, f"talep_{h}.txt okunamadı; dosyayı silme, düzelt.")
    if d.get("TALEP_NO") != str(h) or "BIRIM" not in d:
        return Sonuc(False, "`TALEP_NO` ve `BIRIM` satırlarına dokunma.")
    eksik = []
    if d.get("YAZILI_ONAY") != "var":
        eksik.append("yazılı yönetim onayı yok")
    if d.get("ICERIK") != "zararsiz":
        eksik.append("içerik zararsız değil")
    if d.get("KIMLIK_BILGISI_TOPLANIR") != "hayir":
        eksik.append("gerçek kimlik bilgisi toplanıyor")
    if d.get("SONUC_KULLANIMI") != "egitim":
        eksik.append("sonuç eğitim dışında kullanılıyor")
    if eksik:
        return Sonuc(False, "Hâlâ kurala aykırı: " + "; ".join(eksik) + ".", yakin=len(eksik) < 4)
    return Sonuc(True)


def _sira_hata(verilen, beklenen, b):
    if sorted(verilen) == sorted(beklenen) and verilen[0] != beklenen[0]:
        return "İlk adım yanlış: önce **durup incelemek** gelir, bildirmek ondan sonradır."
    return None


ADIMLAR = [
    Adim("Üç katmanlı savunma", """
Sosyal mühendisliğe karşı savunma **katmanlıdır** ve hiçbir katman tek başına yetmez:

- **Teknik:** spam/phishing filtreleri, MFA (çalınan parola tek başına yetmesin).
- **Süreçsel:** hassas işlemler için doğrulama adımları (Cilt 10'daki maker-checker, yani iki kişi onayı).
- **İnsani:** düzenli farkındalık eğitimi ve bildirme kültürü.

Önce müşterinin dosyalarına bak:
""", komut="ls -R politika"),
    Adim("Bildirim süreci", """
En değerli insani savunma, çalışanın şüpheli mesajı **bildirmesidir**. Bunun için net bir süreç gerekir. Sürecin adımları
dosyada karışık sırada durur:
""", komut="cat politika/bildirim_sureci.txt", sonra="""
Doğru sıra mantığa dayanır: önce dur ve incele, sonra ipuçlarına bak, sonra bildir; SOC incelemeyi yapar, doğrulanırsa engeller
uygulanır, en son bildirene geri bildirim verilir. Geri bildirim önemlidir: bildirenin emeği görülmezse bildirme kültürü ölür.
"""),
    Adim("Teknik katman: MFA envanteri", """
MFA (çok faktörlü kimlik doğrulama) olmayan her sistem, çalınan bir parolayla doğrudan girilebilir demektir. Envanter dosyasına bak:
""", komut="cat politika/onlemler.txt"),
    Adim("Süzme: MFA'sı olmayanlar", """
`grep` ile sorunlu satırları süz, `cut` ile yalnızca sistem adını al:
""", komut="grep 'MFA yok' politika/onlemler.txt | cut -d' ' -f1"),
    Adim("Yetkili phishing simülasyonunun etik kuralları", """
Kurumlar çalışanlarını test etmek için **yetkili** phishing simülasyonları düzenler. Bu konuda yalnızca kavramı ve etik çerçeveyi
öğreniyoruz; **simülasyon içeriği hazırlamıyoruz**. Kurallar:
""", komut="cat politika/etik_kurallari.txt", sonra="""
Etik sınır, bu kitaptaki en keskin sınırdır: teknik bir açığı kendi lab'ında denersin, ama sosyal mühendislik **gerçek insanların
güvenini ve duygularını** kullanır. Bu yüzden yalnızca yazılı izinle ve insanları koruyan kurallarla yapılır. Simülasyon bir
ceza değil, bir **eğitim aracıdır**.
"""),
    Adim("Talep formlarını değerlendirmek", """
Simülasyon yapmak isteyen her birim bir talep formu doldurur. Dört form var; her biri kısa bir anahtar-değer listesi:
""", komut="cat politika/talepler/*.txt"),
    Adim("Programın verisi: tıklama oranı", """
Farkındalık planında her bölümün çalışan, tıklayan ve bildiren sayısı var. **Sayı** ile **oran** farklı şeylerdir: büyük bir
bölümde çok kişi tıklayabilir ama oran düşük olabilir. `awk` ile oranı hesapla ve sırala:
""", komut="awk -F, 'NR>1 {printf \"%.3f %s\\n\", $3/$2, $1}' politika/farkindalik_plani.csv | sort -rn",
         sonra="""
**Hacker gözüyle:** Programın amacı kimin tıkladığını **suçlamak** değil; en çok desteğe ihtiyacı olan bölümü bulup eğitimi oraya
yönlendirmektir. Programın gerçek başarı ölçütü zamanla **bildirme oranının artması** ve tıklamanın azalmasıdır.
"""),
]

GOREVLER = [
    Gorev("`politika/bildirim_sureci.txt` içindeki **altı adımı doğru sıraya** diz. Cevap: ekrandaki numaraları sırayla yaz "
          "(örn. `3 1 5 2 6 4`).",
          Sira("sira", sik_hatalar=_sira_hata),
          ("Süreç mantıklı bir akış: önce kendin ne yaparsın, sonra kime bildirirsin, sonra kurum ne yapar, en son ne olur?",
           "Doğru akış: dur ve incele → ipuçlarına bak → bildir → SOC incelesin → engelle → bildirene geri bildirim.",
           "Her adımın başındaki numarayı yukarıdaki sıraya göre yaz; ilk adım 'dur ve incele'."),
          puan=35, baslik="Bildirim süreci"),
    Gorev("`politika/talepler/` içindeki dört yetkili simülasyon talebinden **dört etik kuralın dördüne de uyanların** numaralarını yaz "
          "(virgülle ayır). Kurallar: `politika/etik_kurallari.txt`.",
          Kume("uygun", tur="sayi", bicim="talep numaraları, virgülle ayrılmış"),
          ("Her talepte dört satır kuralları temsil ediyor: onay, içerik, kimlik bilgisi, sonuç kullanımı.",
           "Kurallara uygun değerler: `YAZILI_ONAY: var`, `ICERIK: zararsiz`, `KIMLIK_BILGISI_TOPLANIR: hayir`, `SONUC_KULLANIMI: egitim`.",
           "`grep -l 'YAZILI_ONAY: var' politika/talepler/*.txt` ile başla; sonuçları diğer üç kuralla da süz (ya da dosyaları tek tek oku)."),
          puan=35, baslik="Uygun talepler"),
    Gorev("`politika/talepler/talep_<<hedef>>.txt` (<<hedef_birim>> birimi) etik kurallara **uymuyor**. Dosyayı düzelt: dört kuralın "
          "dördü de sağlansın. `TALEP_NO` ve `BIRIM` satırlarına dokunma. Bitince `cevap 3` yaz.",
          Durum(_talep_duzelt, "YAZILI_ONAY: var, ICERIK: zararsiz, KIMLIK_BILGISI_TOPLANIR: hayir, SONUC_KULLANIMI: egitim"),
          ("Dosyada hangi satırlar kurallara aykırı? `etik_kurallari.txt` ile karşılaştır.",
           "`nano politika/talepler/talep_<<hedef>>.txt` ile aykırı satırların değerini düzelt; satır biçimi `ANAHTAR: değer`.",
           "`sed -i 's/^YAZILI_ONAY:.*/YAZILI_ONAY: var/; s/^ICERIK:.*/ICERIK: zararsiz/; s/^KIMLIK_BILGISI_TOPLANIR:.*/KIMLIK_BILGISI_TOPLANIR: hayir/; s/^SONUC_KULLANIMI:.*/SONUC_KULLANIMI: egitim/' politika/talepler/talep_<<hedef>>.txt`"),
          puan=45, baslik="Talebi düzelt"),
    Gorev("`politika/farkindalik_plani.csv` içinde **tıklama oranı** (tıklayan / çalışan) en yüksek olan departman hangisi?",
          Metin("en_yuksek", bicim="departman adı"),
          ("Oran = tıklayan ÷ çalışan. En çok tıklayan departman ile en yüksek oranlı olan aynı olmayabilir.",
           "Her satır için 3. sütunu 2. sütuna böl: `awk -F, 'NR>1 {print $3/$2, $1}' politika/farkindalik_plani.csv`.",
           "`... | sort -rn | head -1` ile en yüksek oranı al; departman adı ikinci sütundur."),
          puan=35, baslik="En yüksek tıklama oranı"),
    Gorev("`politika/onlemler.txt` içinde **MFA'sı olmayan** sistemleri yaz (virgülle ayır).",
          Kume("mfasiz", bicim="sistem adları, virgülle ayrılmış"),
          ("Her satırda sistem adı ve MFA durumu var.",
           "`grep 'MFA yok' politika/onlemler.txt`",
           "`grep 'MFA yok' politika/onlemler.txt | cut -d' ' -f1` yalnızca sistem adlarını verir."),
          puan=30, baslik="MFA'sız sistemler"),
    Gorev("MFA, çalınmış bir **parolayı** neden işe yaramaz hâle getirir?",
          Secmeli([
              ("Parolayı bilse bile ikinci faktöre sahip olmadığı için saldırgan giriş yapamaz",
               "Doğru. İkinci faktör, parolanın tek başına yeterli olmasını engeller."),
              ("MFA parolaları otomatik olarak değiştirir ve eski parolayı hemen geçersiz hâle getirir",
               "Yanlış. MFA parolayı değiştirmez; ek bir kanıt ister."),
              ("MFA, parolanın tahmin edilmesini ve çalınmasını matematiksel olarak imkânsız hâle getirir",
               "Yanlış. MFA parola zayıflığını gidermez; çalınmış ya da tahmin edilmiş parolanın tek başına işe yaramamasını sağlar."),
              ("MFA, kullanıcıların hiç phishing mesajı almasını ve kötü bağlantıya tıklamasını engeller",
               "Yanlış. MFA mesaj gelmesini engellemez; çalınan parolanın kullanımını sınırlar."),
          ], dogru=0),
          ("Giriş için iki farklı kanıt isteniyorsa, birini çalan saldırgan ne eksik kalır?",
           "'Bildiğin şey' (parola) ile 'sahip olduğun şey' (telefon) arasındaki farkı düşün.",
           "Doğru şık, ikinci faktör olmadan girişin mümkün olmadığını söyleyen şık."),
          puan=25, baslik="MFA neden önemli"),
    Gorev("Bir phishing simülasyonunun sonuçlarını kurum **nasıl kullanmalıdır**?",
          Secmeli([
              ("Eğitim için kullanmalı; kimseyi küçük düşürmeden, gelişimi destekleyerek",
               "Doğru. Simülasyon bir ceza değil, eğitim aracıdır."),
              ("Tıklayan çalışanların adlarını herkese açık bir listede örnek olarak yayımlamak",
               "Yanlış. Teşhir, bildirme kültürünü öldürür; insanlar hata yapınca saklanmaya başlar."),
              ("Tıklayan çalışanlara otomatik olarak disiplin cezası vermek ve özlük dosyasına işlemek",
               "Yanlış. Ceza, çalışanı bildirmekten caydırır ve simülasyonun amacını bozar."),
              ("Sonuçları yönetimde saklayıp çalışanlara hiç göstermemek ve geri bildirim vermemek",
               "Yanlış. Geri bildirim olmadan öğrenme gerçekleşmez."),
          ], dogru=0),
          ("Programın amacı 'yakalamak' mı, 'öğretmek' mi?",
           "Etik kuralların dördüncü maddesini hatırla.",
           "Doğru şık, eğitimi ve küçük düşürmemeyi söyleyen şık."),
          puan=25, baslik="Sonuçlar nasıl kullanılır"),
    Gorev("Bir farkındalık programının **gerçek başarı ölçütü** hangisidir?",
          Secmeli([
              ("Şüpheli mesajı bildirme oranının zamanla artması (tıklamanın azalması)",
               "Doğru. Bildirme kültürü, hem saldırının erken fark edilmesini hem de çalışanın kendine güvenini gösterir."),
              ("Yalnızca bir kez yapılan çevrimiçi sınavın geçme oranının yüksek çıkması",
               "Yanlış. Tek seferlik ölçüm davranış değişikliğini göstermez; program süreklilik ister."),
              ("Eğitimin toplamda kaç saat sürdüğü ve kaç kişiye ders verildiği (katılım süresi)",
               "Yanlış. Süre bir girdi göstergesidir; davranışın değişip değişmediğini söylemez."),
              ("Hiçbir çalışanın hiçbir zaman hiçbir mesaja tıklamamış olması (sıfır tıklama)",
               "Yanlış. Sıfır tıklama gerçekçi bir hedef değildir; insan davranışı tümden ortadan kaldırılamaz, azaltılır."),
          ], dogru=0),
          ("Çalışan şüpheli mesajı görünce ne yapmalı? Bunu artırmak mı önemli, azaltmak mı?",
           "İnsan davranışı bir yazılım gibi güncellenemez; hedef nedir?",
           "Doğru şık, bildirme oranının artmasını söyleyen şık."),
          puan=25, baslik="Başarı ölçütü"),
]

SEVIYE = Seviye(
    kimlik="c16b03",
    cilt=16,
    bolum=3,
    baslik="Savunma ve Yetkili Simülasyon",
    brifing="""
**<<musteri>>** yönetimi kararını verdi: "Bir farkındalık programı kuruyoruz." <<hikaye>> Selin sana politika klasörünü bıraktı:
bildirim süreci, MFA envanteri, çeşitli birimlerden gelen dört 'phishing simülasyonu' talebi ve geçen dönemin farkındalık verisi.

Selin: "Biz simülasyon **yazmıyoruz**; yönetiyoruz. Hangi talep etik kurallara uyuyor, hangisi uymuyor, uymayanı nasıl
düzeltiriz?" Mert: "Etik kuralları bilmeyen bir güvenlikçi tehlikelidir." Deniz: "Ben bildirim sürecinin doğru sırada işlediğine
bakarım; çalışan bildirince gerçekten bir şey olmalı."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Sosyal mühendisliğe karşı savunma üç katmanlıdır: teknik (filtre, MFA), süreçsel (doğrulama, iki kişi onayı) ve insani (eğitim ve
bildirme kültürü). Saldırgan açısından en zayıf katman çoğu zaman insani olandır; savunmacı açısından o katman en çok yatırım
getirendir. Yetkili simülasyonlar yazılı onay, zararsız içerik, kimlik bilgisi toplamama ve eğitim amacı ilkeleriyle yapılır; bu
sınırları bilmek bir etik hacker'ı tanımlayan şeydir: gücünü insanları korumak için kullanır.
""",
    gercek_hayat="""
- **MFA ve sosyal mühendislik:** Uber 2022 olayında bir çalışan, MFA onay istekleri ve BT'den arıyormuş gibi davranan biri
  tarafından kandırılarak onay verdi. Bu, MFA'nın tek başına yetmediğini, yöntemine (bildirim onayı yerine sayı eşleştirme ya da
  donanım anahtarı gibi daha dirençli yöntemlere) ve çalışan eğitimine bağlı olduğunu gösterir.
- **Önleme:** Katmanlı savunma: posta filtreleri, MFA, hassas işlemler için ikinci onay, düzenli farkındalık eğitimi ve
  bildirme düğmesi. **Tespit:** SOC'un bildirilen mesajları tüm kutularda araması, olağandışı MFA onay isteği yoğunluğunu ve
  alışılmadık konumdan girişleri izlemesi.
- **Simülasyon etiği:** Yetkili phishing simülasyonları yazılı yönetim onayı, zararsız içerik ve kimlik bilgisi toplamama
  koşullarıyla yapılır ve sonuçlar çalışanı cezalandırmak için değil eğitmek için kullanılır; yaygın güvenlik rehberleri de bu
  yaklaşımı önerir.
""",
    sure_hedef_dk=30,
)
