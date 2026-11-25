"""Cilt 19 · Bölüm 1 — Açık Bankacılık Ekosistemi.

Beceri: ekosistemin rollerini (müşteri, banka, ödeme hizmeti sağlayıcı/fintech, düzenleyici) eşlemek,
rıza kayıtlarını (kime, ne kadar süreyle, hangi kapsamda) okumak, süresi geçmiş rızaları ayıklamak,
rızası olmayan bir erişimi erişim kayıtlarında yakalamak ve zayıf halkayı bulmak.

Vakalar: üç farklı banka ve her birinin fintech ortakları. Bütün kurumlar ve kişiler kurgusaldır.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c19_acik_bankacilik.ortak import sec_doldur, sh

VAKALAR = [
    {"vaka": "Ferah Bank ve fintech ortakları", "banka": "Ferah Bank", "alan": "ferahbank.lab",
     "fintech": ["Paramix", "Butcem", "Hesapkolay", "Kredim"], "kisi": "Kaan Bey (bilgi güvenliği müdürü)",
     "klasor": "ekosistem", "riza": "rizalar.csv", "erisim": "erisim.log", "notlar": "fintech_notlari.csv",
     "sahne": "Ferah Bank, dört fintech ortağına müşteri izniyle API erişimi açtı. Kaan Bey: \"Açık bankacılık "
              "denetimi geliyor. Kim kime, hangi izinle erişiyor, bilmem gerek; elimizde sadece dışa aktarılmış "
              "kayıtlar var.\""},
    {"vaka": "Yıldız Bank ve ödeme hizmeti sağlayıcıları", "banka": "Yıldız Bank", "alan": "yildizbank.lab",
     "fintech": ["Cuzdanix", "Taksitim", "Faturam", "Nakitix"], "kisi": "Defne Hanım (API ürün sahibi)",
     "klasor": "acik_bankacilik", "riza": "izinler.csv", "erisim": "api_erisim.log", "notlar": "ortak_degerlendirme.csv",
     "sahne": "Yıldız Bank'ın API ürün sahibi Defne Hanım arıyor: \"Üçüncü taraf ortaklarımız hakkında yıllık gözden "
              "geçirme yapıyoruz. İzin kayıtları, erişim günlüğü ve ortak değerlendirmeleri önünüzde; "
              "tutarsızlık var mı bakın.\""},
    {"vaka": "Kuzgun Katılım ve ortak uygulamalar", "banka": "Kuzgun Katılım", "alan": "kuzgunkatilim.lab",
     "fintech": ["Kuzgunpay", "Sepetpay", "Odemeci", "Bilancom"], "kisi": "Serdar Bey (entegrasyon sorumlusu)",
     "klasor": "katilim_api", "riza": "onaylar.csv", "erisim": "gecit_erisim.log", "notlar": "firma_karnesi.csv",
     "sahne": "Kuzgun Katılım'da yeni bir müşteri şikâyeti geldi: \"Hiç izin vermediğim bir uygulama hesabıma "
              "bakmış.\" Serdar Bey: \"Önce izin kayıtlarıyla erişim günlüğünü yan yana koyalım, emin olalım.\""},
]
KAPSAMLAR = ["hesap_oku", "bakiye_oku", "odeme_baslat"]


def uret(rng):
    v = rng.choice(VAKALAR)
    gun = u.gun(rng)
    bugun = gun.date()
    F = v["fintech"][:]
    rng.shuffle(F)
    C = u.isimler(rng, 6)
    pf = rng.choice(F)               # hedef müşterinin ödeme izni verdiği fintech
    W = F[1]                          # MFA'sı olmayan zayıf halka
    fo1, fo2, fo3 = F[2], F[3], F[0]
    fx = rng.choice([f for f in F if f not in (pf, W)])   # C[0] ile hiç rıza kaydı olmayan fintech

    def gelecek():
        return bugun + timedelta(days=rng.randint(30, 300))

    def gecmis():
        return bugun - timedelta(days=rng.randint(5, 90))

    satirlar = [
        [C[0], pf, "odeme_baslat", gelecek(), "aktif"],
        [C[1], W, "hesap_oku", gelecek(), "aktif"], [C[1], W, "bakiye_oku", gelecek(), "aktif"],
        [C[2], W, "hesap_oku", gelecek(), "aktif"], [C[3], W, "bakiye_oku", gelecek(), "aktif"],
        [C[4], fo1, "hesap_oku", gelecek(), "aktif"],
        [C[5], fo2, "odeme_baslat", gelecek(), "aktif"],
        [C[5], W, "hesap_oku", gecmis(), "aktif"],           # süresi geçmiş ama hâlâ 'aktif' görünen
        [C[0], W, "hesap_oku", gelecek(), "iptal"],
        [C[4], fo1, "bakiye_oku", gecmis(), "aktif"],         # süresi geçmiş ama hâlâ 'aktif' görünen
        [C[3], fo3, "hesap_oku", gelecek(), "iptal"],
    ]
    rng.shuffle(satirlar)
    # erişim günlüğü: geçerli izinlere uyanlar + bir rızasız erişim (fx -> C[0])
    erisimler = []
    t = gun + timedelta(hours=8)
    for m, f, k, b, d in satirlar:
        if d == "aktif" and b >= bugun:
            for _ in range(rng.randint(1, 2)):
                t += timedelta(minutes=rng.randint(3, 40), seconds=rng.randint(0, 59))
                erisimler.append((t, f, m, k))
    t += timedelta(minutes=rng.randint(3, 40))
    erisimler.append((t, fx, C[0], "bakiye_oku"))
    erisimler.sort()
    gecerli = [r for r in satirlar if r[4] == "aktif" and r[3] >= bugun]
    W_musteri = {r[0] for r in gecerli if r[1] == W}
    return {
        "vaka": v["vaka"], "v": v, "gun": gun, "bugun": bugun.isoformat(), "satirlar": satirlar, "erisimler": erisimler,
        "C": C, "W": W, "hedef": C[0], "pf": pf, "fx": fx,
        "metin": {"banka": v["banka"], "sahne": v["sahne"], "kisi": v["kisi"], "klasor": v["klasor"],
                  "riza": v["riza"], "erisim": v["erisim"], "notlar": v["notlar"], "bugun": bugun.isoformat(),
                  "hedef": C[0], "alan": v["alan"]},
        "cevaplar": {
            "odeme_fintech": pf,
            "gecerli_sayi": len(gecerli),
            "rizasiz": fx,
            "mfa_yok": W,
            "w_musteri": len(W_musteri),
        },
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = lab / v["klasor"]
    u.yaz(lab / "OKUBENI.txt", f"{v['banka']} açık bankacılık denetim kopyası (kurgusal).\nBugünün tarihi: {s['bugun']}\n"
          f"{v['klasor']}/ : katılımcılar, rıza kayıtları, erişim günlüğü, fintech notları\n")
    u.yaz(k / "katilimcilar.txt",
          f"BANKA (hesap sağlayıcı): {v['banka']} — hesap verisini ve ödeme işlemini API ile açar\n"
          + "".join(f"ÜÇÜNCÜ TARAF (fintech): {f} — müşteri adına bankaya erişen uygulama\n" for f in v["fintech"])
          + "DÜZENLEYİCİ: çerçeveyi ve güvenlik standardını belirleyen kurum (kayıtlarda adı yok)\n"
          + "MÜŞTERİ: verinin sahibi, rızayı veren — " + ", ".join(s["C"]) + "\n")
    u.yaz(k / v["riza"], "riza_no,musteri,fintech,kapsam,bitis,durum\n" + "".join(
        f"R{i:03d},{m},{f},{kp},{b.isoformat()},{d}\n" for i, (m, f, kp, b, d) in enumerate(s["satirlar"], 1)))
    u.yaz(k / v["erisim"], "".join(f"{t:%Y-%m-%d %H:%M:%S} fintech={f} musteri={m} kapsam={kp} sonuc=200\n"
                                    for t, f, m, kp in s["erisimler"]))
    u.yaz(k / v["notlar"], "fintech,mfa,son_pentest\n" + "".join(
        f"{f},{'yok' if f == s['W'] else 'var'},{2025 + (i % 2)}-{(i * 3) % 12 + 1:02d}\n" for i, f in enumerate(v["fintech"])))


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    r, e, n = f"{v['klasor']}/{v['riza']}", f"{v['klasor']}/{v['erisim']}", f"{v['klasor']}/{v['notlar']}"
    odeme = sh(f"awk -F, '$2==\"{s['hedef']}\" && $4==\"odeme_baslat\" {{print $3}}' {r}", lab)
    sayi = sh(f"awk -F, -v b={s['bugun']} '$6==\"aktif\" && $5>=b' {r} | wc -l", lab)
    rizasiz = sh(f"comm -23 <(awk '{{print $3,$4}}' {e} | sort -u) "
                 f"<(awk -F, 'NR>1{{print \"fintech=\"$3, \"musteri=\"$2}}' {r} | sort -u) | cut -d' ' -f1 | cut -d= -f2", lab)
    mfa = sh(f"awk -F, '$2==\"yok\" {{print $1}}' {n}", lab)
    wm = sh(f"awk -F, -v b={s['bugun']} -v f={mfa} '$3==f && $6==\"aktif\" && $5>=b {{print $2}}' {r} | sort -u | wc -l", lab)
    return sec_doldur({2: odeme, 3: sayi, 4: rizasiz, 5: mfa, 6: wm}, GOREVLER, lab, s)


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return ("Fazla saymışsın. `durum` sütunu `aktif` olsa bile **bitiş tarihi bugünden önceyse** rıza artık geçerli "
                "değildir. Bugünün tarihi OKUBENI.txt'de.")
    return None


def _w_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return ("Bir fazlan var: süresi geçmiş ya da aynı müşteriyi iki satırda saymış olabilirsin. Geçerli rızası olan "
                "**benzersiz** müşterileri say (`sort -u`).")
    if n > beklenen + 1:
        return "İptal edilmiş, süresi geçmiş ve tekrar eden satırları ayıkla; benzersiz müşteri sayısı lazım."
    return None


ADIMLAR = [
    Adim("Kim kimdir?", """
Açık bankacılığı anlamak için önce **kimin kiminle konuştuğunu** bilmek gerekir. Katılımcı listesini oku:
""", komut="cat <<klasor>>/katilimcilar.txt", sonra="""
Dört rol var: **müşteri** (verinin sahibi, rızayı veren), **banka** (hesap sağlayıcı, API'yi açan),
**üçüncü taraf/fintech** (müşteri adına bankaya erişen uygulama) ve **düzenleyici** (çerçeveyi
belirleyen). Eskiden "banka ve saldırgan" vardı; şimdi araya bankanın tam kontrol etmediği uygulamalar girdi.
"""),
    Adim("Rıza kayıtları", """
Açık bankacılığın kalbi **rızadır** (consent): müşteri, hangi fintech'in verisine **ne kadar süreyle**
ve **hangi kapsamda** erişebileceğine izin verir. Rıza kayıtlarının başlığına ve ilk satırlarına bak:
""", komut="head -5 <<klasor>>/<<riza>>", sonra="""
Her satır bir izin: kim (`musteri`), kime (`fintech`), neye (`kapsam`: hesap_oku, bakiye_oku, odeme_baslat),
ne zamana kadar (`bitis`) ve durumu (`durum`).
"""),
    Adim("awk ile sütun süzmek", """
`awk -F, '...'` virgülle ayrılmış dosyada sütunlarla çalışır: `$2` ikinci sütun, `$4` dördüncü.
Koşul yazarsan yalnızca o satırlar çıkar. Ödeme başlatma izinlerini listele:
""", komut="awk -F, '$4==\"odeme_baslat\"' <<klasor>>/<<riza>>", sonra="""
**Hacker gözüyle:** `odeme_baslat` kapsamı, bir fintech'in müşteri adına **para hareketi** başlatabilmesi
demektir; en kıymetli kapsam. Denetimde ilk bakılacak satırlar bunlardır.
"""),
    Adim("Tarih geçmiş rıza hâlâ rıza mı?", """
Bir rızanın `durum` sütunu `aktif` olsa bile `bitis` tarihi geçmişse rıza **artık geçerli değildir**.
Tarihler `YYYY-AA-GG` biçiminde olduğundan awk'ta metin olarak karşılaştırılabilir: `$5>=bugun` bugünden
sonrasını seçer. Bugünün tarihi OKUBENI'de yazıyor (<<bugun>>):
""", komut="awk -F, '$6==\"aktif\" && $5>=\"<<bugun>>\"' <<klasor>>/<<riza>>", sonra="""
Sistem tarafı da bu temizliği yapmalıdır. Süresi geçmiş rızayla erişime izin veren bir banka, müşterinin
iznini aşmış olur.
"""),
    Adim("Erişim günlüğü", """
Rıza kağıt üzerindeki izindir; **erişim günlüğü** gerçekte olanı söyler. Her API çağrısı kimin, kimin
verisine, hangi kapsamda eriştiğini yazar:
""", komut="head -5 <<klasor>>/<<erisim>>", sonra="""
Denetimin temel sorusu şudur: **Günlükteki her erişimin arkasında bir rıza var mı?** Yoksa ya kayıt eksiktir ya
da bir fintech yetkisinin ötesine geçmiştir.
"""),
    Adim("İki listeyi karşılaştırmak: comm", """
`sort -u` tekrarları atıp sıralar, `comm -23 A B` ise yalnızca **A'da olup B'de olmayan** satırları verir.
Bu, iki kaynağı karşılaştırmanın en hızlı yolu. Küçük bir deneme: günlükte kaç farklı fintech görünüyor?
""", komut="awk '{print $3}' <<klasor>>/<<erisim>> | sort -u", sonra="""
Aynı yöntemle "günlükteki (fintech, müşteri) çiftleri" ile "rıza dosyasındaki çiftleri" karşılaştırıp,
**rızası olmayan** çifti bulabilirsin. Bunu görevde yapacaksın.
"""),
]

GOREVLER = [
    Gorev("Açık bankacılıkta **müşteri adına bankaya erişen uygulama** hangi roldedir?",
          Secmeli([
              ("Fintech (ödeme hizmeti sağlayıcı)", "Doğru. Müşteri adına, müşterinin rızasıyla bankaya erişir."),
              ("Hesap sağlayıcı olan banka, yani API'yi açan taraf", "Yanlış. Banka, API'yi açan ve veriyi tutan taraftır; erişen değil."),
              ("Çerçeveyi belirleyen düzenleyici kurumun kendisi", "Yanlış. Düzenleyici çerçeveyi ve standardı belirler; müşteri adına erişmez."),
              ("Rızayı veren ve verinin sahibi olan müşteri", "Yanlış. Müşteri rızayı veren taraftır; uygulama onun adına hareket eder."),
          ], dogru=0),
          ("Katılımcı listesindeki 'müşteri adına' ifadesini ara.",
           "Rızayı veren müşteri, API'yi açan banka, aradaki uygulama: aradaki hangisi?",
           "Cevap: üçüncü taraf / fintech."),
          puan=20, baslik="Roller"),
    Gorev("**<<hedef>>** adlı müşteri hangi fintech'e **ödeme başlatma** (`odeme_baslat`) izni vermiş? "
          "(`<<klasor>>/<<riza>>`)",
          Metin("odeme_fintech", bicim="fintech adı"),
          ("Rıza dosyasında müşteri adı ve kapsam sütunlarını birlikte süz.",
           "`awk -F,` ile `$2` (müşteri) ve `$4` (kapsam) koşullarını birlikte yaz.",
           "`awk -F, '$2==\"<<hedef>>\" && $4==\"odeme_baslat\"' <<klasor>>/<<riza>>` ve fintech sütununa ($3) bak."),
          puan=30, baslik="Ödeme izni"),
    Gorev("Bugün (<<bugun>>) itibarıyla **geçerli** rıza sayısı kaç? (`durum=aktif` **ve** bitiş tarihi bugünden önce "
          "değil)",
          Sayi("gecerli_sayi", sik_hatalar=_sayi_hata),
          ("Sadece durum sütununa bakmak yetmez; bitiş tarihi de önemli.",
           "`awk` ile `$6==\"aktif\"` ve `$5>=\"<<bugun>>\"` koşullarını `&&` ile birleştir.",
           "`awk -F, '$6==\"aktif\" && $5>=\"<<bugun>>\"' <<klasor>>/<<riza>> | wc -l` (başlık satırı koşulu sağlamaz)."),
          puan=40, baslik="Geçerli rıza"),
    Gorev("Erişim günlüğünde (`<<klasor>>/<<erisim>>`) görünen ama rıza dosyasında **hiçbir kaydı olmayan** bir "
          "(fintech, müşteri) çifti var. Bu müşterinin verisine rızasız erişen fintech hangisi?",
          Metin("rizasiz", bicim="fintech adı"),
          ("Günlükteki çiftleri ve rıza dosyasındaki çiftleri ayrı ayrı çıkarıp karşılaştır.",
           "Günlük: `awk '{print $3,$4}' ... | sort -u`; rıza: `awk -F, 'NR>1{print \"fintech=\"$3, \"musteri=\"$2}' ... | sort -u`. Sonra `comm -23`.",
           "`comm -23 <(awk '{print $3,$4}' <<klasor>>/<<erisim>> | sort -u) <(awk -F, 'NR>1{print \"fintech=\"$3, \"musteri=\"$2}' <<klasor>>/<<riza>> | sort -u)`"),
          puan=50, baslik="Rızasız erişim"),
    Gorev("`<<klasor>>/<<notlar>>` dosyasına göre **çok faktörlü doğrulaması (MFA) olmayan** fintech hangisi?",
          Metin("mfa_yok", bicim="fintech adı"),
          ("Dosyanın `mfa` sütununa bak.",
           "`grep` ile `yok` geçen satırı bul.",
           "`grep ',yok,' <<klasor>>/<<notlar>>`"),
          puan=20, baslik="Zayıf halka"),
    Gorev("O MFA'sız fintech'e **geçerli rızası olan kaç farklı müşteri** var? (durum aktif, süresi geçmemiş; aynı "
          "müşteri birden çok kapsam verdiyse bir kez say.)",
          Sayi("w_musteri", sik_hatalar=_w_hata),
          ("İki ayrıştırma var: geçerli olanları seç, sonra müşteri adlarını tekilleştir.",
           "Önce fintech, durum ve tarih koşullarıyla süz; müşteri sütununu ($2) yazdır; `sort -u` ile tekilleştir.",
           "`awk -F, -v b=<<bugun>> -v f=FINTECH '$3==f && $6==\"aktif\" && $5>=b {print $2}' <<klasor>>/<<riza>> | sort -u | wc -l`"),
          puan=50, baslik="Risk altındaki müşteriler"),
    Gorev("Bir fintech'in güvenliği zayıfsa ve bir saldırgan onu ele geçirirse, **banka** neden risk altına girer?",
          Secmeli([
              ("Fintech'in rızalarla eriştiği tüm hesaplara ulaşılır; zincir en zayıf halka kadar güçlüdür",
               "Doğru. Fintech'in erişimi müşterinin rızasına dayanır; fintech ele geçerse o erişim de ele geçer."),
              ("Fintech'in sunucusu bankanın veri merkezinde olduğu için saldırgan doğrudan bankanın iç ağına girer",
               "Yanlış. Fintech kendi altyapısındadır; risk, bankanın API'si üzerinden rıza ile verilmiş erişimin kötüye kullanılmasıdır."),
              ("Düzenleyici kurum, bankanın bütün sorumluluğunu fintech'e devrettiği için banka etkilenmez",
               "Yanlış. Müşteri verisinin korunması ve rızanın yönetimi bankanın da sorumluluğundadır."),
              ("Rıza kayıtları fintech'te tutulduğu için banka sadece olayı sonradan öğrenir ve etkilenmez",
               "Yanlış. Rıza yönetimi bankanın API'sinde de uygulanır; kötüye kullanım bankanın müşterisini ve itibarını vurur."),
          ], dogru=0),
          ("Fintech'in erişiminin neye dayandığını düşün.",
           "Rıza ile verilmiş erişimi ele geçiren, o erişimin sahibi gibi davranır.",
           "Cevap: zincir en zayıf halkası kadar güçlüdür."),
          puan=20, baslik="Güven zinciri"),
]


def _kapanis():
    return """
Açık bankacılık, bankanın kontrolünün **bittiği yerde** başlar: rıza kayıtları, fintech'in güvenliği ve
günlüklerin tutarlılığı artık ortak bir sorumluluk. Saldırgan gözüyle en zayıf halka (MFA'sız bir fintech,
süresi geçmiş ama canlı kalmış bir rıza) ödül demektir. Savunma gözüyle: her erişim bir rızaya bağlanmalı, süresi
geçen rıza kendiliğinden ölmeli ve fintech'ler düzenli değerlendirilmeli.
"""


SEVIYE = Seviye(
    kimlik="c19b01", cilt=19, bolum=1, baslik="Açık Bankacılık Ekosistemi",
    brifing="""
<<sahne>>

Selin: "Bu işin ilk kuralı rollerin haritasını çıkarmak. <<kisi>> bize üç dosya gönderdi: rıza kayıtları, erişim
günlüğü ve fintech notları. Hepsi `<<klasor>>/` klasöründe. Bugün <<bugun>>."

Deniz: "Rıza kayıtlarıyla günlüğü yan yana koyunca genelde birileri yakalanır. Biri bu sefer de yakalanacak."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Rıza merkezli model:** Açık bankacılık düzenlemeleri dünyanın birçok yerinde müşteri rızasını merkeze alır:
  müşteri hangi uygulamaya, hangi kapsamda ve ne kadar süreyle izin verdiğini görebilmeli ve geri alabilmelidir.
  Bu yüzden iyi bir uygulamada rıza kayıtları ile API erişim günlükleri düzenli olarak karşılaştırılır.
- **Tespit:** Rıza kaydı olmayan bir erişim, süresi geçmiş rızayla yapılan bir çağrı ya da iptal edilmiş rızadan
  sonra gelen istek, erişim günlüğü ile rıza deposunun karşılaştırılmasıyla bulunur. Bu karşılaştırmayı otomatik
  çalıştırıp alarm üretmek temel kontroldür.
- **Önleme:** Üçüncü taraflar için kayıt/onboarding aşamasında güvenlik değerlendirmesi (MFA, sızma testi
  geçmişi), süresi dolan rızanın otomatik kapanması ve fintech başına erişim kotası. Türkiye'de bu alan TCMB gözetimi
  ve ilgili ödeme mevzuatı çerçevesinde ilerler; güncel düzenlemeyi ayrıca takip et.
""",
    sure_hedef_dk=30,
)
