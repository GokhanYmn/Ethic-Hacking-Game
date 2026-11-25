"""Cilt 16 · Bölüm 2 — Phishing'i Tanımak.

Beceri: kurgusal .eml dosyalarında başlıkları (From, Reply-To, Received, Authentication-Results) ve bağlantıları
okuyup hangi e-postanın sahte olduğunu, hangi ipucunun onu ele verdiğini bulmak: SPF/DKIM/DMARC sonucu, Reply-To
uyuşmazlığı, benzer (taklit) alan adı, görünen bağlantı ile gerçek hedef farkı.

Vakalar: Ferah Bank, Paramix, Kuzgun Lojistik, Yeşiltepe Belediyesi, Medora Sağlık. E-postalar kurgusal ve çok
kısadır; kullanılabilir bir şablon, sayfa ya da araç yoktur. Bütün alan adları `.lab`, IP'ler TEST-NET'tendir.
"""
from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c16_sosyal.ortak import Esle, sec_doldur, sh, vaka_sec

IPUCLARI = ["Kimlik doğrulama (SPF/DKIM/DMARC) başarısız", "Reply-To uyuşmazlığı",
            "Benzer (taklit) alan adı", "Görünen bağlantı ile gerçek hedef farkı"]
KOTU_HEDEF = ["hesap-dogrulama-merkezi.lab", "guvenli-giris-portali.lab", "belge-onay-servisi.lab"]
KOTU_YANIT = ["yardim-masasi.lab", "destek-hatti-iletisim.lab", "onay-bildirim.lab"]
ASIL_ALAN_ETIKETLERI = ["guvenlik-destek", "hesap-onay", "musteri-destek"]
GUN_AD = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
AY_AD = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def taklit_alan(alan: str, rng) -> str:
    ad = alan.rpartition(".")[0]
    adaylar = []
    i = rng.randrange(1, len(ad) - 2)
    degisik = ad[:i] + ad[i + 1] + ad[i] + ad[i + 2:]
    if degisik != ad:
        adaylar.append(degisik)
    j = rng.randrange(1, len(ad) - 1)
    adaylar.append(ad[:j] + ad[j] + ad[j:])
    adaylar += [ad + "-guvenlik", "guvenli-" + ad]
    return rng.choice(adaylar) + ".lab"


def _tarih(t):
    return f"{GUN_AD[t.weekday()]}, {t.day:02d} {AY_AD[t.month - 1]} {t.year} {t:%H:%M:%S} +0300"


def _eml(gonderen_ad, gonderen, yanit, ip, auth, konu, govde, t, mx_host):
    return (f"Return-Path: <{gonderen}>\n"
            f"Received: from {mx_host} ([{ip}]) by mx.kalkan.lab; {_tarih(t)}\n"
            f"Authentication-Results: mx.kalkan.lab; {auth}\n"
            f"From: \"{gonderen_ad}\" <{gonderen}>\n"
            f"Reply-To: <{yanit}>\n"
            "To: personel@kalkan.lab\n"
            f"Subject: {konu}\n"
            f"Date: {_tarih(t)}\n"
            "Content-Type: text/html; charset=utf-8\n\n"
            f"<p>{govde}</p>\n")


def _gecti(alan):
    return f"spf=pass smtp.mailfrom={alan}; dkim=pass header.d={alan}; dmarc=pass header.from={alan}"


def uret(rng):
    v = vaka_sec(rng)
    alan = v["alan"]
    t0 = u.gun(rng) + timedelta(hours=rng.randint(8, 16), minutes=rng.randint(0, 59))
    taklit = taklit_alan(alan, rng)
    kotu_hedef = rng.choice(KOTU_HEDEF)
    kotu_yanit = rng.choice(KOTU_YANIT)
    etiket = rng.choice(ASIL_ALAN_ETIKETLERI)
    ad = v["ad"]
    mesru_ip = u.dis_ip(rng)
    postalar = []   # (tur, dosya içeriği)

    def mesru_ip_():
        return u.dis_ip(rng)

    postalar.append(("mesru", _eml(f"{ad} Bildirim", f"bildirim@{alan}", f"bildirim@{alan}", mesru_ip_(), _gecti(alan),
                                   "Aylik hesap ozetiniz hazir",
                                   f"Merhaba, aylik ozetiniz hazirdir. Goruntulemek icin <a href=\"https://{alan}/ozet\">https://{alan}/ozet</a> adresinden oturum acabilirsiniz.",
                                   t0, f"mail.{alan}")))
    postalar.append(("mesru", _eml(f"{ad} BT", f"bt@{alan}", f"bt@{alan}", mesru_ip_(), _gecti(alan),
                                   "Planli bakim duyurusu",
                                   f"Cumartesi 02:00-04:00 arasi bakim yapilacaktir. Ayrintilar: <a href=\"https://{alan}/bakim\">https://{alan}/bakim</a>",
                                   t0 + timedelta(hours=2), f"mail.{alan}")))
    postalar.append(("mesru", _eml(f"{ad} Kampanya", f"kampanya@{alan}", f"kampanya@{alan}", mesru_ip_(), _gecti(alan),
                                   "Kampanya bulteni",
                                   f"Bu ayin kampanyalari: <a href=\"https://kampanya.{alan}/bulten\">https://kampanya.{alan}/bulten</a>",
                                   t0 + timedelta(hours=5), f"mail.{alan}")))
    postalar.append(("auth", _eml(f"{ad} Bildirim", f"bildirim@{alan}", f"bildirim@{alan}", mesru_ip_(),
                                  f"spf=fail smtp.mailfrom={alan}; dkim=none; dmarc=fail header.from={alan}",
                                  "Hesap dogrulamasi gerekiyor",
                                  f"Hesabiniz icin acil dogrulama gerekiyor, hemen giris yapin: <a href=\"https://{alan}/dogrula\">https://{alan}/dogrula</a>",
                                  t0 + timedelta(hours=1), "mail-aktarici.bilinmeyen.lab")))
    postalar.append(("replyto", _eml(f"{ad} Destek", f"destek@{alan}", f"cevap@{kotu_yanit}", mesru_ip_(), _gecti(alan),
                                     "Belge numaranizi iletin",
                                     f"Islemin tamamlanmasi icin bu e-postayi yanitlayarak belge numaranizi bildirin. Bilgi: <a href=\"https://{alan}/belge\">https://{alan}/belge</a>",
                                     t0 + timedelta(hours=3), f"mail.{alan}")))
    postalar.append(("taklit", _eml(f"{ad} Guvenlik", f"guvenlik@{taklit}", f"guvenlik@{taklit}", mesru_ip_(), _gecti(taklit),
                                    "Guvenlik uyarisi",
                                    f"Hesabinizda olagandisi islem goruldu. Hemen kontrol edin: <a href=\"https://{taklit}/kontrol\">https://{taklit}/kontrol</a>",
                                    t0 + timedelta(hours=4), f"mail.{taklit}")))
    postalar.append(("baglanti", _eml(f"{ad} Fatura", f"fatura@{alan}", f"fatura@{alan}", mesru_ip_(), _gecti(alan),
                                      "Fatura bilgilendirmesi",
                                      f"Faturaniza ulasmak icin tiklayin: <a href=\"http://{kotu_hedef}/fatura\">https://{alan}/fatura</a>",
                                      t0 + timedelta(hours=6), f"mail.{alan}")))
    rng.shuffle(postalar)
    sahte_no = [i for i, (tur, _) in enumerate(postalar, 1) if tur != "mesru"]
    sahte_harita = {tur: i for i, (tur, _) in enumerate(postalar, 1) if tur != "mesru"}
    kat = list(IPUCLARI)
    rng.shuffle(kat)
    harf = {k: "abcd"[i] for i, k in enumerate(kat)}
    tur_ipucu = {"auth": IPUCLARI[0], "replyto": IPUCLARI[1], "taklit": IPUCLARI[2], "baglanti": IPUCLARI[3]}
    esle = {str(no): harf[tur_ipucu[tur]] for tur, no in sahte_harita.items()}
    esle_metni = ("\n".join(f"{no}) ornek_{no}.eml" for no in sorted(sahte_no)) +
                  "\n\nİpuçları:\n" + "\n".join(f"{harf[k]}) {k}" for k in kat))
    esle = {k: esle[k] for k in sorted(esle)}
    return {
        "vaka": f"{ad} — şüpheli e-posta incelemesi",
        "v": v, "postalar": postalar, "etiket": etiket,
        "metin": {"musteri": ad, "alan": alan, "birim": v["birim"], "hikaye": v["hikaye"], "esle": esle_metni,
                  "ornek_alan": f"{v['kod']}.{etiket}.lab"},
        "cevaplar": {"sahte": sahte_no, "esle": esle, "yanit": kotu_yanit, "taklit": taklit,
                     "hedef": kotu_hedef, "asil": f"{etiket}.lab"},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} çalışanlarının bildirdiği KURGUSAL e-postalar (posta/ klasörü). Meşru alan adı: {v['alan']}\n"
          "Selin'den not: Bazıları gerçek, bazıları sahte. Başlıklara ve bağlantılara bakarak ayır.\n")
    for no, (_, icerik) in enumerate(s["postalar"], 1):
        u.yaz(lab / "posta" / f"ornek_{no}.eml", icerik)
    u.yaz(lab / "ipuclari.txt",
          "Phishing tanıma ipuçları\n"
          "  Kimlik doğrulama : Authentication-Results satırında spf=, dkim=, dmarc= sonuçları (pass = geçti)\n"
          "  Reply-To         : yanıtın gideceği adres; From ile aynı alan adında mı?\n"
          "  Alan adı         : From ve bağlantı alan adı müşterinin gerçek alan adı mı, yoksa ona benzeyen mi?\n"
          "  Bağlantı         : görünen metin ile href (gerçek hedef) aynı alan adını gösteriyor mu?\n")


def coz(lab: Path, s: dict) -> dict:
    alan = s["v"]["alan"]
    cikti = sh(r"""for f in posta/ornek_*.eml; do
 n=$(echo $f | grep -o '[0-9]*' | head -1)
 fr=$(grep -m1 '^From:' $f | sed 's/.*@\([^>]*\)>.*/\1/')
 rp=$(grep -m1 '^Reply-To:' $f | sed 's/.*@\([^>]*\)>.*/\1/')
 ok=$(grep -c 'spf=pass.*dkim=pass.*dmarc=pass' $f)
 gs=$(grep -o '>https\?://[^<]*<' $f | head -1 | sed 's|>https\?://\([^/<]*\).*|\1|')
 hr=$(grep -o 'href="[^"]*"' $f | head -1 | sed 's|href="https\?://\([^/"]*\).*|\1|')
 echo "$n $fr $rp $ok $gs $hr"
done""", lab)
    sahte, yanit, taklit, hedef = [], "", "", ""
    for satir in cikti.splitlines():
        n, fr, rp, ok, gs, hr = satir.split()
        if ok == "0" or fr != rp or fr != alan or gs != hr:
            sahte.append(n)
        if fr != rp:
            yanit = rp
        if fr != alan and fr == rp:
            taklit = fr
        if gs != hr:
            hedef = hr
    esle = GOREVLER[1].kontrol.cevabi_goster(Baglam(s, lab, 2))
    asil = sh("echo " + s["metin"]["ornek_alan"] + " | awk -F. '{print $(NF-1) \".\" $NF}'", lab)
    return sec_doldur({1: " ".join(sahte), 2: esle, 3: yanit, 4: taklit, 5: hedef, 6: asil}, GOREVLER, lab, s)


def _alan_hata(g, beklenen, b):
    if "@" in g:
        return "Sadece **alan adını** yaz (`@` işaretinden sonraki kısım), tam adresi değil."
    if g.startswith("http"):
        return "Adres değil, yalnızca **alan adı** (örn. `ornek.lab`) bekleniyor."
    return None


ADIMLAR = [
    Adim("Bir e-postanın iki yüzü", """
Bir e-postanın ekranda gördüğün kısmı (gönderen adı, konu, metin) ile **başlıkları** vardır. Başlıklar gerçek yolu anlatır:
mesaj hangi sunucudan çıktı, gönderici doğrulandı mı, yanıtlar nereye gidecek. Phishing'i tanımak, bu iki yüzü karşılaştırmaktır.
Lab'da `posta/` klasöründe yedi kurgusal .eml (ham e-posta) dosyası var:
""", komut="ls posta"),
    Adim("Bir e-postayı baştan sona okumak", """
`.eml` düz metin bir dosyadır. İlk e-postayı oku:
""", komut="cat posta/ornek_1.eml", sonra="""
Önemli satırlar: **From** (gönderen), **Reply-To** (yanıt adresi), **Received** (hangi sunucu ve IP), **Authentication-Results**
(SPF/DKIM/DMARC sonuçları) ve metindeki bağlantı (`<a href="...">`).
"""),
    Adim("SPF, DKIM, DMARC", """
Üç kimlik doğrulama kontrolü gönderenin gerçekten o alan adına ait olup olmadığını sınar:

- **SPF:** gönderen IP'si, alan adının izin verdiği sunucular arasında mı?
- **DKIM:** mesaj, alan adının dijital imzasını taşıyor ve değişmemiş mi?
- **DMARC:** SPF/DKIM sonuçları From'daki alan adıyla uyumlu mu ve alan adı sahibi 'başarısız olursa şunu yap' dedi mi?

`pass` geçti demektir; `fail` ya da `none` şüphelidir. Tüm e-postaların sonuçlarını yan yana gör:
""", komut="grep -H '^Authentication-Results' posta/*.eml"),
    Adim("Gönderen ve yanıt adresi", """
`From` ile `Reply-To` genelde aynı alan adındadır. Farklıysa, yanıtın gideceği yer gönderenden başkası demektir:
""", komut="grep -H -E '^(From|Reply-To):' posta/*.eml"),
    Adim("Görünen bağlantı ve gerçek hedef", """
HTML e-postada bağlantının **görünen metni** ile gerçek hedefi (`href`) farklı olabilir. `grep -o` yalnızca eşleşen kısmı basar:
""", komut="grep -o -H -E '(href=\"[^\"]*\"|>https?://[^<]*<)' posta/*.eml", sonra="""
**Hacker gözüyle:** Phishing'in kalbi, meşru görünen sahte adreslerdir. `ornek.guvenlik-destek.lab` adresinde asıl alan adı
`guvenlik-destek.lab`'dir; `ornek` yalnızca bir alt alan adıdır (Cilt 2'deki DNS bilgisi: alan adı **sağdan sola** okunur).
Sahtekâr, kendi sahip olduğu alan adının soluna meşru markanın adını yazabilir.
"""),
    Adim("Taklit (typosquat) alan adı", """
Bazı sahte alan adları harf yer değiştirerek, bir harf ekleyerek ya da ek sözcük koyarak (örn. `-guvenlik`) meşru alan adına
benzer. Saldırgan o alan adının **gerçek sahibi** olduğu için SPF/DKIM/DMARC `pass` verebilir. Gönderen alan adlarını sırala:
""", komut="grep -h '^From:' posta/*.eml | sed 's/.*@//; s/>//' | sort | uniq -c"),
    Adim("Güvenin sınırı", """
Bir e-postada üç ipucuna birden bakmak gerekir: **kimlik doğrulama**, **alan adı/yanıt adresi**, **bağlantının gerçek hedefi**.
Hiçbiri tek başına yeterli değildir: kimlik doğrulama geçse bile alan adı taklit olabilir; alan adı doğru olsa bile bağlantı başka
yere gidebilir. Bu yüzden şüpheli bir mesajda tıklamadan önce hepsine bakılır ve emin olamıyorsan **bildirilir**.
"""),
]

GOREVLER = [
    Gorev("`posta/` klasöründeki 7 e-postadan **sahte olanların** dosya numaralarını yaz (`ornek_N.eml` içindeki N, virgülle ayır).",
          Kume("sahte", tur="sayi", bicim="dosya numaraları, virgülle ayrılmış"),
          ("Meşru e-postada dört şey tutarlıdır: kimlik doğrulama geçer, Reply-To aynı alan adında, alan adı doğru, bağlantı görünen adrese gider.",
           "Her e-postada sırayla şunlara bak: `Authentication-Results`, `From`/`Reply-To`, `From` alan adı (<<alan>>) ve bağlantı (`href`).",
           "Dört sahte e-posta var; her birinde yukarıdaki dört şeyden **yalnızca biri** tutarsız."),
          puan=50, baslik="Hangileri sahte"),
    Gorev("Sahte dört e-postayı, onları ele veren ipucuna göre eşle (numara + harf, örn. `3a 5c 6d 7b`):\n\n<<esle>>",
          Esle("esle"),
          ("Her sahte e-postada yalnızca bir şey bozuk. Hangisi?",
           "Önce `grep -H '^Authentication-Results' posta/*.eml`, sonra `From`/`Reply-To`, sonra alan adları, en son bağlantılar.",
           "`spf=fail` / `dmarc=fail` = kimlik doğrulama; farklı alan adlı Reply-To = uyuşmazlık; benzer ama farklı yazılmış From alan adı = taklit; `href` alan adı ≠ görünen alan adı = bağlantı farkı."),
          puan=45, baslik="İpucu eşleme"),
    Gorev("Bir e-postada `Reply-To` adresi, `From`'dan **farklı bir alan adına** gidiyor. Yanıtların gideceği **alan adını** yaz.",
          Metin("yanit", bicim="alan adı (...lab)", sik_hatalar=_alan_hata),
          ("`From` ve `Reply-To` satırlarını yan yana al.",
           "`grep -H -E '^(From|Reply-To):' posta/*.eml`: bir dosyada iki satır farklı alan adlarını gösterir.",
           "Farklı olan `Reply-To` adresinin `@` işaretinden sonraki kısmı cevaptır."),
          puan=35, baslik="Reply-To nereye gidiyor"),
    Gorev("Bir e-postanın gönderen alan adı <<alan>>'a **benziyor ama farklı** (taklit alan adı) ve kimlik doğrulaması bile `pass` "
          "çıkıyor. Bu **taklit alan adını** yaz.",
          Metin("taklit", bicim="alan adı (...lab)", sik_hatalar=_alan_hata),
          ("Gönderen alan adlarını sırala ve müşterinin gerçek alan adıyla karşılaştır.",
           "`grep -h '^From:' posta/*.eml | sed 's/.*@//; s/>//' | sort | uniq -c`: gerçek alan adının dışında bir adres var.",
           "Gerçek alan adı <<alan>>; ona harf/ek sözcük ile benzeyen tek adres cevaptır."),
          puan=35, baslik="Taklit alan adı"),
    Gorev("Bir e-postada **görünen bağlantı metni** meşru görünürken, `href` (gerçek hedef) başka bir yere gidiyor. Gerçek hedefin "
          "**alan adını** yaz.",
          Metin("hedef", bicim="alan adı (...lab)", sik_hatalar=_alan_hata),
          ("HTML e-postada bağlantı iki parçadır: görünen metin ve `href`.",
           "`grep -o 'href=\"[^\"]*\"' posta/*.eml` bütün gerçek hedefleri listeler; görünen metinle karşılaştır.",
           "Görünen adresle uyuşmayan `href` içindeki alan adı cevaptır."),
          puan=35, baslik="Gerçek bağlantı hedefi"),
    Gorev("`<<ornek_alan>>` adresinde **asıl alan adı** (kayıtlı alan adı) hangisidir?",
          Metin("asil", bicim="alan adı (...lab)", sik_hatalar=_alan_hata),
          ("Alan adı sağdan sola okunur: önce `.lab`, sonra solundaki etiket.",
           "Soldaki ilk etiket (`<<ornek_alan>>` içinde en soldaki) yalnızca alt alan adıdır; asıl alan adı onun sağındaki etiket artı `.lab`'dir.",
           "Asıl alan adı, sondan ikinci etiket ile `.lab`: tam olarak iki etiketten oluşur."),
          puan=25, baslik="Asıl alan adı"),
    Gorev("Bir e-postada SPF, DKIM ve DMARC'ın **üçü de `pass`** çıktı. Bu e-postanın **güvenilir** olduğu anlamına gelir mi?",
          Secmeli([
              ("Hayır: yalnızca gönderenin o alan adına ait olduğunu söyler; alan adı taklit olabilir",
               "Doğru. Saldırgan kendi (benzer) alan adını doğru yapılandırırsa üçü de geçer; alan adına ve bağlantıya yine bakmak gerekir."),
              ("Evet: pass sonuçları e-postanın ve içindeki bağlantıların zararsız olduğunu garanti eder",
               "Yanlış. Pass yalnızca gönderen doğrulamasıdır; içeriğin güvenliğini garanti etmez."),
              ("Evet, ama yalnızca e-postada hiç ek dosya ve hiç bağlantı yoksa güvenilir sayılabilir",
               "Yanlış. Ek olup olmaması kimlik doğrulama sonucunu güvenilirlik kanıtına çevirmez."),
              ("Hayır: pass sonuçları saldırgan tarafından her zaman sahte olarak üretilir ve hiçbir değeri yoktur",
               "Yanlış. Sonuçlar alıcı sunucu tarafından hesaplanır; sorun sonuçların sahte olması değil, anlamının sınırlı olmasıdır."),
          ], dogru=0),
          ("Saldırgan da kendi alan adı için SPF, DKIM ve DMARC kurabilir mi?",
           "Taklit alan adı görevindeki e-postaya bak: kimlik doğrulaması sonucu nedir?",
           "Doğru şık, kimlik doğrulamanın tek başına yeterli olmadığını söyleyen şık."),
          puan=30, baslik="Üç pass yeter mi"),
    Gorev("Şüpheli bir e-posta aldın. **En doğru ilk adım** hangisi?",
          Secmeli([
              ("Bağlantıya tıklamadan ve eki açmadan e-postayı bildirme kanalına iletmek",
               "Doğru. Tıklamadan bildirirsen hem kendini korursun hem SOC'a aynı mesajı tüm posta kutularında arama imkânı verirsin."),
              ("E-postayı yanıtlayarak göndericiye sahte olup olmadığını ve kim olduğunu sormak",
               "Yanlış. Yanıt, saldırgana adresin etkin olduğunu söyler ve onunla etkileşimi başlatır."),
              ("Bağlantıya yalnızca bir kez tıklayıp sayfanın gerçek olup olmadığına bakmak",
               "Yanlış. Tek tıklama bile kötü amaçlı içeriği tetikleyebilir ya da hesabın doğrulandığını bildirir."),
              ("E-postayı sessizce silmek ve kimseye bir şey söylememek, böylece iş kalmaz",
               "Yanlış. Silmek seni korur ama diğer çalışanlar aynı mesajı almaya devam eder; bildirmek kurumu korur."),
          ], dogru=0),
          ("Ne yaparsan saldırganla etkileşime girmeden hem kendini hem başkalarını korursun?",
           "Bildirmek, mesajın başka kutularda da aranmasını sağlar.",
           "Doğru şık, tıklamadan bildirmeyi anlatan şık."),
          puan=25, baslik="İlk adım"),
]

SEVIYE = Seviye(
    kimlik="c16b02",
    cilt=16,
    bolum=2,
    baslik="Phishing'i Tanımak",
    brifing="""
**<<musteri>>** SOC'u (Deniz'in eski ekibi) sana yedi şüpheli e-posta dosyası gönderdi. <<hikaye>> Müşterinin meşru alan adı
**<<alan>>**.

Deniz: "Bunların bir kısmı gerçek duyuru, bir kısmı sahte. Çalışanlar 'hangisine tıklayayım' diye soruyor. Ham dosyalara bak:
başlıklar yalan söylemez." Selin ekliyor: "Her sahte e-postayı hangi ipucunun ele verdiğini de not et; müşteriye eğitimde
göstereceğiz." Mert: "Finansta bu e-postalar hep bir şeyi taklit eder; neyi taklit ettiğini bilirsen sahtesini daha kolay görürsün."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Phishing'i fark etmek öğretilebilen bir beceridir: başlıklardaki kimlik doğrulama sonucu, Reply-To uyuşmazlığı, benzer alan adı ve
görünen bağlantı ile gerçek hedef farkı klasik dört ipucudur. Saldırgan açısından en etkili numara, güvenilir görünen bir
alan adı ve doğru görünen bir bağlantıdır; kimlik doğrulamayı bile kendi (taklit) alan adı için geçirebilir. Savunma dersi: tek
ipucuna güvenme, dört ipucuna birden bak, emin değilsen tıklama ve bildir.
""",
    gercek_hayat="""
- **Taklit alan adları:** Kurumlara ve bankalara ait alan adlarının harf değiştirilmiş taklitleri, kimlik avı kampanyalarında
  çok sık kullanılan, iyi bilinen bir yöntemdir. Bu yüzden kurumlar, markalarına benzeyen alan adlarını izler ve gerektiğinde
  kapattırır.
- **Önleme:** E-posta alan adı için SPF, DKIM ve DMARC'ın sıkı politikayla (`reject`/`quarantine`) yapılandırılması başkasının
  kurum adıyla doğrudan sahte e-posta göndermesini zorlaştırır; posta ağ geçidinde taklit alan adı ve bağlantı taraması,
  çok faktörlü kimlik doğrulama (çalınan parola tek başına yetmesin) ve çalışan farkındalığı. **Tespit:** SOC'un bildirilen
  mesajdaki alan adlarını, bağlantıları ve gönderen IP'lerini tüm posta kutularında araması; benzer alan adı izleme.
- **Finansal phishing:** Sahte banka ve ödeme bildirimleri en yaygın ve en zararlı kimlik avı türlerindendir; bankalar ve
  kamu kurumları parola ya da tek kullanımlık kod istemediklerini sıkça duyurur.
""",
    sure_hedef_dk=25,
)
