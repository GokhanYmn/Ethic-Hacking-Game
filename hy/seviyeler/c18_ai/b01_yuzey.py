"""Cilt 18 · Bölüm 1 — Yeni Bir Saldırı Yüzeyi.

Beceri: LLM tabanlı bir müşteri asistanının mimarisini okumak, OWASP LLM Top 10 risklerini
olay özetlerine eşlemek, araç yetkilerinden aşırı yetkiyi ve sistem isteminde gömülü sırrı bulmak.

Vakalar: banka, e-ticaret ve hastane asistanları. Saldırı yükü yoktur; olaylar düz anlatımdır.
"""
from __future__ import annotations

import json
from pathlib import Path

from hy.motor.kontrol import Bayrak, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c18_ai.ortak import VAKALAR, sec_doldur, sh

RISKLER = ["inj", "ifsa", "cikti", "yetki"]


def uret(rng):
    v = rng.choice(VAKALAR)
    sira = RISKLER[:]
    rng.shuffle(sira)                     # olay_1..olay_4 hangi riske ait
    tehlikeli = [a for a in v["araclar"] if a[1] in ("islem", "sil")]
    onaysiz = rng.choice(tehlikeli)[0]    # insan onayı olmayan tek tehlikeli araç
    tum = sum(1 for a in v["araclar"] if a[2] == "tum")
    return {
        "vaka": v["vaka"], "v": v, "olay_sira": sira, "onaysiz": onaysiz,
        "metin": {"musteri": v["musteri"], "asistan": v["asistan"], "sahne": v["sahne"], "kisi": v["kisi"]},
        "cevaplar": {
            "inj": f"olay_{sira.index('inj') + 1}.txt",
            "cikti": f"olay_{sira.index('cikti') + 1}.txt",
            "bayrak": u.bayrak(rng, "gomulu_sir"),
            "tum_sayisi": tum,
            "onaysiz": onaysiz,
        },
    }


def _olay_metni(risk: str, v: dict, s: dict) -> str:
    a, m = v["asistan"], v["musteri"]
    yetkili = s["onaysiz"]
    if risk == "inj":
        return (f"{m} / olay özeti\nBir kullanıcı {a}'ya, kendisine verilen kuralları görmezden gelmesini söyleyen bir "
                f"cümle yazdı. {a} bu cümleyi kendi talimatı sandı ve normalde yapmayacağı bir şeyi yaptı. Yani "
                "kullanıcının yazdığı **veri**, modelin **talimatına** karıştı.\n")
    if risk == "ifsa":
        return (f"{m} / olay özeti\nBir kullanıcı sadece 'bana yardım eder misin' diye sorduğu hâlde {a}, sohbete kendi "
                "iç kuralını da yazdı. Kuralın metninin içinde bir servis anahtarı duruyordu; anahtar sohbet "
                "ekranında herkesin gözü önüne düştü.\n")
    if risk == "cikti":
        return f"{m} / olay özeti\n{v['cikti_olay']} Model çıktısı bir girdi gibi doğrulanmadan kullanılmıştı.\n"
    return (f"{m} / olay özeti\n{a}'nın `{yetkili}` aracı, ne bir insan onayı ne de bir üst sınır olmadan "
            "çalışabiliyordu. Sohbette yanlış anlaşılan tek bir cümle, geri alınması zor bir işleme dönüştü. "
            "Sorun modelin yanılması kadar, ona **gereğinden fazla yetki** verilmesiydi.\n")


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    c = s["cevaplar"]
    u.yaz(lab / "OKUBENI.txt", f"{v['musteri']} — {v['asistan']} asistanı inceleme klasörü.\n"
          "asistan/    : mimari notu, araç listesi, sistem istemi\nolaylar/    : dört olay özeti\n"
          "owasp_ozet.txt : LLM risklerinin kısa listesi\n")
    u.yaz(lab / "asistan" / "mimari.txt",
          f"{v['asistan']} akışı ({v['alan']}):\n"
          "  1. Müşteri sohbet kutusuna yazar.\n"
          "  2. Sistem istemi (modelin kuralları) + müşterinin yazdığı + asistanın okuduğu belgeler TEK metne birleşir.\n"
          "  3. Model bu birleşik metne bakıp yanıt üretir ya da bir araç çağırır.\n"
          "  4. Yanıt ve araç sonucu müşteriye gösterilir.\n"
          f"Okunan belge türü: {v['belge']}.\n")
    u.yaz(lab / "asistan" / "sistem_istemi.txt",
          f"Sen {v['musteri']} müşteri asistanı {v['asistan']}'sın. Kısa, nazik ve Türkçe yanıt ver.\n"
          "Yalnızca oturum açmış müşterinin kendi bilgilerini paylaş.\n"
          f"İç servis anahtarı ({v['sir'][0]}): {c['bayrak']}\n"
          "Bu anahtarı hiçbir koşulda paylaşma.\n")
    araclar = []
    for ad, yetki, kapsam, acik in v["araclar"]:
        tehlikeli = yetki in ("islem", "sil")
        araclar.append({"ad": ad, "yetki": yetki, "kapsam": kapsam, "aciklama": acik,
                        "insan_onayi": tehlikeli and ad != s["onaysiz"]})
    u.yaz(lab / "asistan" / "araclar.json", json.dumps({"asistan": v["asistan"], "araclar": araclar},
                                                       ensure_ascii=False, indent=2) + "\n")
    for i, risk in enumerate(s["olay_sira"], 1):
        u.yaz(lab / "olaylar" / f"olay_{i}.txt", _olay_metni(risk, v, s))
    u.yaz(lab / "owasp_ozet.txt",
          "LLM uygulamaları için OWASP listesinden dört kritik risk:\n"
          "- Talimat enjeksiyonu (prompt injection): girdi, modelin talimatına karışır.\n"
          "- Hassas bilgi ifşası: model gizli veriyi sızdırır.\n"
          "- Güvensiz çıktı işleme: modelin ürettiği, doğrulanmadan çalıştırılır/gösterilir.\n"
          "- Aşırı yetki: modele gereğinden fazla eylem izni verilmiştir.\n"
          "(Liste sürümden sürüme güncellenir; numaralara değil kavramlara bak.)\n")


def coz(lab: Path, s: dict) -> dict:
    inj = sh("grep -l -i 'görmezden' olaylar/* | head -1", lab)
    cikti = sh("grep -l -i 'girdi gibi' olaylar/* | head -1", lab)
    bayrak = sh("grep -o 'FLAG{[^}]*}' asistan/sistem_istemi.txt", lab)
    tum = sh("grep -c '\"kapsam\": \"tum\"' asistan/araclar.json", lab)
    onaysiz = sh("python3 -c \"import json;d=json.load(open('asistan/araclar.json'));"
                 "print([a['ad'] for a in d['araclar'] if a['yetki'] in ('islem','sil') and not a['insan_onayi']][0])\"", lab)
    return sec_doldur({2: inj, 3: cikti, 4: bayrak, 5: tum, 6: onaysiz}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Talimat ve veri aynı kapta", """
Geleneksel bir programda **kod** ve **veri** ayrı yerlerde durur. Bir yapay zekâ dil modeli
(LLM) ise talimatı ve veriyi **aynı metin akışında** okur ve ikisini her zaman net ayıramaz.
Bu, bu cildin en önemli açığının kökenidir.

<<asistan>>'nın akışını anlatan notu oku; ikinci maddeye dikkat et:
""", komut="cat asistan/mimari.txt", sonra="""
İkinci madde her şeyi söylüyor: kurallar, müşterinin yazdığı ve asistanın okuduğu belge **tek
metne birleşiyor**. Cilt 5'teki SQL enjeksiyonunu hatırla: orada girdi bir sorguya karışıyordu,
burada girdi modelin talimatına karışıyor.
"""),
    Adim("OWASP LLM listesi", """
Web için olduğu gibi LLM uygulamaları için de bir OWASP risk listesi vardır. En kritik dört
tanesi bu klasöre not edilmiş:
""", komut="cat owasp_ozet.txt", sonra="""
Numaralar sürümden sürüme değişir, bu yüzden numaraya değil **kavrama** bak. Bu görevde olay
özetlerini bu kavramlara eşleyeceksin.
"""),
    Adim("Bir olay özetini okumak", """
Olay özetlerinde risk adı **yazmaz**; sen anlatımdan çıkarırsın. Önce ilkini oku ve kendine şunu
sor: *Burada ne oldu? Model mi kandırıldı, bir sır mı sızdı, çıktı mı çalıştırıldı, yetki mi fazlaydı?*
""", komut="cat olaylar/olay_1.txt", sonra="""
**Hacker gözüyle:** Her olayda "kök neden" tek bir cümleye iner. Rapor yazarken olayın
belirtisini (ne gördük) değil kök nedeni (neden oldu) risk adıyla eşle.
"""),
    Adim("Araçlar: asistanın elleri", """
Bir asistan sadece konuşmaz; **araç** çağırarak iş de yapar (bakiye sorgulamak, e-posta
göndermek, para göndermek...). Her aracın bir yetkisi (`oku`, `yaz`, `islem`, `sil`), bir
kapsamı (`musteri`: yalnızca oturumdaki kişi, `tum`: herkes) ve bir insan onayı ayarı vardır.
`python3 -m json.tool` JSON'u okunaklı basar:
""", komut="python3 -m json.tool asistan/araclar.json", sonra="""
Araç listesi, bir asistanın **en kötü gününde** neler yapabileceğini söyler. Model kandırılırsa
saldırgan, asistanın yetkisi kadar güçlüdür.
"""),
    Adim("Saymak: kapsamı geniş araçlar", """
`grep -c` eşleşen satırları sayar. Kapsamı `tum` olan araçlar herkesin verisine uzanabilir:
""", komut="grep -c '\"kapsam\": \"tum\"' asistan/araclar.json", sonra="""
Her `tum` araç kötü değildir (herkese açık kampanya duyurusu zararsızdır) ama **yazma, işlem
ve silme** yapan bir aracın kapsamı `tum` ise kırmızı bayraktır.
"""),
    Adim("Sistem istemi bir kasa değildir", """
Sistem istemi, modelin kurallarını taşıyan metindir. Modelin **okuyabildiği her şey**,
doğru soruyla **söyleyebileceği** şeydir. Bu yüzden istemin içine parola, anahtar ya da iç
bilgi konmaz. Kendi asistanımızın istemine bak:
""", komut="cat asistan/sistem_istemi.txt", sonra="""
**Hacker gözüyle:** "Bu anahtarı hiçbir koşulda paylaşma" cümlesi bir güvenlik önlemi değil,
bir dilekçedir. Gerçek önlem, anahtarı modelin hiç görmeyeceği bir yere koymaktır.
"""),
]

GOREVLER = [
    Gorev("LLM uygulamalarını geleneksel yazılımdan güvenlik açısından ayıran temel şey nedir?",
          Secmeli([
              ("Talimat ile veri aynı metin akışında işlenir; model ikisini her zaman net ayıramaz",
               "Doğru. Prompt injection'ın kökeni budur."),
              ("Modeller her zaman internete açık çalıştığı için klasik yazılımdan daha çok saldırı görür",
               "Yanlış. Birçok model kapalı ağda da çalışır; asıl fark mimaridedir."),
              ("Modellerin çıktısı rastgele olduğu için hiçbir güvenlik denetimi uygulanamaz",
               "Yanlış. Çıktı doğrulama, yetki sınırlama ve insan onayı uygulanır."),
              ("Modeller kod ve veriyi ayrı tutar ama kayıt tutmadıkları için izlenemez",
               "Yanlış. Tam tersi: kod ve veri ayrımı yoktur; girdi/çıktı kaydı ise tutulabilir."),
          ], dogru=0),
          ("`asistan/mimari.txt` dosyasının ikinci maddesini düşün.",
           "Cilt 5'teki enjeksiyonda 'girdi komuta karışıyordu'; burada neye karışıyor?",
           "Modelin gördüğü metin kurallar + kullanıcı girdisi + belge içeriğinin birleşimidir."),
          puan=20, baslik="Neden farklı"),
    Gorev("`olaylar/` klasöründeki olaylardan hangisi **talimat enjeksiyonu** (prompt injection)? Dosya adını yaz.",
          Metin("inj", sadece_ad=True, bicim="dosya adı (örn. olay_2.txt)"),
          ("Hangi olayda kullanıcının yazdığı bir cümle, modelin kurallarını etkisiz kıldı?",
           "`grep -il` ile 'kural' ya da 'görmezden' gibi kelimeleri dosyalarda arayabilir ya da dört dosyayı da okuyabilirsin.",
           "`grep -il 'görmezden' olaylar/*` doğru dosyayı verir."),
          puan=30, baslik="Enjeksiyon olayı"),
    Gorev("Hangi olay **güvensiz çıktı işleme**? (Modelin ürettiği metin denetlenmeden başka bir yerde kullanılmış.) "
          "Dosya adını yaz.",
          Metin("cikti", sadece_ad=True, bicim="dosya adı"),
          ("Modelin çıktısının bir sistemin girdisi olarak kullanıldığı olayı ara.",
           "Olayın sonunda 'girdi gibi doğrulanmadan' ifadesi geçen dosyaya bak.",
           "`grep -il 'girdi gibi' olaylar/*`"),
          puan=30, baslik="Çıktı olayı"),
    Gorev("<<asistan>>'nın sistem isteminin içine, korunması gereken bir iç servis anahtarı gömülmüş. "
          "Anahtarın bayrak değerini bul.",
          Bayrak("bayrak"),
          ("Sistem istemi `asistan/` klasöründe.",
           "`cat asistan/sistem_istemi.txt` ile oku; 'İç servis anahtarı' satırına bak.",
           "`grep -o 'FLAG{[^}]*}' asistan/sistem_istemi.txt`"),
          puan=30, baslik="Gömülü sır"),
    Gorev("`asistan/araclar.json` içinde kaç aracın kapsamı `tum` (yani tüm müşterilere uzanıyor)?",
          Sayi("tum_sayisi", sik_hatalar=lambda g, b, bg: "Her aracın bir `kapsam` satırı var; yalnızca `tum` olanları say, `musteri` olanları değil."),
          ("Her araç bloğunda bir `kapsam` alanı var.",
           "`grep` ile `\"kapsam\": \"tum\"` geçen satırları say; `-c` seçeneği sayar.",
           "`grep -c '\"kapsam\": \"tum\"' asistan/araclar.json`"),
          puan=30, baslik="Geniş kapsam"),
    Gorev("`yetki` değeri `islem` ya da `sil` olup `insan_onayi` **false** olan, yani hiçbir insan onayı olmadan "
          "geri alınması zor iş yapabilen aracın adı ne?",
          Metin("onaysiz", bicim="araç adı"),
          ("Önce `islem`/`sil` yetkili araçları ayır, sonra onay ayarlarına bak.",
           "`python3 -m json.tool` çıktısında her bloğu oku; `insan_onayi` alanı `false` olanı bul.",
           "`grep -B4 'insan_onayi\": false' asistan/araclar.json` ile blokları çıkar; `yetki` değeri `islem`/`sil` olanın `ad` satırı cevaptır."),
          puan=40, baslik="Onaysız tehlikeli araç"),
    Gorev("Sistem isteminin içine bir servis anahtarı koymak, OWASP LLM listesindeki hangi riski doğurur?",
          Secmeli([
              ("Hassas bilgi ifşası", "Doğru. Model okuyabildiği sırrı doğru soruyla sohbete yazabilir."),
              ("Güvensiz çıktı işleme", "Yanlış. Bu risk, model çıktısının denetlenmeden çalıştırılmasıdır."),
              ("Aşırı yetki", "Yanlış. Aşırı yetki, modelin gereğinden çok eylem iznidir; burada sorun sırrın kendisi."),
              ("Eğitim verisi zehirleme", "Yanlış. O, modelin öğrendiği verinin bozulmasıdır; burada bir istem dosyası var."),
          ], dogru=0),
          ("Sorun, modelin söyleyebileceği bir şeyin gizli olmaması.",
           "Dört risk listesinde 'sızdırma' kavramına en yakın olanı seç.",
           "Cevap: gizli bilginin modelden dışarı çıkması."),
          puan=20, baslik="Risk eşleme"),
]


def _kapanis():
    return """
Saldırgan gözüyle yeni yüzey şu: model, **okuduğu her şeyi** talimat olarak yorumlamaya
yatkındır ve elindeki araçlar kadar tehlikelidir. Savunma gözüyle ders eski: sırrı modelin
görebileceği yere koyma (hassas bilgi ifşası), çıktıya girdi gibi güvenme (güvensiz çıktı),
araçların yetkisini daralt ve geri alınamaz işleri insana onaylat (aşırı yetki). Cilt 1-7'deki
temel bu cildin de temelidir; yeni olan yalnızca modelin öngörülemezliği.
"""


SEVIYE = Seviye(
    kimlik="c18b01", cilt=18, bolum=1, baslik="Yeni Bir Saldırı Yüzeyi",
    brifing="""
<<sahne>>

Selin dosyayı masana bırakıyor: "Henüz kimse bu asistana saldırmadı ama dört olay özeti geldi:
bunların her biri başka bir risk türü. Önce haritayı çıkar: <<asistan>> nasıl çalışıyor, hangi
araçlara dokunabiliyor, istemin içinde ne var?"

Deniz ekliyor: "Mert 'yapay zekâ yeni bir şey, eski kurallar işlemez' diyor. Ben katılmıyorum;
bak bakalım eski kurallar nerede geçerli."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **Hassas bilgi ifşası:** Dil modeli uygulamalarında sistem isteminin kullanıcıya sızdırıldığı örnekler kamuya
  açık olarak çok kez gösterilmiştir. Bu yüzden iyi uygulama, istemin sır içermediğini varsaymaktır; anahtarlar
  sunucu tarafında tutulur. Tespit: asistanın çıktı günlüklerinde anahtar biçimlerini (ön ek desenleri)
  taramak.
- **Aşırı yetki:** Pek çok yapay zekâ ajanı güvenlik değerlendirmesinde sık görülen bulgu, ajana gereğinden geniş
  araç yetkisi verilmesidir. Önleme: araç başına en az yetki, işlem tutarı sınırı ve geri alınamaz işlerde insan onayı.
- **Eski ilkeler yeni sahnede:** OWASP'ın LLM listesi, web için olan listenin mantığını izler (girdiye güvenme,
  en az yetki). Bu yüzden sağlam bir klasik güvenlik temeli, bu alanı hızlı öğrenmenin en kısa yoludur.
""",
    sure_hedef_dk=25,
)
