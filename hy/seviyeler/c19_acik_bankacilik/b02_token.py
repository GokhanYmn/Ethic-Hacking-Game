"""Cilt 19 · Bölüm 2 — OAuth, Token ve Kapsam.

Beceri: kurgusal JWT'leri `base64 -d` ile çözüp claim'leri (kapsam, süre, hedef kitle, algoritma) okumak,
kayıtlı kapsamla karşılaştırarak aşırı geniş token'ı bulmak ve süresi geçmiş token'ı kabul eden API
kaydını yakalamak. Token'lar ve imzalar kurgusaldır; hiçbir sistemde geçerli değildir ve token üretme/
sahteciliği öğretilmez: oyuncu yalnızca okur ve analiz eder.

Vakalar: üç banka ve kendi fintech istemcileri. Zamanlar UTC'dir.
"""
from __future__ import annotations

import calendar
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Kume, Metin, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c19_acik_bankacilik.ortak import jwt_yap, sec_doldur, sh

VAKALAR = [
    {"vaka": "Ferah Bank — açık API ağ geçidi", "banka": "Ferah Bank", "alan": "ferahbank.lab",
     "istemciler": ["Paramix", "Butcem", "Hesapkolay", "Kredim", "Nakitix", "Paratek", "Sepetim"],
     "td": "tokenlar", "kayit": "istemci_kayitlari.csv", "log": "api_erisim.log",
     "sahne": "Ferah Bank'ın API ağ geçidi günlükleri ve ortakların kullandığı token örnekleri incelemeye alındı. Bir "
              "fintech, \"sadece hesap okuma\" izniyle ödeme yapabildiğini fark edip bildirmiş. Kaan Bey: \"Hangi "
              "token'ın neyi yapabildiğini ve ağ geçidinin neleri kabul ettiğini görmek istiyorum.\""},
    {"vaka": "Yıldız Bank — ödeme API'si", "banka": "Yıldız Bank", "alan": "yildizbank.lab",
     "istemciler": ["Cuzdanix", "Taksitim", "Faturam", "Nakitim", "Odemeci", "Fonlama", "Kasaben"],
     "td": "token_kutusu", "kayit": "kayitli_istemciler.csv", "log": "gecit.log",
     "sahne": "Yıldız Bank'ta gece nöbetindeki analist, ağ geçidinde süresi dolmuş gibi görünen bir token'ın kabul "
              "edildiğini fark etti. Defne Hanım: \"Token'ları çözün, hangisi sorunlu bulun; ağ geçidi hangi "
              "kurala uymamış, günlüğe bakıp söyleyin.\""},
    {"vaka": "Kuzgun Katılım — hesap bilgisi API'si", "banka": "Kuzgun Katılım", "alan": "kuzgunkatilim.lab",
     "istemciler": ["Kuzgunpay", "Sepetpay", "Bilancom", "Odemex", "Hizlipara", "Cebimde", "Katilimix"],
     "td": "jwt_ornekleri", "kayit": "onayli_uygulamalar.csv", "log": "api.log",
     "sahne": "Kuzgun Katılım'ın iç denetimi, açık bankacılık API'sine gelen çağrıları örnekliyor. Serdar Bey: "
              "\"Elimizde ortakların token'ları ve erişim günlüğü var. Hangisi bizim kurallarımıza uymuyor, hangisini "
              "ağ geçidi yanlışlıkla kabul etmiş?\""},
]
HAVUZ = ["hesap:oku", "bakiye:oku", "islem:oku"]


def uret(rng):
    v = rng.choice(VAKALAR)
    gun = u.gun(rng)
    simdi_dt = gun + timedelta(hours=14, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    simdi = calendar.timegm(simdi_dt.timetuple())
    istemciler = v["istemciler"][:]
    rng.shuffle(istemciler)
    roller = ["normal", "normal", "suresi_ret", "suresi_kabul", "aud", "kapsam", "alg"]
    ik = dict(zip(roller, istemciler))
    ornek = istemciler[0]
    cevap_kapsam = sorted(rng.sample(HAVUZ, 2))
    s = {
        "vaka": v["vaka"], "v": v, "gun": gun, "simdi": simdi, "simdi_dt": simdi_dt, "istemciler": istemciler,
        "roller": dict(zip(istemciler, roller)), "ornek": ornek, "ornek_kapsam": cevap_kapsam,
        "metin": {"banka": v["banka"], "sahne": v["sahne"], "td": v["td"], "kayit": v["kayit"], "log": v["log"],
                  "ornek": ornek, "simdi": str(simdi), "alan": v["alan"]},
        "cevaplar": {
            "ornek_kapsam": cevap_kapsam,
            "aud": [ik["aud"], ik["aud"] + ".jwt"],
            "suresi": [ik["suresi_ret"], ik["suresi_kabul"]],
            "alg": [ik["alg"], ik["alg"] + ".jwt"],
            "kapsam": [ik["kapsam"], ik["kapsam"] + ".jwt"],
            "jti": "",
        },
        "_ik": ik,
    }
    h = _hazirla(rng, s)
    s["_h"] = h
    s["cevaplar"]["jti"] = h["jtiler"][ik["suresi_kabul"]]
    return s


def _jti(rng) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(10))


def _hazirla(rng, s: dict) -> dict:
    """Token ve günlük içeriğini `uret` içinde, aynı rng ile üretir (aynı tohum → aynı sonuç)."""
    v = s["v"]
    simdi = s["simdi"]
    api = f"https://api.{v['alan']}/hesap-bilgisi"
    iss = f"https://kimlik.{v['alan']}"
    kayit = {}
    tokenlar = {}
    jtiler = {}
    gunluk = []
    t0 = s["simdi_dt"] - timedelta(hours=2)
    for c in s["istemciler"]:
        rol = s["roller"][c]
        kayitli = sorted(rng.sample(HAVUZ, rng.randint(1, 2)))
        if c == s["ornek"]:
            kayitli = list(s["ornek_kapsam"])
        tok_kapsam = list(kayitli)
        if rol == "kapsam":
            kayitli = [HAVUZ[0]]
            tok_kapsam = [HAVUZ[0], HAVUZ[1], "odeme:baslat"]
        kayit[c] = kayitli
        exp = simdi + rng.randint(900, 3000)
        aud = api
        alg = "RS256"
        imzali = True
        if rol in ("suresi_ret", "suresi_kabul"):
            exp = simdi - rng.randint(3700, 9000)
        if rol == "aud":
            aud = f"https://api.{v['alan']}/yonetim"
        if rol == "alg":
            alg, imzali = "none", False
        jti = _jti(rng)
        jtiler[c] = jti
        yuk = {"iss": iss, "sub": f"musteri-{rng.randint(1000, 9999)}", "aud": aud, "client_id": c.lower(),
               "scope": " ".join(tok_kapsam), "iat": exp - 3600, "exp": exp, "jti": jti}
        tokenlar[c] = jwt_yap(rng, {"alg": alg, "typ": "JWT"}, yuk, imzali)
        # günlük
        t = t0
        yollar = {"hesap:oku": ("GET", "/hesaplar"), "bakiye:oku": ("GET", "/bakiye"), "islem:oku": ("GET", "/islemler"),
                  "odeme:baslat": ("POST", "/odemeler")}
        for k in tok_kapsam:
            m, y = yollar[k]
            adet = 1 if rol not in ("normal",) else 2
            for _ in range(adet):
                t = t + timedelta(minutes=rng.randint(4, 14), seconds=rng.randint(0, 59))
                sonuc = 200
                if rol == "suresi_ret":
                    sonuc = 401
                if rol == "aud":
                    sonuc = 401
                if rol == "suresi_kabul":
                    sonuc = 200
                nedeni = {401: " neden=" + ("token_suresi_dolmus" if rol == "suresi_ret" else "hedef_kitle_uyumsuz")}.get(sonuc, "")
                gunluk.append((t, f"{t:%Y-%m-%d %H:%M:%S} jti={jti} istemci={c} istek={m} {y} sonuc={sonuc}{nedeni}"))
    gunluk.sort()
    return {"kayit": kayit, "tokenlar": tokenlar, "jtiler": jtiler, "gunluk": [x[1] for x in gunluk]}


def yaz(lab: Path, s: dict) -> None:
    h, v = s["_h"], s["v"]
    u.yaz(lab / "OKUBENI.txt", f"{v['banka']} açık bankacılık API inceleme kopyası (kurgusal).\n"
          f"Şu anki zaman (epoch, UTC): {s['simdi']}  =  {s['simdi_dt']:%Y-%m-%d %H:%M:%S} UTC\n"
          f"{v['td']}/ : ortakların token'ları ({{istemci}}.jwt)\n{v['kayit']} : kayıtlı istemciler ve izinli kapsamları\n"
          f"{v['log']} : API ağ geçidi kaydı (zamanlar UTC)\nAPI hedef kitlesi (aud): https://api.{v['alan']}/hesap-bilgisi\n")
    for c, tok in h["tokenlar"].items():
        u.yaz(lab / v["td"] / f"{c}.jwt", tok + "\n")
    u.yaz(lab / v["kayit"], "istemci;izinli_kapsam\n" + "".join(f"{c};{' '.join(k)}\n" for c, k in h["kayit"].items()))
    u.yaz(lab / v["log"], "\n".join(h["gunluk"]) + "\n")


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    td, kayit, log = v["td"], v["kayit"], v["log"]
    simdi = s["simdi"]
    kapsam = sh(f"cut -d. -f2 {td}/{s['ornek']}.jwt | base64 -d | grep -o '\"scope\":\"[^\"]*\"' | cut -d'\"' -f4", lab)
    aud = sh(f"for f in {td}/*.jwt; do a=$(cut -d. -f2 $f | base64 -d | grep -o '\"aud\":\"[^\"]*\"' | cut -d'\"' -f4); "
             f"case \"$a\" in */hesap-bilgisi) ;; *) basename $f .jwt;; esac; done", lab)
    sure = sh(f"for f in {td}/*.jwt; do e=$(cut -d. -f2 $f | base64 -d | grep -o '\"exp\":[0-9]*' | cut -d: -f2); "
              f"if [ \"$e\" -lt {simdi} ]; then basename $f .jwt; fi; done", lab).replace("\n", " ")
    alg = sh(f"for f in {td}/*.jwt; do if cut -d. -f1 $f | base64 -d | grep -q '\"alg\":\"none\"'; then basename $f .jwt; fi; done", lab)
    kaps = sh(f"for f in {td}/*.jwt; do c=$(basename $f .jwt); "
              f"sc=$(cut -d. -f2 $f | base64 -d | grep -o '\"scope\":\"[^\"]*\"' | cut -d'\"' -f4); "
              f"reg=$(awk -F';' -v c=$c '$1==c {{print $2}}' {kayit}); "
              f"for k in $sc; do echo \"$reg\" | tr ' ' '\\n' | grep -qxF \"$k\" || {{ echo $c; break; }}; done; done", lab)
    jti = sh(f"for f in {td}/*.jwt; do e=$(cut -d. -f2 $f | base64 -d | grep -o '\"exp\":[0-9]*' | cut -d: -f2); "
             f"if [ \"$e\" -lt {simdi} ]; then j=$(cut -d. -f2 $f | base64 -d | grep -o '\"jti\":\"[^\"]*\"' | cut -d'\"' -f4); "
             f"grep \"jti=$j \" {log} | grep 'sonuc=200' | grep -o 'jti=[^ ]*' | head -1 | cut -d= -f2; fi; done", lab)
    return sec_doldur({2: kapsam.replace("\n", " "), 3: aud, 4: sure, 5: alg, 6: kaps, 7: jti}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Token nasıl görünür?", """
Açık bankacılıkta bir fintech, müşteri rıza verince bankadan bir **erişim token'ı** alır. Çoğu zaman bu
bir **JWT**'dir (JSON Web Token). Üç parçadan oluşur, aralarında nokta vardır:
`BAŞLIK.YÜK.İMZA`. İlk token'a bak:
""", komut="cat <<td>>/<<ornek>>.jwt", sonra="""
Başlık ve yük **base64url** ile kodlanmış JSON'dur. Bu bir **şifreleme değil, kodlamadır**: herkes çözebilir.
Token'ın gizliliği değil, **bütünlüğü** imzayla korunur.
"""),
    Adim("Başlığı çözmek", """
`cut -d. -f1` noktayla ayrılmış ilk parçayı alır, `base64 -d` çözer. Başlık, imzanın hangi algoritmayla
atıldığını (`alg`) söyler:
""", komut="cut -d. -f1 <<td>>/<<ornek>>.jwt | base64 -d", sonra="""
`alg` değeri imza algoritmasıdır (örn. RS256). **`none`** değeri "imza yok" demektir; böyle bir token'ı kabul
eden API, kimin ürettiği önemsiz olduğu için tehlikededir. (Gerçek JWT'lerde dolgu `=` karakterleri atılır;
çözerken sona `=` eklemek ve `tr '_-' '/+'` gerekebilir. Bu lab'daki token'lar doğrudan çözülür.)
"""),
    Adim("Yükü (claim'leri) okumak", """
İkinci parça **yük**tür; token'ın iddialarını (claim) taşır. `python3 -m json.tool` okunaklı basar:
""", komut="cut -d. -f2 <<td>>/<<ornek>>.jwt | base64 -d | python3 -m json.tool", sonra="""
Önemli claim'ler: `iss` (kim verdi), `sub` (kimin adına), `aud` (**hedef kitle**: hangi API için), `scope`
(**kapsam**: ne yapabilir), `iat`/`exp` (verilme ve **bitiş** zamanı, epoch saniye), `jti` (token kimliği).
"""),
    Adim("Süreyi okumak: epoch", """
`exp` bir **epoch** değeridir (1970'ten beri geçen saniye). `date -u -d @DEĞER` bunu okunur tarihe çevirir.
Şu anki zamanı OKUBENI'den biliyoruz (<<simdi>>). Bu değeri çevir:
""", komut="date -u -d @<<simdi>>", sonra="""
Bir token'ın `exp` değeri şimdiki zamandan **küçükse** süresi geçmiştir ve API onu reddetmelidir.
"""),
    Adim("Hepsini toplu çözmek", """
Tek tek çözmek yerine bir döngü yaz. Her token için dosya adını ve yükünü basar:
""", komut="for f in <<td>>/*.jwt; do echo \"$f\"; cut -d. -f2 \"$f\" | base64 -d; echo; done", sonra="""
**Hacker gözüyle:** Analistin işi tek token okumak değil, **yüzlercesini** süzmektir. Döngü, `grep -o` ve
`cut` ile her token'dan yalnızca ilgilendiğin claim'i çekebilirsin.
"""),
    Adim("Kayıtlı kapsam ve API kaydı", """
Bir token'ın kapsamı, istemcinin **kayıtlı izinli kapsamını** aşmamalı. Kayıtlı kapsamları oku:
""", komut="cat <<kayit>>", sonra="""
Token kapsamı bu listeden **geniş** çıkıyorsa, token'ı veren taraf aşırı yetki vermiş demektir (en az yetki
ihlali). Bir de API'nin **gerçekte neyi kabul ettiğini** görmek için ağ geçidi kaydına bak:
"""),
    Adim("Ağ geçidi kaydı", """
Her satırda zaman, token kimliği (`jti`), istemci, istek ve sonuç kodu var. 401, API'nin token'ı reddettiği
anlamına gelir; 200 kabul demektir:
""", komut="head -5 <<log>>", sonra="""
Denetim sorusu: **Reddedilmesi gereken bir token için 200 görüyor muyuz?** Görüyorsak bu bir doğrulama
açığıdır ve düzeltilmesi gerekir. Bir sonraki bölümde bunu yapılandırmadan düzelteceksin.
"""),
]

GOREVLER = [
    Gorev("Bir JWT'nin başlık ve yük kısımları base64url ile kodlanmıştır. Bu ne anlama gelir?",
          Secmeli([
              ("Herkes çözüp okuyabilir; imza bütünlüğü korur, içeriğin gizliliğini sağlamaz",
               "Doğru. Kodlama gizlilik sağlamaz; bu yüzden token'a parola, kart numarası gibi sırlar konmaz."),
              ("İçerik şifrelidir; anahtarı olmayan hiçbir saldırgan içindeki claim'leri okuyamaz",
               "Yanlış. base64 şifreleme değildir; anahtar gerekmeden çözülür."),
              ("Token yalnızca bankanın sunucusunda çözülebilir; istemci uygulama içeriğini göremez",
               "Yanlış. İstemci de, aradaki herkes de çözebilir; bu yüzden token kısa ömürlü ve dar kapsamlı olmalı."),
              ("İmza yalnızca süs amaçlıdır; API, imzayı kontrol etmeden de token'a güvenebilir",
               "Yanlış. İmza token'ın değiştirilmediğini kanıtlar; kontrol edilmezse sahte token kabul edilir."),
          ], dogru=0),
          ("Kodlama ile şifreleme arasındaki farkı düşün.",
           "`cut -d. -f2 <<td>>/<<ornek>>.jwt | base64 -d` anahtarsız çalışıyor mu?",
           "Çalışıyor: demek ki içerik herkese açık, imza sadece bütünlük sağlar."),
          puan=20, baslik="Kodlama ≠ şifreleme"),
    Gorev("`<<td>>/<<ornek>>.jwt` token'ının **kapsamları** (scope) neler? (Boşlukla ayır.)",
          Kume("ornek_kapsam", tur="metin", bicim="kapsamlar, boşlukla ayrılmış (örn. hesap:oku bakiye:oku)"),
          ("Kapsam yükün `scope` alanındadır; yük, noktayla ayrılmış ikinci parça.",
           "`cut -d. -f2 dosya | base64 -d` ile yükü çöz, `scope` alanına bak.",
           "`cut -d. -f2 <<td>>/<<ornek>>.jwt | base64 -d | python3 -m json.tool`"),
          puan=30, baslik="Kapsamı oku"),
    Gorev("Bir token'ın hedef kitlesi (`aud`) bu API'den (`https://api.<<alan>>/hesap-bilgisi`) **farklı**: yani başka "
          "bir hizmet için üretilmiş. Hangi istemcinin token'ı? (Dosya adı, `.jwt` olmadan.)",
          Metin("aud", bicim="istemci adı"),
          ("Her token'ın yükünde `aud` alanı var. Hepsini çözüp karşılaştır.",
           "Toplu çözme döngüsünün çıktısında `\"aud\"` alanlarına bak; biri `/hesap-bilgisi` ile bitmiyor.",
           "`for f in <<td>>/*.jwt; do echo $f; cut -d. -f2 $f | base64 -d | grep -o '\"aud\":\"[^\"]*\"'; done`"),
          puan=40, baslik="Yanlış hedef kitle"),
    Gorev("Şu anki zamana (epoch <<simdi>>) göre **süresi geçmiş** token'lar hangi istemcilerin? Adları boşlukla "
          "yaz (`.jwt` olmadan).",
          Kume("suresi", tur="metin", bicim="istemci adları, boşlukla ayrılmış"),
          ("Her token'da `exp` alanı bir epoch değeri; şimdiki zamandan küçükse süresi geçmiş.",
           "Her token'dan `\"exp\":` değerini çek ve <<simdi>> ile karşılaştır.",
           "`for f in <<td>>/*.jwt; do echo $f $(cut -d. -f2 $f | base64 -d | grep -o '\"exp\":[0-9]*'); done`"),
          puan=40, baslik="Süresi geçmiş token'lar"),
    Gorev("Bir token'ın başlığındaki algoritma `none`: yani **imzasız**. Bu hangi istemcinin token'ı?",
          Metin("alg", bicim="istemci adı"),
          ("Algoritma yükte değil, başlıkta (ilk parça).",
           "Her token'ın ilk parçasını çöz ve `alg` değerine bak.",
           "`for f in <<td>>/*.jwt; do echo $f $(cut -d. -f1 $f | base64 -d); done`"),
          puan=40, baslik="İmzasız token"),
    Gorev("Bir istemcinin token'ı, `<<kayit>>` dosyasındaki **kayıtlı izinli kapsamından geniş**. Hangi istemci?",
          Metin("kapsam", bicim="istemci adı"),
          ("Her token'ın `scope` değerini kayıtlı kapsamla karşılaştır: fazladan bir kapsam var mı?",
           "Kayıt dosyasını `cat` ile oku, toplu çözmenin `scope` çıktısıyla yan yana koy.",
           "Fazladan kapsam genelde bir **işlem başlatma** (`odeme:baslat`) izni olur; onu taşıyan token'a bak."),
          puan=40, baslik="Aşırı kapsam"),
    Gorev("`<<log>>` kaydında, **süresi geçmiş bir token'ı kabul eden** (sonuç 200) bir satır var. O token'ın `jti` "
          "(token kimliği) değeri nedir?",
          Metin("jti", bicim="jti değeri (örn. 3fa9c0d812)"),
          ("Önce süresi geçmiş token'ların `jti` değerlerini çıkar; sonra günlükte bu kimliklerin sonuçlarına bak.",
           "Günlükte süresi geçmiş iki token'ın satırları var: biri 401, diğeri 200.",
           "`grep -E 'sonuc=200' <<log>>` içinde, süresi geçmiş iki istemciden birinin `jti=` değerini ara."),
          puan=50, baslik="Kabul edilen süresi geçmiş token"),
]


def _kapanis():
    return """
Token, bir **kimlik kartı** gibidir: içindeki yazıları herkes okuyabilir, güven imzadadır. Saldırgan gözüyle
çalınan, süresi geçmiş, imzasız ya da gereğinden geniş kapsamlı her token bir kapıdır; fintech'in token'ı
çalınırsa saldırgan fintech gibi davranır. Savunma gözüyle: imza **her istekte** doğrulanır, `alg: none`
kabul edilmez, `exp` ve `aud` kontrol edilir, kapsam kayıtlı kapsamı aşamaz ve token ömrü kısa tutulur.
"""


SEVIYE = Seviye(
    kimlik="c19b02", cilt=19, bolum=2, baslik="OAuth, Token ve Kapsam: Token'ı Çöz, Kaydı Oku",
    brifing="""
<<sahne>>

Selin: "JWT'leri çözmeyi öğrenmen şart; hiçbir şey kırmayacağız, sadece **okuyacağız**. Yedi token, bir
kayıtlı istemci listesi ve bir ağ geçidi kaydı var. Zamanlar UTC, şu anki zaman OKUBENI'de."

Mert: "Token'ı çözebilmek için anahtar gerekmediğini hatırla. O yüzden içine sır koyan herkes yanlış yapıyor."
""",
    adimlar=ADIMLAR, gorevler=GOREVLER, uret=uret, yaz=yaz, coz=coz, kapanis=_kapanis(),
    gercek_hayat="""
- **`alg: none` ve imza doğrulaması:** JWT kütüphanelerinde, imza algoritması `none` olan token'ları kabul eden
  yanlış yapılandırmalar yıllarca kamuya açık güvenlik bülteni ve araştırma konusu oldu. Bugün iyi kütüphaneler
  bunu varsayılan olarak reddeder; ama yapılandırmada izin verilen algoritma listesini açıkça tanımlamak hâlâ
  gerekir.
- **Tespit:** Ağ geçidi günlüğünde, `exp` süresi geçmiş ya da hedef kitlesi (`aud`) farklı token'la gelen ve yine
  de 200 dönen isteği aramak; token kapsamını istemcinin kayıtlı kapsamıyla düzenli karşılaştırmak. İkisi de kayıt
  tabanlı basit kontrollerdir.
- **Önleme:** Kısa ömürlü token, her istekte imza + `exp` + `aud` + kapsam doğrulaması, kapsamın sunucuda
  zorlanması ve token'a hassas veri (kart numarası, parola) konmaması. Açık bankacılıkta çalınan token, fintech'in
  yerine geçmek demektir; kısa ömür bu hasarı sınırlar.
""",
    sure_hedef_dk=40,
)
