"""Cilt 1 · Bölüm 4 — Metin İşleme ve Pipe: Logları Konuşturmak.

Beceri: üç akış ve yönlendirme, pipe, grep/wc/cut/sort/uniq/awk ile web erişim logunu ve
SSH auth.log'unu konuşturmak. Kitabın 10 alıştırmasından 1-8 görevlere çevrildi; 9.
(olay özeti) Bölüm 7'nin kapanış görevinde, 10. (kullanıcı listesi) Bölüm 5'te.

Vakalar: her tohumda farklı müşteri, farklı saldırı karışımı (brute-force başarılı/başarısız,
SQL injection, tarayıcı yedek dosyaya ulaştı/ulaşamadı, bazen path traversal). Loglar
`hy.ortak.loglar` ile üretilir.
"""
from __future__ import annotations

import re
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Metin, Sayi, norm
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import loglar
from hy.ortak.vakalar import musteri_sec

LOG_KLASORLERI = ["loglar", "kayitlar", "olay_kayitlari", "toplanan_loglar"]
HAYIR = ["hayır", "hayir", "başarısız", "basarisiz", "olmadı", "olmadi", "yok", "hayır olmadı"]
HAYIR_NORM = {norm(x) for x in HAYIR}
YOK = ["yok", "hayır", "hayir", "ulaşamadı", "ulasamadi", "indiremedi", "hiçbiri"]
TARAYICI_ADLARI = {
    "Nikto": ["Nikto", "nikto/2.5.0", "Mozilla/5.00 (Nikto/2.5.0)"],
    "gobuster": ["gobuster", "gobuster/3.6"],
    "ffuf": ["ffuf", "Fuzz Faster U Fool", "Fuzz Faster U Fool v2.1.0"],
}


def uret(rng):
    m = musteri_sec(rng)
    log_k = rng.choice(LOG_KLASORLERI)
    ekler = ("traversal",) if rng.random() < 0.5 else ()
    web = loglar.web_logu(rng, m, saldirilar=("brute", "sqli", "tarama") + ekler,
                          basari={"brute": rng.random() < 0.6, "tarama": rng.random() < 0.6},
                          brute_deneme=(28, 39), tarama_istek=(16, 24))   # 401 sayısı ≤ 41 (yönetici ≤ 2 hata)
    ssh = loglar.ssh_logu(rng, m, baslangic=web["baslangic"] - timedelta(minutes=rng.randint(20, 50)),
                          sure_dk=220, haric=web["ipler"], mesru_ipler=[web["admin_ip"]])
    o, sa = web["ozet"], web["saldirilar"]
    brute, sqli, tarama = sa["brute"], sa["sqli"], sa["tarama"]
    sayfa = sqli["hedef"]
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — web ve SSH logları",
        "musteri": m,
        "log_k": log_k,
        "access": loglar.metin(web),
        "auth": loglar.metin(ssh),
        "web": {"ozet": o, "saldirilar": sa, "admin_ip": web["admin_ip"], "mesru": web["mesru"]},
        "ssh": {"ozet": ssh["ozet"], "hesaplar": ssh["hesaplar"], "satirlar": ssh["satirlar"]},
        "grep401": sum("401" in s for s in web["satirlar"]),
        "metin": {
            "musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"],
            "sunucu": m["sunucu"], "alan": m["alan"], "log_k": log_k, "giris": m["giris"],
        },
        "cevaplar": {
            "toplam": o["toplam"],
            "en_cok_ip": o["en_cok_ip"],
            "sayi_401": o["sayi_401"],
            "brute_sonuc": [brute["zaman"]] if brute["basarili"] else HAYIR,
            "sqli_sayfa": [sayfa, sayfa + "?" + sqli["parametre"] + "=", sayfa + "?" + sqli["parametre"]],
            "tarayici": TARAYICI_ADLARI[tarama["arac"]],
            "yedek": [tarama["dosya"]] if tarama["dosya"] else YOK,
            "ssh_deneme": ssh["ozet"]["en_cok_basarisiz"],
            "gecersiz": ssh["ozet"]["gecersiz_kullanicilar"],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    (lab / s["log_k"]).mkdir(parents=True, exist_ok=True)
    (lab / s["log_k"] / "access.log").write_text(s["access"], encoding="utf-8")
    (lab / s["log_k"] / "auth.log").write_text(s["auth"], encoding="utf-8")
    (lab / "OKUBENI.txt").write_text(
        f"Kimden : {m['kisi']} — {m['ad']}\n"
        f"Konu   : {m['sunucu']} logları\n\n"
        f"{m['hikaye']}\n"
        f"Web sunucusunun erişim logunu (access.log) ve SSH giriş kaydını (auth.log) {s['log_k']}/\n"
        "klasörüne koydum. Ne olduğunu anlamamıza yardım eder misiniz?\n", encoding="utf-8")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: kitaptaki boru hatlarıyla çözer."""
    a, au = f"{s['log_k']}/access.log", f"{s['log_k']}/auth.log"
    toplam = _sh(f"wc -l < {a}", lab)
    en_cok = _sh(f"cut -d' ' -f1 {a} | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    sayi_401 = _sh(f"grep -c '\" 401 ' {a}", lab)
    brute_ip = _sh(f"grep '\" 401 ' {a} | cut -d' ' -f1 | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}'", lab)
    basari = _sh(f"grep '^{brute_ip} ' {a} | grep 'POST' | grep '\" 200 ' | head -1 | cut -d: -f2-4 | cut -d' ' -f1", lab)
    sqli = _sh(f"grep -iE 'union|select' {a} | head -1 | awk '{{print $7}}' | cut -d'?' -f1", lab)
    tarayici = _sh(f"awk -F'\"' '{{print $6}}' {a} | grep -oiE 'nikto|gobuster|fuzz faster u fool' | head -1", lab)
    yedek = _sh(f"grep -iE 'nikto|gobuster|fuzz faster' {a} | grep '\" 200 ' | grep -v robots.txt | awk '{{print $7}}'", lab)
    deneme = _sh(f"grep 'Failed password' {au} | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -1 | awk '{{print $1}}'", lab)
    gecersiz = _sh(f"grep 'invalid user' {au} | grep -oE 'invalid user [^ ]+' | awk '{{print $3}}' | sort -u", lab)
    return {1: toplam, 2: en_cok, 3: sayi_401, 4: basari or "hayır", 5: sqli, 6: tarayici, 7: yedek or "yok",
            8: deneme, 9: ",".join(gecersiz.split())}


# ---------------------------------------------------------------- sık hata geri bildirimleri

def _satirlar(b) -> list:
    yol = b.lab / b.senaryo["log_k"] / "access.log"
    try:
        return yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []


def _toplam_hata(g, beklenen, b):
    n = int(g)
    if n == len(b.senaryo["ssh"]["satirlar"]):
        return "Bu auth.log'un satır sayısı. Soru web sunucusunun erişim logunu (access.log) soruyor."
    if n == beklenen - 1 or n == beklenen + 1:
        return "Çok yakın. `wc -l` her satır sonunu sayar; dosyayı başka bir araçla mı saydın? `wc -l < access.log` dene."
    return None


def _en_cok_hata(ip, beklenen, b):
    o = b.senaryo["web"]["ozet"]
    if ip == o["ardisik_en_cok_ip"]:
        return ("Bu IP'nin istekleri yan yana en uzun bloğu oluşturuyor, ama toplamda en çok değil. `uniq` sadece "
                "ardışık tekrarları birleştirir: önce `sort` ile aynı IP'leri yan yana getir.")
    sayilar = o["ip_sayilari"]
    if sayilar.get(ip) == min(sayilar.values()):
        return "Bu en az istek gönderen IP. `sort -n` küçükten büyüğe sıralar; ters çevirmek için `-r` ekle (`sort -rn`)."
    return None


def _401_hata(g, beklenen, b):
    n = int(g)
    if n == b.senaryo["grep401"]:
        return ("`grep 401` satırın herhangi bir yerinde 401 geçenleri sayar; bazı cevap boyutlarında da 401 var "
                "(örn. 4012 bayt). Sadece durum kodu 401 olanları say: `grep -c '\" 401 '`.")
    if n == b.senaryo["web"]["saldirilar"]["brute"]["deneme"]:
        return "Sadece saldırganın 401'lerini saydın. Soru, logdaki bütün 401 cevaplarını soruyor."
    return None


def _brute_hata(g, beklenen, b):
    sa = b.senaryo["web"]["saldirilar"]["brute"]
    if g in ("", "basarili", "evet basarili", "oldu"):       # "evet" ön ek olarak atılınca boş kalır
        if sa["basarili"]:
            return "Evet, başarılı. Şimdi o başarılı girişin saatini SS:DD:SS biçiminde yaz."
        return "Emin misin? Saldırganın giriş sayfasına yaptığı son POST isteğinin cevap koduna bak."
    if sa["basarili"] and g in HAYIR_NORM:
        return "Saldırganın giriş sayfasına yaptığı POST isteklerinin en sonuncusuna bak: kodu hâlâ 401 mi?"
    if not re.fullmatch(r"\d{2}:\d{2}(:\d{2})?", g):
        return None
    if sa["basarili"] and g == sa["zaman"][:5]:
        return "Dakikası doğru; saniyesini de ekle (SS:DD:SS)."
    for satir in _satirlar(b):
        if f":{g} " in satir or (len(g) == 5 and f":{g}:" in satir):
            ip = satir.split()[0]
            if ip == b.senaryo["web"]["admin_ip"]:
                return ("Bu saatteki başarılı giriş meşru yöneticiye ait: ofis IP'sinden geliyor ve öncesinde onlarca "
                        "deneme yok. Brute-force yapan IP'ye odaklan.")
            if ip == sa["ip"] and '" 401 ' in satir:
                return "Bu saatteki deneme 401 almış, yani başarısız. Başarılı giriş 401 yerine 200 alır."
    return None


def _sqli_hata(g, beklenen, b):
    m = b.senaryo["musteri"]
    if m["giris"].rsplit("/", 1)[-1].casefold() in g:
        return "Bu giriş sayfası; ona parola denemesi (brute-force) yapıldı. SQL injection izleri `UNION`/`SELECT` ve tırnak içerir."
    trav = b.senaryo["web"]["saldirilar"].get("traversal")
    if trav and trav["hedef"].rsplit("/", 1)[-1].casefold() in g:
        return "Bu sayfaya `../` ile dizin atlama (path traversal) denendi. SQL injection değil."
    return None


def _yedek_hata(g, beklenen, b):
    if g in ("robots.txt", "/robots.txt"):
        return "`robots.txt` herkese açık, zararsız bir dosyadır; yedek değil. Tarayıcının 200 aldığı başka bir dosya var mı?"
    m = b.senaryo["musteri"]
    if g == m["yedek"].lstrip("/").casefold() and not b.senaryo["web"]["saldirilar"]["tarama"]["dosya"]:
        return "Bu dosya istenmiş, ama cevap kodu 404: sunucuda bulunamamış. Yani tarayıcı ona ulaşamamış."
    return None


def _ssh_hata(g, beklenen, b):
    n = int(g)
    ip = b.senaryo["ssh"]["ozet"]["en_cok_basarisiz_ip"][0]
    satirlar = b.senaryo["ssh"]["satirlar"]
    desen = re.compile(rf"(?<![\d.]){re.escape(ip)}(?![\d.])")
    if n == sum(bool(desen.search(s)) for s in satirlar):
        return ("Bu IP'nin geçtiği bütün satırları saydın (bağlantı kapandı, invalid user gibi satırlar dahil). "
                "Sadece `Failed password` satırlarını say.")
    if n == sum(b.senaryo["ssh"]["ozet"]["basarisiz"].values()):
        return "Bu bütün IP'lerin toplamı. IP başına say: `... | sort | uniq -c`."
    return None


def _gecersiz_hata(g, beklenen, b):
    verilen = set(g.split())
    gercek = {h.casefold() for h in b.senaryo["ssh"]["hesaplar"]} & verilen
    if gercek:
        return (f"{', '.join(sorted(gercek))} sistemde var olan hesap(lar). Soru, var olmayan kullanıcı adlarını "
                "(`invalid user`) soruyor.")
    return None


ADIMLAR = [
    Adim("Üç akış: girdi, çıktı, hata", """
Her komutun üç kanalı vardır: **0 stdin** (girdi, klavye), **1 stdout** (çıktı, ekran),
**2 stderr** (hata çıktısı, yine ekran). Yönlendirme ile bunları değiştirirsin:

- `komut > dosya` çıktıyı dosyaya yazar (dosyayı ezer), `>>` sonuna ekler
- `komut 2> hatalar.txt` sadece hataları yazar, `2>/dev/null` hataları çöpe atar
- `komut > hepsi.txt 2>&1` çıktı ve hataları aynı dosyaya yazar

`/dev/null` Linux'un kara deliğidir: içine yazılan her şey yok olur.
""", komut="ls /root 2>/dev/null || echo \"hata gizlendi\""),
    Adim("Pipe: komutları birleştirmek", """
`|` (pipe) bir komutun çıktısını diğerinin girdisi yapar. Linux'un gücü buradan gelir: her
araç tek bir işi iyi yapar, sen onları boru hattı gibi birleştirirsin.
""", komut="cat <<log_k>>/access.log | head -n 3"),
    Adim("Bir log satırının anatomisi", """
Az önce gördüğün satırlardan birini parçalayalım:

```
203.0.113.7 - - [12/Nov/2026:10:05:02 +0300] "POST /admin/login.php HTTP/1.1" 401 120 "-" "curl/8.5.0"
```

- `203.0.113.7` istemcinin IP adresi (boşlukla ayrılmış 1. alan)
- `[12/Nov/2026:10:05:02 +0300]` isteğin zamanı
- `"POST /admin/login.php HTTP/1.1"` metod ve istenen sayfa (6. ve 7. alanlar)
- `401` sunucunun cevap kodu (9. alan; 401 = yetkisiz, 200 = tamam, 404 = yok, 500 = sunucu hatası)
- `120` cevabın bayt cinsinden boyutu
- `"-"` nereden gelindiği (referer), `"curl/8.5.0"` istemcinin kendini tanıttığı **User-Agent**
"""),
    Adim("grep ve wc", """
`grep` desene uyan satırları bulur, `wc -l` satır sayar. `grep`'in sık seçenekleri: `-i`
(büyük-küçük harf duyarsız), `-v` (desene **uymayan** satırlar), `-c` (eşleşen satır sayısı),
`-n` (satır numarasıyla), `-r` (klasörde özyinelemeli), `-oE` (sadece eşleşen parçayı, gelişmiş
desenle). Kaç tane POST isteği var?
""", komut="grep -c \"POST\" <<log_k>>/access.log"),
    Adim("Ezberlenecek tek satır: cut | sort | uniq -c | sort -rn", """
`cut -d' ' -f6` her satırı boşluktan böler ve 6. alanı alır. `sort` aynı değerleri yan yana
getirir, `uniq -c` her değerin kaç kez geçtiğini sayar, son `sort -rn` sonucu büyükten küçüğe
dizer. Bu kalıbı ezberle; log analizinde en çok kullanacağın satır budur. Önce hangi HTTP
metodlarının kullanıldığına bakalım:
""", komut="cut -d' ' -f6 <<log_k>>/access.log | sort | uniq -c | sort -rn", sonra="""
Dikkat: `uniq` sadece **yan yana** duran tekrarları birleştirir. `sort`'u atlarsan aynı
değer birkaç ayrı satırda sayılır ve sonuç yanlış çıkar. 1. alanı (IP) seçersen aynı boru
hattı "kim ne kadar istek gönderdi?" sorusunu cevaplar.
"""),
    Adim("awk ile tırnaktan bölmek", """
`awk -F'"'` satırı **çift tırnak** karakterinden böler. Böylece 2. parça istek satırı,
6. parça User-Agent olur. Normal kullanıcılar `Mozilla/5.0 ...` gibi tarayıcı kimliğiyle
gelir; komut satırı araçları ve güvenlik tarayıcıları çoğu zaman kendi adını söyler.
""", komut="awk -F'\"' '{print $2}' <<log_k>>/access.log | head -n 3"),
    Adim("Saldırı imzaları", """
Bazı karakter dizileri bilinen saldırıların parmak izidir: `UNION`/`SELECT` ve tek tırnak
(SQL injection), `../` (dizin atlama), `<script` (XSS). Kaç satırda böyle bir iz var?
""", komut="grep -ciE \"union|select|\\.\\./|<script\" <<log_k>>/access.log", sonra="""
**Hacker gözüyle:** Saldırgan için ders: yaptığın her istek bir yerde iz bırakır. Varsayılan
User-Agent'la (curl, Nikto, sqlmap) tarama yapmak savunmacıya "ben buradayım" diye
bağırmaktır. Savunmacı için ders: bu birkaç komut, pahalı bir ürün olmadan bir saldırıyı
yeniden kurgulamaya çoğu zaman yeter.
"""),
    Adim("auth.log: SSH'ın günlüğü", """
`auth.log` SSH girişlerini kaydeder. `Failed password` başarısız deneme, `Accepted` başarılı
giriş, `Invalid user` sistemde olmayan bir kullanıcı adıyla deneme demektir. Kaç başarısız
parola denemesi var?
""", komut="grep -c \"Failed password\" <<log_k>>/auth.log"),
]

GOREVLER = [
    Gorev("`access.log` dosyasında toplam kaç istek (satır) var?",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Her istek logda tek bir satırdır.",
           "Satır sayan komut `wc`, seçeneği `-l`.",
           "`wc -l <<log_k>>/access.log`"),
          puan=20, baslik="Toplam istek"),
    Gorev("En çok istek gönderen IP adresi hangisi?",
          IP("en_cok_ip", sik_hatalar=_en_cok_hata),
          ("IP her satırın ilk alanı. IP'leri çıkarıp sayman gerek.",
           "`cut -d' ' -f1` IP'leri verir; ardından `sort | uniq -c | sort -rn`.",
           "`cut -d' ' -f1 <<log_k>>/access.log | sort | uniq -c | sort -rn | head -3` — en üstteki satır."),
          puan=30, baslik="En gürültücü IP"),
    Gorev("Sunucu kaç kez **401** (yetkisiz) cevabı vermiş?",
          Sayi("sayi_401", sik_hatalar=_401_hata),
          ("Cevap kodu satırda tırnaktan hemen sonra gelir.",
           "`grep -c` eşleşen satırları sayar. Ama `401` sadece kod olarak mı geçiyor? Boyutlara da bak.",
           "Desene tırnağı ve boşlukları da kat: `grep -c '\" 401 ' <<log_k>>/access.log`"),
          puan=30, baslik="Yetkisizler"),
    Gorev("Biri `<<giris>>` sayfasına peş peşe parola denemiş (brute-force). Saldırı başarılı oldu "
          "mu? Olduysa başarılı girişin saatini **SS:DD:SS** biçiminde yaz; olmadıysa `hayır` yaz.",
          Metin("brute_sonuc", on_ekleri_at=("evet,", "evet", "saat"), sik_hatalar=_brute_hata,
                bicim="SS:DD:SS ya da hayır"),
          ("Önce brute-force yapan IP'yi bul: en çok 401 alan IP.",
           "O IP'nin satırlarını `grep '^IP '` ile süz. 401'lerden sonra aynı sayfadan 200 almış mı?",
           "`grep '^IP ' <<log_k>>/access.log | grep POST | tail -3` — son POST'un kodu 200 ise o satırın saati cevaptır."),
          puan=40, baslik="Kapı açıldı mı"),
    Gorev("SQL injection denemesi yapılan sayfa hangisi? (sadece sayfa adı, örn. `/sayfa.php`)",
          Metin("sqli_sayfa", sadece_ad=True, sik_hatalar=_sqli_hata, bicim="sayfa yolu"),
          ("SQL injection'ın imzalarını eğitimde gördün.",
           "`grep -iE \"union|select\"` ile satırları bul; 7. alan istenen sayfadır.",
           "`grep -iE \"union|select\" <<log_k>>/access.log | awk '{print $7}'` — `?` işaretinden önceki kısım sayfa adı."),
          puan=30, baslik="Enjeksiyon"),
    Gorev("Bir IP, bilinen bir **güvenlik tarayıcısı** (scanner) kullanmış. Aracın adı ne?",
          Metin("tarayici", bicim="araç adı"),
          ("Araçlar kendini User-Agent alanında tanıtır.",
           "`awk -F'\"' '{print $6}'` User-Agent'ları verir; `sort | uniq -c` ile özetle.",
           "`awk -F'\"' '{print $6}' <<log_k>>/access.log | sort | uniq -c | sort -rn` — Mozilla tarayıcıları ve curl/python dışında kalan araç."),
          puan=30, baslik="Tarayıcının adı"),
    Gorev("Tarayıcı, müşterinin hassas bir yedek ya da yapılandırma dosyasını **200** koduyla indirebilmiş "
          "mi? İndirdiyse dosyanın yolunu, indiremediyse `yok` yaz.",
          Metin("yedek", sadece_ad=True, sik_hatalar=_yedek_hata, bicim="dosya yolu ya da yok"),
          ("Tarayıcının isteklerinin çoğu 404 alır. 200 alanlara odaklan.",
           "Tarayıcının satırlarını adıyla `grep`'le, sonra `grep '\" 200 '` ile süz.",
           "`grep -i <araç> <<log_k>>/access.log | grep '\" 200 '` — robots.txt herkese açıktır; geriye kalan var mı?"),
          puan=35, baslik="Sızan yedek"),
    Gorev("`auth.log`'da **en çok başarısız parola denemesi** yapan IP kaç deneme yapmış?",
          Sayi("ssh_deneme", sik_hatalar=_ssh_hata),
          ("Başarısız denemeler `Failed password` satırlarıdır.",
           "Önce bu satırları süz, sonra IP'leri çıkarıp say: `grep -oE 'from [0-9.]+'`.",
           "`grep \"Failed password\" <<log_k>>/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn`"),
          puan=35, baslik="SSH kapısında"),
    Gorev("`auth.log`'da sistemde **var olmayan** kullanıcı adlarıyla (invalid user) giriş denenmiş. "
          "Hangi kullanıcı adları denenmiş? (virgülle ayır)",
          Kume("gecersiz", sik_hatalar=_gecersiz_hata, bicim="virgülle ayrılmış kullanıcı adları"),
          ("sshd, olmayan bir kullanıcıyı `invalid user` diye işaretler.",
           "`grep \"invalid user\" <<log_k>>/auth.log` satırları verir; kullanıcı adı `user` kelimesinden sonra.",
           "`grep -oE 'invalid user [^ ]+' <<log_k>>/auth.log | sort -u`"),
          puan=35, baslik="Olmayan kullanıcılar"),
]


SEVIYE = Seviye(
    kimlik="c01b04",
    cilt=1,
    bolum=4,
    baslik="Metin İşleme ve Pipe: Logları Konuşturmak",
    brifing="""
Telefon çalıyor. Arayan **<<musteri>>**'den <<kisi>>: "<<hikaye>> Sunucunun
(<<sunucu>>) web ve SSH loglarını size gönderdim. İçinde bir şey var mı, bakabilir misiniz?"

Selin seni masasına çağırıyor: "Deniz bugün SOC'ta, sen onun gözlerisin. Pahalı bir güvenlik
ürünü yok; sadece `grep`, `cut`, `sort`, `uniq` ve `awk` var. Bu kadarı çoğu zaman yeter."

Deniz omzunun üstünden bakıyor: "Önce toplamı, sonra en gürültücüyü, sonra hata kodlarını.
Logu sırayla sorgula, o konuşur."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırgan için bu bölümün dersi: yaptığın her istek bir yerde iz bırakır. Yavaş yapılan bir
brute-force bile `uniq -c` ile ortaya çıkar; varsayılan User-Agent'la gelen bir tarayıcı adını
kendisi söyler. Savunmacı için ders: `cut | sort | uniq -c | sort -rn`, `grep -c '" 401 '` ve
`awk -F'"'` gibi birkaç satır, bir saldırıyı dakikalar içinde yeniden kurgulamaya yeter. Asıl
zor olan logu tutmak ve **bakmaktır**.
""",
    gercek_hayat="""
- **Log4Shell (2021):** Log4j kütüphanesindeki açık ortaya çıktığında, saldırı denemeleri web
  loglarında `jndi` kelimesini içeren tuhaf dizeler olarak görünüyordu. Savunmacılar ilk
  saatlerde kendi loglarını tam da bu bölümdeki gibi `grep` ile tarayıp "bize de denendi mi,
  kimden geldi?" sorusunu cevapladı.
- **SIEM ürünleri:** Splunk, Elastic gibi SIEM (güvenlik olay yönetimi) ürünleri temelde bu
  bölümdeki mantığı otomatikleştirir: logları toplar, sayar, gruplar ve eşiği aşan durumlarda
  alarm üretir. Altta yatan düşünceyi bilen analist, aracı da çok daha iyi kullanır.
- **Fark edilmeyen izler:** Olay müdahalesi raporlarında saldırının izlerinin loglarda
  günlerce, bazen haftalarca durduğu ama kimsenin bakmadığı çok sık yazılır.
""",
    sure_hedef_dk=35,
)
