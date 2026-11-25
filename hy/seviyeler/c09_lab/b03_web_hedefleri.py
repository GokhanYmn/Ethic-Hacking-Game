"""Cilt 9 · Bölüm 3 — Web Hedeflerini Kur.

Beceri: DVWA / Juice Shop / WebGoat'ı compose ile kurmak; Raspberry Pi'nin arm64 olduğunu hesaba
katarak imaj seçmek (`vulnerables/web-dvwa` yalnızca amd64'tür; `ghcr.io/digininja/dvwa` çok
mimarilidir); `docker manifest inspect` ile mimari doğrulama; port eşlemelerini 127.0.0.1'e bağlamak.

Not: manifest dosyaları KURGUSAL örnek çıktılardır; imaj desteği zamanla değişebilir. WebGoat'ın
arm64 desteği bu seviyede bilinçli olarak "belirsiz" bırakılmıştır; doğru alışkanlık, kurmadan önce
kendi makinende `docker manifest inspect` ile kontrol etmektir.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

DVWA_ESKI = "vulnerables/web-dvwa"
DVWA_YENI = "ghcr.io/digininja/dvwa"
JUICE = "bkimminich/juice-shop"
WEBGOAT = "webgoat/webgoat"

VAKALAR = [
    {
        "ad": "Kalkan Güvenlik — stajyer Cilt 5 lab'ı", "kod": "kalkan", "ekstra": "registry.kalkan.lab/ik-portal",
        "brifing": """
Selin: "Cilt 5'in web pratiğini kendi makinende yapabilmen için DVWA ve Juice Shop lazım.
Kitaptaki compose dosyası eski; hâlâ `vulnerables/web-dvwa` kullanıyor. Pi'ne kuracaksın, yani
arm64. Önce neyin çalışıp neyin çalışmayacağını kontrol et, sonra güvenli bir dosya yaz."

Mert: "Bir de portları ağa açık bırakma. Kalkan'ın ofis Wi-Fi'ında DVWA'yı herkes görsün
istemeyiz. Geçen yıl biri `0.0.0.0` bırakmıştı, Deniz'in SOC'u sabaha kadar alarm izledi."

Dosyalar: `kurulum_notu.txt`, `eski_lab.yml`, `manifest_*.txt`.
""",
    },
    {
        "ad": "Paramix — geliştirici güvenlik eğitimi", "kod": "paramix", "ekstra": "registry.paramix.lab/odeme-demo",
        "brifing": """
Ece Hanım (Paramix CTO'su) arıyor: "Yazılımcılarımıza güvenli kod eğitimi vereceğiz. Eğitmenlerin
dizüstü yerine küçük Raspberry Pi'lerde DVWA ve Juice Shop çalıştırmasını istiyorum; hem ucuz
hem sıfırlaması kolay."

Selin: "Eğitim ortamı şirket ağına bağlı olacak. Yani yanlış port bağı, 80 geliştiricinin
erişebileceği zafiyetli bir site demek. Müşterinin eski compose dosyasını düzelt, mimariyi kontrol et."

Dosyalar: `kurulum_notu.txt`, `eski_lab.yml`, `manifest_*.txt`.
""",
    },
    {
        "ad": "Mert'in Pi'si — Juice Shop meydan okumaları", "kod": "mert", "ekstra": "registry.mert.lab/ev-panel",
        "brifing": """
Mert gülümsüyor: "Juice Shop'un iş mantığı açıkları var ya, Cilt 10 için tam aradığım hedef.
Evdeki Pi'ye kurmak istiyorum. Ama internette bulduğum compose dosyası her şeyi `0.0.0.0`'a açıyor
ve eski bir DVWA imajı kullanıyor; Pi'de çalışmıyor."

Selin: "Mert'in dosyasını düzelt. Mimari uyumlu imaj, 127.0.0.1 bağı. Ardından kendi
`lab-web.yml`'ni sıfırdan yazarak öğrendiğini göster."

Dosyalar: `kurulum_notu.txt`, `eski_lab.yml`, `manifest_*.txt`.
""",
    },
]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    p_dvwa = rng.randrange(8081, 8180)
    p_juice = rng.randrange(3000, 3100)
    p_goat = rng.randrange(8200, 8300)
    ekstra_arm = rng.choice([True, False])
    servisler = [("dvwa", DVWA_ESKI, [(p_dvwa, 80)]),
                 ("juice-shop", JUICE, [(p_juice, 3000)]),
                 ("webgoat", WEBGOAT, [(p_goat, 8080), (9090, 9090)])]
    while True:
        bicimler = [[rng.choice(["acik", "hepsi", "lokal"]) for _ in s[2]] for s in servisler]
        duz = [b for sat in bicimler for b in sat]
        if duz.count("lokal") >= 1 and (duz.count("acik") + duz.count("hepsi")) >= 2:
            break
    acik = sum(1 for b in duz if b != "lokal")
    desteklemeyen = [DVWA_ESKI] + ([] if ekstra_arm else [v["ekstra"]])
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v,
        "portlar": {"dvwa": p_dvwa, "juice": p_juice, "goat": p_goat},
        "servisler": servisler, "bicimler": bicimler, "ekstra_arm": ekstra_arm,
        "metin": {"dvwa_port": str(p_dvwa), "juice_port": str(p_juice), "dvwa_yeni": DVWA_YENI, "juice": JUICE,
                  "dvwa_eski": DVWA_ESKI},
        "cevaplar": {"desteklemeyen": desteklemeyen, "acik": acik, "adres": f"127.0.0.1:{p_dvwa}"},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "kurulum_notu.txt",
          "# Kurulum şartnamesi (Selin)\n"
          f"dvwa_port: {s['portlar']['dvwa']}\n"
          f"juice_port: {s['portlar']['juice']}\n"
          "# DVWA konteyner portu 80, Juice Shop konteyner portu 3000.\n"
          "# Bütün portlar yalnızca 127.0.0.1'e bağlanacak.\n")

    def man(dosya, imaj, plat):
        u.yaz(lab / dosya, "# Kurgusal örnek çıktı. Gerçek durum zamanla değişebilir:\n"
                           "# kendi makinende `docker manifest inspect <imaj>` ile kontrol et.\n"
                           f"imaj: {imaj}\nplatformlar: {plat}\n")
    man("manifest_vulnerables_dvwa.txt", DVWA_ESKI, "linux/amd64")
    man("manifest_digininja_dvwa.txt", DVWA_YENI, "linux/amd64, linux/arm64")
    man("manifest_juice_shop.txt", JUICE, "linux/amd64, linux/arm64")
    man("manifest_ekstra.txt", v["ekstra"], "linux/amd64, linux/arm64" if s["ekstra_arm"] else "linux/amd64")
    u.yaz(lab / "manifest_webgoat.txt",
          "# Bu imajın mimari desteği BİLİNMİYOR (kurgusal not: elimizde doğrulanmış bir çıktı yok).\n"
          "# Kurmadan önce kendi makinende `docker manifest inspect webgoat/webgoat` ile kontrol et.\n"
          f"imaj: {WEBGOAT}\nplatformlar: bilinmiyor\n")
    satir = ["services:"]
    for (ad, imaj, pl), bic in zip(s["servisler"], s["bicimler"]):
        satir += [f"  {ad}:", f"    image: {imaj}", "    ports:"]
        for (h, c), b in zip(pl, bic):
            on = {"acik": "", "hepsi": "0.0.0.0:", "lokal": "127.0.0.1:"}[b]
            satir.append(f'      - "{on}{h}:{c}"')
        satir.append("    restart: unless-stopped")
    u.yaz(lab / "eski_lab.yml", "\n".join(satir) + "\n")


# ------------------------------------------------------------------ kontroller

def _acik_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    toplam = sum(len(x) for x in b.senaryo["bicimler"])
    if n == toplam:
        return "Bütün portları saydın. `127.0.0.1:` ile başlayanlar yalnızca senin makinene açık; onları sayma."
    if n == beklenen - 1:
        return "Bir tane eksik: `0.0.0.0:` ile yazılanlar da, **hiç adres yazılmayanlar** da bütün arayüzlere açıktır."
    return None


def _eski_duzelt(b: Baglam) -> Sonuc:
    ad = "eski_lab.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    hata, d = o.compose_denetle(yol, ad)
    if hata:
        return hata
    s = b.senaryo
    sv = o.servisler(d)
    for gerekli in ("dvwa", "juice-shop"):
        if gerekli not in sv:
            return Sonuc(False, f"`{gerekli}` servisi dosyadan çıkmış. Sadece sorunlu satırları düzelt, servisleri silme.")
    for ad_s, imaj, pl in s["servisler"]:
        if ad_s not in sv:
            continue
        mevcut = o.portlar(sv[ad_s])
        if any(p.get("hata") for p in mevcut):
            return Sonuc(False, f"`{ad_s}` servisinin port satırı anlaşılamadı.")
        beklenen = {(h, c) for h, c in pl}
        if {(p["host"], p["konteyner"]) for p in mevcut} != beklenen:
            return Sonuc(False, f"`{ad_s}` servisinin port numaralarını değiştirmişsin. Yalnızca başına `127.0.0.1:` ekle; "
                                "numaralar aynı kalsın.", yakin=True)
        dis = [p for p in mevcut if not p["lokal"]]
        if dis:
            return Sonuc(False, f"`{ad_s}` hâlâ ağa açık bir port taşıyor. Hepsi `\"127.0.0.1:ANA:KONTEYNER\"` biçiminde olmalı.",
                         yakin=True)
    if o.imaj_depo(sv["dvwa"].get("image")) == DVWA_ESKI:
        return Sonuc(False, f"`{DVWA_ESKI}` yalnızca amd64'tür; Pi'de (arm64) çalışmaz. `manifest_*.txt` dosyalarında arm64 destekleyen "
                            "DVWA imajını bul ve `image:` satırını onunla değiştir.", yakin=True)
    if o.imaj_depo(sv["dvwa"].get("image")) != DVWA_YENI:
        return Sonuc(False, f"DVWA için çok mimarili imajı kullan: `{DVWA_YENI}`.", yakin=True)
    if o.imaj_depo(sv["juice-shop"].get("image")) != JUICE:
        return Sonuc(False, f"Juice Shop imajı `{JUICE}` olarak kalmalı.")
    return Sonuc(True, "Dosya düzeldi: DVWA arm64 uyumlu imajla, bütün portlar yalnızca 127.0.0.1'de. "
                       "(WebGoat'ı koruduysan, arm64 desteğini kendi makinende `docker manifest inspect` ile doğrulamayı unutma.)")


def _lab_web(b: Baglam) -> Sonuc:
    ad = "lab-web.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    hata, d = o.compose_denetle(yol, ad)
    if hata:
        return hata
    p = b.senaryo["portlar"]
    sv = o.servisler(d)
    bul = {o.imaj_depo(x.get("image")): (n, x) for n, x in sv.items()}
    if DVWA_ESKI in bul:
        return Sonuc(False, f"`{DVWA_ESKI}` Pi'de çalışmaz (yalnızca amd64). Çok mimarili `{DVWA_YENI}` imajını kullan.", yakin=True)
    for imaj, host, kon, ad_s in ((DVWA_YENI, p["dvwa"], 80, "DVWA"), (JUICE, p["juice"], 3000, "Juice Shop")):
        if imaj not in bul:
            return Sonuc(False, f"{ad_s} servisi yok: `image: {imaj}` olan bir servis ekle.", yakin=True)
        pl = o.portlar(bul[imaj][1])
        es = [x for x in pl if x.get("host") == host and x.get("konteyner") == kon]
        if not es:
            return Sonuc(False, f"{ad_s} için `kurulum_notu.txt`'teki port bağı yok: ana makine {host} -> konteyner {kon}.", yakin=True)
        if not all(x.get("lokal") for x in pl):
            return Sonuc(False, f"{ad_s} servisinde yalnızca `127.0.0.1` ile başlayan port eşlemesi olmalı: "
                                f"`\"127.0.0.1:{host}:{kon}\"`.", yakin=True)
    for n, x in sv.items():
        if any(not q.get("lokal") for q in o.portlar(x)):
            return Sonuc(False, f"`{n}` servisinde ağa açık bir port kalmış; hepsini 127.0.0.1'e bağla.")
    return Sonuc(True, "lab-web.yml tamam: arm64 uyumlu imajlar, portlar yalnızca 127.0.0.1'de. "
                       + ("Docker bu dosyayı da kabul etti." if o.docker_var() else "Docker bu makinede yok, dosya statik denetlendi."))


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Üç klasik hedef", """
Cilt 5'in bütün pratiği üç savunmasız web uygulamasıyla yapılır:

- **DVWA:** SQLi, XSS, komut enjeksiyonu gibi temelleri seviye seviye öğretir.
- **OWASP Juice Shop:** Modern, gerçekçi bir e-ticaret uygulaması; 100'ün üzerinde meydan
  okuma (JWT, iş mantığı...).
- **OWASP WebGoat:** Her açığı önce ders olarak anlatıp sonra uygulatır.

Bu seviyedeki kurulum şartnamesi:
""", komut="cat kurulum_notu.txt"),
    Adim("Raspberry Pi arm64'tür: imaj mimarisi önemli", """
Kitaptaki eski komut `docker run -d -p 8081:80 vulnerables/web-dvwa` Raspberry Pi'de **çalışmaz**:
bu imaj yalnızca amd64 için yayımlanmıştır. Aynı hedefin arm64'ü de destekleyen bir imajı
`ghcr.io/digininja/dvwa` olarak bulunur (DVWA'nın kendi deposundan). Juice Shop'un
`bkimminich/juice-shop` imajı da arm64'ü destekler.

Bir imajın hangi mimarileri desteklediğini gösteren bir örnek çıktıya bakalım (kurgusal dosya):
""", komut="cat manifest_vulnerables_dvwa.txt", sonra="""
`linux/amd64` yazıyor, `linux/arm64` yok: bu imaj bir Pi'de çalışmaz.
"""),
    Adim("Mimariyi kurmadan önce kontrol et", """
Hiçbir imaja güvenip kurma; önce hangi mimarileri desteklediğini sor:

```
docker manifest inspect ghcr.io/digininja/dvwa | grep -E 'architecture|os'
```

Çıktıda `"architecture": "arm64"` satırını görüyorsan Pi'ye uygundur. Bu komut Docker ve
internet gerektirir; sen kendi Kali'nde dene. (İnternetteki bir kayıt defterine sorgu yapar;
kurulumu yapmaz.) **WebGoat** için arm64 desteğini bu yazıda söyleyemeyiz, çünkü sürüme göre
değişebilir; tam da bu yüzden kendi makinende kontrol et.
""", komut="docker manifest inspect ghcr.io/digininja/dvwa", calistir=False),
    Adim("Port eşlemesi: kime açıyorsun?", """
`ports: ["8081:80"]` yazarsan Docker portu ana makinenin **bütün** ağ arayüzlerine açar; yani aynı
Wi-Fi'daki herkes `PI_IP:8081` ile hedefine girebilir. Yalnızca kendi makinen için:
`"127.0.0.1:8081:80"`. Eski compose dosyasına bakalım:
""", komut="cat eski_lab.yml", sonra="""
Satırlara dikkat: bazıları `127.0.0.1:` ile başlıyor, bazıları `0.0.0.0:` ile, bazıları hiç adres
yazmıyor. Son ikisi aynı sonucu verir: ağa açık.
"""),
    Adim("Açıkta kalan portları komutla bul", """
Port satırları `- "..."` biçiminde. Bunların `127.0.0.1:` ile **başlamayanlarını** bulmak için
iki `grep`'i boru ile bağlarız: önce port satırlarını seç, sonra `-v` ile `127.0.0.1:`
olanları ele:
""", komut="grep -E '^ +- \"' eski_lab.yml | grep -v '\"127.0.0.1:'", sonra="""
Gördüğün her satır, ağdaki herkese açık bir porttur.

**Hacker gözüyle:** Docker, yayımlanan portlar için kendi güvenlik duvarı kurallarını ekler; bu yüzden
`ufw` gibi bir araçla "kapattım" demek her zaman yeterli olmaz. En sağlam çözüm baştan `127.0.0.1`'e
bağlamaktır.
"""),
    Adim("Tek komutla kur, tek komutla sil", """
Hedefler hazır olduğunda:

- `docker compose -f lab-web.yml up -d` — hepsini başlat
- `docker compose -f lab-web.yml ps` — durumlarını gör
- `docker compose -f lab-web.yml down` — hepsini durdur ve kaldır

Tarayıcıdan `http://127.0.0.1:<<dvwa_port>>` ile DVWA'ya gireceksin (Burp'ü bu adrese yönlendir).
""", komut="docker compose -f lab-web.yml up -d", calistir=False),
]

GOREVLER = [
    Gorev("`manifest_*.txt` dosyalarını incele (kurgusal `docker manifest inspect` çıktıları). "
          "**arm64 desteği olmayan** (yalnızca amd64) imajların adlarını yaz. (Desteği bilinmeyen WebGoat'ı sayma.)",
          Kume("desteklemeyen", tur="metin", bicim="imaj adları, virgülle ayrılmış"),
          ("Her dosyada `imaj:` ve `platformlar:` satırı var. `linux/arm64` yazmayanları ara.",
           "`grep -L arm64 manifest_*.txt` arm64 geçmeyen dosyaları listeler; WebGoat dosyasında platform bilinmiyor.",
           "`platformlar: linux/amd64` tek başına yazan dosyaların `imaj:` değerleri cevaptır."),
          puan=35, baslik="arm64 desteği"),
    Gorev("`eski_lab.yml` içinde, ağdaki başka cihazların erişebileceği (yani `127.0.0.1` ile başlamayan) "
          "**kaç port eşlemesi** var?",
          Sayi("acik", sik_hatalar=_acik_hata),
          ("Her port bir `- \"...\"` satırıdır. Hangileri yalnızca senin makinene bağlı?",
           "`grep -E '^ +- \"' eski_lab.yml` port satırlarını gösterir; bunlardan `127.0.0.1:` olanları ayıkla.",
           "`grep -E '^ +- \"' eski_lab.yml | grep -vc '\"127.0.0.1:'` açık portların sayısını yazar."),
          puan=30, baslik="Açık portlar"),
    Gorev("`eski_lab.yml` dosyasını **yerinde düzelt**: DVWA'yı Pi'de çalışan (arm64 destekli) imajla "
          "değiştir ve bütün portları yalnızca `127.0.0.1`'e bağla. Port numaralarını ve servisleri değiştirme. "
          "Hazır olunca `cevap 3`.",
          Durum(_eski_duzelt, "```\nsed -i 's#vulnerables/web-dvwa#<<dvwa_yeni>>#; s#\"\\(0\\.0\\.0\\.0:\\)\\?\\([0-9]\\)#\"127.0.0.1:\\2#' eski_lab.yml\n```\n"
                              "(Önce 127.0.0.1 ile başlayan satırlara dokunmadığından emin ol; gerekirse elle düzelt.)"),
          ("İki iş var: bir `image:` satırı değişecek, bazı port satırlarının başına bir şey eklenecek ya da değişecek.",
           "`nano eski_lab.yml`. DVWA'nın imajı için manifest dosyalarından arm64 destekleyeni bul. Port satırlarını `\"127.0.0.1:ANA:KONTEYNER\"` yap.",
           "`image: <<dvwa_yeni>>` ve her port satırı `127.0.0.1:` ile başlamalı (`0.0.0.0:` olanlarda `0.0.0.0` yerine `127.0.0.1` yaz)."),
          puan=50, baslik="Dosyayı düzelt"),
    Gorev("Pi'yi kafedeki ortak Wi-Fi'a bağladın. DVWA compose dosyasında `\"8081:80\"` yazıyor "
          "(`127.0.0.1` yok). Sence ne olur?",
          Secmeli([
              ("Aynı Wi-Fi'daki herkes `Pi_IP:8081` ile DVWA'ya girebilir; zafiyetli uygulama yabancılara açılır",
               "Doğru: adres belirtmeyince Docker portu bütün arayüzlere açar; ağdaki herkes erişebilir."),
              ("Hiç kimse erişemez, çünkü DVWA bir lab imajıdır ve varsayılan olarak yalnızca konteynerin içinden görülebilir",
               "İmajda 'lab modu' diye bir koruma yoktur; port eşlemesi erişimi açar."),
              ("Yalnızca aynı Docker ağındaki diğer konteynerler erişebilir; Wi-Fi'daki cihazlar bağlantı kuramaz hale gelir",
               "Port eşlemesi tam da konteynerin dışarıdan (ana makine ağından) erişilebilmesi içindir."),
              ("Sadece parolayı bilenler girebilir; DVWA'nın giriş ekranı yabancıları durdurmak için yeterli bir korumadır",
               "DVWA'nın varsayılan kullanıcı adı/parolası herkesçe bilinir ve uygulama zaten kasıtlı zafiyetlidir."),
          ], dogru=0),
          ("`ports:` satırında hiçbir adres yazmazsa Docker hangi arayüzlere bağlar?",
           "Adres yazılmazsa `0.0.0.0` (bütün arayüzler) kabul edilir. Wi-Fi arayüzü de bunlardan biridir.",
           "Ortak ağdaki herkes `Pi_IP:8081` adresine gidebilir."),
          puan=30, baslik="Neden 127.0.0.1"),
    Gorev("WebGoat'ın Pi (arm64) için imaj desteğinden emin değilsin. Kurmadan **önce** ne yaparsın?",
          Secmeli([
              ("`docker manifest inspect webgoat/webgoat` ile mimarilere bakar, arm64 yoksa başka hedef seçerim",
               "Doğru: bilinmeyeni kurup denemek yerine önce mimariyi doğrularsın."),
              ("Doğrudan `docker compose up` yapar, hata verirse o zaman bakarım; denemenin hiçbir maliyeti yoktur",
               "Mimari uyuşmazlığı çoğu zaman 'exec format error' ile geç ve kafa karıştırıcı biçimde ortaya çıkar; üstelik indirme boyuna zaman kaybedersin."),
              ("`--platform linux/amd64` ekleyip taklitle çalıştırırım; Java uygulaması her işlemcide hızlı çalışır",
               "Taklit (emülasyon) çok yavaştır, Pi'de sınırlı RAM'i de eritir ve her imajda çalışmaz."),
              ("İmajı bir forumda paylaşılan arm64 `.tar` dosyasından yüklerim; kaynağın kim olduğu önemli değildir",
               "Tanımadığın kaynaktan imaj yüklemek lab'ın kendisini tehlikeye atar (Bölüm 6: resmi/tanınmış depolar)."),
          ], dogru=0),
          ("Kurmadan önce imajın hangi mimarileri desteklediğini öğrenebileceğin bir komut var.",
           "Bölümde öğrendiğin `docker manifest inspect` komutunu düşün.",
           "`docker manifest inspect webgoat/webgoat | grep architecture` desteklenen mimarileri gösterir."),
          puan=30, baslik="WebGoat belirsizliği"),
    Gorev("Sıfırdan **`lab-web.yml`** yaz: arm64 uyumlu DVWA imajı ve Juice Shop imajı; her ikisi de "
          "`kurulum_notu.txt`'teki portlarla yalnızca `127.0.0.1`'e bağlı (DVWA konteyner portu 80, "
          "Juice Shop 3000). Docker varsa dosya canlı da sınanır. Hazır olunca `cevap 6`.",
          Durum(_lab_web, "```\nservices:\n  dvwa:\n    image: <<dvwa_yeni>>\n    ports:\n      - \"127.0.0.1:<<dvwa_port>>:80\"\n"
                          "  juice-shop:\n    image: <<juice>>\n    ports:\n      - \"127.0.0.1:<<juice_port>>:3000\"\n```"),
          ("İki servis, her birinde `image:` ve `ports:`. Portlar şartnamede.",
           "`cat kurulum_notu.txt` ile portları oku. Imaj adları bölümde geçti: biri `ghcr.io/...`, diğeri `bkimminich/...`.",
           "`services:` altında iki servis; port satırları `\"127.0.0.1:ANA:KONTEYNER\"` biçiminde olsun."),
          puan=50, baslik="Kendi lab-web.yml'in"),
    Gorev("`lab-web.yml` ile DVWA'yı çalıştırdığında Kali'deki tarayıcıya hangi adresi (adres:port) yazarsın? "
          "(`http://` olmadan, `127.0.0.1` ile başlayan biçim)",
          Metin("adres", kabul=[], on_ekleri_at=("http://", "https://"), son_ekleri_at=("/",), bicim="adres:port"),
          ("Port eşlemesinde soldaki sayı ve bağlandığı adres tarayıcıya yazdığın adrestir.",
           "`kurulum_notu.txt` DVWA'nın ana makine portunu söylüyor; adres kısmı `127.0.0.1`.",
           "`127.0.0.1:` + DVWA'nın ana makine portu."),
          puan=20, baslik="Tarayıcı adresi"),
]


def _kapanis():
    return """
Üç hedef Cilt 5'in tamamını kapsar, ama onları kurarken yaptığın üç karar seni güvenli ya da
tehlikeli bir lab sahibi yapar: **mimariye uygun imaj**, **127.0.0.1 bağı** ve **kaynağı
bilinen imaj**. Saldırgan gözüyle: ağdaki açık `8081`/`3000` portlarındaki "DVWA" ya da "Juice
Shop" başlıkları kolayca fark edilen, zayıf olduğu bilinen hedeflerdir. Savunma gözüyle: portu
127.0.0.1'e bağladığında yüzey sıfırlanır; manifest'i kontrol ettiğinde "çalışmıyor" hatasıyla
saatler harcamazsın.
"""


SEVIYE = Seviye(
    kimlik="c09b03",
    cilt=9,
    bolum=3,
    baslik="Web Hedeflerini Kur",
    brifing="Pi'ye DVWA ve Juice Shop kurulacak; arm64 uyumlu imajlar, 127.0.0.1 bağlı portlar.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **Kasıtlı zafiyetli uygulamalar internete açılmaz:** DVWA gibi uygulamaların kendi belgeleri,
  onları internete açık bir sunucuya kurmamayı açıkça uyarır. Zafiyetli bir uygulamayı
  yanlışlıkla internete açmak, gerçek saldırganlara hazır bir hedef sunmak demektir. Tespit için
  `docker ps` çıktısında `0.0.0.0:` ile başlayan portlara ve dışarıdan yapılan kendi port
  taramana bakılır.
- **Docker ve güvenlik duvarı:** Docker, yayımlanan portlar için kendi iptables kurallarını
  ekler; kendi belgeleri de `ufw` gibi araçların bu portları her zaman engellemeyebileceğini
  anlatır. Bu yüzden `127.0.0.1` bağı, ayrı bir güvenlik duvarı kuralından daha güvenilirdir.
- **Mimari uyuşmazlığı:** Yalnızca `amd64` yayımlanmış bir imajı arm64 bir makinede çalıştırmaya
  çalışmak tipik olarak "exec format error" ile sonuçlanır. Bu, pratikte en sık yaşanan Pi/Docker
  hayal kırıklıklarından biridir; çözüm baştan `docker manifest inspect` ile kontrol etmektir.
""",
    sure_hedef_dk=30,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    des = sh("grep -l 'platformlar: linux' manifest_*.txt | xargs grep -L arm64 "
             "| xargs awk -F': ' '/^imaj/{print $2}'").split()
    acik = sh("grep -E '^ +- \"' eski_lab.yml | grep -vc '\"127.0.0.1:'")
    # eski_lab.yml'yi düzelt (kopyayı bozmadan yerinde)
    sh("sed -i 's#vulnerables/web-dvwa#ghcr.io/digininja/dvwa#' eski_lab.yml")
    sh("sed -i -E 's#\"(0\\.0\\.0\\.0:)?([0-9]+:[0-9]+)\"#\"127.0.0.1:\\2\"#' eski_lab.yml")
    dp = sh("awk -F': ' '/^dvwa_port/{print $2}' kurulum_notu.txt")
    jp = sh("awk -F': ' '/^juice_port/{print $2}' kurulum_notu.txt")
    (lab / "lab-web.yml").write_text(
        "services:\n  dvwa:\n    image: ghcr.io/digininja/dvwa\n    ports:\n"
        f"      - \"127.0.0.1:{dp}:80\"\n  juice-shop:\n    image: bkimminich/juice-shop\n    ports:\n"
        f"      - \"127.0.0.1:{jp}:3000\"\n")
    adres = sh("grep -oE '127\\.0\\.0\\.1:[0-9]+:80\"' lab-web.yml | cut -d: -f1,2")
    return {1: " ".join(des), 2: acik, 3: "",
            4: SEVIYE.gorevler[3].kontrol.cevabi_goster(Baglam(s, lab, 4))[0],
            5: SEVIYE.gorevler[4].kontrol.cevabi_goster(Baglam(s, lab, 5))[0], 6: "", 7: adres}
