"""Cilt 9 · Bölüm 2 — Docker Temelleri (Lab İçin).

Beceri: imaj / konteyner / volume / port eşleme kavramları; `docker ps` çıktısını okumak; YAML'da
TAB hatası; oyuncunun yazdığı Dockerfile ve docker-compose.yml dosyasını doğrulamak.

Docker varsa compose dosyası canlı (`docker compose config -q`) sınanır; yoksa dosya statik
olarak denetlenir. Hiçbir görev Docker gerektirmez ve imaj indirmez.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Secmeli, Sayi, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

VAKALAR = [
    {
        "kod": "kalkan", "ad": "Kalkan Güvenlik — stajyer test sitesi",
        "repo": "nginx", "tag": "1.27-alpine", "cp": 80, "dest": "/usr/share/nginx/html", "cmd": None,
        "workdir": None, "servis": "stajyer-web", "klasor": "site",
        "adlar": ["stajyer-web", "wiki-test", "rapor-onizleme", "deneme-api"],
        "yan": "redis:7-alpine", "yan_ad": "onbellek",
        "brifing": """
Selin: "İlk Docker görevin. Stajyer lab'ında test için küçük bir statik web sayfası lazım:
`site/` klasöründeki sayfayı bir **nginx** konteynerinden sunacağız. Hem `Dockerfile` hem de
`docker-compose.yml` hazırla; lab'da ne istediğimi `istek.txt` dosyasına yazdım."

Mert: "Ve lütfen `docker run`'ı her seferinde elle yazma. Compose dosyası senin lab'ın tarifi
olsun, silince yeniden kurarsın."
""",
    },
    {
        "kod": "atolye", "ad": "Atölye Kahve — menü sitesi eğitim ortamı",
        "repo": "python", "tag": "3.12-slim", "cp": 8000, "dest": "/app", "cmd": "http.server",
        "workdir": "/app", "servis": "kahve-menu", "klasor": "menu",
        "adlar": ["kahve-menu", "siparis-demo", "stok-panel", "kampanya-test"],
        "yan": "redis:7-alpine", "yan_ad": "oturum-deposu",
        "brifing": """
Berk (Atölye Kahve'nin sahibi) bir akşam yazıyor: "Siteyi kendim yönetiyorum ama deneme
yapmaktan korkuyorum, bozarım diye. Bana siteyi bozup tekrar kurabileceğim bir eğitim ortamı
kur."

Selin senden menü sayfasını (`menu/` klasörü) küçük bir **Python** konteynerinde sunmanı istiyor.
Yapılacaklar `istek.txt` dosyasında. "Berk bozunca tek komutla sıfırlayabilmeli," diyor.
""",
    },
    {
        "kod": "mert", "ad": "Mert'in Pi'si — ders notları sunucusu",
        "repo": "httpd", "tag": "2.4-alpine", "cp": 80, "dest": "/usr/local/apache2/htdocs", "cmd": None,
        "workdir": None, "servis": "ders-notlari", "klasor": "notlar",
        "adlar": ["ders-notlari", "blog-deneme", "wiki-taslak", "foto-galeri"],
        "yan": "memcached:1.6-alpine", "yan_ad": "onbellek",
        "brifing": """
Mert evdeki Pi'sinde ilk Docker kurulumunu yapıyor: "Cilt notlarımı bir Apache konteynerinden
sunmak istiyorum, `notlar/` klasörü sayfaların olduğu yer. Dockerfile'ı ve compose dosyasını
sen yaz, ben yarın sabah bakarım. Yalnız Pi'yi şirketin ağına yanlışlıkla açmayalım."

Selin ekliyor: "Port bağlarken hep aklında olsun: bu sunucu sadece senin makinene (127.0.0.1)
görünmeli."
""",
    },
]


def _ps_satiri(cid, imaj, olusma, durum, portlar, ad):
    return f"{cid:<14} {imaj:<20} {chr(34) + '/entrypoint.sh' + chr(34):<18} {olusma:<13} {durum:<14} {portlar:<42} {ad}\n"


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    hp = rng.randrange(8080, 8199)
    # docker ps çıktısı
    adlar = list(v["adlar"])
    rng.shuffle(adlar)
    hedef_kon = adlar[0]
    portlar, kullanilan = [], {hp}
    for _ in adlar:
        while True:
            p = rng.randrange(3000, 9999)
            if p not in kullanilan:
                kullanilan.add(p)
                break
        portlar.append(p)
    biçim = ["lokal", "hepsi", "lokal", "hepsi"]
    rng.shuffle(biçim)
    ps_hedef_port = portlar[0]
    # tab hatası içeren bozuk compose
    bozuk = [
        "services:",
        f"  {v['servis']}:",
        f"    image: {v['repo']}:{v['tag']}",
        "    ports:",
        f"      - \"127.0.0.1:{hp}:{v['cp']}\"",
        "    volumes:",
        f"      - ./{v['klasor']}:{v['dest']}:ro",
        "    restart: unless-stopped",
        f"  {v['yan_ad']}:",
        f"    image: {v['yan']}",
        "    restart: unless-stopped",
    ]
    tab_satir = rng.choice([3, 5, 7, 8, 10, 11])   # 1 tabanlı
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v, "hp": hp,
        "ps": {"adlar": adlar, "portlar": portlar, "bicim": biçim},
        "bozuk": bozuk, "tab_satir": tab_satir,
        "metin": {"servis": v["servis"], "repo": v["repo"], "tag": v["tag"], "hp": str(hp), "cp": str(v["cp"]),
                  "klasor": v["klasor"], "dest": v["dest"], "hedef_kon": hedef_kon, "tab_dosya": "bozuk.yml",
                  "sayfa": "site" if v["klasor"] == "site" else v["klasor"]},
        "cevaplar": {"ps_port": ps_hedef_port, "tab_satir": tab_satir},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    istek = [
        "# Yapılacak iş (Selin)\n",
        f"servis_adi: {v['servis']}\n",
        f"temel_imaj: {v['repo']}:{v['tag']}\n",
        f"sayfa_klasoru: {v['klasor']}\n",
        f"konteyner_ici_yol: {v['dest']}\n",
        f"konteyner_portu: {v['cp']}\n",
        f"ana_makine_portu: {s['hp']}\n",
        "baglanma: yalnızca 127.0.0.1 (ağdaki başkaları erişmesin)\n",
    ]
    if v["cmd"]:
        istek.append(f"baslatma: python -m http.server {v['cp']} (çalışma klasörü {v['workdir']})\n")
    u.yaz(lab / "istek.txt", "".join(istek))
    u.yaz(lab / v["klasor"] / "index.html",
          f"<!doctype html>\n<title>{v['servis']}</title>\n<h1>Merhaba, lab!</h1>\n")
    # docker ps çıktısı (kurgusal)
    ps = ["CONTAINER ID   IMAGE                COMMAND            CREATED       STATUS         PORTS"
          "                                      NAMES\n"]
    imajlar = [f"{v['repo']}:{v['tag']}", v["yan"], "mariadb:10.11", "nginx:1.27-alpine"]
    for i, ad in enumerate(s["ps"]["adlar"]):
        p = s["ps"]["portlar"][i]
        if s["ps"]["bicim"][i] == "lokal":
            port_s = f"127.0.0.1:{p}->{v['cp']}/tcp"
        else:
            port_s = f"0.0.0.0:{p}->{v['cp']}/tcp, [::]:{p}->{v['cp']}/tcp"
        cid = "".join("0123456789abcdef"[(p * (j + 3) + i * 7) % 16] for j in range(12))
        ps.append(_ps_satiri(cid, imajlar[i], f"{i + 1} hours ago", f"Up {i + 1} hours", port_s, ad))
    u.yaz(lab / "docker_ps_cikti.txt", "".join(ps))
    satirlar = list(s["bozuk"])
    i = s["tab_satir"] - 1
    satirlar[i] = "\t" + satirlar[i].lstrip(" ")
    u.yaz(lab / "bozuk.yml", "\n".join(satirlar) + "\n")


# ------------------------------------------------------------------ kontroller

def _tab_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if abs(n - beklenen) == 1:
        return "Bir satır kaymış. `grep -n` satır numarasını başlıktan saymadan, dosyadaki gerçek sırasıyla verir."
    return None


def _dockerfile_oku(metin: str) -> list:
    """[(KOMUT, argümanlar)] — satır devamlarını (\\) birleştirir, yorumları atar."""
    sonuc, birikim = [], ""
    for ham in metin.splitlines():
        satir = ham.strip()
        if not satir or satir.startswith("#"):
            continue
        if satir.endswith("\\"):
            birikim += satir[:-1] + " "
            continue
        satir = birikim + satir
        birikim = ""
        kom, _, arg = satir.partition(" ")
        sonuc.append((kom.upper(), arg.strip()))
    return sonuc


def _dockerfile(b: Baglam) -> Sonuc:
    yol = o.dosya_bul(b, "Dockerfile")
    if yol is None:
        return o.bulunamadi("Dockerfile")
    v = b.senaryo["v"]
    komutlar = _dockerfile_oku(yol.read_text(encoding="utf-8", errors="replace"))
    if not komutlar:
        return Sonuc(False, "`Dockerfile` boş.")
    froms = [a for k, a in komutlar if k == "FROM"]
    if not froms:
        return Sonuc(False, "`FROM` satırı yok. Her Dockerfile bir temel imajla başlar: `FROM imaj:etiket`.")
    imaj = froms[0].split()[0]
    if o.imaj_depo(imaj) != v["repo"]:
        return Sonuc(False, f"`FROM {imaj}`: istekteki temel imaj `{v['repo']}` olmalıydı.", yakin=True)
    if not o.etiket_sabit_mi(imaj):
        return Sonuc(False, "Temel imaja sabit bir sürüm etiketi ver (örn. `istek.txt`'deki `temel_imaj`). `latest` yarın başka bir şey olabilir.",
                     yakin=True)
    if imaj != f"{v['repo']}:{v['tag']}":
        return Sonuc(False, f"Etiketi `istek.txt`'deki gibi yaz: `{v['repo']}:{v['tag']}`.", yakin=True)
    kopya = [a.split() for k, a in komutlar if k == "COPY"]
    hedef = v["dest"].rstrip("/")
    kopya_ok = any(len(p) >= 2 and p[-2].strip("./").rstrip("/") == v["klasor"] and p[-1].rstrip("/") == hedef
                   for p in kopya)
    if not kopya_ok:
        return Sonuc(False, f"`COPY {v['klasor']} {v['dest']}` biçiminde bir satır bekliyorum: sayfa klasörü, konteynerin içindeki yola kopyalanmalı.",
                     yakin=bool(kopya))
    if not any(k == "EXPOSE" and str(v["cp"]) in [x.split("/")[0] for x in a.split()] for k, a in komutlar):
        return Sonuc(False, f"`EXPOSE {v['cp']}` satırı yok (uygulamanın dinlediği portu belgeler).", yakin=True)
    if v["workdir"] and not any(k == "WORKDIR" and a.rstrip("/") == v["workdir"] for k, a in komutlar):
        return Sonuc(False, f"İstek, çalışma klasörünü `{v['workdir']}` yapmanı da söylüyor: `WORKDIR {v['workdir']}`.",
                     yakin=True)
    if v["cmd"] and not any(k in ("CMD", "ENTRYPOINT") and v["cmd"] in a for k, a in komutlar):
        return Sonuc(False, "Konteyner başlarken ne çalıştıracağını `CMD [\"python\", \"-m\", \"http.server\", \"" + str(v["cp"]) + "\"]` ile belirt.",
                     yakin=True)
    return Sonuc(True, "Dockerfile tam: temel imaj sabitlenmiş, sayfalar kopyalanmış, port belgelenmiş. "
                       "Gerçek bir `docker build`'de bu dosya aynen işe yarar.")


def _compose(b: Baglam) -> Sonuc:
    ad = "docker-compose.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    hata, d = o.compose_denetle(yol, ad)
    if hata:
        return hata
    v = b.senaryo["v"]
    hp = b.senaryo["hp"]
    sv = o.servisler(d)
    if v["servis"] not in sv:
        return Sonuc(False, f"`services:` altında `{v['servis']}` adlı bir servis olmalı. Şimdikiler: {o.adlar_tr(sv)}.",
                     yakin=True)
    s = sv[v["servis"]]
    imaj = s.get("image")
    if o.imaj_depo(imaj) != v["repo"]:
        return Sonuc(False, f"`image:` değeri `{v['repo']}:{v['tag']}` olmalı (şu an: {imaj!r}).", yakin=True)
    if not o.etiket_sabit_mi(imaj):
        return Sonuc(False, f"İmaj etiketini sabitle: `{v['repo']}:{v['tag']}`. Etiketsiz/`latest` imaj yarın değişebilir.",
                     yakin=True)
    pl = o.portlar(s)
    eslesen = [p for p in pl if p.get("host") == hp and p.get("konteyner") == v["cp"]]
    if not eslesen:
        return Sonuc(False, f"`ports:` altında ana makinenin `{hp}` portunu konteynerin `{v['cp']}` portuna bağlayan bir satır bekliyorum "
                     f"(`ana_makine:konteyner`).", yakin=bool(pl))
    if not any(p.get("lokal") for p in eslesen):
        return Sonuc(False, f"Port eşlemesi var ama `127.0.0.1` ile başlamıyor. `\"127.0.0.1:{hp}:{v['cp']}\"` yazarsan yalnızca senin makinen erişir; "
                     "yazmazsan aynı ağdaki herkes erişir.", yakin=True)
    vol = [str(x) for x in (s.get("volumes") or [])]
    if not any(re.match(rf"^\./?{re.escape(v['klasor'])}/?:{re.escape(v['dest'])}/?(:ro|:rw)?$", x) for x in vol):
        return Sonuc(False, f"`volumes:` altında `./{v['klasor']}:{v['dest']}` (ister sonuna `:ro`) eşlemesi bekleniyor. Böylece sayfaları "
                     "imajı yeniden kurmadan değiştirebilirsin.", yakin=True)
    canli = "Docker bu dosyayı kabul etti (canlı kontrol)." if o.docker_var() else "Docker bu makinede yok; dosya statik olarak denetlendi."
    return Sonuc(True, f"docker-compose.yml tamam. {canli}")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Dört kavram", """
Docker'da dört kavramı bilmen yeter:

- **İmaj (image):** Bir uygulamanın hazır, değişmeyen şablonu.
- **Konteyner (container):** Bir imajın **çalışan** örneği. Aynı imajdan istediğin kadar çıkar.
- **Port eşleme:** Konteynerin içindeki portu ana makinene bağlar. `-p 8080:80` = "benim
  8080 portum, konteynerin 80 portu".
- **Volume (disk bağlama):** Konteyner silinince kaybolmaması gereken veri için ana makineden
  bağlanan klasör.

Selin'in isteğini okuyalım:
""", komut="cat istek.txt", sonra="""
Bu dosya bir **şartname**: servis adı, hangi imajdan, sayfaların yeri, hangi porttan sunulacağı.
Görevlerde bu şartnameyi Dockerfile'a ve compose dosyasına çevireceksin.
"""),
    Adim("Dockerfile: imajı tarif eder", """
**Dockerfile**, kendi imajını nasıl kuracağını anlatan bir tarif dosyasıdır:

```
FROM temel:etiket     # hangi imajın üstüne kuruyoruz
COPY klasor /hedef    # dosyaları imajın içine kopyala
EXPOSE 80             # uygulama bu portu dinler (belgeleme)
CMD ["komut", "arg"]  # konteyner başlarken çalışacak komut
```

İmajı derlemek için `docker build -t <<servis>> .` yazılır. Bu komut Docker gerektirir; bu
eğitimde yalnızca yazıyoruz, çalıştırmıyoruz (Docker'ın Kali'nde kurulu olması gerekir).
""", komut="docker build -t <<servis>> .", calistir=False, sonra="""
**Hacker gözüyle:** `FROM nginx` (etiketsiz) yazmak, her derlemede imajın "o günkü" sürümünü
çekmek demektir; bugün çalışan tarif yarın başka bir yazılımla gelebilir. Etiketi sabitle.
"""),
    Adim("docker-compose.yml: tarifi bir dosyada tut", """
Her seferinde uzun `docker run ...` yazmak yerine, hedefini bir **compose** dosyasında
tanımlarsın: hangi servis, hangi imaj, hangi portlar, hangi volume. Örnek bir dosyaya bakalım
(içinde bilerek bir hata var, birazdan bulacaksın):
""", komut="cat bozuk.yml", sonra="""
Compose dosyası **YAML** biçimindedir. İki kural hayatını kurtarır: girinti için **boşluk** kullan
(genelde 2), asla TAB değil; ve `anahtar: değer` biçiminde iki noktadan sonra boşluk bırak.
"""),
    Adim("TAB karakterini göz görmez", """
TAB karakteri ekranda boşluğa benzer, ama YAML için geçersizdir; `docker compose` dosyayı
reddeder. `cat -A` görünmeyen karakterleri gösterir: TAB, `^I` olarak görünür.
""", komut="cat -A bozuk.yml", sonra="""
`^I` gördüğün satır sorunlu satırdır. Satır numarasını bulmak için `grep -nP '\\t' bozuk.yml`
(`-n` satır numarasını yazar, `-P` `\\t`'yi TAB olarak anlar) kullanılır. Görevlerde işine yarayacak.
"""),
    Adim("docker ps çıktısını okumak", """
`docker ps` çalışan konteynerleri listeler. En önemli sütun **PORTS**: `127.0.0.1:8085->80/tcp`
"ana makinenin 127.0.0.1 adresinin 8085 portu, konteynerin 80 portuna bağlı" demektir.
`0.0.0.0:8085->80/tcp` ise "ana makinenin **bütün** ağ arayüzlerinde" yani ağdaki herkese açık
demektir. Kurgusal bir çıktıya bakalım:
""", komut="cat docker_ps_cikti.txt", sonra="""
Bu iki biçim arasındaki fark, lab güvenliğinin en kritik detayıdır; Bölüm 3 ve 6'da tekrar
karşına çıkacak. Not: bu dosya gerçek Docker çıktısı değil, kurgusal.
"""),
    Adim("Boz ve at döngüsü", """
Docker'ın lab için en güzel yanı: hedefi saniyede kaldırır, istediğin kadar bozar, `down` ile
siler ve yeniden kurarsın. Compose ile bu iki komuttur:

- `docker compose up -d` — dosyadaki her şeyi arka planda başlat
- `docker compose down` — hepsini durdur ve kaldır

**Hacker gözüyle:** `docker` grubundaki bir kullanıcı pratikte root'tur (Cilt 1). Bu yüzden
Docker'ı yalnızca kendi lab makinende kullan ve konteynerleri gereksiz yetkiyle çalıştırma.
""", komut="docker compose up -d", calistir=False),
]

GOREVLER = [
    Gorev("`docker run` ile **aynı imajdan iki kez** konteyner başlattın. Docker'da kaç imaj ve kaç "
          "konteyner olur?",
          Secmeli([
              ("1 imaj, 2 konteyner", "Doğru: imaj tek bir şablondur; her `docker run` o şablondan ayrı bir çalışan konteyner üretir."),
              ("2 imaj ve 2 konteyner", "İmaj yalnızca bir kez indirilir; ikinci çalıştırma yeni imaj oluşturmaz."),
              ("1 imaj ve 1 konteyner", "İkinci `docker run` mevcut konteyneri yeniden kullanmaz; yeni bir konteyner oluşturur."),
              ("2 imaj ve 1 konteyner", "İmaj sayısı konteyner sayısından fazla olamaz; tersine, bir imajdan çok konteyner çıkar."),
          ], dogru=0),
          ("İmaj bir şablon, konteyner o şablonun çalışan kopyası.",
           "Bir kurabiye kalıbından kaç kurabiye çıkarabilirsin? Kalıp imaj, kurabiye konteyner.",
           "Şablon bir tane, çalışan örnek iki tane."),
          puan=20, baslik="İmaj ve konteyner"),
    Gorev("Bir compose dosyasında `\"<<hp>>:<<cp>>\"` port eşlemesi var. Bu ne anlama gelir?",
          Secmeli([
              ("Ana makinenin <<hp>> portu, konteynerin <<cp>> portuna bağlanır",
               "Doğru: soldaki sayı ana makinenin (senin bilgisayarının), sağdaki sayı konteynerin portudur."),
              ("Konteynerin <<hp>> portu, ana makinenin <<cp>> portuna bağlanır",
               "Sıra ters: soldaki sayı her zaman ana makinenin portudur."),
              ("Konteynerin içindeki uygulama hem <<hp>> hem <<cp>> portunu dinler",
               "Eşleme uygulamayı değiştirmez; yalnızca iki port arasında köprü kurar."),
              ("<<hp>> numaralı port, <<cp>> numaralı porttan gelen trafiği engeller",
               "Port eşleme bir engel (güvenlik duvarı) değildir; tam tersine erişim açar."),
          ], dogru=0),
          ("`ana_makine:konteyner` sırasını hatırla.",
           "Tarayıcıda `localhost:<<hp>>` yazarsan hangi porta gelirsin? Orası konteynere bağlanır.",
           "Sol: ana makine. Sağ: konteyner."),
          puan=20, baslik="Port eşleme"),
    Gorev("`docker_ps_cikti.txt` dosyasında **<<hedef_kon>>** konteyneri, ana makinenin hangi portuna "
          "bağlı? (Ok işaretinin solundaki port numarası)",
          Sayi("ps_port"),
          ("PORTS sütununda, konteyner adının bulunduğu satıra bak.",
           "`grep <<hedef_kon>> docker_ps_cikti.txt` yalnızca o satırı verir. `->` işaretinden önceki sayıyı al.",
           "`grep -w <<hedef_kon>> docker_ps_cikti.txt | grep -oE ':[0-9]+->'` portu `:PORT->` biçiminde yazar."),
          puan=25, baslik="PORTS sütunu"),
    Gorev("`bozuk.yml` dosyasında Docker'ın reddedeceği bir **TAB karakteri** var. Kaçıncı satırda?",
          Sayi("tab_satir", sik_hatalar=_tab_hata),
          ("Dosyada yalnızca bir tane TAB var; göz onu boşluktan ayırt edemez.",
           "`cat -A bozuk.yml` TAB'ı `^I` olarak gösterir; satır numarası için `grep -nP` kullanabilirsin.",
           "`grep -nP '\\t' bozuk.yml` satırı `NUMARA:içerik` biçiminde yazar."),
          puan=25, baslik="Görünmez hata"),
    Gorev("Lab klasöründe, `istek.txt`'e uygun bir **`Dockerfile`** yaz: sabit etiketli temel imaj, sayfa "
          "klasörünü konteynere kopyalama, port belgeleme (ve istekte varsa çalışma klasörü ile başlatma "
          "komutu). Hazır olunca `cevap 5`.",
          Durum(_dockerfile, "```\nFROM <<repo>>:<<tag>>\nCOPY <<klasor>> <<dest>>\nEXPOSE <<cp>>\n```\n"
                             "(`istek.txt`'te `baslatma` satırı varsa `WORKDIR` ve `CMD` de ekle.)"),
          ("Dockerfile'ın dört yapı taşını hatırla: FROM, COPY, EXPOSE, gerekirse WORKDIR/CMD.",
           "`nano Dockerfile` ile oluştur. Her değer `cat istek.txt` içinde yazıyor: imaj, klasör, hedef yol, port.",
           "`FROM <<repo>>:<<tag>>`, ardından `COPY <<klasor>> <<dest>>`, ardından `EXPOSE <<cp>>`. Başlatma istenmişse `WORKDIR` ve `CMD` satırlarını ekle."),
          puan=45, baslik="Dockerfile yaz"),
    Gorev("Aynı klasörde **`docker-compose.yml`** yaz: istekteki servis adıyla, sabit etiketli imajla, "
          "`127.0.0.1` üzerinden ana makinenin <<hp>> portunu konteynerin <<cp>> portuna bağlayan bir port "
          "eşlemesiyle ve sayfa klasörünü konteynere bağlayan bir volume ile. Docker bu makinede varsa dosya "
          "canlı da sınanır. Hazır olunca `cevap 6`.",
          Durum(_compose, "```\nservices:\n  <<servis>>:\n    image: <<repo>>:<<tag>>\n    ports:\n"
                          "      - \"127.0.0.1:<<hp>>:<<cp>>\"\n    volumes:\n      - ./<<klasor>>:<<dest>>:ro\n```"),
          ("Compose dosyası `services:` ile başlar; altına servis adı, onun altına ayarlar gelir. Girinti: 2 boşluk.",
           "`bozuk.yml`'yi örnek al: aynı yapıyı, kendi şartnamene göre yaz. Port satırı `\"127.0.0.1:ANA:KONTEYNER\"`.",
           "`services:` → `  <<servis>>:` → `    image:`, `    ports:` ve `    volumes:` listeleri (her biri `- ` ile başlar)."),
          puan=50, baslik="Compose yaz"),
    Gorev("Bir veritabanı konteynerini hiçbir volume bağlamadan çalıştırdın, içine veri girdin, sonra "
          "`docker rm` ile sildin. Veriye ne olur?",
          Secmeli([
              ("Veri konteynerle birlikte silinir; geri gelmez", "Doğru: konteynerin kendi dosya sistemi, konteynerle birlikte yok olur. Kalıcılık için volume gerekir."),
              ("Veri imajın içine yazılır; yeni konteyner aynı veriyi görür", "İmajlar değişmez; çalışan konteynerin yazdıkları imaja eklenmez."),
              ("Veri ana makinede otomatik bir yedeğe kopyalanır", "Docker kendiliğinden yedek almaz; bunu sen planlarsın."),
              ("Veri durur; `docker start` ile konteyner yeniden gelince okunur", "`docker rm` konteyneri tamamen siler; `docker stop` olsaydı veri duracaktı."),
          ], dogru=0),
          ("Konteyner geçici bir ortamdır; içindeki dosyalar onunla yaşar.",
           "Kalıcı veri için eğitimde hangi kavramı öğrendin? Onu kullanmadıysan ne olur?",
           "Volume yoksa veri yalnızca konteynerin kendi katmanındadır; `docker rm` onu da siler."),
          puan=25, baslik="Volume neden var"),
]


def _kapanis():
    return """
Docker'ı hedef kurmak için kullanan sen, aynı zamanda onun **saldırı yüzeyini** de belirliyorsun:
hangi port, hangi adres, hangi imaj. `0.0.0.0` ile `127.0.0.1` arasındaki fark, bir lab hedefini
yalnızca kendin için bir hedef mi yoksa ağdaki herkes için bir hedef mi yaptığını belirler.
Saldırgan gözüyle: ağda `0.0.0.0` ile açılmış bir port aramak en kolay keşif yollarından biridir.
Savunma gözüyle: portu 127.0.0.1'e bağla, imaj etiketini sabitle, her şeyi tarifte (compose
dosyasında) tut ki hedefi bozunca sıfırdan aynısını kurabil.
"""


SEVIYE = Seviye(
    kimlik="c09b02",
    cilt=9,
    bolum=2,
    baslik="Docker Temelleri (Lab İçin)",
    brifing="Docker, lab'ının motoru. Bir Dockerfile ve bir compose dosyası yazacaksın.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **Docker grubu = root:** Docker'ın kendi belgeleri, `docker` grubundaki bir kullanıcının
  pratikte root'a eşdeğer olduğunu açıkça söyler. Lab makinesinde bile bu grubu bilinçli kullan;
  ortak bir sunucuda herkesi bu gruba ekleme.
- **İnternete açık Docker API'si:** Docker'ın uzaktan yönetim arayüzü (genelde TCP 2375) kimlik
  doğrulamasız ve internete açık bırakılırsa, güvenlik şirketlerinin raporlarında defalarca
  anıldığı gibi, saldırganlar bu sunucularda kendi konteynerlerini çalıştırabilir (kripto
  madenciliği bunun sık görülen amacıdır). Tespit: `ss -tlnp` çıktısında `0.0.0.0:2375`
  aramak, dışarıdan port taramak. Önlem: API'yi hiç açma ya da yalnızca kimlik doğrulamalı
  ve ağ düzeyinde kısıtlı aç.
- **Etiketsiz imajlar:** `latest` etiketi sabit değildir; aynı komut farklı günlerde farklı bir
  yazılım indirebilir. Güvenlik denetimlerinde imaj etiketlerinin sabitlenmesi (hatta özet
  değeriyle sabitlenmesi) standart bir bulgu başlığıdır.
""",
    sure_hedef_dk=30,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    ad = s["metin"]["hedef_kon"]
    port = sh(f"grep -w {ad} docker_ps_cikti.txt | grep -oE ':[0-9]+->' | head -1 | tr -dc '0-9'")
    tab = sh("grep -nP '\\t' bozuk.yml | cut -d: -f1")
    kom = sh("awk -F': ' '/^temel_imaj/{print $2}' istek.txt")
    klasor = sh("awk -F': ' '/^sayfa_klasoru/{print $2}' istek.txt")
    yol = sh("awk -F': ' '/^konteyner_ici_yol/{print $2}' istek.txt")
    cp = sh("awk -F': ' '/^konteyner_portu/{print $2}' istek.txt")
    hp = sh("awk -F': ' '/^ana_makine_portu/{print $2}' istek.txt")
    servis = sh("awk -F': ' '/^servis_adi/{print $2}' istek.txt")
    baslat = sh("grep -c '^baslatma:' istek.txt")
    dockerfile = f"FROM {kom}\n"
    if baslat == "1":
        dockerfile += f"WORKDIR {yol}\n"
    dockerfile += f"COPY {klasor} {yol}\nEXPOSE {cp}\n"
    if baslat == "1":
        dockerfile += f'CMD ["python", "-m", "http.server", "{cp}"]\n'
    (lab / "Dockerfile").write_text(dockerfile)
    compose = (f"services:\n  {servis}:\n    image: {kom}\n    ports:\n      - \"127.0.0.1:{hp}:{cp}\"\n"
               f"    volumes:\n      - ./{klasor}:{yol}:ro\n    restart: unless-stopped\n")
    (lab / "docker-compose.yml").write_text(compose)
    return {1: SEVIYE.gorevler[0].kontrol.cevabi_goster(Baglam(s, lab, 1))[0],
            2: SEVIYE.gorevler[1].kontrol.cevabi_goster(Baglam(s, lab, 2))[0],
            3: port, 4: tab, 5: "", 6: "",
            7: SEVIYE.gorevler[6].kontrol.cevabi_goster(Baglam(s, lab, 7))[0]}
