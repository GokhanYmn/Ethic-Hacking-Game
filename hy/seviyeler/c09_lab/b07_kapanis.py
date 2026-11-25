"""Cilt 9 · Bölüm 7 — Kapanış Görevi: Kendi Lab'ının Tam Planı.

Oyuncu, `ihtiyac.txt` şartnamesinden Raspberry Pi için eksiksiz ve güvenli bir `docker-compose.yml`
hazırlar: arm64 uyumlu imajlar, 127.0.0.1'e bağlı portlar, `internal: true` arka ağda veritabanı,
yetki sertleştirmesi (privileged/docker.sock/host ağı yok) ve RAM bütçesi (mem_limit toplamı).
Oyun dosyayı statik denetler; Docker kuruluysa `docker compose config -q` ile canlı da sınar.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Secmeli, Serbest, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

DVWA = "ghcr.io/digininja/dvwa"
JUICE = "bkimminich/juice-shop"

VAKALAR = [
    {
        "ad": "Kalkan Güvenlik — stajyer lab'ı, nihai plan", "agler": ("frontend", "backend"),
        "ekstra": None,
        "brifing": """
Selin masana oturuyor: "Cilt 9'un sonu. Şimdi hepsini birleştir: Pi'nde çalışacak, eksiksiz ve
**güvenli** bir lab compose dosyası. Şartname `ihtiyac.txt`'te: hangi hedefler, hangi portlar, RAM
bütçesi. Dosyayı sen yazacaksın; ben yalnızca kontrol edeceğim."

Mert: "Pi'ye şimdi kurup bir ay sonra unutursan başına bela açarsın. Ortamı baştan doğru yap:
127.0.0.1, iç ağ, sertleştirme, bellek sınırı. Yarın Cilt 4'ten başlayıp bu lab'ı kullanacaksın."

Dosyalar: `ihtiyac.txt`.
""",
    },
    {
        "ad": "Paramix — geliştirici eğitim ortamı, nihai plan", "agler": ("on-ag", "arka-ag"),
        "ekstra": ("egitim-notlari", "nginx:1.27-alpine", 80, 64),
        "brifing": """
Ece Hanım (Paramix CTO'su) eğitim ortamını bu hafta devreye almak istiyor: "Her eğitmenin Pi'sinde aynı
ortam kurulabilsin. Tek bir dosya, tek komut. Ama dosya güvenli olmalı: ortam şirket ağına bağlı."

Selin: "İşte şartname. DVWA, Juice Shop, bir veritabanı ve eğitmenin notları için bir sayfa. Pi'nin RAM
bütçesini aşma; `mem_limit` yazmak bu yüzden zorunlu. Dosya hazır olunca sen bana göster."

Dosyalar: `ihtiyac.txt`.
""",
    },
    {
        "ad": "Mert'in Pi'si — ev lab'ı, nihai plan", "agler": ("dis-ag", "ic-ag"),
        "ekstra": ("ders-notlari", "httpd:2.4-alpine", 80, 96),
        "brifing": """
Mert evdeki Pi'sinin son planını istiyor: "Bütün bu aylık uğraşın sonucu: tek bir `docker-compose.yml`.
Çocukların tablet'i aynı Wi-Fi'da; hiçbir şey ağa açık kalmasın."

Selin: "Şartnameyi `ihtiyac.txt`'e yazdım. Pi'nin belleğini aşmayacak, portlar yalnızca 127.0.0.1,
veritabanı iç ağda, hiçbir konteyner privileged değil. Dosyayı yaz, ben de Mert'e senin imzanla vereyim."

Dosyalar: `ihtiyac.txt`.
""",
    },
]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    on, arka = v["agler"]
    p_dvwa = rng.randrange(8081, 8180)
    p_juice = rng.randrange(3000, 3100)
    servisler = [
        {"ad": "dvwa", "imaj": DVWA, "kp": 80, "hp": p_dvwa, "ag": [on, arka], "ram": rng.choice([256, 384])},
        {"ad": "juice-shop", "imaj": JUICE, "kp": 3000, "hp": p_juice, "ag": [on], "ram": rng.choice([512, 768])},
        {"ad": "lab-db", "imaj": "mariadb:10.11", "kp": 3306, "hp": None, "ag": [arka], "ram": rng.choice([256, 384])},
    ]
    if v["ekstra"]:
        ad, imaj, kp, ram = v["ekstra"]
        servisler.append({"ad": ad, "imaj": imaj, "kp": kp, "hp": rng.randrange(8200, 8300), "ag": [on], "ram": ram})
    toplam = sum(x["ram"] for x in servisler)
    butce = toplam + rng.choice([0, 128, 192])
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v, "servisler": servisler, "butce": butce, "on": on, "arka": arka,
        "metin": {"butce": str(butce), "on": on, "arka": arka, "dvwa_port": str(p_dvwa), "juice_port": str(p_juice)},
        "cevaplar": {"ornek": "ornek", "butce": butce},
    }


def yaz(lab: Path, s: dict) -> None:
    satir = ["# Lab şartnamesi (Selin). Raspberry Pi (arm64) için tek bir docker-compose.yml yazılacak.\n",
             f"pi_ram_butcesi_mb: {s['butce']}\n",
             f"on_ag_adi: {s['on']}\n",
             f"arka_ag_adi: {s['arka']}\n",
             "# arka ag 'internal: true' olmalı. ram_mb: servisin ihtiyacı (mem_limit en az bu kadar, hepsinin toplamı bütçeyi aşmasın).\n",
             "# host_port '-' ise o servis hiç port yayımlamaz.\n"]
    for x in s["servisler"]:
        hp = x["hp"] if x["hp"] else "-"
        satir.append(f"servis: {x['ad']} | imaj: {x['imaj']} | konteyner_port: {x['kp']} | host_port: {hp} "
                     f"| ag: {', '.join(x['ag'])} | ram_mb: {x['ram']}\n")
    u.yaz(lab / "ihtiyac.txt", "".join(satir))


# ------------------------------------------------------------------ kontroller

def _al(b: Baglam, adim: str):
    """Ortak ilk adım: docker-compose.yml'yi bul ve çöz. (Sonuc, None) hata ya da (None, d)."""
    ad = "docker-compose.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad), None
    return o.compose_denetle(yol, ad)


def _g1(b: Baglam) -> Sonuc:
    hata, d = _al(b, "servisler")
    if hata:
        return hata
    sv = o.servisler(d)
    for x in b.senaryo["servisler"]:
        if x["ad"] not in sv:
            return Sonuc(False, f"`{x['ad']}` servisi yok. Şartnamedeki her servisi aynı adla yaz.", yakin=True)
        if o.imaj_depo(sv[x["ad"]].get("image")) != o.imaj_depo(x["imaj"]):
            return Sonuc(False, f"`{x['ad']}` için `image:` değeri `{x['imaj']}` olmalı (şu an: {sv[x['ad']].get('image')!r}).", yakin=True)
    db = next(x for x in b.senaryo["servisler"] if x["hp"] is None)
    if not o.etiket_sabit_mi(sv[db["ad"]].get("image")):
        return Sonuc(False, f"`{db['ad']}` veritabanı imajında sürüm etiketi sabit olmalı (`{db['imaj']}`).", yakin=True)
    return Sonuc(True, "Servisler ve imajlar tamam: DVWA ve Juice Shop arm64 uyumlu imajlardan, veritabanı sürümü sabit.")


def _g2(b: Baglam) -> Sonuc:
    hata, d = _al(b, "portlar")
    if hata:
        return hata
    sv = o.servisler(d)
    for x in b.senaryo["servisler"]:
        if x["ad"] not in sv:
            return Sonuc(False, f"`{x['ad']}` servisi yok.", yakin=True)
        pl = o.portlar(sv[x["ad"]])
        if x["hp"] is None:
            if pl:
                return Sonuc(False, f"`{x['ad']}` veritabanıdır; port yayımlamamalı (`ports:` bölümünü kaldır).", yakin=True)
            continue
        if not any(p.get("host") == x["hp"] and p.get("konteyner") == x["kp"] for p in pl):
            return Sonuc(False, f"`{x['ad']}` için şartnamedeki port bağı yok: ana makine {x['hp']} -> konteyner {x['kp']}.", yakin=True)
        if not all(p.get("lokal") for p in pl):
            return Sonuc(False, f"`{x['ad']}` servisinde ağa açık bir port var. Hepsi `\"127.0.0.1:{x['hp']}:{x['kp']}\"` biçiminde olmalı.", yakin=True)
    for a, x in sv.items():
        if any(not p.get("lokal") for p in o.portlar(x)):
            return Sonuc(False, f"`{a}` servisinde ağa açık bir port kalmış.", yakin=True)
    return Sonuc(True, "Portlar tamam: yalnızca web hedefleri yayımlanıyor ve hepsi 127.0.0.1'e bağlı; veritabanı hiç yayımlanmıyor.")


def _g3(b: Baglam) -> Sonuc:
    hata, d = _al(b, "ağ")
    if hata:
        return hata
    s = b.senaryo
    sv = o.servisler(d)
    if not o.ag_ic_mi(d, s["arka"]):
        return Sonuc(False, f"`networks:` bölümünde `{s['arka']}` ağını tanımla ve altına `internal: true` yaz.", yakin=True)
    if (d.get("networks") or {}).get(s["on"]) is None and s["on"] not in (d.get("networks") or {}):
        return Sonuc(False, f"`networks:` bölümünde `{s['on']}` ağı da tanımlı olmalı.", yakin=True)
    if o.ag_ic_mi(d, s["on"]):
        return Sonuc(False, f"`{s['on']}` ağı internal olmamalı; web hedeflerinin yayımlanan portları yalnızca internal olmayan bir ağdan çalışır.", yakin=True)
    for x in s["servisler"]:
        if x["ad"] not in sv:
            return Sonuc(False, f"`{x['ad']}` servisi yok.", yakin=True)
        aglar = set(o.servis_aglari(d, x["ad"]))
        if aglar != set(x["ag"]):
            return Sonuc(False, f"`{x['ad']}` servisinin ağları `{', '.join(x['ag'])}` olmalı (şu an: {', '.join(sorted(aglar))}).", yakin=True)
    db = next(x for x in s["servisler"] if x["hp"] is None)
    for x in s["servisler"]:
        if x["ad"] != db["ad"] and s["arka"] not in x["ag"] and set(o.servis_aglari(d, x["ad"])) & set(o.servis_aglari(d, db["ad"])):
            return Sonuc(False, f"`{x['ad']}` ve `{db['ad']}` ortak ağda olmamalı.", yakin=True)
    return Sonuc(True, "Ağ tasarımı tamam: veritabanı yalnızca `internal: true` arka ağda; yalnızca DVWA ona ulaşabiliyor.")


def _g4(b: Baglam) -> Sonuc:
    hata, d = _al(b, "sertleştirme")
    if hata:
        return hata
    s = b.senaryo
    sv = o.servisler(d)
    for a, kod in o.riskler(d):
        if kod in ("privileged", "sock", "host_ag"):
            return Sonuc(False, f"`{a}` servisinde {o.RISK_ACIKLAMA[kod]}. Lab hedeflerinin buna ihtiyacı yok; kaldır.", yakin=True)
    toplam = 0.0
    for x in s["servisler"]:
        m = o.mem_mb(sv.get(x["ad"], {}).get("mem_limit"))
        if m is None:
            return Sonuc(False, f"`{x['ad']}` servisinde `mem_limit:` yok (örn. `mem_limit: {x['ram']}m`). Pi'nin belleği sınırlı; her servise tavan koy.", yakin=True)
        if m < x["ram"]:
            return Sonuc(False, f"`{x['ad']}` için `mem_limit` çok düşük: şartname en az {x['ram']} MB istiyor, uygulama bellek yetmezse kapanır.", yakin=True)
    for a, x in sv.items():
        m = o.mem_mb(x.get("mem_limit"))
        if m is None:
            return Sonuc(False, f"`{a}` servisinde `mem_limit:` yok.", yakin=True)
        toplam += m
    if toplam > s["butce"]:
        return Sonuc(False, f"Toplam `mem_limit` {toplam:.0f} MB; Pi bütçesi {s['butce']} MB. Her servise ihtiyacı kadar ver, fazlasını değil.", yakin=True)
    return Sonuc(True, f"Sertleştirme ve bellek planı tamam: privileged/docker.sock/host ağı yok, toplam mem_limit {toplam:.0f} MB (bütçe {s['butce']} MB).")


def _g5(b: Baglam) -> Sonuc:
    ad = "lab_notlari.txt"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    satirlar = [x.strip() for x in yol.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    for x in b.senaryo["servisler"]:
        if not any(x["ad"] in l for l in satirlar):
            return Sonuc(False, f"`{x['ad']}` servisi notlarda yok.", yakin=True)
        if x["hp"] and not any(x["ad"] in l and str(x["hp"]) in l for l in satirlar):
            return Sonuc(False, f"`{x['ad']}` için ana makine portu ({x['hp']}) aynı satırda yok. `servis: port` biçiminde yaz.", yakin=True)
    return Sonuc(True, "Lab notların hazır. Bir ay sonra bile hangi hedefin hangi portta olduğunu bileceksin.")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Sorun: eksiksiz ve güvenli bir lab", """
Cilt 9'un sonunda elinde altı parça var: mimari (Bölüm 1), Docker (2), web hedefleri (3),
zafiyetli makineler (4), çok makineli ağ (5) ve yalıtım/hijyen (6). Şimdi hepsini **tek bir dosyada**
birleştireceksin. Şartname:
""", komut="cat ihtiyac.txt", sonra="""
Her `servis:` satırı bir hedefi tarif eder: imaj, portlar, bağlı olacağı ağlar ve RAM ihtiyacı.
Başta bütçe ve iki ağın adı var.
"""),
    Adim("Bütçe: RAM'e sığıyor mu?", """
Önce hesabı yap (Bölüm 1): servislerin toplam ihtiyacı Pi'nin bütçesine sığıyor mu?
""", komut="awk -F'ram_mb: ' '/^servis:/{s+=$2} END{print s}' ihtiyac.txt", sonra="""
Bu toplam bütçeyi aşmamalı. Ayrıca compose dosyasına her servis için `mem_limit:` yazacaksın:
bir hedef çılgına dönüp Pi'nin belleğini tüketirse, Docker onu sınırlar.
"""),
    Adim("Servis adları ve imajlar", """
Önce servislerin adlarını çıkaralım (Bölüm 2-3'te öğrendiğin yapıyla yazılacaklar):
""", komut="grep '^servis:' ihtiyac.txt | cut -d'|' -f1,2", sonra="""
DVWA ve Juice Shop imajları arm64'ü destekleyen sürümlerdir (Bölüm 3); veritabanı imajının **sürümü
sabit** olmalı (Bölüm 6).
"""),
    Adim("Portlar ve ağlar", """
Portlar `host_port`, ağlar `ag:` alanında. Şartnameden yalnızca bu iki bilgiyi çıkaralım:
""", komut="grep '^servis:' ihtiyac.txt | cut -d'|' -f1,4,5", sonra="""
`host_port: -` olan servis (veritabanı) hiç port yayımlamaz. Diğerleri `"127.0.0.1:ANA:KONTEYNER"` ile
yalnızca kendi makinene açılır. Veritabanı yalnızca `internal: true` olan arka ağdadır, internete
çıkamaz. Yalnızca ona ihtiyacı olan servis (DVWA) arka ağa da bağlanır.
"""),
    Adim("Sertleştirme ve bellek sınırı", """
Dosyada olmaması gerekenler: `privileged: true`, `/var/run/docker.sock` bağı, `network_mode: host`.
Olması gereken: her serviste `mem_limit: 512m` gibi bir bellek tavanı. Örnek bir servis bloğu:

```
  juice-shop:
    image: bkimminich/juice-shop
    ports:
      - "127.0.0.1:3000:3000"
    networks: [frontend]
    mem_limit: 768m
    restart: unless-stopped
```

Docker kuruluysa dosyanın geçerliliğini şöyle sınarsın (yalnızca dosyayı okur, bir şey çalıştırmaz):
""", komut="docker compose config -q", calistir=False),
    Adim("Ayağa kaldır ve doğrula", """
Dosya hazır olunca ayağa kaldırır ve **PORTS** sütununu kontrol edersin: her satır `127.0.0.1:` ile
başlamalı; `0.0.0.0:` gördüğün an dosyaya dön.

- `docker compose up -d` — hepsini başlat
- `docker compose ps` — durumlarını gör
- `docker compose down` — hepsini durdur ve kaldır
""", komut="docker compose up -d", calistir=False),
    Adim("Lab'ı kullan", """
Artık Cilt 4-7'nin pratiğini bu lab'da yapabilirsin: Kali'den keşif (Cilt 4), Burp ile web
açıkları (Cilt 5), VM hedefler için ayrı bir x86 makine (Cilt 6), loglardan kendi izlerini okuma
(Cilt 7). Lab'ının **hep aynı** olması bir avantajdır: compose dosyan senin tarifin; bozarsan
`down` ile siler, `up` ile yeniden kurarsın.
""", komut="ls"),
]

GOREVLER = [
    Gorev("Pi için **`docker-compose.yml`** yazmaya başla. Şartnamedeki **her servisi** aynı adla ve istenen "
          "`image:` ile yaz; veritabanı imajının sürümü sabit olsun (şartnamedeki gibi). Docker varsa dosya canlı "
          "da sınanır. Hazır olunca `cevap 1`.",
          Durum(_g1, "```\nservices:\n  dvwa:\n    image: ghcr.io/digininja/dvwa\n  juice-shop:\n    image: bkimminich/juice-shop\n  lab-db:\n    image: mariadb:10.11\n```\n"
                     "(Şartnamedeki diğer servisleri de aynı biçimde ekle.)"),
          ("Önce yalnızca iskeleti kur: `services:` altında her servis adı ve `image:` satırı.",
           "`cat ihtiyac.txt` ile servis adlarını ve imajlarını oku. Girinti 2 boşluk; veritabanı imajında sürüm etiketi var.",
           "`grep '^servis:' ihtiyac.txt | cut -d'|' -f1,2` adları ve imajları yan yana yazar."),
          puan=40, baslik="İskelet: servisler ve imajlar"),
    Gorev("Aynı dosyaya portları ekle: web hedefleri `ihtiyac.txt`'teki `host_port` ve `konteyner_port` ile "
          "**yalnızca `127.0.0.1`**'e bağlansın; `host_port: -` olan servis hiç port yayımlamasın. "
          "Hazır olunca `cevap 2`.",
          Durum(_g2, "```\n    ports:\n      - \"127.0.0.1:<<dvwa_port>>:80\"      (dvwa için)\n      - \"127.0.0.1:<<juice_port>>:3000\"   (juice-shop için)\n```"),
          ("Her web servisi için bir `ports:` listesi; veritabanı için hiçbiri.",
           "Port satırı `\"127.0.0.1:ANA:KONTEYNER\"` biçiminde. Sayılar şartnamedeki `host_port` ve `konteyner_port`.",
           "`grep '^servis:' ihtiyac.txt | cut -d'|' -f1,3,4` servis, konteyner portu ve ana makine portunu yazar."),
          puan=45, baslik="Portlar 127.0.0.1'e"),
    Gorev("Ağları tasarla: `networks:` bölümünde `<<on>>` (normal) ve `<<arka>>` (`internal: true`) ağlarını "
          "tanımla; her servise şartnamedeki `ag:` listesindeki ağları ver. Veritabanı yalnızca iç ağda "
          "olsun. Hazır olunca `cevap 3`.",
          Durum(_g3, "```\nnetworks:\n  <<on>>:\n  <<arka>>:\n    internal: true\n```\n(Her serviste: `networks: [ağ1, ağ2]` — şartnamedeki `ag:` değerleri.)"),
          ("Dosyanın sonuna iki ağ tanımı, her servisin altına bir `networks:` satırı.",
           "`networks: [<<on>>, <<arka>>]` gibi köşeli parantezli liste yazabilirsin. Şartnamedeki `ag:` alanını aynen kopyala.",
           "En altta `networks:` → `  <<on>>:` ve `  <<arka>>:` altında `    internal: true`."),
          puan=50, baslik="Ağ bölümleme"),
    Gorev("Sertleştir ve belleği planla: hiçbir serviste `privileged`, `docker.sock` ya da `network_mode: host` "
          "olmasın; **her** servise `mem_limit:` ver: şartnamedeki `ram_mb` değerinden az olmasın, "
          "hepsinin toplamı Pi bütçesini (<<butce>> MB) aşmasın. Hazır olunca `cevap 4`.",
          Durum(_g4, "```\n    mem_limit: 512m   (her servise, şartnamedeki ram_mb kadar)\n```"),
          ("Sertleştirme çoğunlukla 'eklememek'tir; bellek ise her servise bir tavan koymaktır.",
           "Compose'ta `mem_limit: 384m` biçimi kullanılır. Servis başına şartnamedeki `ram_mb` kadar yaz; toplamı bütçeyle karşılaştır.",
           "`awk -F'ram_mb: ' '/^servis:/{s+=$2} END{print s}' ihtiyac.txt` toplam ihtiyacı verir; her servise tam kendi `ram_mb`'ini yazarsan bütçeye sığar."),
          puan=50, baslik="Sertleştirme ve RAM"),
    Gorev("Lab'ını belgelendir: `lab_notlari.txt` oluştur; her servis için bir satır yaz. Port yayımlayan "
          "servislerde satırda **servis adı ve ana makine portu** birlikte olsun (örn. `dvwa: 8081`). "
          "Hazır olunca `cevap 5`.",
          Durum(_g5, "```\ngrep '^servis:' ihtiyac.txt | awk -F'|' '{print $1 $4}'\n```\n(çıktıyı `servis: port` biçimine getirip `lab_notlari.txt`'e yaz)"),
          ("Notlar için `ihtiyac.txt` yeterli: servis adı ve `host_port`.",
           "Her satır `ad: port` biçiminde olabilir; portu olmayan veritabanı için yalnızca ad yaz.",
           "`grep '^servis:' ihtiyac.txt | cut -d'|' -f1,4` ad ve portu verir; düzenleyip `lab_notlari.txt`'e kaydet."),
          puan=35, baslik="Lab notları"),
    Gorev("Cilt 6'daki **yetki yükseltme ve Active Directory** pratiğini de lab'ına eklemek istiyorsun. "
          "Pi'ndeki planın yanına ne eklersin?",
          Secmeli([
              ("Ayrı bir x86 makinede VM hedefleri kurarım; Pi'yi Kali yapıp ikisini izole bir ağda birleştiririm",
               "Doğru: VM ve AD için x86 + RAM gerekir; izole ağ, yalıtım kuralını korur."),
              ("Hepsini Pi'nin içine eklerim; belleğin yetmediği yerde swap alanını büyütmek ve emülasyon kullanmak çözüm olur",
               "Mimari uyuşmazlığı swap ile çözülmez ve Windows Server VM'leri Pi'de gerçekçi çalışmaz."),
              ("VM hedeflerini ev ağına köprülü (bridged) bağlarım; böylece Kali onlara kolayca ulaşır ve yalıtım şart olmaz",
               "Köprülü ağ hedefleri ev ağındaki herkese açar; lab yalıtımını bozar (Bölüm 1)."),
              ("Hiçbir şey eklemem; Docker hedefleri Cilt 6'daki bütün konuları, çekirdek açıkları dahil, eksiksiz karşılar",
               "Docker konteynerleri çekirdeği paylaşır; çekirdek ve AD pratiği için gerçek VM gerekir (Bölüm 4-5)."),
          ], dogru=0),
          ("Cilt 6 için hem işletim sistemi derinliği hem de gerçek VM'ler gerekir; Pi'nin sınırları ne?",
           "x86 VM'ler Pi'de çalışmaz; ama Pi'yi saldırgan makine yapıp başka bir makineyle ağ kurabilirsin.",
           "Ayrı x86 makine + izole ağ."),
          puan=30, baslik="Cilt 6 için genişleme"),
    Gorev("Yazdığın planın **neden güvenli** olduğunu kendi cümlelerinle, en az üç gerekçeyle açıkla "
          "(tırnak içinde yaz: `cevap 7 \"...\"`).",
          Serbest("Portlar yalnızca 127.0.0.1'e bağlı olduğu için ağdaki başka cihazlar hedeflere ulaşamaz. "
                  "Veritabanı internal bir arka ağda ve hiç port yayımlamıyor; web hedefi ele geçirilse bile "
                  "ona doğrudan ulaşılamaz. Hiçbir konteyner privileged değil, docker.sock bağlı değil ve "
                  "mem_limit ile bellek sınırlı; ayrıca imajlar arm64 uyumlu ve compose dosyasıyla her şey "
                  "yeniden kurulabilir.", min_kelime=12),
          ("Üç şeyi düşün: kim erişebilir, bir hedef ele geçirilirse ne olur, kaynaklar nasıl sınırlı.",
           "127.0.0.1 bağı, internal ağ ve sertleştirme + bellek sınırı; üçü de plana yansıdı.",
           "Her gerekçe bir cümle: 'X yüzünden Y olamaz'."),
          puan=30, baslik="Plan gerekçesi"),
]


def _kapanis():
    return """
Bir lab, bir saldırı yüzeyidir; sen o yüzeyi **bilerek** belirliyorsun. Saldırgan gözüyle: ağa açık bir
port, bir veritabanına giden düz yol, `privileged` bir konteyner ya da sınırsız bellek her biri bir fırsattır.
Savunma gözüyle: 127.0.0.1 bağı, `internal: true` ağ, en az yetki ve kaynak sınırı, bu fırsatları
baştan kapatır. Bu dosya aynı zamanda bir **kanıt**tır: gelecekteki bir müşteriye "lab'ımı bu
şekilde, güvenli kuruyorum" diyebileceğin, tekrar üretilebilir bir tarif. Cilt 10'a bu lab'la geçersin.
"""


SEVIYE = Seviye(
    kimlik="c09b07",
    cilt=9,
    bolum=7,
    baslik="Kapanış Görevi: Kendi Lab'ının Tam Planı",
    brifing="Pi için eksiksiz ve güvenli bir docker-compose.yml hazırlayacaksın.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **Yanlış yapılandırma (misconfiguration):** OWASP Top 10 (2021) "Güvenlik Yanlış Yapılandırması"nı
  ayrı bir kategori olarak listeler; pek çok gerçek olayın kök nedeni bir zafiyet değil, açık bırakılmış
  bir ayar, gereğinden fazla yetki ya da yayımlanmış bir porttur. Tespit: yapılandırma
  dosyalarının (compose, bulut şablonları) kod gibi taranması; önlem: güvenli varsayılanlarla
  yazılmış şablon dosyalar.
- **Capital One (2019):** Olayda yanlış yapılandırılmış bir güvenlik bileşeni ve SSRF üzerinden bulut
  metadata servisine erişim kullanıldı; fazla yetkili bir rol saldırganın işini kolaylaştırdı. Ders,
  bu bölümün planındaki gibi **en az yetki** ilkesidir: her bileşene yalnızca gerekeni ver.
- **Dosya olarak altyapı:** Şirketlerde compose/Kubernetes/Terraform dosyaları, kod incelemesi ve
  otomatik tarama (CI) ile denetlenir. Senin `docker-compose.yml` dosyan da aynı disiplinin küçük
  bir örneğidir: kontrol listesiyle her değişiklikte yeniden denetle.
""",
    sure_hedef_dk=45,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    metin = (lab / "ihtiyac.txt").read_text(encoding="utf-8")
    on = sh("awk -F': ' '/^on_ag_adi/{print $2}' ihtiyac.txt")
    arka = sh("awk -F': ' '/^arka_ag_adi/{print $2}' ihtiyac.txt")
    satir = ["services:"]
    for k in o.kayitlar(metin, "servis"):
        satir += [f"  {k['servis']}:", f"    image: {k['imaj']}"]
        if k["host_port"] != "-":
            satir += ["    ports:", f"      - \"127.0.0.1:{k['host_port']}:{k['konteyner_port']}\""]
        satir += [f"    networks: [{k['ag']}]", f"    mem_limit: {k['ram_mb']}m", "    restart: unless-stopped"]
    satir += ["networks:", f"  {on}:", f"  {arka}:", "    internal: true"]
    (lab / "docker-compose.yml").write_text("\n".join(satir) + "\n")
    sh("grep '^servis:' ihtiyac.txt | awk -F'|' '{split($1,a,\": \"); split($4,b,\": \"); "
       "if (b[2] ~ /^[0-9]+/) print a[2] \": \" b[2]; else print a[2]}' > lab_notlari.txt")
    return {1: "", 2: "", 3: "", 4: "", 5: "",
            6: SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0],
            7: "Portlar 127.0.0.1'e bağlı olduğu için ağdaki başkaları hedeflere erişemez. Veritabanı internal arka "
               "ağda olduğu için web ele geçirilse bile doğrudan ulaşılamaz. Privileged yok ve mem_limit ile "
               "bellek sınırlı olduğu için kaynak tüketimi kontrol altındadır."}
