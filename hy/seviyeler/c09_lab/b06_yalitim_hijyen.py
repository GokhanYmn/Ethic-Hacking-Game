"""Cilt 9 · Bölüm 6 — Yalıtım, Snapshot ve Lab Hijyeni.

Beceri: hedeflerin internete/ağa açılmaması, 127.0.0.1 bağı; compose dosyasındaki beş klasik
güvenlik hatasını (herkese açık port, privileged, docker.sock bağı, host ağı, sabitlenmemiş imaj)
bulup düzeltmek; kullanılmayan konteynerleri temizlemek; snapshot / yeniden kurma kavramı;
lab'ı belgelendirmek.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c09_lab import ortak as o

ETIKET = {"nginx": "1.27-alpine", "python": "3.12-slim", "mariadb": "10.11", "redis": "7-alpine", "alpine": "3.20"}
KONT_PORT = {"nginx": 80, "python": 8000, "mariadb": 3306, "redis": 6379}

VAKALAR = [
    {
        "ad": "Kalkan Güvenlik — önceki stajyerin compose dosyası",
        "servisler": [("web-hedef", "nginx"), ("panel", "python"), ("veritabani", "mariadb"), ("onbellek", "redis")],
        "brifing": """
Selin bir dosya gönderiyor: "Bir önceki stajyerin bıraktığı lab compose dosyası bu. Hatalı olduğunu
biliyorum ama nerelerde, kimse bakmadı. Deniz de ofis ağında beklenmedik bir port görmüş. Önce
dosyadaki güvenlik hatalarını say, sonra düzelt."

Mert: "Hepsini kontrol listesiyle yap: beş kural, hepsi kısa. Ezberlenecek bir şey değil, bir alışkanlık."

Dosyalar: `lab_riskli.yml`, `kontrol_listesi.txt`, `docker_ps_a.txt`.
""",
    },
    {
        "ad": "Atölye Kahve — Berk'in internetten kopyaladığı dosya",
        "servisler": [("menu-sitesi", "nginx"), ("siparis-api", "python"), ("siparis-db", "mariadb"), ("oturum", "redis")],
        "brifing": """
Berk tedirgin: "Eğitim ortamı için internetteki bir yazıdan compose dosyası kopyaladım. Çalıştı
ama bir arkadaşım 'bunu kafenin Wi-Fi'ında açık bırakma' dedi. Haklı mı?"

Selin sana dönüyor: "Haklı olabilir. Dosyayı kontrol listesine göre tara: kaç hata var, hangisi
en tehlikeli? Sonra güvenli bir kopyasını çıkar."

Dosyalar: `lab_riskli.yml`, `kontrol_listesi.txt`, `docker_ps_a.txt`.
""",
    },
    {
        "ad": "Kuzgun Lojistik — depo eğitim ortamı",
        "servisler": [("takip-web", "nginx"), ("depo-api", "python"), ("depo-db", "mariadb"), ("yardimci", "alpine")],
        "brifing": """
Serdar Bey: "Depo ekibinin eğitim ortamı bir hafta içinde başlayacak. Eğitmen compose dosyasını
hazırlamış, ama dosyayı bir güvenlik gözüyle kimse okumadı. Ortam depodaki ağa bağlı olacak;
yanlışlıkla bir zafiyetli hedef bütün depoya açılmasın."

Selin: "Dosyadaki riskleri bul, düzelt, ayrıca ortamı belgele. Eğitim bittikten sonra kullanılmayan
konteynerler de temizlenecek, onlar için bir liste çıkar."

Dosyalar: `lab_riskli.yml`, `kontrol_listesi.txt`, `docker_ps_a.txt`.
""",
    },
]


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    servisler = v["servisler"]
    adlar = [a for a, _ in servisler]
    tur = dict(servisler)
    hp = {a: rng.randrange(8080, 8190) for a in adlar}
    for a in list(hp):   # benzersiz ana makine portları
        while list(hp.values()).count(hp[a]) > 1:
            hp[a] = rng.randrange(8080, 8190)
    # ihlal ataması
    while True:
        ihlal = {a: set() for a in adlar}
        sock_svc = rng.choice(adlar)
        ihlal[sock_svc].add("sock")
        port_adaylar = [a for a in adlar if tur[a] in ("nginx", "python", "mariadb", "redis")]
        for k in ("port", "privileged", "host_ag", "etiket"):
            for a in rng.sample(adlar, rng.choice([1, 1, 2])):
                if k == "port" and a not in port_adaylar:
                    continue
                ihlal[a].add(k)
        for a in adlar:   # host ağı kullanan servis port yayımlamaz
            if "host_ag" in ihlal[a]:
                ihlal[a].discard("port")
        toplam = sum(len(x) for x in ihlal.values())
        if 5 <= toplam <= 8 and all(any(k in x for x in ihlal.values()) for k in ("port", "privileged", "host_ag", "etiket")):
            break
    # docker ps -a
    pa = []
    durumlar = ["Up", "Exited", "Exited", "Up", "Exited", "Up"]
    rng.shuffle(durumlar)
    ps_adlar = u.benzersiz(rng, lambda r: f"{r.choice(['eski', 'deneme', 'test', 'demo', 'gecici', 'yedek'])}-"
                                          f"{r.choice(['web', 'api', 'db', 'panel', 'sunucu'])}-{r.randint(1, 9)}", 6)
    durdu = sorted(a for a, d in zip(ps_adlar, durumlar) if d == "Exited")
    return {
        "vaka": v["ad"], "brifing": v["brifing"], "v": v, "hp": hp, "ihlal": {a: sorted(x) for a, x in ihlal.items()},
        "tur": tur, "ps_adlar": ps_adlar, "ps_durum": durumlar, "sock_svc": sock_svc,
        "etiket_sec": {a: rng.choice(["", ":latest"]) for a in adlar},
        "sifre": "".join(rng.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(8)),
        "metin": {"sock_svc": "?"},
        "cevaplar": {"toplam": toplam, "sock": sock_svc, "durmus": durdu},
    }


def _servis(s: dict, a: str) -> list:
    t = s["tur"][a]
    ihl = set(s["ihlal"][a])
    imaj = t + (s["etiket_sec"][a] if "etiket" in ihl else ":" + ETIKET[t])
    satir = [f"  {a}:", f"    image: {imaj}"]
    if "privileged" in ihl:
        satir.append("    privileged: true")
    if "host_ag" in ihl:
        satir.append("    network_mode: host")
    elif t in ("nginx", "python"):
        kp = KONT_PORT[t]
        on = "0.0.0.0:" if "port" in ihl and s["hp"][a] % 2 == 0 else ""
        on = on if "port" in ihl else "127.0.0.1:"
        satir += ["    ports:", f'      - "{on}{s["hp"][a]}:{kp}"']
    elif "port" in ihl and t in KONT_PORT:
        kp = KONT_PORT[t]
        satir += ["    ports:", f'      - "{kp}:{kp}"']
    vol = []
    if "sock" in ihl:
        vol.append("/var/run/docker.sock:/var/run/docker.sock")
        vol.append(f"./veri-{a}:/veri")
    if vol:
        satir += ["    volumes:"] + [f"      - {x}" for x in vol]
    if t == "mariadb":
        satir += ["    environment:", f"      MARIADB_ROOT_PASSWORD: {s['sifre']}"]
    satir.append("    restart: unless-stopped")
    return satir


def yaz(lab: Path, s: dict) -> None:
    satir = ["services:"]
    for a, _ in s["v"]["servisler"]:
        satir += _servis(s, a)
    u.yaz(lab / "lab_riskli.yml", "\n".join(satir) + "\n")
    u.yaz(lab / "kontrol_listesi.txt",
          "# Lab compose kontrol listesi: her ihlal bir puan\n"
          "1. port: yayımlanan her port '127.0.0.1:' ile başlamalı (adres yazılmayan ya da 0.0.0.0 ihlaldir)\n"
          "2. privileged: 'privileged: true' yasak\n"
          "3. docker.sock: '/var/run/docker.sock' bağlamak yasak\n"
          "4. host ağı: 'network_mode: host' yasak\n"
          "5. sabit etiket: image satırında 'latest' ya da etiketsiz imaj yasak (sürüm yazılmalı)\n")
    ps = ["CONTAINER ID   IMAGE                COMMAND            CREATED        STATUS                    NAMES\n"]
    for i, (ad, d) in enumerate(zip(s["ps_adlar"], s["ps_durum"])):
        cid = "".join("0123456789abcdef"[(i * 5 + j * 3 + len(ad)) % 16] for j in range(12))
        durum = f"Up {i + 1} hours" if d == "Up" else f"Exited (0) {i + 2} weeks ago"
        ps.append(f"{cid:<14} {'nginx:1.27-alpine':<20} {chr(34) + '/entrypoint.sh' + chr(34):<18} "
                  f"{i + 2} weeks ago   {durum:<25} {ad}\n")
    u.yaz(lab / "docker_ps_a.txt", "".join(ps))


# ------------------------------------------------------------------ kontroller

def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n < beklenen:
        return "Eksik saymışsın. Beş kuralın hepsine bak: port, privileged, docker.sock, host ağı, sabit etiket. Aynı serviste birden fazla ihlal olabilir."
    return "Fazla saymışsın. Yalnızca kontrol listesindeki beş kural ihlaldir; `127.0.0.1:` ile başlayan portlar ve sürümü yazılı imajlar ihlal değil."


def _guvenli(b: Baglam) -> Sonuc:
    ad = "lab_guvenli.yml"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    hata, d = o.compose_denetle(yol, ad)
    if hata:
        return hata
    s = b.senaryo
    sv = o.servisler(d)
    for a, t in s["v"]["servisler"]:
        if a not in sv:
            return Sonuc(False, f"`{a}` servisi silinmiş. Servisleri silme, yalnızca riskleri gider.")
        if o.imaj_depo(sv[a].get("image")) != t:
            return Sonuc(False, f"`{a}` servisinin imajı `{t}` olarak kalmalı (yalnızca etiket eklenir).")
    kalan = o.riskler(d)
    if kalan:
        a, kod = kalan[0]
        return Sonuc(False, f"{len(kalan)} ihlal kaldı. İlk bulduğum: `{a}` servisinde {o.RISK_ACIKLAMA[kod]}.", yakin=len(kalan) < s["cevaplar"]["toplam"])
    for a, _ in s["v"]["servisler"]:
        orijinal = [(s["hp"][a], KONT_PORT[s["tur"][a]])] if s["tur"][a] in ("nginx", "python") and "host_ag" not in s["ihlal"][a] else []
        for h, k in orijinal:
            if not any(p.get("host") == h and p.get("konteyner") == k for p in o.portlar(sv[a])):
                return Sonuc(False, f"`{a}` servisinin portunu silmişsin ya da numarasını değiştirmişsin. Port `127.0.0.1:{h}:{k}` olarak kalmalı.", yakin=True)
    return Sonuc(True, "lab_guvenli.yml temiz: portlar 127.0.0.1'e bağlı, privileged/docker.sock/host ağı yok, imajlar sabit. "
                       + ("Docker bu dosyayı da kabul etti." if o.docker_var() else "Docker bu makinede yok; dosya statik denetlendi."))


def _notlar(b: Baglam) -> Sonuc:
    ad = "lab_notlari.txt"
    yol = o.dosya_bul(b, ad)
    if yol is None:
        return o.bulunamadi(ad)
    s = b.senaryo
    satirlar = [x.strip() for x in yol.read_text(encoding="utf-8", errors="replace").splitlines() if x.strip()]
    for a, t in s["v"]["servisler"]:
        if not any(a in x for x in satirlar):
            return Sonuc(False, f"`{a}` servisi notlarda yok. Her servis için bir satır yaz.", yakin=True)
        if t in ("nginx", "python") and "host_ag" not in s["ihlal"][a]:
            port = str(s["hp"][a])
            if not any(a in x and port in x for x in satirlar):
                return Sonuc(False, f"`{a}` için ana makine portu ({port}) aynı satırda yazılı değil. `servis: port` biçiminde yaz.", yakin=True)
    return Sonuc(True, "Lab notların hazır: hangi hedef hangi portta, tek dosyada. Bir ay sonra bile neyi nerede çalıştırdığını bileceksin.")


# ------------------------------------------------------------------ eğitim

ADIMLAR = [
    Adim("Güçlü lab güvenli labdır", """
Savunmasız hedefler **internete erişmemeli ve internetten erişilememelidir**. Lab'ını hem dış
dünyadan hem de kendi hatalarından korumak için beş kısa kural vardır. Kontrol listesi:
""", komut="cat kontrol_listesi.txt", sonra="""
Beş kuralın her biri, bir saldırganın ya da bir kazanın lab'ından dışarı sıçramasını engeller.
Sırayla bakalım.
"""),
    Adim("Kural 1: 127.0.0.1 bağı", """
Port eşlemesinde adres yazmazsan (ya da `0.0.0.0` yazarsan) Docker portu **bütün** ağ arayüzlerine
açar: aynı ağdaki herkes lab'ına ulaşır. `127.0.0.1:` önekiyle yalnızca kendi makinen erişir.
Riskli dosyadaki port satırlarına bakalım:
""", komut="grep -n -A1 'ports:' lab_riskli.yml", sonra="""
Bazı satırlar `127.0.0.1:` ile başlıyor, bazılarında hiç adres yok. Veritabanı gibi servislerin
portu hiç yayımlanmamalı; onlara yalnızca diğer konteynerler ağ üzerinden ulaşır.
"""),
    Adim("Kural 2-4: konteynere fazla yetki verme", """
Üç satır, konteyneri ana makineden neredeyse ayırt edilemez yapar:

- **`privileged: true`:** Konteynere ana makinenin neredeyse bütün yetkilerini ve cihazlarını verir.
- **`/var/run/docker.sock` bağı:** Konteynerin içinden Docker'ı yönetmeyi sağlar; Docker'ı
  yönetebilen biri ana makineyi yönetir (Cilt 1'deki "docker grubu = root").
- **`network_mode: host`:** Konteyner ana makinenin ağına doğrudan çıkar; port yalıtımı kalkar.

Dosyada bunları arayalım:
""", komut="grep -nE 'privileged|docker.sock|network_mode' lab_riskli.yml", sonra="""
Zafiyetli bir uygulamayı bu yetkilerle çalıştırmak, uygulama ele geçirildiğinde ana makinenin de
ele geçirilmesi demektir. Lab hedefleri **hiçbirine** ihtiyaç duymaz.
"""),
    Adim("Kural 5: imajı sabitle", """
`image: nginx` ya da `image: nginx:latest` her çekişte farklı bir yazılım getirebilir. Sürüm yazmak
(`nginx:1.27-alpine`) lab'ının her kurulduğunda aynı olmasını sağlar. İmaj satırlarına bakalım:
""", komut="grep -n 'image:' lab_riskli.yml"),
    Adim("Temizlik: kullanılmayan konteynerler", """
Lab zamanla durmuş konteynerlerle dolar. `docker ps -a` durmuş olanlar dahil hepsini listeler;
**STATUS** sütununda `Exited` yazanlar artık çalışmıyor. Silmek için `docker rm <ad>` kullanılır.
Kurgusal bir çıktıya bakalım:
""", komut="cat docker_ps_a.txt", sonra="""
Toplu temizlik için `docker system prune` vardır: durmuş konteynerleri, kullanılmayan ağları ve
bağlı olmayan imajları siler. `-a` ve `--volumes` ekledikçe kapsamı büyür; kullanılmayan
volume'leri de silebileceği için **önemli verin volume'de duruyorsa önce yedek al**.
Bu komutlar Docker gerektirir; eğitimde çalıştırmıyoruz.
"""),
    Adim("Snapshot ve yeniden kurma", """
Bir hedefi bozduktan sonra sıfırlamanın iki yolu vardır:

- **Sanal makinede snapshot:** Temiz hâlinin anlık görüntüsünü al; bozunca ona dön.
- **Docker'da compose dosyası:** `docker compose down` konteynerleri siler, `docker compose up -d`
  dosyadan sıfırdan kurar. Compose dosyan senin "snapshot"ındır; bu yüzden dosyayı yedekle.

**Hacker gözüyle:** Hedefe saldırmadan önce temiz bir başlangıç noktan olsun. Bozmaktan
korkmayan hızlı öğrenir, ama hiçbir noktaya dönemeyen yarım gün kaybeder.
""", komut="docker compose down", calistir=False),
    Adim("Lab'ı belgele", """
Hangi hedefin hangi portta çalıştığını bir not dosyasında tut (Cilt 4'teki keşif düzeninin aynısı).
Altı ay sonra "bu 8084 neydi?" diye düşünmezsin; ayrıca ağında fark etmediğin bir hedefi de
fark edersin. Ayrıca bu notlar bir rapora dönüşebilir.
""", komut="ls"),
]

GOREVLER = [
    Gorev("`lab_riskli.yml` dosyasını `kontrol_listesi.txt`'teki beş kurala göre tara. Toplam **kaç ihlal** var? "
          "(Her servis ve her kural ayrı bir ihlaldir; bir serviste birden fazla ihlal olabilir.)",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Beş kuralın her biri için dosyada ayrı bir arama yap, sayıları topla.",
           "`grep -c 'privileged: true'`, `grep -c docker.sock`, `grep -c 'network_mode: host'`... Port ve etiket için `grep`'i `grep -v` ile zincirle.",
           "Port: `grep -E '^ +- \"' lab_riskli.yml | grep -vc '\"127.0.0.1:'`. Etiket: `grep -E '^ +image:' lab_riskli.yml | grep -vcE ':[0-9v]'`. Dördüncü ve beşinci kural: `grep -c`. Hepsini topla."),
          puan=45, baslik="İhlalleri say"),
    Gorev("Hangi servis `docker.sock` dosyasını konteynerin içine bağlamış? (Servisin adı)",
          Metin("sock", sadece_ad=True, bicim="servis adı"),
          ("Bu bağ `volumes:` listesinde durur.",
           "`grep -n docker.sock lab_riskli.yml` satırı bulur; hangi servisin altında olduğuna yukarı doğru bak.",
           "`awk '/^  [a-z0-9_-]+:$/{s=$1} /docker.sock/{print s}' lab_riskli.yml` servis adını `ad:` biçiminde yazar."),
          puan=25, baslik="docker.sock"),
    Gorev("`lab_riskli.yml`'nin bir kopyasını `lab_guvenli.yml` adıyla kaydet ve **beş kuralın hiçbirini "
          "ihlal etmeyecek** biçimde düzelt: portlar `127.0.0.1`'e bağlı, `privileged`/`docker.sock`/`host` ağı "
          "yok, imajlar sürümlü. Servisleri ve port numaralarını silme. Docker varsa dosya canlı da sınanır. "
          "Hazır olunca `cevap 3`.",
          Durum(_guvenli, "```\ncp lab_riskli.yml lab_guvenli.yml\nsed -i -E 's#\"(0\\.0\\.0\\.0:)?([0-9]+:[0-9]+)\"#\"127.0.0.1:\\2\"#' lab_guvenli.yml\n"
                          "sed -i '/privileged: true/d; /network_mode: host/d; /docker.sock/d' lab_guvenli.yml\n```\n"
                          "(Ardından etiketsiz `image:` satırlarına sürüm ekle, örn. `nginx:1.27-alpine`.)"),
          ("Önce kopyala. Sonra hata hata ilerle: her kural için bir düzeltme var.",
           "`cp lab_riskli.yml lab_guvenli.yml`; ardından `nano` ile ya da `sed -i` ile satırları sil/değiştir. Portlar için `127.0.0.1:` ekle.",
           "`sed -i -E 's#\"(0\\.0\\.0\\.0:)?([0-9]+:[0-9]+)\"#\"127.0.0.1:\\2\"#'` portları, `sed -i '/privileged: true/d; /network_mode: host/d; /docker.sock/d'` yasak satırları halleder. İmajlara sürüm yaz."),
          puan=70, baslik="Güvenli kopya"),
    Gorev("Cilt 6'da bir VM hedefini bozdun ve temiz hâline hızla dönmek istiyorsun; ayrıca Docker "
          "hedeflerini de sıfırlamak istiyorsun. Doğru yöntemler hangisi?",
          Secmeli([
              ("VM'de aldığın temiz snapshot'a dönersin; Docker'da konteyneri silip compose'dan yeniden kurarsın",
               "Doğru: snapshot VM'in anlık görüntüsüdür; compose dosyası Docker hedefinin tarifidir."),
              ("VM'de snapshot gereksizdir, Docker hedefinde `docker restart` komutu hedefi fabrika ayarlarına döndürür",
               "`restart` konteyneri yeniden başlatır ama değişiklikler (yazılan dosyalar) kalır; fabrika ayarına dönmez."),
              ("Her ikisinde de makineyi yeniden başlatmak yeterlidir; yapılan bütün değişiklikler kendiliğinden silinir",
               "Yeniden başlatma değişiklikleri silmez; diskteki bozulma yeniden başlatmayla gitmez."),
              ("Snapshot yalnızca Docker'da bulunur; sanal makinede değişiklikleri elle tek tek geri almak zorundasın",
               "Snapshot asıl olarak sanal makinelerin özelliğidir; elle geri alma gerekmez."),
          ], dogru=0),
          ("VM ve Docker'ın 'temiz hâle dönme' yöntemleri farklıdır.",
           "VM için bir 'anlık görüntü', Docker için bir 'tarif' kavramı var.",
           "Snapshot (VM) ve compose ile yeniden kurma (Docker)."),
          puan=25, baslik="Sıfırlama"),
    Gorev("`docker_ps_a.txt` çıktısında kullanılmayan (**Exited**) konteynerlerin adları nedir? "
          "(Temizlenecekler listesi)",
          Kume("durmus", tur="metin", bicim="konteyner adları, virgülle ayrılmış"),
          ("STATUS sütununda `Exited` yazanlar durmuştur; `Up` yazanlar çalışıyor.",
           "`grep Exited docker_ps_a.txt` yalnızca durmuş konteynerleri verir; adlar son sütunda.",
           "`grep Exited docker_ps_a.txt | awk '{print $NF}'` yalnızca adları yazar."),
          puan=30, baslik="Temizlik listesi"),
    Gorev("`docker system prune -a --volumes` komutunu çalıştırmadan önce neye dikkat etmelisin?",
          Secmeli([
              ("Durmuş konteynerlerle birlikte kullanılmayan imajları ve volume'leri de silebilir; önemli veri varsa yedek alırım",
               "Doğru: kapsam geniştir, volume'deki veri kaybolabilir; yedek almak güvenli alışkanlıktır."),
              ("Yalnızca durmuş konteynerleri siler; imajlara ve volume'lere dokunmaz, bu yüzden her zaman tamamen risksizdir",
               "`-a` kullanılmayan bütün imajları, `--volumes` volume'leri de kapsamına alır."),
              ("Çalışan konteynerleri de zorla durdurup siler; bu yüzden yalnızca lab tamamen kapalıyken çalıştırılması gerekir",
               "`prune` çalışan konteynerlere dokunmaz; kullanılmayanları siler."),
              ("Yalnızca günlük (log) dosyalarını temizler; veriyle ilgisi yoktur ve her koşulda güvenle çalıştırılabilir bir komuttur",
               "Log temizleme değil, kaynak temizliğidir; volume'leri silebileceği için dikkat gerekir."),
          ], dogru=0),
          ("`-a` ve `--volumes` seçeneklerinin ne eklediğini düşün.",
           "Hangi veriler volume'de durur? Onlar 'kullanılmıyor' sayılabilir mi?",
           "Geniş kapsam: imajlar, ağlar, volume'ler. Önce yedek."),
          puan=30, baslik="prune dikkati"),
    Gorev("Lab'ını belgelendir: `lab_notlari.txt` oluştur ve her servis için bir satır yaz. Port yayımlayan "
          "servislerde satırda **servis adı ve ana makine portu** birlikte olsun (örn. `web: 8081`). "
          "Hazır olunca `cevap 7`.",
          Durum(_notlar, "```\nawk '/^  [a-z0-9_-]+:$/{s=$1;sub(\":\",\"\",s);print s} /^      - \"/{p=$0;gsub(/[ \"-]/,\"\",p);n=split(p,a,\":\");print s\": \"a[n-1]}' lab_riskli.yml > lab_notlari.txt\n```"),
          ("Notlar için `lab_riskli.yml`'deki servis adlarına ve port satırlarına ihtiyacın var.",
           "Servis adı ve ana makine portu (iki noktanın ortasındaki sayı) aynı satırda olmalı. Elle de yazabilirsin.",
           "Her servis için `ad: port` yazman yeterli; veritabanı gibi portsuz servisler için sadece adı yaz."),
          puan=35, baslik="Lab notları"),
]


def _kapanis():
    return """
Bir güvenlik uzmanının kendi lab'ını güvensiz kurması ironik ama yaygın bir hatadır. Saldırgan
gözüyle: ağdaki `0.0.0.0` ile açılmış bir port, `docker.sock` bağlı bir konteyner ya da
`privileged` bir hedef kolay bir basamaktır. Savunma gözüyle: beş kuralı kontrol listesi olarak
uygula, kullanılmayan her şeyi temizle ve bir hatada geri dönebileceğin bir tarif/snapshot
bulundur. Bu bölümde kendi dosyana uyguladığın yalıtım, en az erişim ve bilinen-iyi kaynak,
Cilt 7'deki savunma ilkelerinin ta kendisidir.
"""


SEVIYE = Seviye(
    kimlik="c09b06",
    cilt=9,
    bolum=6,
    baslik="Yalıtım, Snapshot ve Lab Hijyeni",
    brifing="Bir compose dosyasındaki güvenlik hatalarını bulacak, düzeltecek ve lab'ı belgeleyeceksin.",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=lambda lab, s: coz(lab, s),
    kapanis=_kapanis(),
    gercek_hayat="""
- **İnternete açık Docker API'si:** Docker'ın uzaktan yönetim arayüzü kimlik doğrulaması olmadan
  internete açık bırakıldığında, güvenlik şirketlerinin raporlarında defalarca belirtildiği gibi,
  otomatik taramalarla bulunup kripto madenciliği için kullanılmıştır. Tespit: `ss -tlnp` ve dışarıdan
  port taraması; önlem: API'yi ağa hiç açmamak ya da kimlik doğrulama ve ağ kısıtıyla açmak.
- **docker.sock = root:** Docker'ın kendi belgeleri, `docker.sock` erişimini ana makinede root
  erişimine eşdeğer sayar. Bu soketi bir konteynere bağlamak, o konteyner ele geçirildiğinde
  makinenin ele geçirilmesi demektir; güvenlik denetimlerinde klasik bir bulgudur.
- **İnternete açık veritabanları:** Parolasız MongoDB ve Elasticsearch gibi veritabanlarının internete
  açık bırakılıp otomatik araçlarla silindiği ya da fidye için kullanıldığı olaylar (2017'deki MongoDB
  fidye dalgası, 2020'deki "Meow" saldırısı gibi) çok kez raporlanmıştır. Veritabanı portunu hiç
  yayımlamamak (ya da yalnızca 127.0.0.1'e bağlamak) bu risk sınıfını kapatır.
""",
    sure_hedef_dk=35,
)


def coz(lab: Path, s: dict) -> dict:
    sh = lambda k: o.sh(k, lab)  # noqa: E731
    toplam = sh("a=$(grep -E '^ +- \"' lab_riskli.yml | grep -vc '\"127\\.0\\.0\\.1:'); "
                "b=$(grep -c 'privileged: true' lab_riskli.yml); c=$(grep -c 'docker.sock' lab_riskli.yml); "
                "d=$(grep -c 'network_mode: host' lab_riskli.yml); "
                "e=$(grep -E '^ +image:' lab_riskli.yml | grep -vcE ':[0-9v]'); echo $((a+b+c+d+e))")
    sock = sh("awk '/^  [a-z0-9_-]+:$/{s=$1; sub(\":\",\"\",s)} /docker.sock/{print s}' lab_riskli.yml")
    sh("cp lab_riskli.yml lab_guvenli.yml")
    sh("sed -i -E 's#\"(0\\.0\\.0\\.0:)?([0-9]+:[0-9]+)\"#\"127.0.0.1:\\2\"#' lab_guvenli.yml")
    sh("sed -i '/privileged: true/d; /network_mode: host/d; /docker.sock/d' lab_guvenli.yml")
    for repo, tag in ETIKET.items():
        sh(f"sed -i -E 's#image: {repo}(:latest)?$#image: {repo}:{tag}#' lab_guvenli.yml")
    sh("awk '/^  [a-z0-9_-]+:$/{s=$1;sub(\":\",\"\",s);print s} /^      - \"/{p=$0;gsub(/[ \"-]/,\"\",p);"
       "n=split(p,a,\":\");print s\": \"a[n-1]}' lab_riskli.yml > lab_notlari.txt")
    durmus = sh("grep Exited docker_ps_a.txt | awk '{print $NF}'").split()
    return {1: toplam, 2: sock, 3: "", 4: SEVIYE.gorevler[3].kontrol.cevabi_goster(Baglam(s, lab, 4))[0],
            5: " ".join(durmus), 6: SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0], 7: ""}
