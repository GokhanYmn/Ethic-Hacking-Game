"""Cilt 13 · Bölüm 1 — Konteyner Güvenliğinin Temeli.

Beceri: kurgusal compose ve Dockerfile dosyalarında `privileged`, docker.sock bağlama, host ağ ve
root kullanıcı sorunlarını bulmak ve dosyaları düzeltmek. `cevap <no>` dosyaların son halini kontrol
eder (Durum görevleri). Hiçbir konteyner çalıştırılmaz; dosyalar yalnızca okunur ve düzenlenir.

Vakalar: e-ticaret, hastane, fintech, lojistik. Hangi servisin hangi riski taşıdığı ve hangi
Dockerfile'ların root olarak çalıştığı her vakada değişir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c13_konteyner.ortak import py, sec_doldur, servis_bloklari, sh, sirket_sec

YIGINLAR = {
    "python": ("python:3.12-slim", 'CMD ["python", "sunucu.py"]', "COPY . .\nRUN pip install -r gereksinimler.txt"),
    "node": ("node:20-alpine", 'CMD ["node", "sunucu.js"]', "COPY . .\nRUN npm ci --omit=dev"),
    "java": ("eclipse-temurin:21-jre", 'CMD ["java", "-jar", "uygulama.jar"]', "COPY uygulama.jar ."),
}
SAHNE = {
    "pazarix": "Pazarix'in DevOps ekibi, kampanya öncesi compose dosyasını canlıya almadan önce Selin'e gösterdi.",
    "medora": "Medora Sağlık'ın randevu sistemi bir konteyner platformuna taşınıyor; ilk inceleme bu.",
    "paramix": "Paramix'in ödeme servisi konteynerlerde çalışıyor ve denetçi 'izolasyonu nasıl sağladınız?' diye soruyor.",
    "kuzgun": "Kuzgun Lojistik'in filo takip sistemi aniden yavaşladı; ekip konteyner yapılandırmasından şüpheleniyor.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on = sk["on"]
    sv = sk["servisler"]
    oz = {a: {"priv": False, "sock": False, "host": False} for a in sv}
    oz[sv[3]] = {"priv": True, "sock": True, "host": True}
    ek = rng.choice(["isci_sock", "api_priv", "isci_priv"])
    if ek == "isci_sock":
        oz[sv[2]]["sock"] = True
    elif ek == "api_priv":
        oz[sv[1]]["priv"] = True
    else:
        oz[sv[2]]["priv"] = True
    portlar = {sv[0]: f"{rng.choice([80, 8080])}:80", sv[1]: f"{rng.choice([8443, 9000])}:8000",
               sv[2]: "9001:9001", sv[3]: "9100:9100"}
    root = rng.sample(sv[:3], rng.randint(2, 3))
    yigin = rng.choice(list(YIGINLAR))
    return {
        "vaka": f"{sk['ad']} — konteyner yapılandırması",
        "sirket": sk, "oz": oz, "portlar": portlar, "root": root, "yigin": yigin,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "ajan": sv[3]},
        "cevaplar": {
            "priv": [a for a in sv if oz[a]["priv"]],
            "sock": [a for a in sv if oz[a]["sock"]],
            "root": root,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    sk = s["sirket"]
    on, sv = sk["on"], sk["servisler"]
    satirlar = [f"# {sk['ad']} — docker-compose (KURGUSAL)", "services:"]
    for a in sv:
        o = s["oz"].get(a, {})
        satirlar += [f"  {a}:", f"    image: {'postgres:16-alpine' if a == sv[4] else f'{on}/{a}:1.4'}"]
        if o.get("priv"):
            satirlar.append("    privileged: true")
        if o.get("host"):
            satirlar.append("    network_mode: host")
        if a in s["portlar"]:
            satirlar += ["    ports:", f'      - "{s["portlar"][a]}"']
        vol = [f"./veri/{a}:/veri"] if a != sv[4] else ["./veri/db:/var/lib/postgresql/data"]
        if o.get("sock"):
            vol.insert(0, "/var/run/docker.sock:/var/run/docker.sock")
        satirlar += ["    volumes:"] + [f"      - {v}" for v in vol]
    u.yaz(lab / "konteyner/compose.yml", "\n".join(satirlar) + "\n")
    imaj, cmd, kopya = YIGINLAR[s["yigin"]]
    for a in sv[:3]:
        d = [f"FROM {imaj}", "WORKDIR /uygulama", *kopya.splitlines(), "EXPOSE 8000"]
        if a not in s["root"]:
            d.append("USER 10001")
        d.append(cmd)
        u.yaz(lab / f"konteyner/dockerfiles/{a}.Dockerfile", "\n".join(d) + "\n")
    u.yaz(lab / "konteyner/OKU.txt",
          f"{sk['ad']} konteyner dosyaları (KURGUSAL). Hiçbir şey çalıştırılmaz; dosyaları oku ve düzelt.\n"
          "`compose.yml`: servisler. `dockerfiles/`: imaj tarifleri. Dosyaları düzenledikten sonra `cevap <no>` yaz.\n"
          "Gerçek hayatta compose dosyasını değiştirdikten sonra servisleri yeniden oluşturup ÇALIŞTIĞINI doğrula.\n")


def _compose(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "konteyner/compose.yml"
    if not yol.is_file():
        return Sonuc(False, "`konteyner/compose.yml` yok.")
    metin = yol.read_text(encoding="utf-8", errors="replace")
    bl = servis_bloklari(metin)
    sv = s["sirket"]["servisler"]
    if set(bl) != set(sv):
        return Sonuc(False, "Servis silinmiş ya da eklenmiş. Servisleri silme; yalnızca riskli ayarları kaldır.")
    for a in sv:
        if re.search(r"^\s+privileged:\s*true\b", bl[a], re.M):
            return Sonuc(False, f"`{a}` servisi hâlâ `privileged: true`. Bu, konteynere ana makinenin hemen her yetkisini verir.", yakin=True)
    for a in sv:
        if "docker.sock" in bl[a]:
            return Sonuc(False, f"`{a}` servisi hâlâ docker.sock'u bağlıyor: bu, konteynerden ana makinede root olmak demektir.", yakin=True)
    for a in sv:
        if re.search(r"^\s+network_mode:\s*[\"']?host", bl[a], re.M):
            return Sonuc(False, f"`{a}` servisi hâlâ host ağını kullanıyor; konteyner ağ yalıtımını kaybeder.", yakin=True)
    for a in sv:
        if re.search(r"^\s+-\s*(ALL|SYS_ADMIN)\s*$", bl[a], re.M):
            return Sonuc(False, f"`{a}` içinde `ALL`/`SYS_ADMIN` yetkisi var: `privileged` gibi tehlikeli.", yakin=True)
    for a in sv:
        if re.search(r"^(\s+)volumes:[ \t]*\n(?!\1[ \t]+-)", bl[a] + "\n", re.M):
            return Sonuc(False, f"`{a}` içinde boş bir `volumes:` kalmış (öğesi yok). Öğeyi sildiysen anahtarı da sil, YAML bozulur.", yakin=True)
    for a, p in s["portlar"].items():
        if p not in bl[a]:
            return Sonuc(False, f"`{a}` servisinin yayınlanan portunu (`{p}`) silmişsin; servis erişilemez olur. Yalnızca riskli ayarı kaldır.", yakin=True)
    for a in sv:
        if f"./veri/{a}:/veri" not in bl[a] and a != sv[4]:
            return Sonuc(False, f"`{a}` servisinin meşru veri bağını (`./veri/{a}:/veri`) silmişsin; yalnızca docker.sock satırı gitmeli.", yakin=True)
    return Sonuc(True, "Hiçbir servis privileged değil, docker.sock bağlı değil, host ağı kullanılmıyor; portlar ve veri bağları yerinde.")


def _dockerfile(b: Baglam) -> Sonuc:
    s = b.senaryo
    for a in s["root"]:
        yol = b.lab / f"konteyner/dockerfiles/{a}.Dockerfile"
        if not yol.is_file():
            return Sonuc(False, f"`{yol.name}` yok.")
        satirlar = yol.read_text(encoding="utf-8", errors="replace").splitlines()
        if not any(re.match(r"^\s*FROM\s", x) for x in satirlar):
            return Sonuc(False, f"`{yol.name}` içindeki `FROM` satırı silinmiş.")
        komut = [i for i, x in enumerate(satirlar) if re.match(r"^\s*(CMD|ENTRYPOINT)\b", x)]
        if not komut:
            return Sonuc(False, f"`{yol.name}` içindeki `CMD`/`ENTRYPOINT` silinmiş; imaj bir şey çalıştırmalı.")
        kul = [(i, re.match(r"^\s*USER\s+(\S+)", x).group(1)) for i, x in enumerate(satirlar) if re.match(r"^\s*USER\s+\S+", x)]
        if not kul:
            return Sonuc(False, f"`{yol.name}` hâlâ `USER` satırı içermiyor: konteyner **root** olarak çalışır. root olmayan bir kullanıcı ver.", yakin=True)
        i, deger = kul[-1]
        if deger.split(":")[0].lower() in ("root", "0"):
            return Sonuc(False, f"`{yol.name}` içinde `USER {deger}`: bu hâlâ root. Root olmayan bir kullanıcı (örn. `10001`) ver.", yakin=True)
        if i > komut[0]:
            return Sonuc(False, f"`{yol.name}` içinde `USER` satırı `CMD`'den **sonra**: etkisi olmaz. `CMD`/`ENTRYPOINT`'ten önce yaz.", yakin=True)
    return Sonuc(True, "Eskiden root olarak çalışan imajların hepsi artık root olmayan bir kullanıcıyla başlıyor.")


def coz(lab: Path, s: dict) -> dict:
    k = "konteyner"
    ad = lambda deger: sh(f"awk '/^  [a-z-]+:$/ {{s=$1}} /{deger}/ {{print s}}' {k}/compose.yml | tr -d ':' | tr '\\n' ' '", lab)
    priv = ad("privileged: true")
    sock = ad("docker.sock")
    root = sh(f"for f in {k}/dockerfiles/*.Dockerfile; do grep -q '^USER' $f || basename $f .Dockerfile; done | tr '\\n' ' '", lab)
    sh(f"sed -i '/privileged: true/d;/docker.sock/d;/network_mode: host/d' {k}/compose.yml", lab)
    for a in s["root"]:
        sh(f"sed -i '0,/^CMD/s//USER 10001\\nCMD/' {k}/dockerfiles/{a}.Dockerfile", lab)
    return sec_doldur({1: "", 2: priv, 3: sock, 4: root, 5: "", 6: ""}, GOREVLER, lab, s)


def _priv_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen & {x.lower() for x in b.senaryo["cevaplar"]["sock"]} - {x.lower() for x in beklenen}:
        return "Listende docker.sock bağlayan ama `privileged` olmayan bir servis var. İkisi ayrı risklerdir; burada yalnızca `privileged: true` olanlar."
    return None


def _sock_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen & {x.lower() for x in b.senaryo["cevaplar"]["priv"]} - {x.lower() for x in beklenen}:
        return "Listende `privileged` olan ama docker.sock bağlamayan bir servis var. Burada yalnızca `docker.sock` satırı olanlar."
    return None


def _root_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen > beklenen:
        return "Listende `USER` satırı olan bir Dockerfile var; o zaten root olmayan bir kullanıcıyla çalışıyor."
    return None


ADIMLAR = [
    Adim("Konteyner sanal makine değildir", """
Bir **sanal makinenin** kendi çekirdeği (kernel) vardır; bir **konteyner** ise ana makinenin
çekirdeğini paylaşan, yalnızca izole edilmiş bir süreçtir. Bu onları hafif yapar ama yalıtımları VM'den
zayıftır: konteynerden çıkıp ana makineye ulaşmak (**container escape**, konteyner kaçışı) bir VM'den
çıkmaktan daha olasıdır.

**<<musteri>>**. <<sahne>> Elindeki dosyalar: bir `compose.yml` ve servislerin Dockerfile'ları.
(Hiçbir şey çalıştırılmayacak; dosyaları okuyup düzelteceksin.)
""", komut="cat konteyner/compose.yml"),
    Adim("privileged: her kapının anahtarı", """
`privileged: true` konteynere ana makine yetkilerinin neredeyse tamamını verir: aygıtlara erişim,
çekirdek ayarları, güvenlik profillerinin kapatılması. Konteyner izolasyonu fiilen yok olur.
Hangi servisler `privileged`?
""", komut="grep -n 'privileged' konteyner/compose.yml", sonra="""
Satır numarası sana yeri söyler; **hangi servise** ait olduğunu görmek için servis adı satırlarını da
listele: `grep -n 'privileged\\|^  [a-z]' konteyner/compose.yml`
"""),
    Adim("docker.sock: root'a giden kısayol", """
`/var/run/docker.sock`, Docker yönetim soketidir. Bir konteynere bağlarsan, konteyner içindeki süreç
**ana makinenin Docker'ını yönetebilir**; yani yeni ayrıcalıklı konteynerler başlatabilir. Cilt 1'i
hatırla: `docker` grubundaki kullanıcı pratikte root'tur. Aynı şey soketi içeri alan konteyner için
geçerlidir.
""", komut="grep -n 'docker.sock' konteyner/compose.yml", sonra="""
Bu servis için gerçekten ana makinenin Docker'ına ihtiyaç var mı? Çoğu zaman cevap **hayır**: bir
"izleme" ya da "kolaylık" aracı, soketin yerine daha dar bir arayüzle (salt okunur metrik, ayrı bir
yetkili servis) aynı işi görebilir.
"""),
    Adim("Host ağı", """
`network_mode: host` konteyneri ana makinenin ağ yığınına koyar: konteyner ana makinenin tüm
arayüzlerini ve yerel (127.0.0.1) servislerini görür. Ağ yalıtımı kalmaz.
""", komut="grep -n 'network_mode' konteyner/compose.yml"),
    Adim("Root olarak çalışan imajlar", """
Dockerfile'da `USER` satırı yoksa konteyner **root** kullanıcıyla çalışır. Konteyner içindeki root,
bir escape bulunursa ana makinede de root'a dönüşme riskini büyütür. Hangi Dockerfile'larda `USER`
satırı **yok**? `grep -L` içinde eşleşme olmayan dosyaları listeler:
""", komut="grep -L '^USER' konteyner/dockerfiles/*.Dockerfile", sonra="""
Çıktıdaki dosyalar root olarak çalışır. Çözüm: `CMD`/`ENTRYPOINT`'ten **önce** bir `USER` satırı
(root olmayan bir kullanıcı) eklemek.
"""),
    Adim("Düzeltme ilkeleri", """
Düzeltirken en az ayrıcalık ilkesi: `privileged` yok, docker.sock bağlanmaz, host ağı yok, root değil.
Bir servisin gerçekten özel bir yetkiye ihtiyacı varsa **tek bir** yetenek ver (`cap_add: [NET_ADMIN]`
gibi), `ALL` ya da `SYS_ADMIN` verme.

Ama dikkat: düzeltme servisi bozmamalı. Portlar ve meşru veri bağları yerinde kalmalı; bir `volumes:`
anahtarının altını boşaltırsan YAML bozulur.
"""),
]

GOREVLER = [
    Gorev("Konteyner ile sanal makine arasındaki temel fark nedir?",
          Secmeli([
              ("Konteyner ana makinenin çekirdeğini paylaşır; VM'in kendi çekirdeği vardır",
               "Doğru. Hafifliğin bedeli, çekirdek paylaşımı yüzünden daha zayıf yalıtımdır."),
              ("Konteyner her zaman ayrı bir fiziksel sunucuda çalışır, VM ise yalnızca bulutta bulunur",
               "Yanlış. İkisi de aynı donanım üzerinde çalışabilir; fark çekirdek paylaşımıdır."),
              ("VM ana makinenin çekirdeğini kullanır, konteyner ise kendi çekirdeğini yanında getirir",
               "Yanlış. Roller ters yazılmış: çekirdeği paylaşan konteynerdir."),
              ("İkisi arasında güvenlik açısından fark yoktur; yalnızca adları ve ikonları farklıdır",
               "Yanlış. Yalıtım düzeyi güvenlik açısından önemli bir farktır."),
          ], dogru=0),
          ("Çekirdek kimde?",
           "Çekirdeği paylaşmak yalıtımı güçlendirir mi zayıflatır mı?",
           "Konteyner = ana makinenin çekirdeği; VM = kendi çekirdeği."),
          puan=20, baslik="Konteyner ve VM"),
    Gorev("`compose.yml` içinde **`privileged: true`** olan servislerin adlarını yaz.",
          Kume("priv", sik_hatalar=_priv_hata, bicim="servis adları, virgülle ayrılmış"),
          ("Önce `privileged` satırlarını bul, sonra hangi servisin altında olduklarına bak.",
           "`grep -n 'privileged\\|^  [a-z]' konteyner/compose.yml` hem servis adlarını hem `privileged` satırlarını sıralı gösterir.",
           "`awk '/^  [a-z-]+:$/ {s=$1} /privileged: true/ {print s}' konteyner/compose.yml`"),
          puan=30, baslik="Privileged servisler"),
    Gorev("`docker.sock`'u kendi içine bağlayan servislerin adlarını yaz.",
          Kume("sock", sik_hatalar=_sock_hata, bicim="servis adları, virgülle ayrılmış"),
          ("Soketin yolu `/var/run/docker.sock`.",
           "`grep -n 'docker.sock\\|^  [a-z]' konteyner/compose.yml` ile servis adlarıyla birlikte gör.",
           "`awk '/^  [a-z-]+:$/ {s=$1} /docker.sock/ {print s}' konteyner/compose.yml`"),
          puan=30, baslik="docker.sock bağlayanlar"),
    Gorev("Hangi Dockerfile'lar **root** olarak çalışıyor (`USER` satırı yok)? Servis adlarını yaz "
          "(`.Dockerfile` olmadan).",
          Kume("root", sik_hatalar=_root_hata, bicim="servis adları, virgülle ayrılmış"),
          ("Aradığın şey bir eksik: `USER` yok.",
           "`grep -L '^USER' konteyner/dockerfiles/*.Dockerfile`",
           "Çıktıdaki dosya adlarından `.Dockerfile` uzantısını at."),
          puan=30, baslik="Root imajlar"),
    Gorev("`compose.yml` dosyasında **`<<ajan>>`** başta olmak üzere bütün servislerden `privileged: true`, "
          "`docker.sock` bağlantısı ve `network_mode: host` ayarlarını kaldır. Portlar ve veri bağları kalsın. "
          "Bitince `cevap 5`.",
          Durum(_compose, "privileged, docker.sock ve network_mode: host satırları silinir"),
          ("Üç ayar tür tür silinecek; başka satırlara dokunma.",
           "Satırları `grep -n` ile bul; `sed -i '/DESEN/d'` satır siler. Boş `volumes:` bırakma.",
           "`sed -i '/privileged: true/d;/docker.sock/d;/network_mode: host/d' konteyner/compose.yml`"),
          puan=50, baslik="Compose'u düzelt"),
    Gorev("Root olarak çalışan Dockerfile'lara `CMD`'den **önce** root olmayan bir `USER` ekle (örn. `USER 10001`). "
          "Bitince `cevap 6`.",
          Durum(_dockerfile, "USER 10001 (CMD'den önce) ekle"),
          ("`USER` satırının yeri önemlidir: `CMD`'den önce.",
           "Önceki görevde bulduğun Dockerfile'lara `USER 10001` satırı ekle.",
           "`sed -i '0,/^CMD/s//USER 10001\\nCMD/' konteyner/dockerfiles/<servis>.Dockerfile` ya da `nano` ile."),
          puan=40, baslik="Root olmayan kullanıcı"),
    Gorev("Bir konteynere `/var/run/docker.sock` bağlamak neden tehlikelidir?",
          Secmeli([
              ("Konteyner, ana makinenin Docker'ını yönetip ayrıcalıklı konteyner başlatabilir",
               "Doğru. Cilt 1'deki 'docker grubu = root' ilkesinin konteyner içindeki karşılığıdır."),
              ("Soket konteynerin disk alanını doldurduğu için ana makine çöker ama başka bir risk yoktur",
               "Yanlış. Asıl risk disk değil, Docker'ın yönetim yetkisidir."),
              ("Soket yalnızca log yazar; bu yüzden tehlikesi sadece log dosyalarının şişmesidir",
               "Yanlış. Docker soketi yönetim API'sidir, log dosyası değil."),
              ("Soket konteynerin internete çıkışını kapatır ve servis yalnızca yerel ağda çalışır",
               "Yanlış. Soketin ağ erişimiyle ilgisi yoktur."),
          ], dogru=0),
          ("Soket neyin kapısı?",
           "Cilt 1'de `docker` grubu için ne demiştik?",
           "Docker'ı yönetebilen = pratikte root."),
          puan=20, baslik="docker.sock tehlikesi"),
    Gorev("'Container escape' (konteyner kaçışı) ne demektir?",
          Secmeli([
              ("Konteynerin izolasyonunu kırıp ana makineye (host) ulaşmak",
               "Doğru. `privileged` ve docker.sock bu kaçışı neredeyse hediye eder."),
              ("Bir konteynerin kendi kendine kapanması ve yeniden başlamaması",
               "Yanlış. Bu bir çökmedir; escape bir güvenlik kavramıdır."),
              ("İmajın yerel diskten silinip internetten yeniden çekilmesi",
               "Yanlış. Bu bir imaj yönetimi işlemidir, güvenlik ihlali değil."),
              ("Bir konteynerin başka bir konteynerle aynı adı kullanması",
               "Yanlış. Ad çakışması bir yapılandırma hatasıdır; escape değil."),
          ], dogru=0),
          ("Kaçmak = bir sınırı geçmek.",
           "Hangi sınır?",
           "Konteyner sınırı; hedef ana makine."),
          puan=20, baslik="Container escape"),
]


def _kapanis():
    return """
Konteyner güvenliğinin kalbi **kaçış**tır: izolasyonu kırıp ana makineye ulaşmak. `privileged`, docker.sock
bağı ve host ağı bunu neredeyse hediye eder; saldırgan konteynerde kod çalıştırabilirse bu üç ayarı
hemen arar. Savunma dersi: bunları compose/Kubernetes dosyalarında otomatik tarayan bir kontrol yaz,
en az ayrıcalığı varsayılan yap, imajları root olmayan kullanıcıyla başlat ve düzeltmeyi yaparken
servisi bozmadığını (port, veri bağı) doğrula. Konteyner VM kadar güvenilir değildir; ek katmanlar
(izleme, ağ kısıtı) gerekir.
"""


SEVIYE = Seviye(
    kimlik="c13b01",
    cilt=13,
    bolum=1,
    baslik="Konteyner Güvenliğinin Temeli",
    brifing="""
Mert compose dosyasını ekrana atıyor: "**<<musteri>>**. <<sahne>> `docker-compose.yml` ve
Dockerfile'ları aldık. Bu dosyalarda bir konteyner kaçışının üç klasik ön koşulundan biri ya da hepsi
olabilir. Bul ve kapat. Ama servisi bozarsan sabah erkenden DevOps ekibi sana bakacak."

Selin: "Hiçbir şeyi çalıştırmayacaksın. Dosyaları oku, riski anla, düzelt. Güvenlik, kurulumdan önce
başlar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **docker grubu ve docker.sock:** Docker'ın kendi belgeleri, Docker yönetim yetkisine (örneğin
  `docker` grubuna üyelik) sahip olmanın ana makinede root'a eşdeğer olduğunu belirtir. Soketi bir
  konteynere bağlamak aynı yetkiyi o konteynere vermektir.
- **Yaygın bulgu:** Pek çok konteyner güvenliği denetiminde `privileged` konteynerler, soket bağları
  ve root olarak çalışan imajlar en sık raporlanan bulgular arasındadır; bu yüzden CIS Docker
  Benchmark gibi rehberler bunları açıkça ele alır.
- **Tespit ve önleme:** Statik tarayıcılar (compose/Kubernetes dosyalarını okuyan denetimler) bu
  ayarları dağıtımdan önce yakalar; çalışma zamanında `privileged` konteyner başlatılması veya
  docker.sock bağlanması izleme araçlarında alarm olarak tanımlanabilir. Ayrıca varsayılan olarak
  root olmayan kullanıcı ve düşürülmüş yetenekler (capabilities) uygulanır.
""",
    sure_hedef_dk=35,
)
