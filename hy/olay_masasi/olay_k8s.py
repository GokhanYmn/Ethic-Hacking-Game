"""Olay Masası — Konteyner / Kubernetes Yanlış Yapılandırma Denetimi.

TAMAMEN SAVUNMACI ve KURGUSAL: oyuncu, bir müşterinin Kubernetes dağıtım dosyasını (`dagitim.yaml`) ve
imaj tarama özetini (`imaj_tarama.csv`) DENETLER. Hiçbir kümeye bağlanılmaz, hiçbir şey çalıştırılmaz.
Manifestte iki konteyner vardır: biri yanlış yapılandırılmış (privileged, hostPath, root, açık sır,
bazen `:latest` ve kaynak limitsizliği), diğeri düzgün (ama korkutucu görünen tuzaklar taşır:
`privileged: false`, `secretKeyRef` ile bağlanan `DB_PASSWORD`). İmaj taramasında kritik açığı
olan imaj manifestte kullanılan imajdır; manifestte kullanılmayan başka bir imajda da kritik açık vardır (tuzak).

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. `uret` ve `yaz` aynı
`random.Random(_alt)` ile `_akis(alt)` üzerinden veriyi yeniden üretir.
PyYAML yoktur; çözümler grep/awk ile yapılır.
"""
from __future__ import annotations

import random
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import csv_yaz, sec_doldur, sh

SENARYOLAR = [
    {"musteri": "Pazarix", "sektor": "e-ticaret", "kisi": "Tuncay Bey (platform sorumlusu)", "kod": "pzx",
     "latest": True, "limitsiz": False,
     "uygulama": "siparis-api", "yan": "vitrin",
     "hikaye": "Kampanya haftası öncesi sipariş servisi hızla kümeye taşındı; kimse ayarlara ikinci kez bakmadı."},
    {"musteri": "Medora Sağlık", "sektor": "hastane", "kisi": "Dr. Aslı Hanım (bilgi işlem sorumlusu)", "kod": "mdr",
     "latest": False, "limitsiz": True,
     "uygulama": "randevu-api", "yan": "portal",
     "hikaye": "Randevu servisi, kümeye geçerken test ortamından kopyalanan bir dosyayla canlıya çıktı."},
    {"musteri": "Paramix", "sektor": "fintech", "kisi": "Kaan Bey (güvenlik mühendisi)", "kod": "pmx",
     "latest": True, "limitsiz": True,
     "uygulama": "odeme-api", "yan": "webhook-isci",
     "hikaye": "PCI denetimi öncesi, ödeme servisinin dağıtım dosyası ilk kez dışarıdan biri tarafından okunuyor."},
]

SIR_ADLARI = ["API_TOKEN", "ADMIN_PASSWORD", "JWT_SECRET", "ODEME_API_KEY", "SMTP_PASSWORD"]
HOST_YOLLARI = ["/var/log", "/etc", "/opt/veri"]
CVE_PAKETLERI = ["openssl", "zlib", "glibc", "libxml2", "curl", "busybox", "sqlite", "expat"]
ALAN = "kayit.lab"
NS = "uretim"
KARISIK = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _cve(rng, kullanilan: set) -> str:
    while True:
        c = f"CVE-2026-{rng.randint(1000, 48999)}"
        if c not in kullanilan:
            kullanilan.add(c)
            return c


def _akis(alt: int) -> dict:
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    kod = sen["kod"]
    kotu, temiz = sen["uygulama"], sen["yan"]
    sir_ad = rng.choice(SIR_ADLARI)
    sir_deger = "".join(rng.choice(KARISIK) for _ in range(14))
    host = rng.choice(HOST_YOLLARI)
    kotu_etiket = "latest" if sen["latest"] else f"{rng.randint(1, 3)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}"
    temiz_etiket = f"{rng.randint(2, 4)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}"
    kotu_imaj = f"{ALAN}/{kod}/{kotu}:{kotu_etiket}"
    temiz_imaj = f"{ALAN}/{kod}/{temiz}:{temiz_etiket}"
    eski_imaj = f"{ALAN}/{kod}/{rng.choice(['bakim-araci', 'rapor-araci', 'yedek-araci'])}:{rng.randint(1, 2)}.{rng.randint(0, 9)}"
    port_k, port_t = rng.choice([8080, 8000, 9000]), rng.choice([3000, 8081, 8443])

    kotu_limit = "" if sen["limitsiz"] else (
        "          resources:\n            limits:\n              cpu: \"500m\"\n              memory: \"256Mi\"\n")
    yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {kotu}
  namespace: {NS}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: {kotu}
  template:
    metadata:
      labels:
        app: {kotu}
    spec:
      containers:
        - name: {kotu}
          image: {kotu_imaj}
          ports:
            - containerPort: {port_k}
          env:
            - name: LOG_LEVEL
              value: "info"
            - name: {sir_ad}
              value: "{sir_deger}"
          securityContext:
            privileged: true
            runAsUser: 0
{kotu_limit}          volumeMounts:
            - name: ana-makine
              mountPath: /host
        - name: {temiz}
          image: {temiz_imaj}
          ports:
            - containerPort: {port_t}
          env:
            - name: LOG_LEVEL
              value: "warn"
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: {kod}-veritabani
                  key: parola
          securityContext:
            privileged: false
            runAsUser: 10001
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
          resources:
            limits:
              cpu: "250m"
              memory: "128Mi"
          volumeMounts:
            - name: gecici
              mountPath: /tmp
      volumes:
        - name: gecici
          emptyDir: {{}}
        - name: ana-makine
          hostPath:
            path: {host}
"""
    # imaj taraması
    kul: set = set()
    satir = []
    n_krit = rng.randint(2, 4)
    kotu_satirlar = [("CRITICAL", rng.choice(CVE_PAKETLERI)) for _ in range(n_krit)]
    kotu_satirlar += [(rng.choice(["HIGH", "MEDIUM", "HIGH", "LOW"]), rng.choice(CVE_PAKETLERI)) for _ in range(rng.randint(2, 4))]
    for cid, pk in kotu_satirlar:
        satir.append((kotu_imaj, pk, _cve(rng, kul), cid))
    for _ in range(rng.randint(3, 5)):
        satir.append((temiz_imaj, rng.choice(CVE_PAKETLERI), _cve(rng, kul), rng.choice(["HIGH", "MEDIUM", "MEDIUM", "LOW"])))
    satir.append((eski_imaj, rng.choice(CVE_PAKETLERI), _cve(rng, kul), "CRITICAL"))
    satir.append((eski_imaj, rng.choice(CVE_PAKETLERI), _cve(rng, kul), "MEDIUM"))
    rng.shuffle(satir)
    csv = [f"{i},{p},{c},{d}" for i, p, c, d in satir]

    kisa = kotu_imaj.split("/")[-1].split(":")[0]
    toplam = 4 + (1 if sen["latest"] else 0) + (1 if sen["limitsiz"] else 0)
    return {"sen": sen, "yaml": yaml, "csv": csv, "kotu": kotu, "temiz": temiz, "sir_ad": sir_ad,
            "sir_deger": sir_deger, "kotu_imaj": kotu_imaj, "temiz_imaj": temiz_imaj, "eski_imaj": eski_imaj,
            "imaj_kabul": [kotu_imaj, kotu_imaj.rsplit(":", 1)[0], kisa], "n_krit": n_krit, "toplam": toplam}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — konteyner güvenlik denetimi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"], "hikaye": sen["hikaye"]},
        "cevaplar": {
            "konteyner": v["kotu"],
            "sir": [v["sir_ad"], v["sir_deger"]],
            "imaj": v["imaj_kabul"],
            "n_krit": v["n_krit"],
            "toplam": v["toplam"],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    u.yaz(lab / "dagitim.yaml", v["yaml"])
    csv_yaz(lab / "imaj_tarama.csv", "imaj,paket,cve,ciddiyet", v["csv"])
    u.yaz(lab / "OKUBENI.txt",
          f"{v['sen']['musteri']} denetim dosyaları. KURGUSAL; hiçbir küme veya servise bağlanılmaz.\n"
          "dagitim.yaml    : Kubernetes dağıtım dosyası (YAML), iki konteyner içerir\n"
          "imaj_tarama.csv : imaj güvenlik taraması özeti (imaj,paket,cve,ciddiyet)\n"
          "                  ciddiyet: CRITICAL (kritik) | HIGH | MEDIUM | LOW\n")


# ----------------------------------------------------------------------------- şık hata ipuçları

def _kont_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["temiz"].casefold():
        return ("Bu konteynerde `privileged: false`, dar bir kullanıcı ve limitler var; korkutucu görünen satırlar "
                "aslında güvenli ayar. Yetkiyi `true` yapan konteyneri ara.")
    return None


def _sir_hata(g, beklenen, b):
    if g == "db_password":
        return ("`DB_PASSWORD` değeri dosyada yazmıyor, `secretKeyRef` ile Kubernetes Secret'ından alınıyor; "
                "bu doğru yöntem. Açık sır, `value:` ile düz yazılmış olandır.")
    if g == "log_level":
        return "`LOG_LEVEL` bir sır değil, sıradan bir ayar. Adında PASSWORD/TOKEN/SECRET/KEY geçeni ara."
    return None


def _imaj_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g in {v["eski_imaj"].casefold(), v["eski_imaj"].rsplit(":", 1)[0].casefold(), v["eski_imaj"].split("/")[-1].casefold()}:
        return ("Bu imajın da kritik açığı var ama `dagitim.yaml` içinde kullanılmıyor; risk yok değil ama bu "
                "dağıtımda çalışmıyor. Manifestteki `image:` satırlarıyla taramayı eşle.")
    if g in {v["temiz_imaj"].casefold(), v["temiz_imaj"].rsplit(":", 1)[0].casefold(), v["temiz_imaj"].split("/")[-1].casefold()}:
        return "Bu imajın tarama kayıtlarında yalnızca HIGH/MEDIUM/LOW var; kritik (CRITICAL) olan başka."
    return None


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == int(beklenen) - 1:
        return ("Bir tanesini kaçırmış olabilirsin: privileged, hostPath, root, açık sır, `:latest` etiket, "
                "kaynak limiti yok. Hepsine tek tek bak.")
    return None


# ----------------------------------------------------------------------------- çözüm (SADECE TEST)

def coz(lab: Path, s: dict) -> dict:
    kont = sh(r"""awk '/^        - name:/{c=$3} /privileged: true/{print c}' dagitim.yaml | head -1""", lab)
    sir_ad = sh(r"""grep -A1 -E 'name: .*(PASSWORD|TOKEN|SECRET|KEY)' dagitim.yaml | """
                r"""awk '/name:/{n=$NF} /value:/{print n}' | head -1""", lab)
    imaj = sh(r"""for i in $(grep 'image:' dagitim.yaml | awk '{print $NF}'); do """
              r"""grep -q "^$i,.*,CRITICAL$" imaj_tarama.csv && echo "$i"; done | head -1""", lab)
    n_krit = sh(f"grep -c '^{imaj},.*,CRITICAL$' imaj_tarama.csv", lab)
    priv = int(sh("grep -c 'privileged: true' dagitim.yaml", lab))
    hp = int(sh("grep -c 'hostPath:' dagitim.yaml", lab))
    root = int(sh("grep -c 'runAsUser: 0$' dagitim.yaml", lab))
    sir = int(sh("grep -A1 -E 'name: .*(PASSWORD|TOKEN|SECRET|KEY)' dagitim.yaml | grep -c 'value:'", lab))
    latest = int(sh("grep -c 'image: .*:latest$' dagitim.yaml", lab))
    limitsiz = int(sh("grep -c 'image:' dagitim.yaml", lab)) - int(sh("grep -c 'limits:' dagitim.yaml", lab))
    toplam = priv + hp + root + sir + latest + limitsiz
    return sec_doldur({1: kont, 2: sir_ad, 4: imaj, 5: n_krit, 6: toplam}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("`dagitim.yaml` içindeki iki konteynerden hangisi **yanlış yapılandırılmış** (ana makineye tam yetki "
          "isteyen)? Konteynerin adını yaz.",
          Metin("konteyner", sik_hatalar=_kont_hata, bicim="konteyner adı"),
          ("Dosyada iki konteyner var; her birinin `securityContext:` bölümü onun güvenlik ayarlarıdır.",
           "`privileged: true` konteynere ana makinenin neredeyse tüm yetkisini verir. `grep -n 'privileged' dagitim.yaml` "
           "iki satır gösterir; biri `false`.",
           "`awk '/^        - name:/{c=$3} /privileged: true/{print c}' dagitim.yaml` — konteynerin adını yazdırır."),
          puan=15, baslik="Yanlış yapılandırılmış konteyner"),
    Gorev("Aynı konteynerin ortam değişkenlerinde **düz metin olarak yazılmış bir sır** (parola/token/anahtar) var. "
          "Değişkenin **adını** ya da **değerini** yaz. (`secretKeyRef` ile alınan sır açık değildir.)",
          Metin("sir", sik_hatalar=_sir_hata, bicim="değişken adı ya da değeri"),
          ("`env:` altındaki her değişkenin ya doğrudan `value:` değeri vardır ya da bir Secret'a bağlıdır (`valueFrom`).",
           "Adında PASSWORD, TOKEN, SECRET ya da KEY geçen ve hemen altında `value:` olan satırı ara.",
           "`grep -A1 -E 'name: .*(PASSWORD|TOKEN|SECRET|KEY)' dagitim.yaml` — hangisinin altında `value:` var, hangisinde `valueFrom:`?"),
          puan=15, baslik="Açık sır"),
    Gorev("Bu konteynerdeki ayarlardan hangisi **en tehlikeli**? (Konteyner kaçışı ve ana makinenin ele geçirilmesi açısından.)",
          Secmeli([
              ("`privileged: true` (ayrıcalıklı mod)",
               "Doğru. Privileged konteyner, ana makinenin cihazlarına ve çekirdek yeteneklerine erişir; içeriden ana "
               "makineye (node) çıkmak çok kolaydır. Diğer ayarlar zararı artırır ama kapıyı bu açar."),
              ("`hostPath` ile ana makine diskinin bağlanması",
               "Tehlikeli ama tek başına ikinci sırada. Konteyner yalnızca bağlanan dizini görür; privileged ise bütün makineyi."),
              ("`runAsUser: 0` (root kullanıcı)",
               "Kötü bir alışkanlık ama konteyner içindeki root sınırlıdır; privileged olmadan ana makineye doğrudan geçiş vermez."),
              ("Ortam değişkeninde açık sır",
               "Ciddi bir sızıntı (sırrı herkes görebilir) ama bir kaçış değil; sır döndürülerek kapatılır. Ana makineyi ele "
               "geçirten ayar daha tehlikelidir."),
          ]),
          ("Soru, hangi ayarın bir saldırganı konteynerin dışına, yani ana makineye çıkarabileceğini soruyor.",
           "Konteyner normalde izole bir kutudur; bazı ayarlar bu duvarı ince yapar, biri ise tamamen kaldırır.",
           "Ana makinenin cihazlarına ve çekirdek yeteneklerine tam erişim veren ayar duvarı en çok yıkar."),
          puan=15, baslik="En tehlikeli ayar"),
    Gorev("`imaj_tarama.csv` ile `dagitim.yaml`'ı karşılaştır: dağıtımda **kullanılan** ve taramada **CRITICAL** "
          "(kritik) açığı olan imaj hangisi? İmaj adını yaz (etiketle ya da etiketsiz).",
          Metin("imaj", sik_hatalar=_imaj_hata, bicim="imaj adı"),
          ("Taramadaki her satır bir imajın bir açığını anlatır; ama hepsi bu dağıtımda çalışmıyor.",
           "Önce `grep 'image:' dagitim.yaml` ile kullanılan imajları al, sonra `grep CRITICAL imaj_tarama.csv` ile eşle.",
           "`for i in $(grep 'image:' dagitim.yaml | awk '{print $NF}'); do grep -q \"^$i,.*,CRITICAL$\" imaj_tarama.csv && echo $i; done`"),
          puan=20, baslik="Kritik açıklı imaj"),
    Gorev("Bu imajda toplam kaç **CRITICAL** satırı (açık) var?",
          Sayi("n_krit"),
          ("Sadece o imajın satırlarını, sadece `CRITICAL` olanları say.",
           "İmaj adı satırın başındadır; ciddiyet son sütundur.",
           "`grep '^<imaj>,' imaj_tarama.csv | grep -c ',CRITICAL$'`"),
          puan=10, baslik="Kritik açık sayısı"),
    Gorev("`dagitim.yaml` içinde toplam kaç **yanlış ayar** var? Say: `privileged: true`, `hostPath` bağlama, "
          "root (`runAsUser: 0`), açık sır, `:latest` imaj etiketi ve kaynak limiti (`limits:`) olmayan konteyner. "
          "Her biri bir kez sayılır.",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Her ayar türü için ayrı ayrı say, sonra topla. `:latest` ve limitsizlik her dosyada yok olabilir.",
           "`grep -c 'privileged: true'`, `grep -c 'hostPath:'`, `grep -c 'runAsUser: 0$'`, `grep -c ':latest$'`; limit için "
           "konteyner sayısı (`image:` satırları) eksi `limits:` satırları.",
           "Açık sır sayısı: `grep -A1 -E 'name: .*(PASSWORD|TOKEN|SECRET|KEY)' dagitim.yaml | grep -c 'value:'`. Hepsini topla."),
          puan=15, baslik="Toplam hata"),
    Gorev("Sızan sırrı ve riskli ayarları gördün. **En doğru düzeltme** hangisi?",
          Secmeli([
              ("`privileged`'ı kaldır, hostPath'i çıkar, root dışı kullanıcıya geç; sırrı Kubernetes Secret'a taşı ve açıkta "
               "kalan parolayı değiştir; imajı yamalı ve sabit sürüme geçir; kaynak limiti ekle",
               "Doğru. Kaçış kapısını kapatır, sızan sırrı geçersiz kılar ve imajı yeniler. Sır YAML'da göründüğü için "
               "değiştirmek şart: dosyadan silmek yetmez."),
              ("Dosyadaki sır satırını sil, geri kalan her şey olduğu gibi kalsın",
               "Yetmez. Sır dosyanın geçmişinde ve kümede kalır, hâlâ geçerlidir; üstelik privileged ve hostPath ayakta."),
              ("Yalnızca imajı `:latest` etiketine al; en yeni sürüm zaten yamalıdır",
               "Hayır. `:latest` her çekildiğinde değişen belirsiz bir sürümdür; denetlenemez. Sabit, yamalı bir sürüm gerekir."),
              ("Kaynak limiti ekle ve konteyneri yeniden başlat; ayarlar sonra konuşulur",
               "Limit faydalıdır ama kaçış kapısı (privileged/hostPath) ve sızmış sır açık kalır; asıl riskler çözülmemiş."),
          ]),
          ("Düzeltme hem kaçış riskini, hem sızan sırrı, hem de imajı kapsamalı.",
           "Bir sır bir kez görüldüyse onu dosyadan silmek yetmez; geçerliliğini sonlandırmak gerekir.",
           "Tam düzeltme: ayrıcalığı kısmak + sırrı Secret'a taşıyıp değiştirmek + imajı sabit/yamalı sürüme geçirmek."),
          puan=25, baslik="Doğru düzeltme"),
]

SEVIYE = Seviye(
    kimlik="olay_k8s",
    cilt=13,
    bolum=123,
    baslik="Konteyner / Kubernetes Yanlış Yapılandırma Denetimi",
    brifing="""
Deniz Kara ekranını sana çeviriyor: "**<<musteri>>** (<<sektor>>) Kubernetes dağıtımları için bağımsız bir güvenlik
incelemesi istedi. <<hikaye>> <<kisi>> bize iki dosya gönderdi."

"`dagitim.yaml`: iki konteynerli bir dağıtım dosyası. `imaj_tarama.csv`: kullanılan imajların güvenlik taraması
(imaj,paket,cve,ciddiyet). Saldırı yok, kümeye bağlantı yok: dosyaları okuyup yanlış yapılandırmayı bulacaksın."
Mert ekliyor: "YAML'ı grep ve awk ile oku, `jq` ya da `yq` yok. Dikkat: her korkutucu görünen satır hata değil.
`privileged: false` güvenlidir, `secretKeyRef` sırrı doğru yoldan alır. Taramadaki bir imaj da hiç kullanılmıyor olabilir."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Konteyner güvenliğinin çoğu birkaç alışkanlıktır: **en az yetki** (`privileged` yok, root yok, ana makine dizini
bağlama yok), **sırlar kodda değil Secret'ta** (ve sızarsa değiştirilir), **imajı sabitle ve tara** (`:latest` yerine sabit
etiket, kritik açıklı imaj dağıtıma girmesin) ve **kaynak limiti** koy. Bu kontrolleri dağıtımdan önce otomatik çalıştırmak
(admission policy, imaj tarayıcı) hataları kümeye girmeden yakalar.
""",
    gercek_hayat="""
- **Tesla, Şubat 2018:** Bulut güvenlik firması RedLock, Tesla'nın şifresiz açıkta kalmış bir Kubernetes yönetim panelini
  bulduğunu açıkladı. Panelde bulut erişim bilgileri duruyordu ve saldırganlar kümede kripto para madenciliği yaptı. Ders:
  yönetim paneli kimlik doğrulamasız internete açılmaz, sırlar düz metin tutulmaz.
- **runC konteyner kaçışı, Şubat 2019:** runC'deki bir açık (CVE-2019-5736), kötü niyetli bir konteynerin ana makinedeki
  runC dosyasını ezmesine izin veriyordu. Ayrıcalıklı ve gereğinden yetkili konteynerler bu tür açıklarda zararı büyütür.
  Ocak 2024'te runC'de benzer şekilde "Leaky Vessels" adıyla duyurulan açıklar da imaj ve yetki sınırlarını aşabiliyordu.
- **Açıkta kalan Kubernetes panoları:** Araştırmacılar internet taramalarıyla kimlik doğrulamasız açık çok sayıda
  Kubernetes ve konteyner yönetim arayüzü buldu; bunların bir kısmı kripto madencisi yerleştirmek için kullanıldı.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c13b03",),
)
