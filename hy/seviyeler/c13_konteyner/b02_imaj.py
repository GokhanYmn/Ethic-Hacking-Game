"""Cilt 13 · Bölüm 2 — İmaj Güvenliği.

Beceri: kurgusal `docker history` çıktısında katmana gömülü sırrı bulmak (silinmiş görünse bile),
`latest` etiketli imajları ayıklamak, bir tarama raporundan kritik paketleri çıkarmak ve zayıf bir
Dockerfile'ı (sabit etiket, küçük temel imaj, sır yok) düzeltmek. `cevap <no>` dosyanın son halini
kontrol eder. Hiçbir imaj çekilmez ya da oluşturulmaz; zafiyet kimlikleri kurgusaldır (`LAB-...`).

Vakalar: e-ticaret, hastane, fintech, lojistik. Sırrın gömülme yolu üç farklı biçimde gelir:
`.env` dosyası (sonradan silinen), `ENV` satırı, bağlantıya gömülü kimlik.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c13_konteyner.ortak import hex_, py, sec_doldur, sh, sirket_sec

TABANLAR = {"python": "3.12-slim", "node": "20-alpine", "golang": "1.22-alpine"}
PAKETLER = ["libssl3", "zlib1g", "libcurl4", "libc6", "libexpat1", "busybox", "libxml2", "sqlite3", "perl-base",
            "tar", "gzip", "bash", "libpcre2-8-0", "libgnutls30"]
BASLIKLAR = ["Bellek taşması", "Kimlik doğrulama atlatma", "Hizmet reddi", "Yol geçişi", "Bilgi sızıntısı",
             "Sınır dışı okuma", "Şifreleme zayıflığı", "Yetki yükseltme"]
SAHNE = {
    "pazarix": "Pazarix'in konteyner imajları canlıya çıkmadan önce güvenlik kapısından geçmek zorunda.",
    "medora": "Medora Sağlık'ın bir yazılımcısı, imajda unutulmuş bir parola olabileceğinden şüpheleniyor.",
    "paramix": "Paramix'in CI/CD hattında bir bağlantıya gömülmüş kimlik bilgisi bulundu; imaj geçmişi inceleniyor.",
    "kuzgun": "Kuzgun Lojistik'in imajları aylardır güncellenmedi ve bir tarama raporu çıkarıldı.",
}


def uret(rng):
    sk = sirket_sec(rng)
    on, alan, sv = sk["on"], sk["alan"], sk["servisler"]
    taban = rng.choice(list(TABANLAR))
    varyant = rng.choice(["env_dosyasi", "env_satiri", "baglanti"])
    gizli = {"env_dosyasi": f"{on}_live_{hex_(rng, 10)}", "env_satiri": u.parola(rng) + hex_(rng, 3),
             "baglanti": f"tok_{hex_(rng, 12)}"}[varyant]
    # imajlar
    adaylar = [f"{on}/{sv[0]}:latest", f"{on}/{sv[1]}:latest", "nginx:latest", "busybox:latest"]
    latest = rng.sample(adaylar, rng.randint(2, 3)) + [rng.choice(["redis", "memcached", "rabbitmq"])]
    sabit = [f"{on}/{sv[2]}:1.4", "postgres:16-alpine", f"{on}/{sv[3]}:2.0", "traefik:v3.0"]
    imajlar = latest + rng.sample(sabit, rng.randint(3, 4))
    rng.shuffle(imajlar)
    # tarama
    adet = {"CRITICAL": rng.randint(3, 5), "HIGH": rng.randint(4, 6), "MEDIUM": rng.randint(3, 5), "LOW": rng.randint(2, 3)}
    paketler = rng.sample(PAKETLER, 12)
    satirlar = []
    krit_paket = []
    i = 0
    for onem, n in adet.items():
        for _ in range(n):
            p = paketler[i % len(paketler)]
            i += 1
            if onem == "CRITICAL":
                krit_paket.append(p)
            ma, mi = rng.randint(1, 3), rng.randint(0, 20)
            kur = f"{ma}.{mi}.{rng.randint(1, 9)}-1"
            duz = "-" if (onem == "LOW" and rng.random() < 0.5) else f"{ma}.{mi}.{rng.randint(10, 19)}-1"
            satirlar.append((p, f"LAB-2026-{rng.randint(1000, 9999)}", onem, kur, duz, rng.choice(BASLIKLAR)))
    # bir paket hem CRITICAL hem HIGH olsun (tuzak): ilk kritik paket için ek HIGH satırı
    p0 = krit_paket[0]
    ma, mi = rng.randint(1, 3), rng.randint(0, 20)
    satirlar.append((p0, f"LAB-2026-{rng.randint(1000, 9999)}", "HIGH", f"{ma}.{mi}.1-1", f"{ma}.{mi}.7-1", rng.choice(BASLIKLAR)))
    adet["HIGH"] += 1
    rng.shuffle(satirlar)
    kritik = [x for x in satirlar if x[2] == "CRITICAL"]
    sorgu = rng.choice(kritik)
    return {
        "vaka": f"{sk['ad']} — imaj denetimi",
        "sirket": sk, "taban": taban, "varyant": varyant, "gizli": gizli, "imajlar": imajlar,
        "tarama": satirlar, "adet": adet,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "paket": sorgu[0]},
        "cevaplar": {
            "gizli": gizli, "latest": latest,
            "kritik_sayi": len(kritik), "kritik_paket": sorted({x[0] for x in kritik}),
            "duzeltme": sorgu[4],
        },
    }


def _dockerfile(s: dict) -> str:
    sk = s["sirket"]
    taban = s["taban"]
    satirlar = [f"FROM {taban}:latest", "WORKDIR /uygulama"]
    v = s["varyant"]
    if v == "baglanti":
        satirlar.append(f"RUN git clone https://ci-bot:{s['gizli']}@git.{sk['alan']}/ekip/uygulama.git /uygulama")
    else:
        satirlar.append("COPY . .")
    if v == "env_satiri":
        satirlar.append(f"ENV VERITABANI_PAROLASI={s['gizli']}")
    if v == "env_dosyasi":
        satirlar.append(f'RUN echo "API_ANAHTARI={s["gizli"]}" > /uygulama/.env')
    satirlar.append("RUN true  # bağımlılıkları kur")
    if v == "env_dosyasi":
        satirlar.append("RUN rm /uygulama/.env")
    satirlar.append('CMD ["./baslat.sh"]')
    return "\n".join(satirlar) + "\n"


def yaz(lab: Path, s: dict) -> None:
    k = lab / "konteyner/imaj"
    u.yaz(k / "Dockerfile", _dockerfile(s))
    # docker history: en yeni katman en üstte
    katmanlar = []
    for ham in reversed(_dockerfile(s).splitlines()):
        if ham.startswith("FROM"):
            continue
        ad = ham.split("  #")[0]
        if ad.startswith(("RUN", "ENV", "COPY")):
            ad = f"/bin/sh -c {ad[ad.index(' ') + 1:]}" if ad.startswith("RUN") else f"/bin/sh -c #(nop)  {ad}"
        else:
            ad = f"/bin/sh -c #(nop)  {ad}"
        katmanlar.append(ad)
    satirlar = ["IMAGE         CREATED       CREATED BY                                                         SIZE"]
    for i, ad in enumerate(katmanlar):
        satirlar.append(f"<missing>     {i + 2} days ago    {ad}    {'0B' if ad.endswith(('CMD', 'WORKDIR')) or 'CMD' in ad else '4.2MB'}")
    satirlar += ["<missing>     3 weeks ago   /bin/sh -c #(nop)  CMD [\"bash\"]    0B",
                 f"<missing>     3 weeks ago   /bin/sh -c #(nop) ADD file:e3b0c44298fc in /    74.8MB"]
    u.yaz(k / "docker_history.txt", "\n".join(satirlar) + "\n")
    u.yaz(k / "imajlar.txt", "# üretimde kullanılan imajlar\n" + "\n".join(s["imajlar"]) + "\n")
    t = ["Hedef: uygulama-imaji (debian 12.5)  [KURGUSAL RAPOR; zafiyet kimlikleri uydurmadır]",
         "Toplam: %d (LOW: %d, MEDIUM: %d, HIGH: %d, CRITICAL: %d)" %
         (len(s["tarama"]), s["adet"]["LOW"], s["adet"]["MEDIUM"], s["adet"]["HIGH"], s["adet"]["CRITICAL"]),
         "", "PAKET  ZAFIYET  ONEM  KURULU-SURUM  DUZELTME-SURUMU  BASLIK"]
    t += [" ".join(x) for x in s["tarama"]]
    u.yaz(k / "tarama_raporu.txt", "\n".join(t) + "\n")


def _etiket(metin: str):
    m = re.search(r"^\s*FROM\s+(?:--\S+\s+)?(\S+)", metin, re.M)
    if not m:
        return None, None
    ref = m.group(1)
    ad, _, et = ref.partition(":")
    return ad, et


def _duzelt(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "konteyner/imaj/Dockerfile"
    if not yol.is_file():
        return Sonuc(False, "`konteyner/imaj/Dockerfile` yok.")
    metin = yol.read_text(encoding="utf-8", errors="replace")
    ad, et = _etiket(metin)
    if ad is None:
        return Sonuc(False, "`FROM` satırı silinmiş. Temel imajı silme, sürümünü sabitle.")
    if not et or et == "latest":
        return Sonuc(False, f"`FROM {ad}` hâlâ `latest`/etiketsiz. Sürümü sabitle ki imaj tekrar üretilebilir olsun.", yakin=True)
    if not re.match(r"^\d[\w.]*-(slim|alpine)[\w.]*$", et):
        return Sonuc(False, f"`{ad}:{et}` sabit ama küçük bir imaj değil. En küçük temel imajı seç (`-slim` ya da `-alpine` sürümü).", yakin=True)
    if s["gizli"] in metin or "ci-bot:" in metin:
        return Sonuc(False, "Sır hâlâ Dockerfile'da duruyor. Satırı sadece silmek yetmez de olabilir (geçmişte kalır) ama önce kaynağından kaldır.", yakin=True)
    if re.search(r"^\s*(RUN|CMD|ENTRYPOINT)\b", metin, re.M) is None or "CMD" not in metin:
        return Sonuc(False, "`CMD` satırı silinmiş; imaj bir şey çalıştırmalı.")
    return Sonuc(True, f"`{ad}:{et}` sabit ve küçük, Dockerfile'da sır yok.")


def coz(lab: Path, s: dict) -> dict:
    k = "konteyner/imaj"
    v = s["varyant"]
    desen = {"env_dosyasi": "API_ANAHTARI=[^\" ]*", "env_satiri": "VERITABANI_PAROLASI=[^ ]*", "baglanti": "ci-bot:[^@]*"}[v]
    gizli = sh(f"grep -oE '{desen}' {k}/docker_history.txt | head -1 | sed -E 's/^[^=:]*[=:]//'", lab)
    latest = sh(f"grep -v '^#' {k}/imajlar.txt | awk -F: 'NF==1 || $2==\"latest\" {{print $0}}' | tr '\\n' ' '", lab)
    krit = sh(f"grep -c ' CRITICAL ' {k}/tarama_raporu.txt", lab)
    paket = sh(f"awk '$3==\"CRITICAL\" {{print $1}}' {k}/tarama_raporu.txt | sort -u | tr '\\n' ' '", lab)
    duz = sh(f"awk '$1==\"{s['metin']['paket']}\" && $3==\"CRITICAL\" {{print $5}}' {k}/tarama_raporu.txt", lab)
    # düzeltme
    etiket = TABANLAR[s["taban"]]
    sh(f"sed -i -E 's#^FROM ([a-z-]+):latest#FROM \\1:{etiket}#' {k}/Dockerfile", lab)
    sh(f"sed -i '/API_ANAHTARI/d;/rm \\/uygulama\\/.env/d;/VERITABANI_PAROLASI/d;s#^RUN git clone .*#COPY . /uygulama#' {k}/Dockerfile", lab)
    return sec_doldur({1: "", 2: gizli, 3: latest, 4: krit, 5: paket, 6: duz, 7: ""}, GOREVLER, lab, s)


def _latest_hata(g, beklenen, b):
    verilen = set(g.split())
    if verilen and len(verilen) == len(beklenen) - 1 and verilen < beklenen:
        return "Bir eksik var. Etiket **hiç yazılmamış** bir imaj da `latest` sayılır; etiketi olmayan satırı da bul."
    return None


def _krit_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Bir fazla. Başlıktaki `CRITICAL` toplamını ya da aynı paketin HIGH satırını saymış olabilirsin; yalnızca önem sütunu CRITICAL olan satırlar."
    return None


def _duz_hata(g, beklenen, b):
    s = b.senaryo
    p = s["metin"]["paket"]
    for x in s["tarama"]:
        if x[0] == p and x[2] == "HIGH" and g == x[4]:
            return f"Bu, `{p}` paketinin **HIGH** zafiyetinin düzeltme sürümü. Sorulan CRITICAL olanınki."
    return None


ADIMLAR = [
    Adim("İmaj katman katmandır", """
Bir konteyner bir **imajdan** doğar; imaj güvensizse ondan doğan her konteyner güvensizdir. İmajlar
**katman katman** oluşur ve **her katman saklanır**: Dockerfile'daki her `RUN`, `COPY`, `ENV` satırı bir
katman olur. Yaygın hata: bir katmanda bir sır (parola, anahtar) eklenip sonraki katmanda **silinmesi**.
Silinen dosya son imajda görünmez ama **önceki katman hâlâ imajın içindedir** ve imaj geçmişini
inceleyen herkes sırrı görebilir.

**<<musteri>>**. <<sahne>> Önce müşterinin Dockerfile'ına bak:
""", komut="cat konteyner/imaj/Dockerfile"),
    Adim("docker history ile geçmişi okumak", """
`docker history --no-trunc <imaj>` imajın katmanlarını, her katmanı oluşturan **komutla birlikte**
listeler (en yeni en üstte). Bu lab'da bunun bir çıktısı hazır:
""", komut="cat konteyner/imaj/docker_history.txt", sonra="""
Sırrın en son imajda görünmemesi, geçmişte görünmediği anlamına gelmez. Bir parola `ENV`, `ARG`, `RUN echo`
ya da bir bağlantı içine gömülü kimlik (`https://kullanici:parola@...`) olarak geçmişte kalır.
"""),
    Adim("Sır avı: grep", """
Geçmiş dosyasında parola/anahtar gibi sözcükleri ara. Bu lab'daki sır `PAROLA`, `ANAHTAR` ya da
`TOKEN` sözcüklerinden biriyle ya da bir bağlantının içinde geçiyor:
""", komut="grep -inE 'parola|anahtar|token|ci-bot' konteyner/imaj/docker_history.txt", sonra="""
Bulduğun değer artık **sızmış** sayılır: imaj yayınlandıysa onu çeken herkes görebilir. Doğru
müdahale: sırrı hemen **iptal et ve yenile**, sonra imajı sır olmadan yeniden üret.
"""),
    Adim("latest etiketi", """
`latest` etiketi, "o an hangi sürüm en yeniyse o" demektir ve sabit değildir. Bu yüzden iki sorun
çıkarır: aynı imajı iki gün arayla çekersen farklı içerik gelir (tekrar üretilemezlik) ve güncelleme
**haber vermeden** gelir. Bir imaj adında **etiket hiç yazılmamışsa** Docker onu `latest` sayar.
Üretimde kullanılan imajlar:
""", komut="cat konteyner/imaj/imajlar.txt", sonra="""
`:latest` yazanları ve etiketsiz yazılanları ayıkla. Güvenli alışkanlık: **sabit bir sürüm** (ve
mümkünse bir özet/digest) kullan.
"""),
    Adim("Tarama raporu", """
İmaj tarayıcıları (örneğin Trivy), imajdaki paketleri bilinen zafiyetler listesiyle karşılaştırır.
Bu, Cilt 6'daki "sürüm → CVE → exploit" zincirinin konteyner halidir. (Bu rapor kurgusaldır;
zafiyet kimlikleri uydurmadır.) Rapora bak:
""", komut="cat konteyner/imaj/tarama_raporu.txt", sonra="""
Önem sütunu: LOW, MEDIUM, HIGH, CRITICAL. İlk bakılacak yer **CRITICAL** olanlardır, özellikle
`DUZELTME-SURUMU` dolu olanlar: yamalanmış bir sürüm zaten var, yani **hemen düzeltilebilir**.
"""),
    Adim("Kritikleri süzmek", """
`awk` ile üçüncü sütunu `CRITICAL` olan satırların paketini listele:
""", komut="awk '$3==\"CRITICAL\" {print $1, $5}' konteyner/imaj/tarama_raporu.txt", sonra="""
Aynı paket hem CRITICAL hem HIGH zafiyetler taşıyabilir; satırın önem sütununa bak, paket adına değil.
"""),
    Adim("Güvenli imaj ilkeleri", """
Güvenli imaj için: **en küçük temel imajı** kullan (`-slim`, `-alpine`; az yazılım = az zafiyet, az
saldırı yüzeyi), **imajları düzenli tara ve güncelle**, **sırları imaja gömme** (çalışma zamanında
ortamdan ya da sır yönetiminden ver) ve imajları **doğrulanmış kaynaklardan** al.
"""),
]

GOREVLER = [
    Gorev("Bir sır bir katmanda eklenip sonrakinde silinse bile neden hâlâ bulunabilir?",
          Secmeli([
              ("İmaj katman katman kaydedilir; silinen dosya önceki katmanda hâlâ durur",
               "Doğru. Silme yeni bir katman olarak eklenir; eski katmandaki veri imajın parçası olarak kalır."),
              ("Çünkü Docker silme komutlarını görmezden gelir ve hiçbir dosyayı gerçekten silmez",
               "Yanlış. Komut çalışır ama katmanlı yapı nedeniyle eski katman yok olmaz."),
              ("Çünkü sırlar her zaman imajın dışında, ana makinenin diskinde bir kopya olarak tutulur",
               "Yanlış. Sır imajın katmanının içindedir; ana makinedeki bir kopyayla ilgisi yok."),
              ("Çünkü imajı çeken herkes silinen dosyayı Docker'ın internet çöp kutusundan geri alır",
               "Yanlış. Böyle bir çöp kutusu yok; veri doğrudan imaj katmanındadır."),
          ], dogru=0),
          ("Docker imajı bir yığın katmandan oluşur.",
           "Silme komutu eski katmana ne yapar?",
           "Silmek yeni bir katman ekler; eski katman yerinde kalır."),
          puan=20, baslik="Silinen sır neden kalır"),
    Gorev("`docker_history.txt` içinde bir katmana **gömülü sırrın değeri** nedir? (Sadece değer; `=`, `:` ya da `@` işaretleri hariç.)",
          Metin("gizli", bicim="sır değeri"),
          ("Sır bir parola, anahtar ya da token olabilir; bir değişken adının yanında ya da bir bağlantının içinde.",
           "`grep -inE 'parola|anahtar|token|ci-bot' konteyner/imaj/docker_history.txt`",
           "Değerin başında değişken adı (`API_ANAHTARI=`, `VERITABANI_PAROLASI=`) ya da `kullanici:` bulunur; yalnızca değeri yaz."),
          puan=40, baslik="Gömülü sır"),
    Gorev("`imajlar.txt` içinde **`latest` etiketli ya da etiketsiz** (örtük `latest`) imajları yaz.",
          Kume("latest", sik_hatalar=_latest_hata, bicim="imaj adları, virgülle ayrılmış"),
          ("İki durum var: açıkça `:latest` yazılanlar ve hiç etiket yazılmayanlar.",
           "Etiketsiz imaj adında `:` karakteri yoktur.",
           "`grep -v '^#' konteyner/imaj/imajlar.txt | awk -F: 'NF==1 || $2==\"latest\"'`"),
          puan=40, baslik="latest imajlar"),
    Gorev("Tarama raporunda önemi **CRITICAL** olan kaç zafiyet satırı var?",
          Sayi("kritik_sayi", sik_hatalar=_krit_hata),
          ("Başlıktaki toplam satır, her önemi değil yalnızca CRITICAL'ı verir.",
           "Önem sütunu tam olarak `CRITICAL` olan satırlar; HIGH olanlar sayılmaz.",
           "`grep -c ' CRITICAL ' konteyner/imaj/tarama_raporu.txt`"),
          puan=30, baslik="Kritik sayısı"),
    Gorev("CRITICAL zafiyeti olan **paketlerin adlarını** yaz.",
          Kume("kritik_paket", bicim="paket adları, virgülle ayrılmış"),
          ("Önceki görevde saydığın satırların paket adı sütunu.",
           "İlk sütun paket, üçüncü sütun önem.",
           "`awk '$3==\"CRITICAL\" {print $1}' konteyner/imaj/tarama_raporu.txt | sort -u`"),
          puan=30, baslik="Kritik paketler"),
    Gorev("`<<paket>>` paketinin **CRITICAL** zafiyetini kapatan düzeltme sürümü hangisi? "
          "(Aynı paketin başka önemdeki satırlarına dikkat.)",
          Metin("duzeltme", sik_hatalar=_duz_hata, bicim="sürüm numarası"),
          ("Aynı paket birden çok satırda geçebilir.",
           "Önem sütunu CRITICAL olan satırın `DUZELTME-SURUMU` sütunu.",
           "`awk '$1==\"<<paket>>\" && $3==\"CRITICAL\" {print $5}' konteyner/imaj/tarama_raporu.txt`"),
          puan=30, baslik="Düzeltme sürümü"),
    Gorev("`konteyner/imaj/Dockerfile` dosyasını düzelt: temel imajı **sabit ve küçük** bir etikete çek "
          "(`-slim` ya da `-alpine`, `latest` değil) ve **sırrı** Dockerfile'dan kaldır. `CMD` kalsın. "
          "Bitince `cevap 7`.",
          Durum(_duzelt, "FROM <ad>:<sürüm>-slim|alpine; sır satırı yok"),
          ("İki ayrı sorun: tabanın etiketi ve gömülü sır.",
           "`FROM ...:latest` satırını sabit bir sürümle değiştir; sırrı taşıyan satırı sil ya da yerine sırsız bir satır yaz.",
           "Örneğin `sed -i -E 's#^FROM ([a-z-]+):latest#FROM \\1:3.12-slim#' ...` (python için); sırrın geçtiği satırı `grep -n` ile bulup `sed -i 'N d'` ile sil."),
          puan=50, baslik="Dockerfile'ı düzelt"),
    Gorev("Güvenlik açısından neden **en küçük** temel imaj tercih edilir?",
          Secmeli([
              ("Daha az yazılım demek daha az zafiyet ve daha küçük saldırı yüzeyi demektir",
               "Doğru. İmajda olmayan bir paket, istismar edilemez."),
              ("Küçük imajlar şifreli olduğu için içindeki dosyalar okunamaz",
               "Yanlış. Boyut şifrelemeyle ilgili değildir."),
              ("Küçük imajlar her zaman root olmayan kullanıcıyla başlar, bu yüzden güvenlidir",
               "Yanlış. Kullanıcı bir Dockerfile ayarıdır; boyutla otomatik gelmez."),
              ("Küçük imajlar daha az disk kullandığı için sunucuyu daha serin çalıştırır",
               "Yanlış. Isınma güvenlik değildir; asıl fayda yüzeyin küçülmesidir."),
          ], dogru=0),
          ("İmajda ne kadar çok paket varsa o kadar çok…",
           "Zafiyet paketlerde yaşar.",
           "Daha az paket = daha az zafiyet."),
          puan=20, baslik="Neden küçük imaj"),
    Gorev("İmaj tarayıcısının (örneğin Trivy) yaptığı iş hangisidir?",
          Secmeli([
              ("Paket sürümlerini bilinen zafiyet listeleriyle karşılaştırıp raporlar",
               "Doğru. Cilt 6'daki 'sürüm → CVE → exploit' zincirinin konteyner karşılığıdır."),
              ("İmajı otomatik olarak çalıştırıp içindeki programların hangisinin yavaş olduğunu ölçer",
               "Yanlış. Tarayıcı performans ölçmez; bilinen zafiyetleri arar."),
              ("Dockerfile'daki yorumları siler ve imajı küçültüp yeniden paketler",
               "Yanlış. Tarayıcı imajı değiştirmez; yalnızca rapor üretir."),
              ("İmajın kaynağını internete yükleyip herkese açık bir koda dönüştürür",
               "Yanlış. Tarama yerel olarak yapılır; imajı yayımlamaz."),
          ], dogru=0),
          ("Cilt 6'daki 'sürüm → CVE → exploit' zincirini hatırla.",
           "Paket sürümü + bilinen zafiyet listesi.",
           "Karşılaştır ve raporla."),
          puan=20, baslik="Tarayıcı ne yapar"),
]


def _kapanis():
    return """
İmaj, konteynerin DNA'sıdır: içindeki her katman, her paket, her unutulmuş sır, ondan doğan her
konteynere geçer. Saldırgan imaj geçmişini kazıp gömülü anahtarları bulur ya da imajdaki eski bir
paketin bilinen zafiyetini kullanır. Savunma dersi: sırları imaja gömme (çalışma zamanında ver), sızan
sırrı hemen iptal et, sürümleri sabitle, en küçük temel imajı seç, imajları CI'da tara ve
düzeltmesi hazır olan CRITICAL bulguları kapatmadan yayına çıkarma.
"""


SEVIYE = Seviye(
    kimlik="c13b02",
    cilt=13,
    bolum=2,
    baslik="İmaj Güvenliği",
    brifing="""
Deniz imaj dosyalarını getiriyor: "**<<musteri>>**. <<sahne>> Elimizde bir Dockerfile, o imajın
`docker history` çıktısı, üretimde kullanılan imaj listesi ve bir tarama raporu var. Dört soru:
gömülü sır var mı, hangi imajlar `latest`, kaç kritik zafiyet var ve Dockerfile nasıl düzelir?"

Selin: "Sır bulursan önce müşteriye 'hemen iptal edin' dersin; Dockerfile'ı düzeltmek ikinci adım."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Sızan sırlar ve katmanlar:** Herkese açık kayıt defterlerindeki imajların geçmişinde unutulmuş
  parola ve anahtarların bulunması, güvenlik araştırmalarında sık anılan bir bulgudur. Docker'ın
  kendi belgeleri de sırların imaja gömülmemesini, `docker history` ile katmanların incelenebildiğini
  belirtir.
- **Log4Shell 2021:** Kitaplığın imajlara paketlenmiş olması nedeniyle birçok kuruluş, hangi
  konteyner imajlarının etkilendiğini tarama raporlarıyla aradı. İmaj envanteri ve düzenli tarama,
  böyle bir anda "bizde var mı?" sorusunu dakikalara indirir.
- **Tespit ve önleme:** CI hattında imaj taraması (zafiyet ve gömülü sır taraması), `latest`
  etiketini yasaklayan bir kural, küçük taban imajlar ve imajları yalnızca doğrulanmış kayıt
  defterinden almak en yaygın önlemlerdir.
""",
    sure_hedef_dk=40,
)
