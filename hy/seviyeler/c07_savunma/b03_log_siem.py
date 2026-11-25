"""Cilt 7 · Bölüm 3 — Log Yönetimi ve SIEM.

Beceri: web, SSH (auth) ve güvenlik duvarı loglarını IP ve zaman üzerinden ilişkilendirmek
(korelasyon), farklı zaman biçimlerini ortak bir çizelgeye oturtmak ve basit bir SIEM kuralını
(`kural.sh` ya da `kural.py`) kendi elinle yazmak.

Loglar `hy.ortak.loglar.olay_uret` ve `ortak.fw_logu` ile üretilir (tek aktörlü, tutarlı olay).
Vakalar: farklı müşteri, farklı güvenlik duvarı log biçimi (iptables / anahtar=değer), farklı
klasör adları. Test: oyuncunun betiği, kontrol anında üretilen yeni bir log çiftine karşı çalıştırılır.
"""
from __future__ import annotations

import random
import re
import subprocess
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Metin, Secmeli, Sonuc, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import loglar
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec
from hy.seviyeler.c07_savunma import ortak
from hy.seviyeler.c07_savunma.ortak import OLAY_ADLARI, Sira, fw_satiri, sec_doldur, sh

KLASORLER = ["merkezi_loglar", "siem_girdi", "toplanan_loglar", "kayit_deposu"]


def uret(rng):
    m = musteri_sec(rng)
    klasor = rng.choice(KLASORLER)
    bicim = rng.choice(ortak.FW_BICIMLERI)
    o = ortak.tam_olay(rng, m, bicim)
    perm = list(range(6))
    rng.shuffle(perm)                      # olay_listesi.txt'deki gösterim sırası
    beklenen = [perm.index(e) + 1 for e in o["sira"]]
    esik = rng.randint(5, 8)
    return {
        "vaka": f"{m['ad']} — {m['sektor']} olayı ({'iptables' if bicim == 'iptables' else 'anahtar=değer'} güvenlik duvarı logu)",
        "musteri": m, "klasor": klasor, "bicim": bicim, "o": o, "perm": perm, "esik": esik,
        "kural_tohumu": rng.randint(1, 10**6),
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "klasor": klasor, "esik": str(esik),
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "ip": o["ip"], "drop_port": o["fw"]["drop_port"], "ilk_iz": o["fw"]["ilk"], "sira": beklenen,
        },
    }


def _kural_loglari(tohum: str, bicim: str, esik: int, sunucu: str = "ornek-sunucu"):
    """Kural testi için küçük bir auth + güvenlik duvarı log çifti ve beklenen IP kümesi."""
    rng = random.Random(tohum)
    t0 = datetime(2026, 3, 9, 10, 0, 0)
    ipler = u.benzersiz(rng, lambda r: u.dis_ip(r), 7)
    vaka = [  # (ip, başarısız, fw eylemi, başarılı_giriş, geçersiz kullanıcı mı, yakalanmalı mı, etiket)
        (ipler[0], esik + 2, "DROP", 0, False, True, "eşiğin üstünde ve duvarda engellenmiş"),
        (ipler[1], esik + 3, "ACCEPT", 0, False, False, "duvarda hiç DROP yok"),
        (ipler[2], esik - 2, "DROP", 0, False, False, "eşiğin altında"),
        (ipler[3], esik, "DROP", 0, False, True, "tam eşikte (>= olmalı)"),
        (ipler[4], esik, "DROP", 0, True, True, "'invalid user' denemeleri de başarısız parola sayılır"),
        (ipler[5], 1, "DROP", esik + 2, False, False, "başarılı girişler sayılmaz"),
        (ipler[6], esik + 1, "DROP", 0, False, True, "eşiğin bir üstünde"),
    ]
    auth, fw, beklenen, etiket = [], [], set(), {}
    for ip, basarisiz, eylem, basarili, gecersiz, yakala, ad in vaka:
        t = t0 + timedelta(seconds=rng.randint(0, 3000))
        for _ in range(basarisiz):
            t += timedelta(seconds=rng.randint(1, 20))
            port = rng.randint(30000, 60000)
            if gecersiz:
                auth.append((t, f"Failed password for invalid user {rng.choice(['test', 'oracle', 'guest'])} from {ip} port {port} ssh2"))
            else:
                auth.append((t, f"Failed password for root from {ip} port {port} ssh2"))
        for _ in range(basarili):
            t += timedelta(seconds=rng.randint(1, 20))
            auth.append((t, f"Accepted password for deploy from {ip} port {rng.randint(30000, 60000)} ssh2"))
        for _ in range(rng.randint(1, 3)):
            z = t0 + timedelta(seconds=rng.randint(0, 3600))
            fw.append((z, fw_satiri(bicim, z, ip, "10.20.0.5", rng.choice([22, 23, 3389]), eylem, 40000, "fw-test")))
        if yakala:
            beklenen.add(ip)
        etiket[ip] = ad
    auth.sort(key=lambda x: x[0])
    fw_s = [satir for _, satir in sorted(fw, key=lambda x: x[0])]
    auth_s = [f"{u.syslog_zamani(t)} {sunucu} sshd[{rng.randint(1000, 9999)}]: {olay}" for t, olay in auth]
    return "\n".join(auth_s) + "\n", "\n".join(fw_s) + "\n", beklenen, etiket


def yaz(lab: Path, s: dict) -> None:
    k, o = lab / s["klasor"], s["o"]
    m = s["musteri"]
    u.yaz(k / "access.log", loglar.metin(o["web"]))
    u.yaz(k / "auth.log", loglar.metin(o["ssh"]))
    u.yaz(k / "guvenlik_duvari.log", "\n".join(o["fw"]["satirlar"]) + "\n")
    olaylar = [f"{i + 1}. {OLAY_ADLARI[e]}" for i, e in enumerate(s["perm"])]
    u.yaz(lab / "olay_listesi.txt", "Olay çizelgesi için altı olay (karışık sırada):\n" + "\n".join(olaylar) + "\n")
    u.yaz(lab / "kural_kurali.txt",
          "SIEM KURALI (senden istenen)\n"
          "----------------------------\n"
          "Betiğin adı: kural.sh (bash) ya da kural.py (python3).\n"
          "Çağrılış   : bash kural.sh AUTH_LOGU GUVENLIK_DUVARI_LOGU\n"
          "Kural      : auth logunda EN AZ " + str(s["esik"]) + " başarısız parola denemesi (`Failed password`) yapmış\n"
          "             VE güvenlik duvarı logunda en az bir DROP kaydı olan IP'leri bul.\n"
          "Çıktı      : satır başına bir IP, başka hiçbir şey yazma.\n"
          "Deneme logları kural_ornek/ klasöründe; kontrol ise sana gösterilmeyen yeni loglarla yapılır.\n")
    a, f, *_ = _kural_loglari(f"ornek:{s['kural_tohumu']}", s["bicim"], s["esik"], m["sunucu"])
    u.yaz(lab / "kural_ornek/auth.log", a)
    u.yaz(lab / "kural_ornek/guvenlik_duvari.log", f)
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} merkezi log klasörü ({s['klasor']}/): web, SSH ve güvenlik duvarı kayıtları. KURGUSAL.\n"
          f"Deniz'den not: {m['hikaye']}\n")


# ----------------------------------------------------------------------------- kontroller

def _betik_bul(b):
    for d in (b.calisma_dizini, b.lab):
        if d:
            for ad in ("kural.sh", "kural.py"):
                if (Path(d) / ad).is_file():
                    return Path(d) / ad
    return None


def _kural_kontrol(b) -> Sonuc:
    betik = _betik_bul(b)
    if betik is None:
        return Sonuc(False, "`kural.sh` ya da `kural.py` bulunamadı. Lab klasöründe oluştur (kural_kurali.txt'ye bak).")
    s = b.senaryo
    with tempfile.TemporaryDirectory() as gecici:
        g = Path(gecici)
        for tur in ("a", "b"):
            auth, fw, beklenen, etiket = _kural_loglari(f"kontrol{tur}:{s['kural_tohumu']}", s["bicim"], s["esik"])
            (g / "auth.log").write_text(auth)
            (g / "fw.log").write_text(fw)
            komut = ["python3", str(betik)] if betik.suffix == ".py" else ["bash", str(betik)]
            try:
                r = subprocess.run(komut + [str(g / "auth.log"), str(g / "fw.log")], capture_output=True, text=True,
                                   timeout=10, cwd=gecici)
            except subprocess.TimeoutExpired:
                return Sonuc(False, "Betik 10 saniyede bitmedi; dosya argümanlarını okuyor musun? (`$1`, `$2`)")
            if r.returncode != 0 and not r.stdout.strip():
                return Sonuc(False, "Betik hata verdi: " + (r.stderr.strip().splitlines() or ["?"])[-1][:160])
            cikti = r.stdout.strip().splitlines()
            gecerli = all(re.fullmatch(r"\s*(?:\d{1,3}\.){3}\d{1,3}\s*", x) for x in cikti)
            if not gecerli:
                return Sonuc(False, "Çıktıda IP olmayan satır var; sadece IP yaz, satır başına bir tane.", yakin=True)
            verilen = {x.strip() for x in cikti}
            eksik, fazla = beklenen - verilen, verilen - beklenen
            if eksik:
                return Sonuc(False, f"Yakalaman gereken IP kaçtı: {sorted(eksik)[0]} ({etiket[sorted(eksik)[0]]}).", yakin=True)
            if fazla:
                return Sonuc(False, f"Yakalamaman gereken IP'yi yakaladın: {sorted(fazla)[0]} ({etiket[sorted(fazla)[0]]}).", yakin=True)
    return Sonuc(True, "Betik iki yeni log çiftinde de doğru IP'leri buldu.")


def _port_hata(g, beklenen, b):
    f = b.senaryo["o"]["fw"]
    try:
        n = int(g)
    except ValueError:
        return None
    if n == f["drop_satir"] and n != beklenen:
        return "Satırları saymışsın; aynı port birkaç kez denenmiş olabilir. Farklı port sayısını (`sort -u`) say."
    if n in (f["drop_port"] + f["accept_port"], f["satir_toplam"]):
        return "İzin verilen (ACCEPT) bağlantıları da saymışsın. Sadece engellenen (DROP) portlar."
    return None


def _iz_hata(g, beklenen, b):
    web = b.senaryo["o"]["web"]["saldirilar"]["tarama"]["ilk"]
    if g == web:
        return "O, web logundaki ilk iz. Aynı IP güvenlik duvarında daha önce de görünüyor."
    return None


def _sira_hata(verilen, beklenen, b):
    if verilen == sorted(verilen):
        return "Listedeki sıraya göre yazmışsın. Her olayın saatini loglardan bulup saate göre dizmelisin."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["klasor"]
    fw, web, auth = f"{k}/guvenlik_duvari.log", f"{k}/access.log", f"{k}/auth.log"
    ip = sh(f"comm -12 <(comm -12 <(grep -i drop {fw} | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort -u) "
            f"<(cut -d' ' -f1 {web} | sort -u)) <(grep -oE 'from [0-9.]+' {auth} | cut -d' ' -f2 | sort -u)", lab)
    port = sh(f"grep -i drop {fw} | grep -w '{ip}' | grep -oiE '(dpt|dport)=[0-9]+' | cut -d= -f2 | sort -u | wc -l", lab)
    sat = r"(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}"
    iz = sh(f"for f in {fw} {web} {auth}; do grep -wm1 '{ip}' $f | grep -oP '{sat}' | head -1; done | sort | head -1", lab)
    yedek = s["musteri"]["yedek"]
    komutlar = {
        "Güvenlik duvarında": f"grep -wm1 '{ip}' {fw} | grep -oP '{sat}' | head -1",
        "yedek dosyanın": f"grep -F '{yedek}' {web} | grep ' 200 ' | grep -w '{ip}' | head -1 | grep -oP '{sat}'",
        "parolayla başarılı": f"grep 'Accepted password' {auth} | grep -w '{ip}' | head -1 | grep -oP '{sat}'",
        "sudo ile root": f"grep 'COMMAND=/bin/bash' {auth} | head -1 | grep -oP '{sat}'",
        "useradd": f"grep 'new user:' {auth} | head -1 | grep -oP '{sat}'",
        "root hesabına ilk": f"grep -m1 'Failed password for root' {auth} | grep -oP '{sat}'",
    }
    zamanlar = []
    for satir in (lab / "olay_listesi.txt").read_text().splitlines()[1:]:
        no = int(satir.split(".", 1)[0])
        for anahtar, komut in komutlar.items():
            if anahtar in satir:
                zamanlar.append((sh(komut, lab), no))
    sira = " ".join(str(no) for _, no in sorted(zamanlar))
    n = s["esik"]
    sh("cat > kural.sh <<'EOS'\n"
       "#!/bin/bash\n"
       f"comm -12 <(awk -v n={n} '/Failed password/ {{for(i=1;i<=NF;i++) if($i==\"from\") c[$(i+1)]++}} END {{for(ip in c) if(c[ip]>=n) print ip}}' \"$1\" | sort -u) "
       "<(grep -i drop \"$2\" | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort -u)\n"
       "EOS", lab)
    return sec_doldur({1: ip, 2: port, 3: iz, 4: sira, 5: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Neden merkezi log?", """
Tek bir makinenin logunu okumak kolaydır; yüzlercesini okumak imkânsızdır. Üstelik saldırgan
girdiği makinenin loglarını siler (iz temizleme). Çözüm **merkezi loglama**: her makine
kayıtlarını anında ayrı, güvenli bir sunucuya gönderir; yerel kopya silinse de merkezdeki kalır.
Bu merkezi sunucuya toplanan loglar **SIEM** (Security Information and Event Management) denen
sistemde birleştirilir ve kurallarla taranır. Cilt 3'te yazdığın log avcısı bunun küçük
kardeşidir.

<<musteri>> vakasında üç kaynak merkezde toplanmış. Klasöre bak:
""", komut="ls -l <<klasor>>"),
    Adim("Üç kaynak, üç biçim", """
Web logu, SSH logu ve güvenlik duvarı logu aynı olayı anlatır ama **farklı dilde**. Her dosyanın
ilk iki satırına bak ve zamanın, IP'nin nasıl yazıldığını karşılaştır:
""", komut="head -n 2 <<klasor>>/access.log <<klasor>>/auth.log <<klasor>>/guvenlik_duvari.log", sonra="""
Web logunda zaman `[gün/Ay/yıl:SS:DD:SS +0300]`, SSH logunda `Ay gün SS:DD:SS`, güvenlik duvarında
dosyaya göre ya `Ay gün SS:DD:SS` ya da ISO biçimi. IP bir yerde ilk sütunda, bir yerde
`from ...`, bir yerde `SRC=`/`src=` ardında. SIEM'in ilk işi bunları **normalleştirmektir**.
"""),
    Adim("Zamanı ayıklamak", """
Ortak çizelgeye oturtmak için her satırdan sadece `SS:DD:SS` kısmını çekebilirsin. `grep -o` yalnızca
eşleşen parçayı yazar, `-P` Perl tarzı düzenli ifadedir. `(?<![0-9])` "öncesinde rakam olmasın"
demektir; bunu eklememizin nedeni aşağıda:
""", komut="grep -ohP '(?<![0-9])[0-9]{2}:[0-9]{2}:[0-9]{2}' <<klasor>>/guvenlik_duvari.log | head -3", sonra="""
**Tuzak:** Web logunda saat, yılın hemen yanında durur (`2026:15:33:57`). Basit bir `[0-9]{2}:[0-9]{2}:[0-9]{2}`
kalıbı önce `26:15:33` gibi yanlış bir parça yakalar. "Öncesinde rakam olmasın" kuralı bunu önler.
Zaman ayıklarken ilk bakılacak şey, **çıkan saatin gerçekten bir saat olup olmadığıdır**.
"""),
    Adim("Ortak IP: kümelerin kesişimi", """
"Üç logda da görünen IP kim?" sorusu bir küme kesişimidir. `comm -12` iki **sıralı** listenin ortak
satırlarını verir. Bash'in `<( ... )` yapısı bir komutun çıktısını dosya gibi gösterir. Web logu ile
SSH logunda ortak IP'ler:
""", komut="comm -12 <(cut -d' ' -f1 <<klasor>>/access.log | sort -u) <(grep -oE 'from [0-9.]+' <<klasor>>/auth.log | cut -d' ' -f2 | sort -u)", sonra="""
Çıkan listede meşru yöneticinin ofis IP'si de vardır. Saldırganı ayıran şey, **güvenlik duvarında
engellenmiş (DROP)** kaydı olmasıdır. Kesişime üçüncü bir küme (DROP gören IP'ler) ekleyerek
iki adımda daraltırsın.
"""),
    Adim("Korelasyon kuralı: SIEM'in mantığı", """
Bir SIEM kuralı, birden fazla kaynağı bağlayan bir cümledir: "aynı IP'den 5 dakikada 10 başarısız
giriş → alarm" ya da "duvarda engellenen IP'den sonra başarılı SSH girişi → kritik alarm". Tek
kaynak sinyali zayıftır (herkesin başarısız girişi olur); **iki kaynağı bağlayınca** gürültü
düşer.

Senden küçük bir kural yazmanı istiyorum. Şartı oku:
""", komut="cat kural_kurali.txt"),
    Adim("Betiğin iskeleti", """
Başarısız giriş sayısını IP başına `awk` ile sayabilirsin. `from` kelimesinden sonraki alan IP'dir.
Örnek loglarda her IP'nin kaç başarısız denemesi var, en çoktan başla:
""", komut="awk '/Failed password/ {for(i=1;i<=NF;i++) if($i==\"from\") c[$(i+1)]++} END {for(ip in c) print c[ip], ip}' kural_ornek/auth.log | sort -rn | head -3", sonra="""
Bu sadece **ilk yarı**. İkinci yarı: aynı IP'ler güvenlik duvarı logunda DROP gördü mü? İki listeyi
`comm -12` ile kesiştir. Betiği `nano kural.sh` ile yaz; argümanlar `$1` (auth) ve `$2`
(güvenlik duvarı). Dikkat: `Failed password for invalid user ...` satırları da sayılır, çünkü `from`
sözcüğü yine IP'den önce gelir.
"""),
    Adim("Hacker gözüyle: loglar iz bırakır", """
**Hacker gözüyle:** Cilt 1-6 boyunca her saldırının iz bıraktığını gördün: brute-force `auth.log`'da,
SQL enjeksiyonu web logunda, port tarama güvenlik duvarında. SIEM bu izleri gürültünün içinden
çekip alır. Saldırgan açısından ders "görünmez olmaya çalışmak"tır: düşük ve yavaş gitmek, logları
silmek. Savunmacı açısından ders: **her şeyi logla, merkeze gönder**; saldırganın silemeyeceği bir
kopya en iyi delildir. Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("<<musteri>>'in `<<klasor>>/` klasöründe: güvenlik duvarında **engellenmiş (DROP)** kaydı olan, "
          "aynı zamanda web logunda ve `auth.log`'da da görünen **tek IP** hangisi?",
          IP("ip"),
          ("Üç kümenin kesişimi: DROP gören IP'ler, web logundaki IP'ler, auth.log'daki IP'ler.",
           "Her log için IP'leri `sort -u` ile tekilleştir, sonra `comm -12` ile kesiştir. DROP satırlarını `grep -i drop` ile al.",
           "`comm -12 <(DROP_IP_LISTESI) <(WEB_IP_LISTESI)` sonucunu bir kez daha auth.log IP listesiyle kesiştir."),
          puan=40, baslik="Üç logda tek IP"),
    Gorev("Bu IP güvenlik duvarında kaç **farklı porta** yönelik bağlantı denemesinde **engellendi (DROP)**? "
          "(Port taramasının büyüklüğü)",
          Sayi("drop_port", sik_hatalar=_port_hata),
          ("Aynı portu birkaç kez deneyebilir; satır sayısı port sayısı değil.",
           "DROP satırlarından sadece hedef port bilgisini (`DPT=` ya da `dport=`) çek, tekilleştir, say.",
           "`grep -i drop <<klasor>>/guvenlik_duvari.log | grep -w 'IP' | grep -oiE '(dpt|dport)=[0-9]+' | sort -u | wc -l`"),
          puan=40, baslik="Taranan port sayısı"),
    Gorev("Bu IP'nin **herhangi bir logdaki en erken izi** hangi saatte (SS:DD:SS)?",
          Metin("ilk_iz", sik_hatalar=_iz_hata, bicim="SS:DD:SS"),
          ("Üç logda da bu IP'nin ilk geçtiği satırı ara; en erkenini seç.",
           "Her dosyada `grep -wm1 IP dosya` ile ilk satırı al (`-w` tam sözcük: 203.0.113.2 ile 203.0.113.25 karışmasın), `grep -oE` ile sadece saati çıkar.",
           "Üç dosyada saatleri toplayıp `sort | head -1` ile en küçüğünü al. Saat biçimleri aynı (SS:DD:SS) olduğu için sıralanır."),
          puan=40, baslik="İlk iz"),
    Gorev("`olay_listesi.txt` içindeki altı olayı **gerçekleşme sırasına** diz (en erken olan başta). "
          "Cevap olarak listedeki **numaraları** sırayla yaz (örn. `4 2 1 6 3 5`).",
          Sira("sira", sik_hatalar=_sira_hata),
          ("Her olayın saatini ilgili logdan bulman gerek: güvenlik duvarı, web, auth.log.",
           "Saatleri tek tek çek (`grep`, `grep -oP`); web logunda saat yılın yanında durur, ilk 'saat' gibi görünen parça yanlış olabilir. Sonra yan yana yazıp sırala.",
           "Altı saati bir kâğıda yaz: olay no → saat. Sonra saate göre sırala ve olay numaralarını oku."),
          puan=60, baslik="Zaman çizelgesi"),
    Gorev("`kural_kurali.txt` dosyasındaki SIEM kuralını uygulayan `kural.sh` (ya da `kural.py`) betiğini lab "
          "klasöründe yaz. Betiğin yeni log çiftlerinde doğru IP'leri bulması gerekir. Bitince `cevap 5`.",
          Durum(_kural_kontrol, "kural.sh: awk ile başarısız parola sayımı + comm -12 ile güvenlik duvarı DROP kesişimi"),
          ("İki ayrı küme çıkarıp kesiştireceksin: başarısız giriş yapan IP'ler ve DROP gören IP'ler.",
           "Birinci küme: `awk` ile `Failed password` satırlarındaki `from` sonrası IP'yi say, sayısı eşikten büyük ya da eşit olanları yaz. İkinci küme: `grep -i drop | grep -oiE 'src=[0-9.]+'`.",
           "`comm -12 <(awk ... \"$1\" | sort -u) <(grep -i drop \"$2\" | grep -oiE 'src=[0-9.]+' | cut -d= -f2 | sort -u)`; eşik <<esik>>. İki listenin de sıralı olduğundan emin ol."),
          puan=80, baslik="Korelasyon kuralı yaz"),
    Gorev("Merkezi loglama, tek makinedeki yerel loglamadan neden daha güvenlidir?",
          Secmeli([
              ("Saldırgan girdiği makinede yerel logu silse bile kayıtların kopyası ayrı sunucuda durur",
               "Doğru. İz temizleme (log silme) merkezi kopyayı etkilemez; delil korunur."),
              ("Merkezi sunucu, kayıtları daha hızlı yazar ve bu yüzden hiçbir olay kaçmaz",
               "Yanlış. Merkezileştirmenin amacı hız değil, kopyanın saldırganın erişemeyeceği yerde olmasıdır."),
              ("Kayıtlar tek yerde toplandığı için artık hiçbir sunucuda log tutmaya gerek kalmaz",
               "Yanlış. Yerel log da tutulur; merkezi kopya onu tamamlar, yerine geçmez."),
              ("Saldırgan merkezi sunucunun adresini göremez ve bu yüzden saldırıdan vazgeçer",
               "Yanlış. Güvenlik gizlilikle sağlanmaz; asıl fark kopyanın ayrı ve korunaklı olmasıdır."),
          ], dogru=0),
          ("Saldırgan girdiği makinede neyi silebilir?",
           "Loglar bir de başka bir yerde duruyorsa silme işlemi neyi değiştirir?",
           "Doğru cevap 'yerel log silinse de kopya kalır' fikrini söyler."),
          puan=20, baslik="Merkezi log"),
    Gorev("Aşağıdaki SIEM kurallarından hangisi, farklı log kaynaklarını bağlayarak **en değerli** sinyali üretir?",
          Secmeli([
              ("Güvenlik duvarında çok porta engellenen bir IP'nin, ardından aynı IP'den başarılı SSH girişi yapması",
               "Doğru. İki kaynağı bağlar: tarama ardından başarılı giriş, 'keşiften ilk erişime' geçişi gösterir."),
              ("Güvenlik duvarında DROP gören her IP'nin otomatik ve kalıcı olarak tamamen engellenmesi",
               "Yanlış. Bu bir korelasyon değil, gürültüye tepki: sürekli yanlış alarm ve gereksiz engel üretir."),
              ("Web logunda her 404 yanıtında yöneticiye alarm e-postası gönderilmesi",
               "Yanlış. 404'ler normal trafikte de çok olur; kural gürültü fırtınası çıkarır."),
              ("auth.log'da her başarılı girişte yöneticiye e-posta gönderilmesi",
               "Yanlış. Başarılı giriş çoğunlukla meşrudur; tek başına, bağlam olmadan işe yaramaz."),
          ], dogru=0),
          ("İyi bir korelasyon kuralı en az iki kaynağı birleştirir.",
           "Tek kaynak sinyallerinin gürültülü olduğunu düşün; bağlam, gürültüyü azaltır.",
           "Tarama (keşif) ve sonrasında başarılı giriş (ilk erişim) birleşimi zincirdeki iki halkayı bağlar."),
          puan=20, baslik="İyi kural"),
]


def _kapanis():
    return """
Üç ayrı log aynı saldırgana ait üç ayrı cümleydi: duvar "bu IP çok porta vurdu" dedi, web logu "bu IP
yedek dosyayı indirdi", SSH logu "bu IP girdi ve root oldu". Hiçbiri tek başına yeterince güçlü
değildi; birleşince zincir ortaya çıktı. Saldırgan açısından ders: düşük ve yavaş gitmek ya da logları
silmek bu birleşimi zorlaştırır. Savunma dersi: kaynakları ortak zamana ve ortak IP'ye bağla, kuralı
sadece sayıya değil bağlama dayandır ve loglar merkeze akıyor olsun ki silinemesin.
"""


SEVIYE = Seviye(
    kimlik="c07b03",
    cilt=7,
    bolum=3,
    baslik="Log Yönetimi ve SIEM",
    brifing="""
Deniz Kara ekranını sana çeviriyor: "**<<musteri>>** (<<sektor>>) için üç kaynaktan log geldi:
web sunucusu, SSH ve güvenlik duvarı. Her biri tek başına masum görünüyor. <<hikaye>>"

Deniz devam ediyor: "SIEM'in yaptığı iş şu: bu üçünü ortak zamana ve ortak IP'ye bağlamak. Önce
elle yap: kim, ne zaman, hangi sırayla? Sonra kuralı bir betiğe dök ki bir daha elle yapmayalım.
Eşik <<esik>> başarısız parola." Mert uzaktan ekliyor: "Zamanlar üç loglarda üç ayrı biçimde. Çizelgeye
dökmeden hiçbir şey anlamazsın."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **SolarWinds 2020:** Saldırının fark edilmesine, kamuya açıklanan bilgilere göre, bir güvenlik
  firmasının kendi çalışanının hesabına ait **olağandışı bir MFA cihazı kaydını** görmesi yol açtı.
  Yani tek bir tuhaf log satırı, doğru kişi tarafından ilişkilendirilince zinciri açığa çıkardı.
  Bu bölümdeki beceri tam budur: loglardaki küçük tutarsızlığı başka kaynakla bağlamak.
- **Target 2013:** Güvenlik ürünleri alarm üretmişti ama alarmlar zamanında aksiyona çevrilmedi.
  Önleme: alarm yalnızca üretilmemeli, bir kişi/süreç tarafından **sahiplenilip** izlenmelidir.
  Tespit: kuralların bağlamla (iki kaynak) zenginleştirilmesi gürültüyü azaltır ve gerçek alarmı öne çıkarır.
- **Merkezi log pratiği:** Saldırganların girdikleri makinede yerel logları silmeye çalışması
  iyi bilinen bir tekniktir (MITRE ATT&CK: Indicator Removal). Logları anında ayrı bir sunucuya
  göndermek, bu iz silme girişimini boşa çıkarır ve delili korur.
""",
    sure_hedef_dk=40,
)
