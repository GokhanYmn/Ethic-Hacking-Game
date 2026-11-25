"""Cilt 7 · Bölüm 2 — Sistem Sertleştirme (Hardening).

Beceri: kurgusal bir sunucunun yapılandırma kopyasında (sshd_config, sudoers, parola politikası,
açık servis listesi, güvenlik duvarı kuralları) zayıflıkları bulmak ve dosyaları düzeltmek.
`cevap <no>` komutu dosyaların son halini kontrol eder (Durum görevleri).

Vakalar: web sunucusu, hastane dosya sunucusu, belediye e-hizmet sunucusu. Her vakada zayıflığın
yeri farklıdır: ana dosyada, çift satırda (sshd ilk satırı kullanır) ya da Include ile okunan
bir alt dosyada.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Durum, Kume, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

# (port, protokol, süreç, açıklama)
GEREKSIZ_HAVUZ = [
    (21, "tcp", "vsftpd", "eski FTP"), (23, "tcp", "telnetd", "telnet"), (111, "tcp", "rpcbind", "RPC"),
    (3306, "tcp", "mysqld", "veritabanı"), (5900, "tcp", "x11vnc", "uzak ekran"),
    (8080, "tcp", "java", "test uygulaması"), (161, "udp", "snmpd", "ağ izleme"), (25, "tcp", "postfix", "e-posta"),
]

VAKALAR = [
    {
        "ad": "Pazarix — web sunucusu", "musteri": "Pazarix", "kok": "web01_kopya", "host": "pzx-web01",
        "gerekli": [(22, "tcp", "sshd", "yönetim"), (80, "tcp", "apache2", "web"), (443, "tcp", "apache2", "web")],
        "root_yer": "ana", "parola_yer": "ana", "kim": "devops_destek", "servis": "apache2", "minlen": 6,
        "established": True, "sahne": "Kampanya öncesi sunucu denetimi: sunucu 'kurulduğu gibi' bırakılmış.",
    },
    {
        "ad": "Medora Sağlık — dosya sunucusu", "musteri": "Medora Sağlık", "kok": "dosya_sunucusu", "host": "medora-dosya",
        "gerekli": [(22, "tcp", "sshd", "yönetim"), (445, "tcp", "smbd", "dosya paylaşımı"), (443, "tcp", "nginx", "portal")],
        "root_yer": "cift", "parola_yer": "dropin", "kim": "%destek", "servis": "smbd", "minlen": 8,
        "established": False, "sahne": "Hasta dosyalarının tutulduğu sunucu KVKK denetimine girecek.",
    },
    {
        "ad": "Yeşiltepe Belediyesi — e-hizmet sunucusu", "musteri": "Yeşiltepe Belediyesi", "kok": "ebelediye_kopya",
        "host": "ytb-ebelediye",
        "gerekli": [(22, "tcp", "sshd", "yönetim"), (443, "tcp", "nginx", "e-hizmet")],
        "root_yer": "dropin", "parola_yer": "ana", "kim": "bakim_firma", "servis": "tomcat9", "minlen": 4,
        "established": True, "sahne": "Dış bakım firması sunucuya yıllardır erişiyor; kimse ayarlara bakmamış.",
    },
]


def uret(rng):
    v = rng.choice(VAKALAR)
    gerekli_portlar = {p for p, *_ in v["gerekli"]}
    adaylar = [x for x in GEREKSIZ_HAVUZ if x[0] not in gerekli_portlar]
    gereksiz = rng.sample(adaylar, rng.randint(3, 4))
    kalan = [x for x in adaylar if x not in gereksiz]
    yerel = rng.sample(kalan, 1) + [(631, "tcp", "cupsd", "yazıcı")]          # sadece 127.0.0.1 (zararsız)
    fw_gereksiz = [x for x in gereksiz if x[1] == "tcp"][:2]
    pids = rng.sample(range(500, 2500), 12)
    return {
        "vaka": v["ad"], "v": v, "gereksiz": gereksiz, "yerel": yerel, "fw_gereksiz": fw_gereksiz, "pids": pids,
        "metin": {"musteri": v["musteri"], "kok": v["kok"], "host": v["host"], "kim": v["kim"], "servis": v["servis"],
                  "sahne": v["sahne"]},
        "cevaplar": {"gereksiz": sorted(x[0] for x in gereksiz)},
    }


def _ss_satirlari(s: dict) -> list:
    v, pids = s["v"], iter(s["pids"])
    satir = ["Netid State  Recv-Q Send-Q          Local Address:Port    Peer Address:Port Process"]
    for p, proto, sur, _ in v["gerekli"] + s["gereksiz"]:
        pid = next(pids)
        durum = "LISTEN" if proto == "tcp" else "UNCONN"
        satir.append(f'{proto:<5} {durum:<6} 0      128                0.0.0.0:{p:<6}        0.0.0.0:*    users:(("{sur}",pid={pid},fd=3))')
        if proto == "tcp" and p in (22, 80, 443):
            satir.append(f'{proto:<5} {durum:<6} 0      128                   [::]:{p:<6}           [::]:*    users:(("{sur}",pid={pid},fd=4))')
    for p, proto, sur, _ in s["yerel"]:
        satir.append(f'{proto:<5} LISTEN 0      70             127.0.0.1:{p:<6}        0.0.0.0:*    users:(("{sur}",pid={next(pids)},fd=21))')
    satir.append(f'udp   UNCONN 0      0          127.0.0.53%lo:53           0.0.0.0:*    users:(("systemd-resolve",pid={next(pids)},fd=13))')
    return satir


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = lab / v["kok"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['musteri']} — {v['host']} sunucusunun yapılandırma kopyası ({v['kok']}/). KURGUSAL.\n"
          "Selin'den not: Gerçek sunucuda değil, kopyada çalışıyoruz. Dosyaları düzenle, sonra `cevap <no>` ile kontrol et.\n"
          "Gerçek hayatta sshd_config'i değiştirdikten sonra `sshd -t` ile sözdizimini denemeyi ve mevcut oturumu\n"
          "AÇIK TUTARAK yeni bir oturumla test etmeyi unutma; kendini sunucudan kilitlemek klasik hatadır.\n")
    ana = ["# sshd_config — kurgusal kopya", "Include /etc/ssh/sshd_config.d/*.conf", "", "Port 22", "AddressFamily any",
           "#LoginGraceTime 2m"]
    drop = {}
    ry, py = v["root_yer"], v["parola_yer"]
    if ry == "ana":
        ana.append("PermitRootLogin yes")
    elif ry == "cift":
        ana += ["# eski ayar (geçiş döneminden kalma)", "PermitRootLogin yes", "# yeni ayar", "PermitRootLogin no"]
    else:
        ana.append("PermitRootLogin no")
        drop.setdefault("60-bakim.conf", ["# bakım firması geçici ayarı (2021)"]).append("PermitRootLogin yes")
    if py == "ana":
        ana.append("PasswordAuthentication yes")
    else:
        ana.append("PasswordAuthentication no")
        drop.setdefault("50-cloud-init.conf", ["# otomatik üretilen ayar"]).append("PasswordAuthentication yes")
    ana += ["PermitEmptyPasswords no", "UsePAM yes", "X11Forwarding yes", "PrintMotd no", "AcceptEnv LANG LC_*",
            "Subsystem sftp /usr/lib/openssh/sftp-server"]
    u.yaz(k / "etc/ssh/sshd_config", "\n".join(ana) + "\n")
    for ad, satirlar in drop.items():
        u.yaz(k / "etc/ssh/sshd_config.d" / ad, "\n".join(satirlar) + "\n")
    if not drop:
        (k / "etc/ssh/sshd_config.d").mkdir(parents=True, exist_ok=True)
    u.yaz(k / "etc/sudoers.d/90-bakim",
          f"# Bakım ekibi için eklendi (kurgusal kopya)\n{v['kim']} ALL=(ALL) NOPASSWD: ALL\n"
          "deploy ALL=(root) NOPASSWD: /usr/local/bin/surum_yukle.sh\n", mod=0o644)
    u.yaz(k / "etc/security/pwquality.conf",
          f"# Parola kalitesi (kurgusal kopya)\nminlen = {v['minlen']}\n# dcredit = -1\n# ucredit = -1\nminclass = 1\n")
    u.yaz(k / "acik_servisler.txt", "\n".join(_ss_satirlari(s)) + "\n")
    u.yaz(k / "gerekli_servisler.txt", "# port protokol süreç neden\n" +
          "\n".join(f"{p} {pr} {sur} {n}" for p, pr, sur, n in v["gerekli"]) + "\n")
    kural = ["# iptables-save çıktısı (kurgusal kopya)", "*filter", ":INPUT ACCEPT [0:0]", ":FORWARD DROP [0:0]",
             ":OUTPUT ACCEPT [0:0]", "-A INPUT -i lo -j ACCEPT"]
    if v["established"]:
        kural.append("-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT")
    for p, pr, *_ in v["gerekli"]:
        if pr == "tcp":
            kural.append(f"-A INPUT -p tcp --dport {p} -j ACCEPT")
    for p, pr, *_ in s["fw_gereksiz"]:
        kural.append(f"-A INPUT -p tcp --dport {p} -j ACCEPT")
    kural.append("COMMIT")
    u.yaz(k / "etc/iptables/rules.v4", "\n".join(kural) + "\n")


# ----------------------------------------------------------------------------- kontroller

def _kok(b) -> Path:
    return b.lab / b.senaryo["v"]["kok"]


def sshd_etkili(kok: Path) -> dict:
    """sshd'nin gördüğü etkili ayarlar: Include yerinde açılır, ilk eşleşen satır kazanır."""
    sonuc: dict = {}

    def oku(yol: Path, derinlik: int = 0):
        if derinlik > 3 or not yol.is_file():
            return
        for no, ham in enumerate(yol.read_text(errors="replace").splitlines(), 1):
            satir = ham.strip()
            if not satir or satir.startswith("#"):
                continue
            parca = satir.split(None, 1)
            anahtar, deger = parca[0].lower(), (parca[1].strip() if len(parca) > 1 else "")
            if anahtar == "include":
                for desen in deger.split():
                    hedef = kok / desen.lstrip("/") if desen.startswith("/") else kok / "etc/ssh" / desen
                    for f in sorted(hedef.parent.glob(hedef.name)):
                        oku(f, derinlik + 1)
                continue
            sonuc.setdefault(anahtar, (deger.lower(), yol.relative_to(kok), no))

    oku(kok / "etc/ssh/sshd_config")
    return sonuc


def _ssh_kontrol(anahtar: str, istenen: str, ad: str):
    def kontrol(b) -> Sonuc:
        etkili = sshd_etkili(_kok(b)).get(anahtar)
        if etkili is None:
            return Sonuc(False, f"`{ad}` için hiçbir satır kalmamış (varsayılan geçerli olur). Açıkça `{ad} {istenen}` yaz.")
        deger, dosya, no = etkili
        if deger == istenen:
            return Sonuc(True, f"sshd'nin gördüğü etkili değer: {ad} {istenen} ({dosya}, satır {no}).")
        return Sonuc(False, f"sshd şu an `{ad} {deger}` görüyor (kaynak: {dosya}, satır {no}). "
                            "sshd aynı ayar için ilk satırı kullanır ve Include satırı alt dosyaları yerinde okur; "
                            "etkili satırı düzelt.", yakin=True)
    return kontrol


def _sudo_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = _kok(b) / "etc/sudoers.d/90-bakim"
    if not yol.is_file():
        return Sonuc(False, "etc/sudoers.d/90-bakim dosyasını silmişsin; kuralı daraltmalısın, dosyayı yok etmemelisin.")
    satirlar = [x.strip() for x in yol.read_text(errors="replace").splitlines() if x.strip() and not x.strip().startswith("#")]
    if any(re.search(r"NOPASSWD:\s*ALL\b", x) for x in satirlar):
        return Sonuc(False, "Hâlâ `NOPASSWD: ALL` içeren bir satır var. Bir hesaba 'her şeyi parolasız çalıştır' demek, "
                            "o hesabı pratikte root yapar.", yakin=True)
    if not any("deploy" in x and "surum_yukle.sh" in x for x in satirlar):
        return Sonuc(False, "`deploy` kullanıcısının meşru kuralını silmişsin; sadece sorunlu satırı değiştir.")
    kendi = [x for x in satirlar if x.split()[0] == v["kim"]]
    if not kendi:
        return Sonuc(False, f"`{v['kim']}` için hiç kural kalmamış; bakım ekibi işini yapamaz. Satırı silme, daralt.", yakin=True)
    if not any(f"systemctl restart {v['servis']}" in x for x in kendi):
        return Sonuc(False, f"`{v['kim']}` yalnızca `/usr/bin/systemctl restart {v['servis']}` komutunu çalıştırabilmeli.", yakin=True)
    if any(re.search(r"(:|,)\s*ALL\s*$", x) or re.search(r"\)\s*ALL\s*$", x) for x in kendi):
        return Sonuc(False, "Komut listesinde hâlâ `ALL` var.")
    return Sonuc(True, "Bakım hesabı artık yalnızca tek bir komutu parolasız çalıştırabilir.")


def _parola_kontrol(b) -> Sonuc:
    yol = _kok(b) / "etc/security/pwquality.conf"
    deger = None
    if yol.is_file():
        for ham in yol.read_text(errors="replace").splitlines():
            m = re.match(r"^\s*minlen\s*=\s*(\d+)", ham)
            if m:
                deger = int(m.group(1))
    if deger is None:
        return Sonuc(False, "pwquality.conf içinde yorum olmayan bir `minlen = ...` satırı kalmamış.")
    if deger < 12:
        return Sonuc(False, f"minlen şu an {deger}. Modern öneriler uzun parolayı öne çıkarır; en az 12 karakter iste.", yakin=True)
    return Sonuc(True, f"minlen = {deger}")


def _fw_kontrol(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = _kok(b) / "etc/iptables/rules.v4"
    if not yol.is_file():
        return Sonuc(False, "rules.v4 dosyası yok.")
    metin = yol.read_text(errors="replace")
    politika = re.search(r"^:INPUT\s+(\w+)", metin, re.M)
    if not politika or politika.group(1) != "DROP":
        return Sonuc(False, f"INPUT varsayılan politikası `{politika.group(1) if politika else 'yok'}`. "
                            "Güvenli model 'varsayılan reddet, gerekeni izin ver'dir (`:INPUT DROP`).", yakin=True)
    kabul = {int(x) for x in re.findall(r"^-A INPUT\b[^\n]*--dport\s+(\d+)[^\n]*-j ACCEPT", metin, re.M)}
    gerekli = {p for p, pr, *_ in v["gerekli"] if pr == "tcp"}
    fazla = sorted(kabul - gerekli)
    if fazla:
        return Sonuc(False, f"Hâlâ gerekmeyen portlara izin veren kural var: {', '.join(map(str, fazla))}.", yakin=True)
    eksik = sorted(gerekli - kabul)
    if eksik:
        return Sonuc(False, f"Gerekli port(lar) kapanmış: {', '.join(map(str, eksik))}. Servisler çalışmaya devam etmeli.", yakin=True)
    if not re.search(r"^-A INPUT\b[^\n]*ESTABLISHED[^\n]*-j ACCEPT", metin, re.M):
        return Sonuc(False, "Kurulmuş bağlantılara izin kuralı yok (`--state ESTABLISHED,RELATED`). Politikayı DROP yapınca "
                            "şu an açık olan SSH oturumun bile düşer.", yakin=True)
    return Sonuc(True, "Varsayılan reddet, yalnızca gerekli portlar açık, kurulmuş bağlantılar serbest.")


def _gereksiz_hata(girdi, beklenen, b):
    ports = {int(x) for x in re.findall(r"\d+", girdi)}
    gerekli = {p for p, *_ in b.senaryo["v"]["gerekli"]}
    if ports & gerekli:
        return f"{sorted(ports & gerekli)[0]} numaralı port bu sunucunun işi için gerekli (gerekli_servisler.txt); onu listeye alma."
    yerel = {p for p, *_ in b.senaryo["yerel"]}
    if ports & yerel:
        return f"{sorted(ports & yerel)[0]} numaralı servis sadece 127.0.0.1'de dinliyor; dışarıdan erişilemez, saldırı yüzeyi sayılmaz."
    return None


def coz(lab: Path, s: dict) -> dict:
    v = s["v"]
    k = v["kok"]
    ports = sh(f"awk '$5 ~ /^(0\\.0\\.0\\.0|\\[::\\]|\\*):/ {{n=split($5,a,\":\"); print a[n]}}' {k}/acik_servisler.txt | sort -un "
               f"| grep -vxFf <(awk '!/^#/ {{print $1}}' {k}/gerekli_servisler.txt)", lab).split()
    sh(f"sed -i -E 's/^PermitRootLogin[[:space:]]+(yes|without-password|prohibit-password)/PermitRootLogin no/' {k}/etc/ssh/sshd_config {k}/etc/ssh/sshd_config.d/*.conf 2>/dev/null; true", lab)
    sh(f"sed -i -E 's/^PasswordAuthentication[[:space:]]+yes/PasswordAuthentication no/' {k}/etc/ssh/sshd_config {k}/etc/ssh/sshd_config.d/*.conf 2>/dev/null; true", lab)
    sh(f"sed -i -E 's#^({v['kim']})[[:space:]].*NOPASSWD: *ALL.*#\\1 ALL=(root) NOPASSWD: /usr/bin/systemctl restart {v['servis']}#' {k}/etc/sudoers.d/90-bakim", lab)
    sh(f"sed -i -E 's/^minlen.*/minlen = 12/' {k}/etc/security/pwquality.conf", lab)
    desen = "|".join(ports)
    sh(f"sed -i -E '/--dport ({desen})/d' {k}/etc/iptables/rules.v4; sed -i 's/^:INPUT ACCEPT/:INPUT DROP/' {k}/etc/iptables/rules.v4; "
       f"grep -q ESTABLISHED {k}/etc/iptables/rules.v4 || sed -i '/-i lo/a -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT' {k}/etc/iptables/rules.v4", lab)
    return sec_doldur({1: " ".join(ports), 2: "", 3: "", 4: "", 5: "", 6: ""}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("Sertleştirme: saldırı yüzeyini daralt", """
Selin: "Saldırı yüzeyi, saldırganın dokunabileceği her şeydir: açık port, açık servis, zayıf ayar."
**Sertleştirme** (hardening) gereksiz olan her şeyi kapatmak, kalan her şeyi güvenli
yapılandırmak demektir. Cilt 6'daki yetki yükseltme yollarının çoğu iyi sertleştirilmiş bir
sistemde yoktur.

Temel ilkeler: **en az yetki**, **saldırı yüzeyini daralt**, **varsayılanları değiştir**,
**güncel tut**, **logla**. Bugün <<host>> sunucusunun kopyasında bunları uygulayacaksın.
Bir de sunucunun ne iş yaptığını gösteren dosyaya bak: bu sunucunun *gerçekten* ihtiyacı olan
portlar:
""", komut="cat <<kok>>/gerekli_servisler.txt"),
    Adim("Hangi servis dışarıya açık?", """
`ss -tulpn` komutunun çıktısı bu dosyaya kaydedilmiş (Cilt 2'de görmüştün). Önemli olan **yerel
adres** sütunudur: `0.0.0.0:PORT` ya da `[::]:PORT` dışarıdan erişilebilir demektir;
`127.0.0.1:PORT` sadece makinenin kendisine açıktır.
""", komut="cat <<kok>>/acik_servisler.txt", sonra="""
Dışarıya açık olup **gerekli olmayanlar** saldırı yüzeyidir. `awk` ile sadece dışarıya açık
olanları süzmek istersen yerel adres, 5. sütundur:
`awk '$5 ~ /^(0\\.0\\.0\\.0|\\[::\\]|\\*):/ {print $5, $7}' <<kok>>/acik_servisler.txt`
"""),
    Adim("SSH: iki kritik ayar", """
Cilt 5'teki parola deneme saldırıları ve Cilt 1'deki `root` brute-force denemeleri hep aynı
kapıya vurur: SSH. Savunma: **root'un doğrudan girişini kapat** (`PermitRootLogin no`) ve
**parolayla girişi kapat**, sadece anahtarla girişe izin ver (`PasswordAuthentication no`).

Ama dikkat: sshd bir ayar için **ilk eşleşen satırı** kullanır ve `Include` satırıyla başka
dosyaları yerinde okur. Bir ayarı bir yerde düzeltmek, başka yerde kalan satırı iptal etmez.
Tüm SSH ayarlarına tek komutla bak:
""", komut="grep -rn -iE 'PermitRootLogin|PasswordAuthentication' <<kok>>/etc/ssh", sonra="""
Satırların hangi dosyada ve kaçıncı satırda olduğuna dikkat et. Etkili olan, sshd'nin **ilk**
okuduğudur; `Include` en üstte olduğu için alt dosyalar ana dosyadan önce okunur.
"""),
    Adim("sudo: kimin neye hakkı var?", """
`sudoers` dosyaları kimin hangi komutu root olarak çalıştırabileceğini söyler. Cilt 6'da
`sudo -l` ile bakıp bu satırları arıyordun. Savunmacı olarak tam o satırları daraltırsın.
`NOPASSWD: ALL` 'şu hesap parolasız her şeyi yapabilir' demektir; ele geçirilen o hesap anında
root olur.
""", komut="cat <<kok>>/etc/sudoers.d/*", sonra="""
Doğrusu **en az yetki**: hesap sadece işi için gereken tek komutu çalıştırabilsin; örneğin
`hesap ALL=(root) NOPASSWD: /usr/bin/systemctl restart servis`. Gerçek sunucuda sudoers'ı
`visudo` ile düzenle; yazım hatası seni sudo'dan kilitleyebilir.
"""),
    Adim("Parola politikası", """
Güçlü parola politikası, Cilt 5'teki kimlik doğrulama saldırılarını zorlaştırır. Günümüzdeki
öneriler (örneğin NIST) karmaşıklık kuralları yerine **uzunluğu** öne çıkarır. Politikada
asgari uzunluğu `minlen` belirler:
""", komut="cat <<kok>>/etc/security/pwquality.conf"),
    Adim("Güvenlik duvarı: varsayılan reddet", """
İyi bir güvenlik duvarı kuralı **varsayılan olarak her şeyi reddeder** (`:INPUT DROP`), sonra
sadece gerekli olanlara izin verir. Mevcut kuralları oku:
""", komut="cat <<kok>>/etc/iptables/rules.v4", sonra="""
Politikayı `DROP` yaparken **kurulmuş bağlantılara izin kuralını** (`--state ESTABLISHED,RELATED`)
unutma; yoksa açık SSH oturumun da düşer. Sunucuya uzaktan bağlıysan bu klasik bir kilitlenme
hatasıdır.
"""),
    Adim("CIS Benchmark ve simetri", """
Her şeyi sıfırdan düşünmek zordur. **CIS Benchmarks** ve **DISA STIG** gibi herkese açık,
adım adım sertleştirme rehberleri vardır; profesyoneller onları temel alır.

**Hacker gözüyle:** Sertleştirme, Cilt 6'daki yetki yükseltme bölümünün tam tersidir. Orada
"yanlış yapılandırma ara" diyorduk; burada "yanlış yapılandırma bırakma" diyoruz. Saldırgan
olarak `sudo -l`, SUID ve açık servis aradığın listeyi, savunmacı olarak sen kapatırsın.
Şimdi görevlere geç; düzenlemelerini bitirince her görev için `cevap <no>` yaz.
"""),
]

GOREVLER = [
    Gorev("`<<kok>>/acik_servisler.txt` içinde **dışarıya açık (0.0.0.0 ya da [::])** olan ama "
          "`gerekli_servisler.txt` listesinde **olmayan** portları yaz (TCP ve UDP fark etmez).",
          Kume("gereksiz", tur="sayi", sik_hatalar=_gereksiz_hata, bicim="port numaraları, virgülle ayrılmış"),
          ("Önce dışarıya açık portları, sonra gerekli olanları listele; farkı al.",
           "Yerel adres sütunu `0.0.0.0:` ya da `[::]:` ile başlayanlar dışarıya açıktır; `127.0.0.1` olanlar değil.",
           "`awk '$5 ~ /^(0\\.0\\.0\\.0|\\[::\\]|\\*):/ {n=split($5,a,\":\"); print a[n]}' <<kok>>/acik_servisler.txt | sort -un` dışarıya açık portları verir; gerekli listeyi çıkar."),
          puan=40, baslik="Gereksiz açık portlar"),
    Gorev("SSH'ta **root'un doğrudan girişini kapat**: sshd'nin gördüğü etkili ayar `PermitRootLogin no` olsun. "
          "Düzelttikten sonra `cevap 2` yaz.",
          Durum(_ssh_kontrol("permitrootlogin", "no", "PermitRootLogin"), "PermitRootLogin no (etkili satır)"),
          ("sshd ayarları `<<kok>>/etc/ssh` altında; `PermitRootLogin` satırının kaç yerde geçtiğine bak.",
           "`grep -rn PermitRootLogin <<kok>>/etc/ssh` ile tüm satırları gör. sshd ilk eşleşeni kullanır; `Include` en üstte.",
           "Etkili satırı bul ve `sed -i 's/PermitRootLogin yes/PermitRootLogin no/' DOSYA` ile ya da `nano` ile düzelt."),
          puan=40, baslik="Root girişini kapat"),
    Gorev("SSH'ta **parolayla girişi kapat**: etkili ayar `PasswordAuthentication no` olsun. "
          "Düzelttikten sonra `cevap 3` yaz.",
          Durum(_ssh_kontrol("passwordauthentication", "no", "PasswordAuthentication"), "PasswordAuthentication no (etkili satır)"),
          ("Aynı ayar birden çok dosyada geçebilir; sshd hangisini okuyor?",
           "`grep -rn PasswordAuthentication <<kok>>/etc/ssh` bütün dosyalardaki satırları gösterir.",
           "`yes` yazan etkili satırı `no` yap. Ana dosya `no` diyorsa alt dosyadaki (`sshd_config.d`) satıra bak."),
          puan=40, baslik="Parola girişini kapat"),
    Gorev("`etc/sudoers.d/90-bakim` içindeki `NOPASSWD: ALL` satırını **daralt**: <<kim>> yalnızca "
          "`/usr/bin/systemctl restart <<servis>>` komutunu parolasız çalıştırabilsin. `deploy` satırına dokunma. "
          "Bitince `cevap 4`.",
          Durum(_sudo_kontrol, "<kim> ALL=(root) NOPASSWD: /usr/bin/systemctl restart <servis>"),
          ("Satırı silmek yerine komut kısmını değiştireceksin; hesap işini yapabilmeli.",
           "Biçim: `hesap ALL=(root) NOPASSWD: /tam/yol/komut argümanlar`.",
           "`nano <<kok>>/etc/sudoers.d/90-bakim`; `ALL` komutunu `/usr/bin/systemctl restart <<servis>>` ile değiştir."),
          puan=40, baslik="sudo kuralını daralt"),
    Gorev("`pwquality.conf` içindeki asgari parola uzunluğunu (`minlen`) **en az 12** yap. Bitince `cevap 5`.",
          Durum(_parola_kontrol, "minlen = 12"),
          ("Dosyada hangi satır uzunluğu belirliyor?",
           "`minlen = SAYI` satırı; `#` ile başlayan satırlar yorumdur, etkisizdir.",
           "`sed -i -E 's/^minlen.*/minlen = 12/' <<kok>>/etc/security/pwquality.conf`"),
          puan=30, baslik="Parola uzunluğu"),
    Gorev("`<<kok>>/etc/iptables/rules.v4` dosyasını sertleştir: INPUT varsayılan politikası `DROP` olsun, "
          "**gerekmeyen portlara izin veren kuralları sil**, gerekli portlar ve kurulmuş bağlantılar açık kalsın. "
          "Bitince `cevap 6`.",
          Durum(_fw_kontrol, ":INPUT DROP, yalnızca gerekli --dport ACCEPT kuralları, ESTABLISHED,RELATED kuralı"),
          ("Üç şey var: varsayılan politika, fazla kurallar, kurulmuş bağlantılar.",
           "`:INPUT ACCEPT [0:0]` satırını `:INPUT DROP [0:0]` yap. Gerekli olmayan `--dport` satırlarını sil. ESTABLISHED kuralı yoksa ekle.",
           "ESTABLISHED kuralı: `-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT` (loopback kuralından sonra)."),
          puan=50, baslik="Güvenlik duvarı"),
    Gorev("SSH'ta parolayla girişi kapatıp yalnızca anahtara izin vermek, hangi saldırıyı **etkisiz** hale getirir?",
          Secmeli([
              ("Parola tahmin etme (brute-force): denenecek parola kalmaz",
               "Doğru. Parola girişi kapalıysa saldırganın parola denemesi hiçbir yere varmaz."),
              ("SQL enjeksiyonu: veritabanı sorgusuna sızdırılan komutlar çalışmaz",
               "Yanlış. SQL enjeksiyonu web uygulamasının zafiyetidir; SSH ayarıyla ilgisi yok."),
              ("XSS: sayfaya yerleştirilen betikler kullanıcının tarayıcısında çalışmaz",
               "Yanlış. XSS tarayıcıda çalışan bir web zafiyetidir; sshd ayarından etkilenmez."),
              ("ARP sahteciliği: yerel ağdaki yanıltıcı ARP cevapları işe yaramaz",
               "Yanlış. ARP sahteciliği yerel ağ katmanında çalışır; SSH'ın kimlik doğrulama yöntemiyle ilgisi yok."),
          ], dogru=0),
          ("Hangi saldırı 'parola denemek' üzerine kurulu?",
           "Cilt 1'de auth.log'da gördüğün 'Failed password' satırlarının arkasındaki saldırıyı düşün.",
           "Parola girişi kapalıysa denenecek parola kalmaz: bu, brute-force'u kökten durdurur."),
          puan=20, baslik="Anahtar mı parola mı"),
    Gorev("CIS Benchmark nedir ve neden işe yarar?",
          Secmeli([
              ("Her sistem için herkese açık, adım adım yapılandırma rehberi; sertleştirmeyi sıfırdan düşünme yükünü alır",
               "Doğru. Profesyoneller CIS Benchmarks ya da DISA STIG gibi rehberleri temel alır."),
              ("Bir sistemin kaç saniyede açılabildiğini ölçen, firmalara özel ücretli bir hız testi",
               "Yanlış. Benchmark burada karşılaştırma testi değil, güvenli ayar rehberidir."),
              ("Sadece Windows sunucularda geçerli olan, üreticinin kapalı kaynaklı güvenlik yazılımı",
               "Yanlış. CIS Benchmarks Linux, Windows, bulut ve daha pek çok sistem için yayımlanır."),
              ("Saldırgan tarafında kullanılan, zayıf parolaları deneyen bir sızma testi aracı",
               "Yanlış. Benchmark savunma rehberidir; parola deneyen araç değildir."),
          ], dogru=0),
          ("Benchmark'ın Türkçesi 'ölçüt/referans'; burada neyin referansı?",
           "Sertleştirme listelerini kim hazırlıyor ve herkese açık mı?",
           "'Neyi nasıl yapılandır' diyen, herkese açık adım adım rehber arıyorsun."),
          puan=20, baslik="CIS Benchmark"),
]


def _kapanis():
    return """
Sertleştirme, saldırganın listesini savunmacının listesine çevirmektir: `sudo -l`, açık servis,
`PermitRootLogin yes`, parolasız sudo, ACCEPT varsayılan politikası. Bu kopyada hepsi vardı ve
bazıları iki ayrı yerde saklanıyordu; saldırgan bunu bilir ve ayarı tek yerde düzeltenleri
sever. Savunma dersi: düzelttiğinden **etkili değeri** doğrula, hiçbir kontrole tek başına
güvenme ve her değişikliği meşru işin devam ettiğini kontrol ederek yap.
"""


SEVIYE = Seviye(
    kimlik="c07b02",
    cilt=7,
    bolum=2,
    baslik="Sistem Sertleştirme",
    brifing="""
Deniz Kara yapılandırma kopyasını masana bırakıyor: "**<<musteri>>**'nin **<<host>>** sunucusu.
<<sahne>> Bu bir kopya; buradaki hatayı gerçek sunucuda yapmamak için burada yaparsın."

Selin ekliyor: "Dört dosya, bir açık servis listesi ve bir güvenlik duvarı kuralı var. Zayıflıkları
bul, dosyaları kendi elinle düzelt. Hatırla: bir ayarı düzeltmek, başka yerde kalan aynı ayarı
düzeltmez."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Mirai 2016:** Bu botnet, internete açık ve **varsayılan parolası değiştirilmemiş** IoT
  cihazlarına (telnet gibi gereksiz açık servisler üzerinden) girdi. Gereksiz servisi kapatmak
  ve varsayılan parolayı değiştirmek, tam da bu bölümün ilk iki ilkesidir.
- **Yanlış yapılandırma:** Capital One 2019 olayında, kamuya açıklanan bilgilere göre bir
  uygulama güvenlik duvarının yanlış yapılandırılması ve aşırı geniş yetkili bir rol, saldırının
  önemli parçalarıydı. Pek çok sızma testi raporunda da en sık görülen bulgular zayıf
  yapılandırmalardır: açık gereksiz servisler, gevşek izinler, aşırı sudo yetkisi.
- **Önleme ve tespit:** Sertleştirmeyi CIS Benchmarks gibi herkese açık rehberlere göre yapmak
  ve kurulum sonrası ayarları düzenli **tarayıp karşılaştırmak** (yapılandırma kayması, drift)
  hem önleme hem tespittir; yetkisiz bir ayar değişikliği alarm üretmelidir.
""",
    sure_hedef_dk=35,
)
