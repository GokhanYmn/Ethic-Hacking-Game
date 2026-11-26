"""Cilt 1 · Bölüm 8 — Sistem Günlükleri: Sunucunun Güncesini Okumak.

Beceri: Linux günlüklerinin nerede durduğunu (`/var/log`), `auth.log` ile `syslog`'un ne
anlattığını, `grep` ve `awk` ile süzmeyi, zaman penceresi seçmeyi ve journald'nin (`journalctl`)
mantığını öğrenmek. Lab'da gerçek journald çağrılmaz; aynı mantık düz metin dosyalarıyla çalışılır.

Vakalar: her tohumda farklı gün, kullanıcılar, saldırgan IP'si, saldırı saati ve hata veren servis.
Gece bir IP parola deneyerek bir hesaba girer; ayrıca günün içinde normal girişler, yazım hatası
kaynaklı birkaç başarısız deneme ve bir servisin hata satırı vardır.
"""
from __future__ import annotations

import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

LOG_KLASORLERI = ["var_log", "gunluk_kopyasi", "sunucu_gunlukleri"]
AYLAR_TR = ["Ocak", "Şubat", "Mart", "Nisan", "Mayıs", "Haziran", "Temmuz", "Ağustos", "Eylül", "Ekim",
            "Kasım", "Aralık"]
SUNUCU_ADLARI = ["srv-web01", "srv-dosya02", "srv-uygulama03", "srv-mail01", "srv-depo01"]
GECERSIZ_ADLAR = ["admin", "test", "oracle", "ubuntu", "postgres", "user", "guest"]
SERVISLER = {
    "nginx": ("[error] connect() failed (111: Connection refused) while connecting to upstream",
              "signal process started"),
    "mysqld": ("ERROR 1040: Too many connections", "ready for connections"),
    "apache2": ("[error] AH00128: File does not exist: /var/www/html/favicon.ico", "caught SIGWINCH, ignoring"),
    "redis-server": ("# Error condition on socket for SYNC: Connection refused", "Ready to accept connections"),
}
DIGER_SERVISLER = {
    "smartd": "Device: /dev/sda, error count increased from 0 to 1",
    "cupsd": "error: Unable to open listen socket for address [::1]:631",
}


def _pid(rng, kullanilan: set) -> int:
    while True:
        p = rng.randint(300, 31000)
        if p not in kullanilan:
            kullanilan.add(p)
            return p


def _saat(t) -> str:
    return f"{t:%H:%M:%S}"


def uret(rng):
    m = musteri_sec(rng)
    log_k = rng.choice(LOG_KLASORLERI)
    host = rng.choice(SUNUCU_ADLARI)
    gun = u.gun(rng)
    kullanilan: set = set()
    isimler = u.isimler(rng, 5)
    hedef, kurban, digerleri = isimler[0], isimler[1], isimler[2:]

    auth: list = []   # (zaman, satir)
    sys_: list = []

    def ssh(t, olay, pid=None):
        auth.append((t, u.ssh_satiri(t, host, pid or _pid(rng, kullanilan), olay)))

    port = lambda: rng.randint(40000, 60999)  # noqa: E731

    # --- normal girişler (gün içi, anahtarla) ---
    ic = {k: u.ic_ip(rng, "192.168.10") for k in isimler}
    ilk = gun + timedelta(hours=8, minutes=rng.randint(0, 40), seconds=rng.randint(0, 59))
    ikinci = gun + timedelta(hours=13, minutes=rng.randint(0, 50), seconds=rng.randint(0, 59))
    hedef_hata = ilk - timedelta(seconds=rng.randint(20, 70))
    ssh(hedef_hata, f"Failed password for {hedef} from {ic[hedef]} port {port()} ssh2")
    for t in (ilk, ikinci):
        pid = _pid(rng, kullanilan)
        ssh(t, f"Accepted publickey for {hedef} from {ic[hedef]} port {port()} ssh2: RSA SHA256:{rng.randint(10**5, 10**6)}abc", pid)
        ssh(t + timedelta(seconds=1), f"pam_unix(sshd:session): session opened for user {hedef}(uid=1001) by (uid=0)", pid)
    for k in digerleri:
        t = gun + timedelta(hours=rng.randint(8, 17), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        pid = _pid(rng, kullanilan)
        ssh(t, f"Accepted publickey for {k} from {ic[k]} port {port()} ssh2: RSA SHA256:{rng.randint(10**5, 10**6)}xyz", pid)
        ssh(t + timedelta(seconds=1), f"pam_unix(sshd:session): session opened for user {k}(uid=1002) by (uid=0)", pid)
    for _ in range(rng.randint(2, 3)):    # yazım hataları
        k = rng.choice(digerleri)
        t = gun + timedelta(hours=rng.randint(9, 16), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        ssh(t, f"Failed password for {k} from {ic[k]} port {port()} ssh2")

    # --- gece saldırısı ---
    saat = rng.randint(2, 4)
    saldirgan = u.dis_ip(rng)
    t = gun + timedelta(hours=saat, minutes=rng.randint(2, 12), seconds=rng.randint(0, 59))
    deneme = rng.randint(26, 38)
    for i in range(deneme):
        t += timedelta(seconds=rng.randint(2, 9))
        if i < deneme - 9:
            ad = rng.choice(GECERSIZ_ADLAR)
            ssh(t, f"Invalid user {ad} from {saldirgan} port {port()}")
            ssh(t, f"Failed password for invalid user {ad} from {saldirgan} port {port()} ssh2")
        else:
            ssh(t, f"Failed password for {kurban} from {saldirgan} port {port()} ssh2")
    t += timedelta(seconds=rng.randint(3, 9))
    basari_t = t
    pid = _pid(rng, kullanilan)
    ssh(t, f"Accepted password for {kurban} from {saldirgan} port {port()} ssh2", pid)
    ssh(t + timedelta(seconds=1), f"pam_unix(sshd:session): session opened for user {kurban}(uid=1003) by (uid=0)", pid)
    sys_.append((t + timedelta(seconds=1),
                 f"{u.syslog_zamani(t + timedelta(seconds=1))} {host} systemd-logind[612]: New session {rng.randint(30, 90)} of user {kurban}."))

    # --- zararsız ikinci dalga (pencere dışı) ---
    ikinci_ip = u.dis_ip(rng)
    while ikinci_ip == saldirgan:
        ikinci_ip = u.dis_ip(rng)
    t2 = gun + timedelta(hours=rng.randint(20, 22), minutes=rng.randint(0, 40), seconds=rng.randint(0, 59))
    for _ in range(rng.randint(3, 7)):
        t2 += timedelta(seconds=rng.randint(5, 25))
        ad = rng.choice(GECERSIZ_ADLAR)
        ssh(t2, f"Failed password for invalid user {ad} from {ikinci_ip} port {port()} ssh2")

    # --- syslog: cron, servisler ---
    for h in range(24):
        tc = gun + timedelta(hours=h, minutes=17)
        sys_.append((tc, f"{u.syslog_zamani(tc)} {host} CRON[{_pid(rng, kullanilan)}]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)"))
    servis = rng.choice(list(SERVISLER))
    hata_msg, bilgi_msg = SERVISLER[servis]
    hata_pid = _pid(rng, kullanilan)
    bilgi_pid = _pid(rng, kullanilan)
    hata_t = gun + timedelta(hours=rng.randint(9, 17), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
    bas_t = gun + timedelta(hours=7, minutes=rng.randint(0, 20), seconds=rng.randint(0, 59))
    sys_.append((bas_t, f"{u.syslog_zamani(bas_t)} {host} systemd[1]: Started {servis}.service."))
    sys_.append((bas_t, f"{u.syslog_zamani(bas_t)} {host} {servis}[{bilgi_pid}]: {bilgi_msg}"))
    sys_.append((hata_t, f"{u.syslog_zamani(hata_t)} {host} {servis}[{hata_pid}]: {hata_msg}"))
    for dsv, dmsg in DIGER_SERVISLER.items():
        td = gun + timedelta(hours=rng.randint(1, 23), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        sys_.append((td, f"{u.syslog_zamani(td)} {host} {dsv}[{_pid(rng, kullanilan)}]: {dmsg}"))
    for _ in range(4):
        td = gun + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
        sys_.append((td, f"{u.syslog_zamani(td)} {host} systemd[1]: Starting Daily apt download activities..."))

    auth.sort(key=lambda x: x[0])
    sys_.sort(key=lambda x: x[0])
    auth_satirlar = [s for _, s in auth]
    sys_satirlar = [s for _, s in sys_]
    toplam_basarisiz = sum("Failed password" in s for s in auth_satirlar)
    pencere = sum(bas <= t_.hour < bas + 1 and "Failed password" in s
                  for bas in (saat,) for t_, s in auth)

    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {host} sistem günlükleri",
        "log_k": log_k,
        "host": host,
        "auth": "\n".join(auth_satirlar) + "\n",
        "syslog": "\n".join(sys_satirlar) + "\n",
        "musteri": m,
        "hata_saat_hedef": _saat(hedef_hata),
        "toplam_basarisiz": toplam_basarisiz,
        "ikinci_ip": ikinci_ip,
        "hata_pid_bilgi": bilgi_pid,
        "metin": {
            "musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "sunucu": m["sunucu"],
            "log_k": log_k, "host": host,
            "tarih": f"{gun.day} {AYLAR_TR[gun.month - 1]} {gun.year}",
            "hedef": hedef, "servis": servis,
            "bas": f"{saat:02d}:00:00", "bit": f"{saat:02d}:59:59",
        },
        "cevaplar": {
            "hedef_saat": _saat(ilk),
            "pencere": pencere,
            "saldirgan_ip": saldirgan,
            "basari_saat": _saat(basari_t),
            "kurban": kurban,
            "hata_pid": hata_pid,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    (lab / s["log_k"]).mkdir(parents=True, exist_ok=True)
    (lab / s["log_k"] / "auth.log").write_text(s["auth"], encoding="utf-8")
    (lab / s["log_k"] / "syslog").write_text(s["syslog"], encoding="utf-8")
    (lab / "OKUBENI.txt").write_text(
        f"Kimden : {m['kisi']} — {m['ad']}\n"
        f"Konu   : {s['host']} günlükleri\n\n"
        f"Sunucudan aldığım /var/log kopyası {s['log_k']}/ klasöründe: auth.log (girişler) ve\n"
        "syslog (genel sistem olayları). Gece bir şey olmuş gibi geliyor; bakar mısınız?\n",
        encoding="utf-8")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: grep/awk ile günlüklerden cevapları çıkarır."""
    au, sy = f"{s['log_k']}/auth.log", f"{s['log_k']}/syslog"
    v = s["metin"]
    hedef_saat = _sh(f"grep 'Accepted' {au} | grep 'for {v['hedef']} ' | head -1 | awk '{{print $3}}'", lab)
    pencere = _sh(f"awk '$3>=\"{v['bas']}\" && $3<=\"{v['bit']}\"' {au} | grep -c 'Failed password'", lab)
    ip = _sh(f"grep 'Failed password' {au} | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -1 | awk '{{print $3}}'", lab)
    basari = _sh(f"grep 'Accepted password' {au} | awk '{{print $3}}'", lab)
    kurban = _sh(f"grep 'Accepted password' {au} | awk '{{print $9}}'", lab)
    pid = _sh(f"grep '{v['servis']}\\[' {sy} | grep -i error | grep -oE '\\[[0-9]+\\]' | tr -d '[]'", lab)
    return {1: hedef_saat, 2: pencere, 3: ip, 4: basari, 5: kurban, 6: pid}


# ---------------------------------------------------------------- sık hata geri bildirimleri

def _hedef_hata(g, beklenen, b):
    if g == b.senaryo["hata_saat_hedef"]:
        return ("Bu saat kullanıcının yazım hatasıyla yaptığı başarısız denemeye ait. Girişin saati, "
                "`Accepted` satırındadır.")
    return None


def _pencere_hata(g, beklenen, b):
    if int(g) == b.senaryo["toplam_basarisiz"]:
        return "Bu bütün gün boyunca olan başarısız denemelerin toplamı. Sadece verilen saat penceresini say."
    return None


def _ip_hata(ip, beklenen, b):
    if ip == b.senaryo["ikinci_ip"]:
        return "Bu IP de başarısız denemeler yapmış ama çok az. En çok deneyen IP'yi bul: `sort | uniq -c | sort -rn`."
    return None


def _basari_hata(g, beklenen, b):
    return None


def _pid_hata(g, beklenen, b):
    if int(g) == b.senaryo["hata_pid_bilgi"]:
        return "Bu PID servisin normal başlangıç satırına ait. `error` geçen satırdaki PID'yi ara."
    return None


ADIMLAR = [
    Adim("Günlükler nerede?", """
Linux, olan biteni **günlük** (log) dosyalarına yazar. Bunlar geleneksel olarak `/var/log`
klasöründe durur. En önemli ikisi:

- `auth.log` (bazı dağıtımlarda `secure`): girişler, `sudo`, parola denemeleri
- `syslog` (bazı dağıtımlarda `messages`): genel sistem ve servis olayları

Laboratuvarındaki `<<log_k>>/` klasörü, `<<host>>` sunucusunun `/var/log` kopyasıdır.
Analiz hep kopya üzerinde yapılır; asıl günlükler kanıttır.
""", komut="ls -l <<log_k>>"),
    Adim("Bir günlük satırının anatomisi", """
Her satır aynı kalıpla başlar:

```
Nov 26 03:12:44 srv-web01 sshd[2411]: Failed password for admin from 203.0.113.9 port 51234 ssh2
```

- `Nov 26 03:12:44` olayın zamanı (3. alan saat bilgisidir: `SS:DD:SS`)
- `srv-web01` kaydı yazan makine
- `sshd[2411]` kaydı yazan program ve **PID**'i (süreç numarası)
- iki noktadan sonrası olayın kendisi

Bu düzen sayesinde `awk` ile alan seçmek çok kolaydır. İlk beş satıra bak:
""", komut="head -n 5 <<log_k>>/auth.log"),
    Adim("grep ile süzmek", """
Günlükler binlerce satırdır; sen sadece ilgilendiğin olayı istersin. `sshd` iki sözcük bilir:
`Accepted` (giriş başarılı) ve `Failed password` (başarısız). Kaç başarısız deneme var?
""", komut="grep -c \"Failed password\" <<log_k>>/auth.log", sonra="""
Süzmeleri art arda bağlayabilirsin: `grep Accepted dosya | grep 'for ali '` ali'nin başarılı
girişlerini verir. Gerçek hayatta aynı iş için `journalctl` kullanırsın; aşağıda görecek.
"""),
    Adim("awk ile zaman penceresi", """
Olay müdahalesinde ilk soru "ne zaman?"dır. Bir zaman penceresi seçmek için 3. alana (saat)
`awk` ile karşılaştırma koyabilirsin. Saatler `SS:DD:SS` biçiminde olduğu için metin olarak
doğru sıralanır. Sabah 08:00 ile 09:59 arasındaki satırlar:
""", komut="awk '$3>=\"08:00:00\" && $3<=\"09:59:59\"' <<log_k>>/auth.log | head -n 5", sonra="""
Aynı yöntemle `awk '{print $3}'` sadece saatleri, `awk '{print $9}'` 9. alanı (çoğu giriş
satırında kullanıcı adı) yazar. Dikkat: alanları saymak için önce bir satırı gözünle sına.
"""),
    Adim("journald: günlüğün modern hâli", """
Modern Linux'larda `systemd-journald` günlükleri **ikili (binary)** bir veritabanında tutar ve
`journalctl` ile okunur. Mantık aynıdır, sadece süzme daha kolaydır:

- `journalctl -u nginx` yalnızca nginx servisinin kayıtları
- `journalctl --since "03:00" --until "04:00"` zaman penceresi
- `journalctl -p err` yalnızca hata ve daha ciddi kayıtlar

Laboratuvarda gerçek journald yok; onun dosya karşılığını kullanıyoruz. `journalctl -p err`
yerine hata içeren syslog satırlarını süzelim:
""", komut="grep -i error <<log_k>>/syslog", sonra="""
Gördüğün gibi `grep -i` büyük-küçük harfe bakmaz. Hangi servis, hangi PID'yle hata vermiş?
Bu bilgi bir arızayı ya da bir saldırıyı sonradan açıklamak için çoğu zaman tek ipucudur.
"""),
]

GOREVLER = [
    Gorev("<<kisi>> (<<musteri>>) şunu soruyor: `<<hedef>>` kullanıcısı bugün sunucuya **ilk kez** hangi saatte "
          "başarıyla girdi? (SS:DD:SS)",
          Metin("hedef_saat", on_ekleri_at=("saat",), sik_hatalar=_hedef_hata, bicim="SS:DD:SS"),
          ("Başarılı girişler `Accepted` kelimesiyle işaretlenir. Başarısız denemeler sayılmaz.",
           "`grep Accepted` ile süz, sonra `grep 'for <<hedef>> '` ile kullanıcıyı seç; ilk satır, 3. alan saattir.",
           "`grep Accepted <<log_k>>/auth.log | grep 'for <<hedef>> ' | head -1 | awk '{print $3}'`"),
          puan=25, baslik="İlk giriş"),
    Gorev("Gece <<bas>> ile <<bit>> arasında `auth.log`'da kaç **Failed password** satırı var?",
          Sayi("pencere", sik_hatalar=_pencere_hata),
          ("Önce saat penceresini seç (3. alan), sonra başarısız denemeleri say.",
           "`awk '$3>=\"<<bas>>\" && $3<=\"<<bit>>\"' dosya` pencereyi verir; çıktıyı `grep -c` ile say.",
           "`awk '$3>=\"<<bas>>\" && $3<=\"<<bit>>\"' <<log_k>>/auth.log | grep -c 'Failed password'`"),
          puan=35, baslik="Zaman penceresi"),
    Gorev("En çok başarısız parola denemesi yapan IP adresi hangisi?",
          IP("saldirgan_ip", sik_hatalar=_ip_hata),
          ("Başarısız denemeler `Failed password` satırlarıdır; IP `from` sözcüğünden sonra gelir.",
           "`grep -oE 'from [0-9.]+'` ile IP'leri çıkar; `sort | uniq -c | sort -rn` ile say.",
           "`grep 'Failed password' <<log_k>>/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -3`"),
          puan=30, baslik="Saldırının kaynağı"),
    Gorev("Bu IP sonunda **parolayla** bir hesaba girmeyi başardı. Başarılı girişin saati nedir? (SS:DD:SS)",
          Metin("basari_saat", on_ekleri_at=("saat",), sik_hatalar=_basari_hata, bicim="SS:DD:SS"),
          ("Meşru kullanıcılar bu sunucuya anahtarla girer (`publickey`). Parolayla girişi arayın.",
           "`grep 'Accepted password'` tek bir satır döndürmeli; 3. alan saattir.",
           "`grep 'Accepted password' <<log_k>>/auth.log | awk '{print $3}'`"),
          puan=30, baslik="Kapı açıldı"),
    Gorev("Saldırgan hangi **hesaba** girdi? (kullanıcı adı)",
          Metin("kurban", bicim="kullanıcı adı"),
          ("Aynı `Accepted password` satırında hesap adı da yazar.",
           "Satırı alanlara böl: `for` sözcüğünden sonraki alan kullanıcıdır (9. alan).",
           "`grep 'Accepted password' <<log_k>>/auth.log | awk '{print $9}'`"),
          puan=25, baslik="Ele geçen hesap"),
    Gorev("`syslog`'da **<<servis>>** servisi bir **error** satırı yazmış. Bu satırdaki PID (köşeli parantez "
          "içindeki süreç numarası) nedir?",
          Sayi("hata_pid", sik_hatalar=_pid_hata),
          ("Önce servisin satırlarını süz; hepsinde bir PID var ama biri hata satırı.",
           "`grep '<<servis>>\\['` servisin satırlarını verir; ondan sonra `grep -i error` ile hatayı seç.",
           "`grep '<<servis>>\\[' <<log_k>>/syslog | grep -i error` — köşeli parantezin içindeki sayı."),
          puan=30, baslik="Hatalı servis"),
]


SEVIYE = Seviye(
    kimlik="c01b08",
    cilt=1,
    bolum=8,
    baslik="Sistem Günlükleri",
    brifing="""
**<<musteri>>**'den <<kisi>> arıyor: "<<tarih>> gecesi <<host>> sunucusunda bir şeyler oldu gibi.
Sabah baktığımızda <<hedef>> bir şey fark etti. Günlüklerin kopyasını size bıraktım."

Selin dosyaları gösteriyor: "İki dosya var: `auth.log` kimin girdiğini, `syslog` sistemin ne
yaptığını anlatır. Sunucunun güncesini okuyabilen, geçmişi yeniden kurabilir."

Deniz ekliyor: "Önce zamana bak. 'Ne zaman?' sorusunu cevaplayınca gerisi dizilir."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Saldırgan için bu bölümün dersi: her başarısız parola `auth.log`'a satır olarak düşer; gece 3'te
yapılan 30 deneme sabah tek bir `uniq -c` ile ortaya çıkar. Savunmacı için ders: günlükler ancak
**tutulur, korunur ve okunursa** işe yarar. Başarısız girişlere eşik koy (fail2ban gibi),
günlükleri başka bir makineye de gönder ve parola yerine anahtarla girişi zorunlu kıl.
""",
    gercek_hayat="""
- **SolarWinds (2020):** Saldırganlar aylarca içerideydi; müdahale ekipleri neyin, ne zaman, hangi
  hesapla yapıldığını büyük ölçüde günlük kayıtlarını zaman sırasına dizerek çözdü. Kayıtları
  yeterince uzun tutan kurumlar etkilerini daha çabuk ölçebildi.
- **Günlük silme:** Saldırganların ilk işlerinden biri çoğu zaman `/var/log` içini temizlemektir.
  Bu yüzden olgun kurumlar günlükleri ayrı bir günlük sunucusuna ya da SIEM'e anında kopyalar.
- **Fail2ban ve SIEM:** `Failed password` satırlarını sayıp eşiği aşan IP'yi engelleyen araçlar,
  bu bölümde elle yaptığın `grep | uniq -c` işinin otomatik hâlidir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=False,
    on_kosul=("c01b07",),
)
