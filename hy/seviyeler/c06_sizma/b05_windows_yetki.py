"""Cilt 6 · Bölüm 5 — Windows Yetki Yükseltme (genel bakış, artefakt okuma).

Beceri: kurgusal `whoami /priv`, servis yapılandırması, klasör izinleri (icacls) ve zamanlanmış görev
çıktılarını okuyup riskli yetki/yapılandırmayı tanımak ve düzeltme önerisini uygulamak.

Hiçbir istismar yöntemi ya da araç komutu yoktur. Çıktılar metin dosyasıdır; Kali'de `cat`, `grep`, `awk`
ile okunur. Mantık Linux'takiyle aynıdır: yanlış yapılandırmayı bul, kapat.
"""
from __future__ import annotations

from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c06_sizma._ortak import sh

VAKALAR = [
    {"kod": "ferahbank", "alan": "FERAH", "kul": "sube.kasiyer", "ayar": "FerahYedekAjan",
     "ayar_yol": "C:\\Program Files\\Ferah Yedek\\bin\\ajan.exe", "servis": "KurSenkron",
     "klasor": "C:\\Isler\\KurSenk", "exe": "kurservis.exe", "gorev": "GunSonuTemizle",
     "gorev_klasor": "C:\\Araclar", "betik": "gunsonu.bat", "pc": "FB-SUBE02-PC",
     "olay": "Şube bilgisayarlarında 'tek yönetici hesabı her yerde' alışkanlığı var; sızma testi sonrası kontrol isteniyor."},
    {"kod": "yesiltepe", "alan": "YESILTEPE", "kul": "tahsilat1", "ayar": "BelediyeYazdir",
     "ayar_yol": "C:\\Program Files\\Belediye Yazici\\yazdir.exe", "servis": "MeclisYayin",
     "klasor": "C:\\Uygulamalar\\Meclis", "exe": "yayin.exe", "gorev": "GeceYedegi",
     "gorev_klasor": "C:\\Betikler", "betik": "yedek.cmd", "pc": "YTB-TAHSILAT-PC",
     "olay": "Belediyenin tahsilat ofisindeki bilgisayarlarının güvenlik denetimi yapılıyor."},
    {"kod": "medora", "alan": "MEDORA", "kul": "hemsire01", "ayar": "PacsYedek",
     "ayar_yol": "C:\\Program Files\\Pacs Arsiv\\yedek.exe", "servis": "LabAkis",
     "klasor": "C:\\Hizmetler\\LabAkis", "exe": "labakis.exe", "gorev": "RaporTemizle",
     "gorev_klasor": "C:\\Ortak", "betik": "temizle.bat", "pc": "MEDORA-SERVIS-PC",
     "olay": "Hastane servisindeki ortak bilgisayarlarda hemşire hesaplarının yetkileri inceleniyor."},
]
RISKLI_YETKI = [
    ("SeDebugPrivilege", "Debug programs"),
    ("SeLoadDriverPrivilege", "Load and unload device drivers"),
    ("SeTakeOwnershipPrivilege", "Take ownership of files or other objects"),
    ("SeBackupPrivilege", "Back up files and directories"),
]
YAZMA_HESAPLARI = ("BUILTIN\\Users", "Everyone")


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    risk, risk_acik = rng.choice(RISKLI_YETKI)
    hesap_servis = rng.choice(YAZMA_HESAPLARI)
    hesap_gorev = rng.choice([x for x in YAZMA_HESAPLARI if x != hesap_servis] + [hesap_servis])
    gun = u.gun(rng)
    sure = rng.choice(["03:00", "02:30", "23:45", "01:15"])
    return {
        "vaka": f"{m['ad']} — {v['pc']} Windows denetimi",
        "musteri": m, "v": v, "risk": risk, "risk_acik": risk_acik, "hesap_servis": hesap_servis,
        "hesap_gorev": hesap_gorev, "gun": gun, "sure": sure,
        "brifing": f"""
Deniz Kara bir çıktı klasörünü masana bırakıyor: "**{m['ad']}**'in **{v['pc']}** bilgisayarından yetkili
bir arkadaşımız `whoami /priv`, servis, klasör izni ve zamanlanmış görev çıktılarını aldı. {v['olay']}
Windows makinesine dokunmuyoruz; sadece **çıktıları okuyoruz**."

Selin ekliyor: "Linux'ta yaptığın işin aynısı: kim ne yetkiyle çalışıyor, onu kim değiştirebiliyor? Sadece
komut adları farklı. `{v['kul']}` hesabı ele geçirilirse nereye kadar yükselebileceğini bul ve öner."
""",
        "metin": {"musteri": m["ad"], "pc": v["pc"], "kul": v["kul"], "alan": v["alan"]},
        "cevaplar": {
            "risk": risk,
            "ayar": v["ayar"],
            "servis": v["servis"],
            "gorev": v["gorev"],
        },
    }


def _ayarlar(s: dict):
    v = s["v"]
    return [
        ("Spooler", "C:\\Windows\\System32\\spoolsv.exe", "LocalSystem", "AUTO_START"),
        ("W32Time", "C:\\Windows\\System32\\w32tm.exe", "NT AUTHORITY\\LocalService", "DEMAND_START"),
        (v["ayar"], v["ayar_yol"], "LocalSystem", "AUTO_START"),
        ("RaporMotoru", "\"C:\\Program Files\\Rapor Motoru\\rapor.exe\"", "LocalSystem", "AUTO_START"),
        ("YerelDestek", "C:\\Destek\\ajan.exe", "NT AUTHORITY\\LocalService", "AUTO_START"),
        (v["servis"], f"{v['klasor']}\\{v['exe']}", "LocalSystem", "AUTO_START"),
        ("Dnscache", "C:\\Windows\\System32\\dnsapi.exe", "NT AUTHORITY\\NetworkService", "AUTO_START"),
    ]


def _servis_dosyasi(s: dict) -> str:
    satir = ["# SERVIS_ADI|BINARY_PATH_NAME|START_NAME|START_TYPE   (sc qc benzeri, kurgusal)"]
    satir += ["|".join(x) for x in _ayarlar(s)]
    return "\n".join(satir) + "\n"


def _acl_dosyasi(s: dict) -> str:
    v = s["v"]
    bloklar = []
    bloklar.append(f"{v['klasor']}\n"
                   f"        {s['hesap_servis']}:(OI)(CI)(M)\n"
                   "        BUILTIN\\Administrators:(OI)(CI)(F)\n"
                   "        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n")
    bloklar.append("C:\\Program Files\\Rapor Motoru\n"
                   "        BUILTIN\\Users:(OI)(CI)(RX)\n"
                   "        BUILTIN\\Administrators:(OI)(CI)(F)\n"
                   "        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n")
    bloklar.append(f"{v['gorev_klasor']}\n"
                   f"        {s['hesap_gorev']}:(OI)(CI)(F)\n"
                   "        BUILTIN\\Administrators:(OI)(CI)(F)\n"
                   "        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n")
    bloklar.append("C:\\Windows\\System32\\Tasks\\Bakim\n"
                   "        BUILTIN\\Users:(OI)(CI)(RX)\n"
                   "        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n")
    bloklar.append("C:\\Program Files\\Ortak Araclar\n"
                   "        BUILTIN\\Users:(OI)(CI)(RX)\n"
                   "        BUILTIN\\Administrators:(OI)(CI)(F)\n")
    return "\n".join(bloklar)


def _gorev_dosyasi(s: dict) -> str:
    v = s["v"]
    return ("# KUR|GOREV_ADI|CALISACAK_GOREV|CALISTIRAN_KULLANICI|ZAMANLAMA   (schtasks benzeri, kurgusal)\n"
            "GOREV|\\Microsoft\\Windows\\Defrag|C:\\Windows\\System32\\defrag.exe|SYSTEM|Haftalık\n"
            f"GOREV|\\{v['gorev']}|{v['gorev_klasor']}\\{v['betik']}|SYSTEM|Her gün {s['sure']}\n"
            f"GOREV|\\KullaniciTemizlik|{v['gorev_klasor']}\\temp_temizle.cmd|{v['alan']}\\{v['kul']}|Her gün 18:00\n"
            "GOREV|\\RaporArsivi|C:\\Program Files\\Rapor Motoru\\arsivle.exe|SYSTEM|Her hafta Pazar 04:00\n")


def _priv_dosyasi(s: dict) -> str:
    v = s["v"]
    return (f"KULLANICI: {v['alan']}\\{v['kul']}   (sıradan kullanıcı, yönetici değil)\n"
            f"BILGISAYAR: {v['pc']}\n\n"
            "PRIVILEGES INFORMATION\n"
            "----------------------\n\n"
            "Privilege Name                Description                          State\n"
            "============================= ==================================== ========\n"
            "SeShutdownPrivilege           Shut down the system                 Disabled\n"
            "SeChangeNotifyPrivilege       Bypass traverse checking             Enabled\n"
            f"{s['risk']:<29} {s['risk_acik']:<36} Enabled\n"
            "SeUndockPrivilege             Remove computer from docking station Disabled\n"
            "SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled\n"
            "SeTimeZonePrivilege           Change the time zone                 Disabled\n")


def yaz(lab: Path, s: dict) -> None:
    m = s["musteri"]
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} · {v['pc']} Windows çıktıları (KURGUSAL, metin dosyası).\n"
          "kopya_win/whoami_priv.txt          : `whoami /priv` çıktısı\n"
          "kopya_win/servisler.txt            : servis yapılandırması (sc qc benzeri)\n"
          "kopya_win/icacls_cikti.txt         : klasör izinleri (icacls benzeri)\n"
          "kopya_win/zamanlanmis_gorevler.txt : zamanlanmış görevler (schtasks benzeri)\n")
    u.yaz(lab / "kopya_win" / "whoami_priv.txt", _priv_dosyasi(s))
    u.yaz(lab / "kopya_win" / "servisler.txt", _servis_dosyasi(s))
    u.yaz(lab / "kopya_win" / "icacls_cikti.txt", _acl_dosyasi(s))
    u.yaz(lab / "kopya_win" / "zamanlanmis_gorevler.txt", _gorev_dosyasi(s))


def _bloklar(yol: Path) -> dict:
    """icacls dosyasını {klasör: [ACL satırları]} sözlüğüne çevirir."""
    sonuc, aktif = {}, None
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for x in satirlar:
        if not x.strip():
            aktif = None
        elif not x.startswith((" ", "\t")):
            aktif = x.strip()
            sonuc[aktif] = []
        elif aktif is not None:
            sonuc[aktif].append(x.strip())
    return sonuc


def _yazma_var(acl: list) -> list:
    return [a for a in acl if a.startswith(YAZMA_HESAPLARI + ("NT AUTHORITY\\Authenticated Users",))
            and any(f"({x})" in a for x in ("M", "F", "W"))]


def _tirnak_duzeldi(b) -> Sonuc:
    v = b.senaryo["v"]
    yol = b.lab / "kopya_win" / "servisler.txt"
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except OSError:
        return Sonuc(False, "servisler.txt yok.")
    for x in satirlar:
        p = x.split("|")
        if p[0] == v["ayar"]:
            if len(p) < 4:
                return Sonuc(False, "Satırın alan yapısı bozulmuş; dört alan (`|` ile ayrılmış) olmalı.")
            if p[1] == f"\"{v['ayar_yol']}\"":
                return Sonuc(True, "Yol tırnak içine alındı. Windows'ta bunu `sc config` ile yapardın; "
                                   "yol tırnaklıysa boşluklu parçalar program adı sanılmaz.")
            if p[1].startswith("\"") and p[1].endswith("\""):
                return Sonuc(False, "Tırnak koymuşsun ama yol değişmiş görünüyor; özgün yolu olduğu gibi tırnağa al.", yakin=True)
            return Sonuc(False, "Yol hâlâ tırnaksız. Yolun **tamamını** çift tırnak içine al.")
    return Sonuc(False, f"{v['ayar']} satırı bulunamadı; satırı silmek çözüm değil.")


def _acl_duzeldi(b) -> Sonuc:
    v = b.senaryo["v"]
    bloklar = _bloklar(b.lab / "kopya_win" / "icacls_cikti.txt")
    for klasor in (v["klasor"], v["gorev_klasor"]):
        if klasor not in bloklar:
            return Sonuc(False, f"`{klasor}` bloğu silinmiş. Bloğu silmek yerine yalnızca fazla izin satırını çıkar.")
        acl = bloklar[klasor]
        kalan = _yazma_var(acl)
        if kalan:
            return Sonuc(False, f"`{klasor}` içinde hâlâ geniş yazma izni var: `{kalan[0]}`. Sıradan kullanıcılar "
                                "için okuma/çalıştırma (RX) yeter.")
        if not any(a.startswith("NT AUTHORITY\\SYSTEM") for a in acl):
            return Sonuc(False, f"`{klasor}` bloğundan SYSTEM satırını da silmişsin; servis çalışamaz. "
                                "Yalnızca geniş yazma iznini kaldır.", yakin=True)
    return Sonuc(True, "Artık bu iki klasöre yalnız yöneticiler ve SYSTEM yazabiliyor. Gerçek sistemde "
                       "`icacls` ile miras ve sahiplik de gözden geçirilir.")


def coz(lab: Path, s: dict) -> dict:
    from hy.motor.kontrol import Baglam
    v = s["v"]
    risk = sh(r"""awk '/Enabled/ && $1!="SeChangeNotifyPrivilege" {print $1}' kopya_win/whoami_priv.txt""", lab)
    ayar = sh(r"""awk -F'|' '/^#/{next} $2 !~ /^"/ && $2 ~ / / && $2 !~ /^C:\Windows/ {print $1}' kopya_win/servisler.txt""", lab)
    yazilabilir = (r"""awk '/^[A-Za-z]:/{d=$0} (/Everyone/||/Users/) && (/\(M\)/||/\(F\)/||/\(W\)/){print d}' """
                   "kopya_win/icacls_cikti.txt")
    servis = sh(yazilabilir + r""" | while read -r d; do D="$d" awk -F'|' '/^#/{next} index($2,ENVIRON["D"] "\\")==1{print $1}' kopya_win/servisler.txt; done""", lab)
    gorev = sh(yazilabilir + r""" | while read -r d; do D="$d" awk -F'|' '/^#/{next} $4=="SYSTEM" && index($3,ENVIRON["D"] "\\")==1{print $2}' kopya_win/zamanlanmis_gorevler.txt; done""", lab)
    gorev = gorev.lstrip("\\")
    sec = {n: SEVIYE.gorevler[n - 1].kontrol.cevabi_goster(Baglam(s, lab, n))[0] for n in (5, 6)}
    # Düzelt: servis yolunu tırnakla, yazma izinlerini kaldır
    sh("S='" + v["ayar"] + r"""' awk -F'|' -v OFS='|' '$1==ENVIRON["S"]{$2="\"" $2 "\""}1' kopya_win/servisler.txt > kopya_win/.t """
       "&& mv kopya_win/.t kopya_win/servisler.txt", lab)
    sh(r"""grep -v -E '^ +(Everyone|BUILTIN.Users):\(OI\)\(CI\)\((M|F)\)$' kopya_win/icacls_cikti.txt > kopya_win/.t """
       "&& mv kopya_win/.t kopya_win/icacls_cikti.txt", lab)
    return {1: risk, 2: ayar, 3: servis, 4: gorev, 5: sec[5], 6: sec[6], 7: "", 8: ""}


def _risk_hata(g, beklenen, b):
    if g == "sechangenotifyprivilege":
        return ("`SeChangeNotifyPrivilege` her kullanıcıda varsayılan olarak açıktır (klasörlerde dolaşmak için). "
                "Sıradan bir hesapta alışılmadık olanı ara.")
    if g in ("seshutdownprivilege", "seundockprivilege", "seincreaseworkingsetprivilege", "setimezoneprivilege"):
        return "Bu yetki kapalı (`Disabled`) ya da zararsız. `State` sütununda `Enabled` olanlara bak."
    return None


ADIMLAR = [
    Adim("Linux'tan Windows'a", """
Windows'ta da yetki yükseltmenin mantığı aynıdır: **yanlış yapılandırmayı bul**. Sadece komutlar farklı:

| Linux | Windows |
|---|---|
| `id`, `sudo -l` | `whoami /priv`, `whoami /groups` |
| SUID dosyaları | servis izinleri, tırnaksız servis yolu |
| `cron` | Zamanlanmış Görevler (Task Scheduler) |
| `linpeas` | `winPEAS` |

Elimizde bir Windows makinesinden alınmış, **kurgusal** çıktılar var. Bunlar metin olduğu için Kali'de
`cat` ve `grep` ile okunur. Önce klasöre bak:
""", komut="cat OKUBENI.txt"),
    Adim("whoami /priv: ayrıcalıklar", """
Windows'ta bir hesabın **ayrıcalıkları (privileges)** vardır: sistem genelinde belli işleri yapabilme hakkı.
`whoami /priv` bunları ve durumunu (`Enabled` açık, `Disabled` kapalı) listeler. Bu, Linux'taki `id` ve
`sudo -l`'e benzer.
""", komut="cat kopya_win/whoami_priv.txt", sonra="""
Sıradan bir kullanıcıda birkaç zararsız ayrıcalık olur (örneğin klasörlerde dolaşmak için `SeChangeNotifyPrivilege`).
**Yönetici düzeyinde sayılan** bir ayrıcalığın sıradan bir hesapta `Enabled` görünmesi alarm işaretidir.
"""),
    Adim("Hangi ayrıcalıklar dikkat çekicidir?", """
Bazı ayrıcalıklar doğrudan yönetici işlerine denktir:

- `SeDebugPrivilege`: başka süreçleri inceleme/değiştirme.
- `SeLoadDriverPrivilege`: sürücü yükleme (sistem çekirdeğine dokunur).
- `SeTakeOwnershipPrivilege`: herhangi bir dosyanın sahipliğini alma.
- `SeBackupPrivilege`: izinleri aşarak her dosyayı okuyabilme.
- `SeImpersonatePrivilege`: başka bir hesabın kimliğine bürünebilme. IIS ve SQL gibi **servis hesaplarında**
  varsayılan olarak bulunur ve ele geçirilen bir servis hesabının daha yüksek yetkiye çıkabilmesinin
  bilinen yollarından birinin dayanağıdır. Savunma: servisi gereğinden yüksek yetkili hesapla çalıştırma,
  yamaları güncel tut.
""", komut="grep Enabled kopya_win/whoami_priv.txt", sonra="""
Listede `SeChangeNotifyPrivilege` meşru. Diğer `Enabled` satırı ise sıradan bir kullanıcıya hiç yakışmıyor.
"""),
    Adim("Servis yapılandırması", """
Windows servisleri bir **programı** bir **hesapla** çalıştırır; çoğu `LocalSystem` (en yüksek yerel hesap)
ile çalışır. `sc qc` bir servisin hangi dosyayı ve hangi hesapla çalıştırdığını gösterir. Kurgusal dökümde:
""", komut="cat kopya_win/servisler.txt", sonra="""
İkinci alan **BINARY_PATH_NAME**: servisin çalıştırdığı dosya. Üçüncü alan: hangi hesapla. **SYSTEM yetkisiyle
çalışan** bir dosyayı ya da onun klasörünü sıradan bir kullanıcı değiştirebiliyorsa, bu doğrudan yetki
yükseltmedir (Linux'taki yazılabilir cron betiğiyle aynı mantık).
"""),
    Adim("Tırnaksız servis yolu", """
Yolunda **boşluk** bulunan ve **çift tırnak içine alınmamış** bir servis yolu (örneğin `C:\\Program Files\\...`)
sorunludur: Windows tırnaksız yolu yorumlarken boşluklardan sonraki parçaları da olası program adı olarak
değerlendirir. Yol üzerindeki bir klasör sıradan kullanıcıya açıksa bu bir risktir. Çözüm basit: **yolu
tırnak içine almak**.

Yolunda boşluk olanlara bakalım:
""", komut="awk -F'|' '$2 ~ / /' kopya_win/servisler.txt", sonra="""
Bunların bir kısmı zaten tırnaklı (güvenli). Tırnaksız olanı görevlerde bulacaksın. Yolda boşluk yoksa
tırnaksızlık bir sorun değildir; Windows klasöründeki varsayılan servisler de bu sebeple elenir.
"""),
    Adim("Klasör izinleri (icacls)", """
`icacls` bir klasörün **kimin ne yetkisi olduğunu** gösterir. Kısaltmalar: `(F)` tam denetim, `(M)` değiştirme
(yazma dahil), `(RX)` okuma ve çalıştırma. `BUILTIN\\Users` bilgisayardaki **tüm sıradan kullanıcılar**,
`Everyone` herkes demektir.
""", komut="cat kopya_win/icacls_cikti.txt", sonra="""
`Users`/`Everyone` için `(M)` veya `(F)` görürsen, o klasöre sıradan herkes dosya yazabilir. Bu klasördeki dosyayı
bir **servis** ya da **zamanlanmış görev** SYSTEM yetkisiyle çalıştırıyorsa, kapı açıktır.
"""),
    Adim("Zamanlanmış görevler", """
Zamanlanmış görev, Linux cron'unun Windows karşılığıdır. Önemli iki sütun: hangi dosyayı çalıştırıyor ve
**hangi kullanıcıyla**. `SYSTEM` ile çalışan görev en değerli hedeftir.
""", komut="cat kopya_win/zamanlanmis_gorevler.txt", sonra="""
Dört görevden biri yönetici olmayan bir hesapla çalışıyor, ikisi güvenli klasörlerde. Birinin dosyası ise
bir önceki adımda gördüğün **yazılabilir klasörlerden birinde** duruyor.
"""),
    Adim("Düzeltme ve LAPS", """
Bu bölümdeki düzeltmeler tek ilkeye dayanır: **en az yetki**.

- Servis yollarını tırnak içine al.
- Servis ve görev klasörlerinde sıradan kullanıcılara yalnızca okuma/çalıştırma (RX) ver; yazmayı yöneticilere bırak.
- Sıradan hesaplardan yönetici düzeyi ayrıcalıkları kaldır.
- Her bilgisayarda aynı yerel yönetici parolası kullanma; Microsoft **LAPS** ile her makineye benzersiz,
  otomatik değişen parola ver (Bölüm 6'da neden önemli olduğunu göreceksin).

Kaç görev SYSTEM ile çalışıyor?
""", komut="grep -c SYSTEM kopya_win/zamanlanmis_gorevler.txt"),
]

GOREVLER = [
    Gorev("`kopya_win/whoami_priv.txt` içinde sıradan `<<kul>>` hesabında **açık (`Enabled`) ve "
          "olağan dışı** olan ayrıcalığın adı nedir?",
          Metin("risk", sik_hatalar=_risk_hata, bicim="Se...Privilege adı"),
          ("State sütununa bak: Enabled olanlar etkin. Birinin sıradan kullanıcıda işi yok.",
           "`SeChangeNotifyPrivilege` her kullanıcıda açık gelir; onu saymayabilirsin.",
           "`grep Enabled kopya_win/whoami_priv.txt` iki satır verir; birinde `Bypass traverse checking` yazıyor."),
          puan=20, baslik="Riskli ayrıcalık"),
    Gorev("`kopya_win/servisler.txt` içinde yolu **boşluk içeren ama tırnak içine alınmamış** servisin "
          "adı nedir? (`C:\\Windows` altındakiler hariç.)",
          Metin("ayar", bicim="servis adı"),
          ("İkinci alan servisin çalıştırdığı dosyanın yolu. İki koşul birden: boşluk var, tırnak yok.",
           "`awk -F'|' '$2 ~ / /'` boşluklu yolları listeler; bunların bir kısmı tırnaklı.",
           "Boşluklu yolların içinde `\"` ile başlamayanı seç."),
          puan=25, baslik="Tırnaksız yol"),
    Gorev("`kopya_win/icacls_cikti.txt` içinde `Users` ya da `Everyone` için **yazma yetkisi** "
          "(`(M)` veya `(F)`) verilmiş klasörlerden hangisinin içindeki dosyayı bir **servis** "
          "çalıştırıyor? O servisin adı nedir?",
          Metin("servis", bicim="servis adı"),
          ("Önce `icacls_cikti.txt` içinde Users/Everyone satırlarında `(M)` ya da `(F)` ara; sonra o klasörün adıyla `servisler.txt`'de ara.",
           "`grep -B1 -E 'Users|Everyone' kopya_win/icacls_cikti.txt` klasör adını da gösterir (başka klasörler de çıkabilir).",
           "Çıkan klasörlerden hangisinin yolu, `servisler.txt`'de bir servisin dosya yolunun başında geçiyor?"),
          puan=30, baslik="Yazılabilir servis klasörü"),
    Gorev("`kopya_win/zamanlanmis_gorevler.txt` içinde **SYSTEM** ile çalışan ve dosyası "
          "**herkesin yazabildiği bir klasörde** duran görevin adı nedir? (Başındaki `\\` işaretini yazmasan da olur.)",
          Metin("gorev", on_ekleri_at=("\\",), bicim="görev adı"),
          ("Aynı klasör listesini görevlerin dosya yollarıyla karşılaştır; ayrıca kullanıcı sütununa bak.",
           "Dört görevden biri SYSTEM değil; ikisi SYSTEM ama güvenli klasörlerde.",
           "Yazılabilir klasörlerden biri `Betikler`/`Araclar`/`Ortak` gibi bir ad taşıyor; görevlerin dosya yolunda geçeni bul."),
          puan=30, baslik="Riskli zamanlanmış görev"),
    Gorev("SYSTEM ile çalışan bir görevin ya da servisin **dosyasının klasörüne sıradan kullanıcıların "
          "yazabilmesi** neden tehlikelidir?",
          Secmeli([
              ("Dosyayı değiştiren, onu SYSTEM yetkisiyle çalıştırtmış olur",
               "Doğru. Dosyayı kim değiştirirse, bir sonraki çalışmada SYSTEM yetkisiyle yürür. Linux'taki yazılabilir cron betiğiyle aynı mantık."),
              ("Klasör dolar ve disk kotası aşıldığı için sistem servisleri durur",
               "Disk dolması bir hizmet sorunu olabilir ama yetki yükseltme değildir."),
              ("Windows, yazılabilir klasördeki dosyaları otomatik silerek güvenliği korur",
               "Windows böyle bir silme yapmaz; dosya olduğu gibi çalışır, sorun da bu."),
              ("Dosyaların tarihleri değişir ve zamanlanmış görev yanlış saatte çalışır",
               "Tarih değişikliği görevi etkilemez; asıl tehlike dosyanın içeriğinin değiştirilebilmesi."),
          ]),
          ("Dosyayı kim çalıştırıyor, kim değiştirebiliyor?",
           "Cilt 6'nın 4. bölümünde yazılabilir cron betiği hakkında ne öğrenmiştin?",
           "Değiştirilebilen dosya, çalıştıran hesabın yetkisiyle çalışır."),
          puan=20, baslik="Neden tehlikeli"),
    Gorev("Tırnaksız servis yolu ve yazılabilir servis klasörü bulgularında **en doğru düzeltme** hangisidir?",
          Secmeli([
              ("Yolu çift tırnak içine al, klasör izinlerini yönetici ve SYSTEM ile sınırla",
               "Doğru. Tırnak, yolun parçalara ayrılıp yanlış yorumlanmasını önler; izin daraltma da dosyayı değiştirmeyi önler."),
              ("Servisi silip her seferinde elle başlatmak; böylece otomatik çalışmaz",
               "Servisi kaldırmak sorunu gizler ama işi bozar; gereken yapılandırma düzeltmesidir."),
              ("Bilgisayarın adını değiştirip servisleri yeniden adlandırmak",
               "Ad değiştirmek yol ve izin sorununu çözmez."),
              ("Servisi daha yüksek yetkili bir hesapla çalıştırmak, sorunlar çıkmasın diye",
               "Yetkiyi artırmak sorunu büyütür. Servisler gerekenden fazla yetkiyle çalışmamalı."),
          ]),
          ("Sorun iki yerde: yolun yazılışı ve klasörün izni. Çözüm de iki parçalı.",
           "Tırnak yolu bütünleştirir; izin kısıtı dosyayı korur.",
           "Tırnak + izin daraltma."),
          puan=20, baslik="Doğru düzeltme"),
    Gorev("`kopya_win/servisler.txt` içinde tırnaksız servis yolunu **tırnak içine al** (yolun tamamını, "
          "olduğu gibi). Bitince `cevap 7` yaz.",
          Durum(_tirnak_duzeldi, "BINARY_PATH_NAME alanını çift tırnak içine al"),
          ("Düzenlenecek alan ikinci alan. Dosya `|` ile ayrılmış.",
           "Yalnızca o satırdaki yolun başına ve sonuna `\"` ekle.",
           "`sed -i '/^<servis>|/s/|\\(C:[^|]*\\)|/|\"\\1\"|/' kopya_win/servisler.txt` ya da bir metin düzenleyici."),
          puan=30, baslik="Yolu tırnakla"),
    Gorev("`kopya_win/icacls_cikti.txt` içinde bulduğun **iki** riskli klasörde (servis klasörü ve "
          "görev klasörü) sıradan kullanıcılara/herkese verilen yazma iznini kaldır. Yöneticiler ve SYSTEM "
          "satırları kalsın. Bitince `cevap 8` yaz.",
          Durum(_acl_duzeldi, "Users/Everyone (M)/(F) satırlarını bu iki klasörün bloğundan sil"),
          ("Riskli satırlar `Users` ve `Everyone` için `(M)`/`(F)` olanlar. İki klasörde var.",
           "Başka klasörlerdeki `Users:(RX)` satırlarına dokunmanın gereği yok; yalnızca `(M)` ve `(F)` olanları çıkar.",
           "`grep -v -E '^ +(Everyone|BUILTIN.Users):\\(OI\\)\\(CI\\)\\((M|F)\\)$' kopya_win/icacls_cikti.txt` dosyayı süzer; sonucu dosyaya yazmayı unutma."),
          puan=35, baslik="İzinleri daralt"),
]


def _kapanis():
    return """
Saldırganın gözüyle: Windows'ta da yükselme, yanlış yapılandırmayı bulmaktır; ayrıcalık, servis, klasör izni,
zamanlanmış görev. Linux'la aynı sorular: kimim, neyi çalıştırabilirim, çalışan şeyi kim değiştirebilir?
Savunmanın gözüyle: SYSTEM ile çalışan her dosyanın ve klasörünün yalnızca yöneticilere yazılabilir olması,
servis yollarının tırnaklı olması ve sıradan hesaplarda yönetici ayrıcalığı bulunmaması üç temel
denetimdir. Bir Windows makinesinde yerel yönetici olmak çoğu zaman bitiş değil, başlangıçtır: sıradaki
durak Active Directory (Bölüm 6). Uygulamalı pratiği **kendi laboratuvarında** yap; Windows
hedefleri için Cilt 9'da anlatıldığı gibi ayrı bir makinede izole bir ortam kurarsın.
"""


SEVIYE = Seviye(
    kimlik="c06b05",
    cilt=6,
    bolum=5,
    baslik="Windows Yetki Yükseltme: Artefakt Okuma",
    brifing="""
**<<musteri>>**'nin **<<pc>>** bilgisayarından alınan kurgusal çıktılar masanda. Selin: "`<<kul>>`
hesabı ele geçirilirse nereye kadar yükselebilir? Çıktıları oku, düzeltmeyi öner."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Tırnaksız servis yolu** ve **zayıf servis/klasör izinleri**, Windows denetim rehberlerinde (örneğin
  CIS Benchmark'lar) ve pek çok sızma testi raporunda yinelenen bulgulardır.
- **LAPS:** Microsoft'un LAPS çözümü, her bilgisayardaki yerel yönetici parolasını benzersiz ve otomatik
  değişen hale getirir; aynı parolanın her yerde kullanılması yüzünden olan yayılmayı büyük ölçüde keser.
- **Tespit:** Windows olay günlüklerinde yeni bir servis kurulumu (Sistem günlüğü, olay kimliği 7045),
  yeni bir zamanlanmış görev (Güvenlik günlüğü, 4698; denetim açıksa) ve özel ayrıcalıklarla oturum
  açılması (4672) izlenebilir. Önleme: en az yetki, servis ve görev klasörlerinde sıkı izinler, güncel yama.
""",
    sure_hedef_dk=30,
)
