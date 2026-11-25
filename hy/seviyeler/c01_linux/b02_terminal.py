"""Cilt 1 · Bölüm 2 — Terminalde Yolunu Bulmak.

Beceri: kimim (whoami/id), neredeyim (pwd), etrafımda ne var (ls -la), dolaşmak (cd,
göreli yol), en son değişeni bulmak (ls -lt) ve komut geçmişinin hacker için değeri.

Vakalar: aynı beceri farklı müşterilerin "eski sunucu kopyası" üzerinde.
"""
from __future__ import annotations

import grp
import os
import pwd
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Bayrak, Dinamik, Metin, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

ROOT_KAPILARI = {"sudo", "wheel", "admin", "docker", "lxd", "disk"}

VAKA_KLASORLERI = [
    # (web klasörü, log klasörü, görev klasörü, rapor klasörü)
    ("web", "loglar", "arsiv", "rapor_taslaklari"),
    ("site", "kayitlar", "eski_isler", "raporlar"),
    ("public_html", "log", "devir_teslim", "taslaklar"),
    ("www", "gunlukler", "yedek_notlar", "belgeler"),
]


def uret(rng):
    m = musteri_sec(rng)
    web, log, gorev_k, rapor_k = rng.choice(VAKA_KLASORLERI)
    kullanici = rng.choice(u.ISIMLER)
    gizli_klasor = "." + rng.choice(["gizli", "eski", "cache", "tmp_", "config_", "local"]) + rng.choice(["", "2", "_x", "_old"])
    gizli_dosya = "." + rng.choice(["not", "anahtar", "hatirlatma", "bilgi"]) + ".txt"
    gizli_sayi = rng.randint(3, 6)
    parola = u.parola(rng)
    taslaklar = rng.sample(["bulgular.md", "ozet.txt", "musteri_notu.txt", "tarama_sonucu.txt",
                            "toplanti.md", "yapilacaklar.txt", "kapsam.txt"], 5)
    en_yeni = rng.choice(taslaklar)
    gun = u.gun(rng)
    return {
        "vaka": f"{m['ad']} — eski sunucu kopyası ({m['sunucu']})",
        "musteri": m,
        "klasorler": (web, log, gorev_k, rapor_k),
        "kullanici": kullanici,
        "gizli": (gizli_klasor, gizli_dosya),
        "gizli_sayi": gizli_sayi,
        "taslaklar": taslaklar,
        "gun": gun,
        "metin": {
            "musteri": m["ad"], "sunucu": m["sunucu"], "web": web, "log": log, "gorev_k": gorev_k,
            "rapor_k": rapor_k, "kullanici": kullanici,
        },
        "cevaplar": {
            "bayrak": u.bayrak(rng, "ilk_adim"),
            "goreli": f"../{log}",
            "gizli_sayi": gizli_sayi,
            "en_yeni": en_yeni,
            "parola": parola,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    web, log, gorev_k, rapor_k = s["klasorler"]
    m = s["musteri"]
    c = s["cevaplar"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} sunucusunun ({m['sunucu']}) laboratuvar kopyası.\n"
          "Selin'den not: Acele etme. Önce nerede olduğunu ve kim olduğunu öğren.\n")
    u.yaz(lab / web / "index.php", "<?php echo 'Hoş geldiniz'; ?>\n")
    u.yaz(lab / web / "iletisim.php", "<?php // iletişim formu ?>\n")
    u.yaz(lab / log / "access.log", "192.168.1.10 - - [12/Nov/2026:10:01:12 +0300] \"GET / HTTP/1.1\" 200 512\n")
    # Görev klasörü: tek görünen dosya + gizli klasörün içinde gizli dosyada bayrak
    gizli_klasor, gizli_dosya = s["gizli"]
    u.yaz(lab / gorev_k / "okubeni.txt", "Burada bir şey yok, gizli dosyalara bak.\n")
    u.yaz(lab / gorev_k / gizli_klasor / gizli_dosya, f"Tebrikler, ilk bayrağı buldun: {c['bayrak']}\n")
    # Kullanıcının ev dizini: belirli sayıda gizli girdi + komut geçmişinde unutulmuş parola
    ev = lab / "ev" / s["kullanici"]
    gecmis = [
        "ls -la", "cd /var/www", "sudo systemctl restart apache2", "tail -f /var/log/apache2/error.log",
        f"mysql -u root -p{c['parola']} {m['kod']}_db", "df -h", "exit",
    ]
    u.yaz(ev / ".bash_history", "\n".join(gecmis) + "\n")
    adaylar = [".profile", ".bashrc", ".ssh/known_hosts", ".viminfo", ".lesshst", ".selected_editor"]
    eklenecek = s["gizli_sayi"] - 1  # .bash_history zaten bir tane
    for ad in adaylar[:eklenecek]:
        u.yaz(ev / ad, "# \n")
    u.yaz(ev / "notlar.txt", "Yarın yedekleri kontrol et.\n")
    # Rapor taslakları: değişiklik zamanları farklı; en yenisi belli
    t = s["gun"] + timedelta(hours=9)
    sirali = [x for x in s["taslaklar"] if x != c["en_yeni"]] + [c["en_yeni"]]
    for i, ad in enumerate(sirali):
        u.yaz(lab / rapor_k / ad, f"{ad} taslağı\n", t=t + timedelta(hours=i * 7, minutes=i * 13))


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def coz(lab: Path, s: dict) -> dict:
    """Test çözücüsü: kitabın cevaplarındaki komutlarla çözer."""
    web, log, gorev_k, rapor_k = s["klasorler"]
    bayrak = _sh(f"cat {gorev_k}/.*/.* 2>/dev/null | grep -o 'FLAG{{[^}}]*}}'", lab)
    gizli = _sh(f"ls -A ev/{s['kullanici']} | grep -c '^\\.'", lab)
    en_yeni = _sh(f"ls -t {rapor_k} | head -1", lab)
    parola = _sh(f"grep -o -- '-p[^ ]*' ev/{s['kullanici']}/.bash_history | cut -c3-", lab)
    gruplar = set(_sh("id -nG", lab).split())
    kapi = sorted(gruplar & ROOT_KAPILARI)
    grup_cevap = "root" if os.getuid() == 0 else (kapi[0] if kapi else "yok")
    return {1: _sh("whoami", lab), 2: bayrak, 3: f"../{log}", 4: grup_cevap, 5: gizli, 6: en_yeni, 7: parola}


def _root_kapilari(b) -> list:
    if os.getuid() == 0:
        return ["root", "zaten root", "root kullanıcısıyım"]
    gruplar = set()
    for gid in os.getgroups():
        try:
            gruplar.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    kapi = sorted(gruplar & ROOT_KAPILARI)
    return kapi or ["yok", "hiçbiri", "hicbiri", "hiç", "yok."]


def _gizli_sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 2:
        return "`.` ve `..` girdilerini de saymışsın. Onlar her klasörde vardır; `ls -A` ile dene."
    if n == beklenen - 1:
        return "Bir tane eksik. Gizli **klasörler** de sayılır (örn. `.ssh`)."
    return None


ADIMLAR = [
    Adim("Kimim?", """
Bir sisteme ilk girdiğinde, ister kendi bilgisayarın ister sızdığın bir sunucu olsun, ilk
soru hep aynıdır: **Kimim, neredeyim, etrafımda ne var?**

`whoami` sadece kullanıcı adını verir.
""", komut="whoami"),
    Adim("id: Kimliğin tamamı", """
`id` çok daha fazlasını söyler: kullanıcı numaran (UID), ana grubun (GID) ve üyesi olduğun
**tüm gruplar**.
""", komut="id", sonra="""
**Hacker gözüyle:** `sudo`, `docker`, `lxd` gibi gruplara üyelik çoğu zaman doğrudan root'a
giden kapıdır. `docker` grubundaki bir kullanıcı pratikte root'tur. Bunu Cilt 6'da
kullanacağız.
"""),
    Adim("Neredeyim?", """
Linux'ta her şey tek bir ağaçtan dallanır; kökü `/` karakteridir. Windows'taki `C:\\`
gibi ayrı sürücüler yoktur. `pwd` (print working directory) bulunduğun klasörün tam
yolunu yazar.
""", komut="pwd"),
    Adim("Etrafımda ne var?", """
`ls` klasör içeriğini listeler. `-l` uzun format (izinler, sahip, boyut, tarih), `-a`
gizli dosyaları da gösterir (adı nokta ile başlayanlar).
""", komut="ls -la", sonra="""
En üstteki `.` bulunduğun klasör, `..` bir üst klasördür. Bunlar her klasörde vardır;
gizli dosya sayarken bunları sayma. Sadece gerçek gizli girdileri görmek için `ls -A`
kullanılır.
"""),
    Adim("Dolaşmak: cd ve göreli yol", """
Bir dosyaya iki şekilde işaret edebilirsin:

- **Mutlak yol** `/` ile başlar: `/home/kali/hackeryolu/lab/...`
- **Göreli yol** bulunduğun yerden başlar: `<<web>>/index.php`

Üç kısayol: `.` (bulunduğum klasör), `..` (bir üst klasör), `~` (ev dizinim).
Şimdi `<<web>>` klasörüne gir ve oradan bir üst klasöre dönüp yine `<<log>>`'a geç;
hepsi tek satırda:
""", komut="cd <<web>> && pwd && cd ../<<log>> && pwd", sonra="""
`cd` ile `..` arasında **boşluk zorunludur**. `cd..` yazarsan Linux bunu tek bir komut adı
sanır ve "command not found" der.
"""),
    Adim("En son ne değişti?", """
`ls -lt` dosyaları değiştirilme zamanına göre sıralar, en yeni üstte. Bir sunucuda
saldırganın en son dokunduğu dosyayı bulmanın en hızlı yollarından biridir.
""", komut="ls -lt <<rapor_k>>"),
    Adim("Komut geçmişi", """
Kabukta yazdığın her komut bir geçmiş dosyasına kaydedilir: bash için `~/.bash_history`,
Kali'nin varsayılan kabuğu zsh için `~/.zsh_history`. `history` komutu bunu numaralı
listeler; **yukarı ok** önceki komutları getirir, **Ctrl+R** geçmişte arar.

**Hacker gözüyle:** Yöneticiler bazen komut satırına parola yazar, örneğin
`mysql -u root -pGizli123`. Bir sisteme girdiğinde kullanıcıların geçmiş dosyalarına bakmak
klasik bir keşif adımıdır. Savunma dersi de açık: **parolayı asla komut satırına yazma.**
"""),
    Adim("Yardım almak", """
Hiçbir hacker tüm seçenekleri ezbere bilmez; bilmediğinde nereye bakacağını bilir.
`man ls` tam kılavuzu açar (çıkmak için `q`), `--help` kısa özet verir, `apropos kelime`
açıklamasında o kelime geçen komutları bulur. Kısa özeti dene:
""", komut="ls --help | head -15"),
]

GOREVLER = [
    Gorev("Bu kabukta hangi kullanıcısın?", Dinamik(lambda b: pwd.getpwuid(os.geteuid()).pw_name, bicim="kullanıcı adı"),
          ("Kim olduğunu söyleyen en kısa komut.",
           "`whoami` yaz.",
           "`whoami` çıktısındaki tek kelimeyi `cevap 1 <kelime>` olarak gönder."),
          puan=20, baslik="Kimim"),
    Gorev("`<<gorev_k>>` klasöründe tek bir dosya görünüyor ama gerisi gizli. Gizli olan her şeyi "
          "bul ve içindeki bayrağı oku.",
          Bayrak("bayrak"),
          ("Gizli dosya ve klasörlerin adı nokta ile başlar; düz `ls` onları göstermez.",
           "`ls -la <<gorev_k>>` ile gizli bir klasör göreceksin. Onun içine de `ls -la` ile bak.",
           "`cd <<gorev_k>>`, `ls -la`, gizli klasöre `cd` ile gir, tekrar `ls -la`, sonra `cat .dosyaadi`."),
          puan=40, baslik="Gizli bayrak"),
    Gorev("`<<web>>` klasöründeyken, `<<log>>` klasörüne **göreli yolla** gitmek için `cd`'nin "
          "yanına ne yazarsın?",
          Metin("goreli", on_ekleri_at=("cd ",), son_ekleri_at=("/",), bicim="göreli yol (örn. ../klasor)"),
          ("İki klasör de aynı üst klasörün içinde.",
           "Önce bir üst klasöre çıkman, sonra hedefe inmen gerek. Bir üst klasörün kısayolu `..`",
           "Göreli yol: `../` + hedef klasörün adı."),
          puan=30, baslik="Göreli yol"),
    Gorev("`id` çıktında sana root yetkisi kazandırabilecek bir grup var mı? Varsa grubun adını yaz, "
          "yoksa `yok` yaz.",
          Dinamik(_root_kapilari, bicim="grup adı ya da yok"),
          ("`id` komutunu çalıştır ve `groups=` kısmına bak.",
           "Eğitimde root'a kapı açan gruplardan bahsettik: sudo, wheel, docker, lxd...",
           "`id -nG` grupları adlarıyla listeler. Bunlardan biri sudo/wheel/docker/lxd ise onu yaz."),
          puan=30, baslik="Yetki kapısı"),
    Gorev("`ev/<<kullanici>>` klasöründe kaç tane gizli dosya veya klasör var? (`.` ve `..` hariç)",
          Sayi("gizli_sayi", sik_hatalar=_gizli_sayi_hata),
          ("Gizli girdileri görmek için `ls`'e bir seçenek eklemen gerek.",
           "`ls -la ev/<<kullanici>>` hepsini gösterir; `.` ve `..` sayılmaz.",
           "`ls -A ev/<<kullanici>>` nokta ile başlayanları `.` ve `..` olmadan gösterir; onları say."),
          puan=30, baslik="Gizliler"),
    Gorev("`<<rapor_k>>` klasöründe **en son değiştirilen** dosya hangisi?",
          Metin("en_yeni", sadece_ad=True, bicim="dosya adı"),
          ("Dosyaları değişiklik zamanına göre sıralayan bir `ls` seçeneği var.",
           "`ls -lt <<rapor_k>>` en yeniyi en üste koyar.",
           "`ls -t <<rapor_k>> | head -1` sadece en yeni dosyanın adını verir."),
          puan=30, baslik="En yeni"),
    Gorev("<<kullanici>> adlı yönetici, veritabanına bağlanırken parolasını komut satırına yazmış. "
          "Parola ne?",
          Metin("parola", bicim="parola"),
          ("Yöneticinin yazdığı komutlar ev dizinindeki bir geçmiş dosyasında durur.",
           "`cat ev/<<kullanici>>/.bash_history` ile bak; `mysql` satırını bul.",
           "`mysql -u root -pPAROLA` biçiminde: `-p`'ye bitişik yazılan kısım paroladır."),
          puan=40, baslik="Unutulan parola"),
]


def _kapanis():
    return """
İlk sızdığın bir sistemde attığın ilk adımlar hep aynıdır: `whoami`, `id`, `pwd`,
`ls -la` ve geçmiş dosyaları. Saniyeler sürer ama sana kim olduğunu, hangi kapıların açık
olduğunu ve yöneticinin neyi unuttuğunu söyler. Savunma tarafı için ders: komut satırına
parola yazılmaz, gizli dosya "gizli" değildir (sadece `ls`'te görünmez) ve `docker`/`sudo`
grubuna kimin üye olduğu düzenli denetlenir.
"""


SEVIYE = Seviye(
    kimlik="c01b02",
    cilt=1,
    bolum=2,
    baslik="Terminalde Yolunu Bulmak",
    brifing="""
**<<musteri>>**'nin eski sunucusu **<<sunucu>>** emekliye ayrılmadan önce bir kopyası
alındı ve laboratuvarına kondu. Selin: "Bu sunucuyu yıllarca <<kullanici>> adında bir
yönetici kullanmış. Ne bıraktığını kimse bilmiyor. Senden bir envanter istiyorum: kim
olarak bağlısın, neler var, gizli ne var, en son neye dokunulmuş?"

Mert monitörün arkasından sesleniyor: "Eski yöneticilerin geçmiş dosyalarına bak. Hep bir
şey unuturlar."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Komut satırındaki parolalar:** Ortak sunucularda `ps aux` ile çalışan süreçlerin komut
  satırları başka kullanıcılara da görünebilir; `mysql -pParola` gibi bir komut çalışırken
  parola bu yolla da sızabilir. Bu yüzden MySQL istemcisi bile komut satırında parola
  kullanmanın güvensiz olduğuna dair uyarı basar.
- **Geçmiş dosyaları ve sızma testleri:** Sızma testi raporlarında "kullanıcı geçmiş
  dosyasında açık metin parola" bulgusu çok sık geçer. Saldırganlar da bir sisteme
  girdiklerinde ilk iş `.bash_history` dosyalarını okur.
- **Docker grubu = root:** Docker'ın kendi belgeleri, `docker` grubuna üye olmanın root'a
  eşdeğer yetki verdiğini açıkça uyarır. Bu grup üyeliği, Linux yetki yükseltme
  kontrol listelerinin değişmez maddelerindendir.
""",
    sure_hedef_dk=25,
)
