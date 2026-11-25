"""Cilt 17 · Bölüm 2 — Statik ve Dinamik Analiz.

Beceri: zararsız örnek dosyalarda `file` (gerçek tür), `strings` (gömülü metin) ve base64 çözme ile statik analiz yapmak;
base64 ile kodlanmış KURGUSAL ve zararsız bir yapılandırma metninden alan adı (.lab), IP (TEST-NET) ve port çıkarmak;
kurgusal bir sandbox raporundan (JSON) dinamik davranışı (ağ bağlantısı, kalıcılık) okumak.

Vakalar: Ferah Bank, Kuzgun Lojistik, Medora Sağlık, Paramix. Hiçbir dosya çalıştırılmaz; hiçbiri zararlı değildir: bir PNG,
bir gzip'lenmiş metin ve içinde yalnızca okunabilir birkaç satır ve kodlanmış kurgusal yapılandırma olan bir "ikili" dosya.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c17_zararli.ortak import (Icerir, gurultu, gzip_bytes, hex_, png_bytes, sec_doldur, sh, vaka_sec)

PDF_ADLARI = {"ferah": "ekstre_mart.pdf", "kuzgun": "irsaliye_2026.pdf", "medora": "sonuc_belgesi.pdf",
              "paramix": "fatura_eki.pdf"}
DAT_ADLARI = {"ferah": "sube_guncelleme.dat", "kuzgun": "terminal_surucu.dat", "medora": "goruntuleyici_yama.dat",
              "paramix": "odeme_araci.dat"}
GZ_ADLARI = {"ferah": "rapor_paketi.bin", "kuzgun": "etiket_paketi.bin", "medora": "yedek_paketi.bin",
             "paramix": "mutabakat_paketi.bin"}
ALAN_ETIKETLERI = ["guncelleme-merkezi", "bulut-senkron", "surucu-destek", "hizmet-aktarici", "yardimci-servis"]


def uret(rng):
    v = vaka_sec(rng)
    domain = rng.choice(ALAN_ETIKETLERI) + f"{rng.randint(1, 9)}.lab"
    ip = u.dis_ip(rng)
    ntp_ip = u.dis_ip(rng)
    port = rng.randint(20000, 45000)
    aralik = rng.choice([30, 45, 60, 120, 300])
    kimlik = "LAB-" + hex_(rng, 6)
    cfg = f"sunucu={domain}\nip={ip}\nport={port}\naralik_sn={aralik}\nkimlik={kimlik}\n"
    b64 = base64.b64encode(cfg.encode()).decode()
    dat = (gurultu(rng, 60) + b"\x00ZARARSIZ EGITIM ORNEGI - Kalkan Lab\x00" + gurultu(rng, 40) +
           b"\x00User-Agent: LabAjan/1.0\x00" + gurultu(rng, 30) + b"CFG=" + b64.encode() + b"\x00" +
           gurultu(rng, 50) + b"\x00dosya-sonu\x00" + gurultu(rng, 30))
    kalici = f"sistem_yardimcisi_{hex_(rng, 4)}.desktop"
    kalici_yol = f"/home/analiz/.config/autostart/{kalici}"
    ag = [{"hedef_alan": "ntp.kurum.lab", "hedef_ip": ntp_ip, "port": 123, "protokol": "udp"},
          {"hedef_alan": domain, "hedef_ip": ip, "port": port, "protokol": "tcp"}]
    rng.shuffle(ag)
    rapor = {
        "ornek": DAT_ADLARI[v["kod"]], "sure_sn": rng.choice([90, 120, 180]),
        "surecler": [{"pid": rng.randint(1100, 1900), "ad": DAT_ADLARI[v["kod"]], "ebeveyn": "bash"},
                     {"pid": rng.randint(2000, 2900), "ad": "bekleme_sureci", "ebeveyn": DAT_ADLARI[v["kod"]]}],
        "dosya_olaylari": [{"islem": "okundu", "yol": "/etc/hostname"},
                           {"islem": "olusturuldu", "yol": f"/tmp/lab_gecici_{hex_(rng, 6)}.tmp"},
                           {"islem": "olusturuldu", "yol": kalici_yol}],
        "ag": ag,
        "kalicilik": {"tur": "autostart", "dosya": kalici_yol},
    }
    return {
        "vaka": f"{v['ad']} — şüpheli dosyanın statik ve dinamik analizi",
        "v": v, "png": png_bytes(rng), "dat": dat, "gz": gzip_bytes(f"ZARARSIZ EGITIM ORNEGI - sikistirilmis metin {hex_(rng, 8)}\n"),
        "rapor": rapor,
        "metin": {"musteri": v["ad"], "pc": v["pc"], "hikaye": v["hikaye"], "pdf": PDF_ADLARI[v["kod"]],
                  "dat": DAT_ADLARI[v["kod"]], "gz": GZ_ADLARI[v["kod"]]},
        "cevaplar": {"tur": "PNG", "alan": domain, "port": port, "ip": ip, "kalici": kalici},
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = v["kod"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['pc']} bilgisayarından alınan üç ZARARSIZ eğitim örneği ve bir KURGUSAL sandbox raporu.\n"
          "Selin'den not: dosyaları çalıştırmıyoruz. Statik analiz için file, strings ve base64; dinamik bilgi için sandbox raporu.\n")
    (lab / "ornekler").mkdir(parents=True, exist_ok=True)
    (lab / "ornekler" / PDF_ADLARI[k]).write_bytes(s["png"])
    (lab / "ornekler" / DAT_ADLARI[k]).write_bytes(s["dat"])
    (lab / "ornekler" / GZ_ADLARI[k]).write_bytes(s["gz"])
    u.yaz(lab / "rapor" / "sandbox_raporu.json", json.dumps(s["rapor"], ensure_ascii=False) + "\n")


def coz(lab: Path, s: dict) -> dict:
    pdf, dat = s["metin"]["pdf"], s["metin"]["dat"]
    tur = sh(f"file ornekler/{pdf}", lab)
    cfg = "LC_ALL=C grep -a -o 'CFG=[A-Za-z0-9+/=]*' ornekler/" + dat + " | cut -d= -f2- | base64 -d"
    alan = sh(cfg + " | grep '^sunucu=' | cut -d= -f2", lab)
    port = sh(cfg + " | grep '^port=' | cut -d= -f2", lab)
    ip = sh(f"python3 -m json.tool rapor/sandbox_raporu.json | grep -A1 '\"hedef_alan\": \"{alan}\"' | grep hedef_ip "
            "| grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+'", lab)
    kalici = sh("python3 -m json.tool rapor/sandbox_raporu.json | grep -A3 kalicilik | grep dosya "
                "| grep -o '[A-Za-z0-9_]*\\.desktop'", lab)
    return sec_doldur({1: tur, 2: alan, 3: port, 4: ip, 5: kalici}, GOREVLER, lab, s)


def _port_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n in (123,):
        return "123 saat eşitleme (NTP) bağlantısının portu. Sorulan, kodlanmış yapılandırmadaki `port=` değeri."
    return None


def _alan_hata(g, beklenen, b):
    if "=" in g:
        return "Sadece alan adını yaz (`sunucu=` kısmı olmadan)."
    return None


ADIMLAR = [
    Adim("İki yaklaşım", """
Zararlı analizi iki yaklaşımla yapılır; ikisi birlikte tam resmi verir:

- **Statik analiz:** zararlı **çalıştırılmadan** incelenir: dosya türü, içindeki metinler, bilinen imzalar. Güvenlidir çünkü kod
  çalışmaz; ama gelişmiş zararlılar kendini gizleyebilir (paketleme, şifreleme).
- **Dinamik analiz:** zararlı **izole ortamda çalıştırılıp** gözlemlenir: hangi dosyaları oluşturdu, hangi süreçleri başlattı, hangi
  ağ bağlantılarını yaptı, nasıl kalıcı olmaya çalıştı. "Sandbox" denen otomatik ortamlar bunu raporlar.

Bu seviyede statik analizi **kendin yapacak**, dinamik sonucu ise hazır bir sandbox raporundan okuyacaksın. Önce elimizdekiler:
""", komut="ls -l ornekler"),
    Adim("file: dosyanın gerçek türü", """
Dosyanın uzantısı yalan söyleyebilir; içeriği gerçeği söyler. `file`, dosyanın başındaki baytlara bakarak **gerçek türünü** bildirir
(Cilt 1'deki araç). Üç dosyanın türüne bak:
""", komut="file ornekler/*", sonra="""
Bir dosya `.pdf` adını taşıyıp gerçekte başka bir türde çıkabilir; bu klasik bir **şüphe işaretidir**. Saldırganlar masum görünen
uzantıları kullanır. Aynı şekilde `.bin` gibi belirsiz bir uzantı sıkıştırılmış bir arşiv de olabilir.
"""),
    Adim("strings: dosyadaki okunabilir metin", """
İkili bir dosyanın içinde okunabilir metin parçaları olabilir: adresler, komutlar, mesajlar. `strings` bunları çıkarır (`-n 8` en az
8 karakterlik dizileri ister):
""", komut="strings -n 8 ornekler/<<dat>>"),
    Adim("strings yoksa", """
`strings` binutils paketindedir; her sistemde bulunmayabilir. Aynı işi `grep` de yapar: `-a` ikili dosyayı metin sayar, `-o` yalnızca
eşleşeni basar, `LC_ALL=C` karakter kodlaması karışıklığını önler:
""", komut="LC_ALL=C grep -a -o -E '[[:print:]]{8,}' ornekler/<<dat>>", sonra="""
Çıktıda 'ZARARSIZ EGITIM ORNEGI' gibi düz satırların yanında `CFG=` ile başlayan uzun, anlamsız görünen bir dizi var. Bu bir
**base64** kodlamasıdır: şifreleme değil, yalnızca metni 64 harf/rakamla temsil etme biçimi. Tek komutla geri çevrilir.
"""),
    Adim("base64 -d: kodu çözmek", """
Önce zararsız bir deneme: `base64 -d` kodlanmış metni çözer.
""", komut="echo 'a2Fsa2Fu' | base64 -d"),
    Adim("Gömülü yapılandırmayı çıkarmak", """
`CFG=` ile başlayan diziyi yalnızca değer kısmını alacak şekilde süz, sonra çöz. Bu **kurgusal ve zararsız** bir yapılandırma metni;
gerçek analizde böyle bir metin, zararlının nereye bağlanacağını söyleyen bir gösterge olurdu:
""", komut="LC_ALL=C grep -a -o 'CFG=[A-Za-z0-9+/=]*' ornekler/<<dat>> | cut -d= -f2- | base64 -d", sonra="""
**Hacker gözüyle:** Zararlı yazanlar adresleri okunur biçimde bırakmaz, kodlar. Ama kodlama (base64) bir engel değildir; analist
saniyeler içinde çözer. Gerçek göstergeler (alan adı, IP, port) bu tür metinlerden çıkar ve tespit kurallarına dönüşür.
"""),
    Adim("Dinamik: sandbox raporunu okumak", """
Sandbox raporu tek satırlık bir JSON. `python3 -m json.tool` onu okunur biçimde girintiler:
""", komut="python3 -m json.tool rapor/sandbox_raporu.json"),
    Adim("Raporda ağ ve kalıcılık", """
Raporda dikkat edilecek bölümler: `ag` (hangi adreslere bağlandı), `dosya_olaylari` (ne yarattı) ve `kalicilik` (yeniden açılışta
kendini nasıl başlatıyor). Ağ bağlantılarına odaklan:
""", komut="python3 -m json.tool rapor/sandbox_raporu.json | grep -E 'hedef|port|protokol'"),
]

GOREVLER = [
    Gorev("`ornekler/<<pdf>>` adı PDF gibi görünüyor. `file` komutuna göre **gerçek türü** nedir? (kısa tür adı yeter)",
          Icerir(["png"], bicim="dosya türü"),
          ("Uzantıya değil içeriğe bakan komut Cilt 1'den tanıdık.",
           "`file ornekler/<<pdf>>`",
           "Çıktıdaki ilk iki sözcük gerçek türü söyler."),
          puan=25, baslik="Gerçek tür"),
    Gorev("`ornekler/<<dat>>` içinde `CFG=` ile başlayan base64 dizisini çözünce **sunucu alan adını** (`sunucu=`) yaz.",
          Metin("alan", bicim="alan adı (...lab)", sik_hatalar=_alan_hata),
          ("Önce `strings` ya da `grep -a` ile `CFG=` satırını bul.",
           "`LC_ALL=C grep -a -o 'CFG=[A-Za-z0-9+/=]*' ornekler/<<dat>>` dizisini al, `=` işaretinden sonrasını `cut -d= -f2-` ile ayır, `base64 -d` ile çöz.",
           "`... | cut -d= -f2- | base64 -d | grep sunucu`: değer `sunucu=` satırında."),
          puan=40, baslik="Alan adını çıkar"),
    Gorev("Aynı çözülmüş yapılandırmadaki **`port=`** değeri kaç?",
          Sayi("port", sik_hatalar=_port_hata),
          ("Aynı metni yeniden çöz; `port=` satırına bak.",
           "Önceki görevdeki komutu `| grep '^port='` ile bitir.",
           "`... | base64 -d | grep '^port=' | cut -d= -f2`"),
          puan=25, baslik="Portu çıkar"),
    Gorev("`rapor/sandbox_raporu.json` içinde, yukarıda bulduğun **alan adına bağlanan IP adresi** hangisi? (Raporda aynı bağlantıyı "
          "`hedef_alan` ve `hedef_ip` birlikte verir.)",
          IP("ip"),
          ("Raporda `ag` listesinde iki bağlantı var; biri saat eşitleme.",
           "`python3 -m json.tool rapor/sandbox_raporu.json | grep -A1 hedef_alan` alan adı ile IP'yi alt alta gösterir.",
           "Senin bulduğun alan adının altındaki `hedef_ip` satırı cevaptır."),
          puan=35, baslik="Bağlandığı IP"),
    Gorev("Sandbox raporuna göre örnek, yeniden başlatmada çalışmak için hangi **dosyayı** oluşturmuş? (`kalicilik` bölümü; yalnızca dosya adı)",
          Metin("kalici", sadece_ad=True, bicim="dosya adı (.desktop)"),
          ("Raporda `kalicilik` başlıklı bir bölüm var.",
           "`python3 -m json.tool rapor/sandbox_raporu.json | grep -A3 kalicilik`",
           "`dosya` satırındaki yolun son parçası dosya adıdır."),
          puan=30, baslik="Kalıcılık dosyası"),
    Gorev("`file` ve `strings` gibi **statik analiz** neden tek başına yeterli olmayabilir?",
          Secmeli([
              ("Zararlı kendini paketleyip şifreleyebilir; içindeki metinler dışarıdan görünmez",
               "Doğru. Gelişmiş zararlılar statik inceleme araçlarından saklanır; davranışını görmek için dinamik analiz gerekir."),
              ("Statik analiz zararlıyı gerçekten çalıştırdığı için her zaman güvensizdir ve riskli kabul edilir",
               "Yanlış. Statik analiz dosyayı çalıştırmaz; güvenli olan tarafı budur."),
              ("`file` komutu yalnızca Windows dosyalarını tanır, Linux dosyalarında hiçbir sonuç vermez",
               "Yanlış. `file` birçok dosya türünü tanır; sınırı gizlenmiş içeriktir."),
              ("`strings` her zaman yanlış ve anlamsız sonuç verdiği için hiçbir zaman işe yaramaz",
               "Yanlış. `strings` doğru çalışır; ama gizlenmiş bir yükte okunabilir metin bulamaz."),
          ], dogru=0),
          ("Statik analizde dosya çalışmıyor; peki içindeki bilgi gizlenmişse ne olur?",
           "Paketleme ve şifreleme, içerikteki metinleri nasıl etkiler?",
           "Doğru şık, gizleme (paketleme/şifreleme) yüzünden statik analizin yetmediğini söyleyen şık."),
          puan=25, baslik="Statik analizin sınırı"),
    Gorev("Sandbox raporunda aşağıdaki davranışlardan hangisi **birlikte** görüldüğünde şüpheyi en çok artırır?",
          Secmeli([
              ("Kendini otomatik başlatmaya ekleyip bilinmeyen bir alan adına bağlanmak",
               "Doğru. Kalıcılık + bilinmeyen dış bağlantı, zararlı davranışın klasik birleşimidir."),
              ("/etc/hostname dosyasını okumak ve ardından kurumun saat eşitleme sunucusuna bağlanmak",
               "Yanlış. Bunlar çoğu normal programda görülen, tek başına zararsız davranışlardır."),
              ("Geçici bir dosya oluşturup işi bitince onu silmek, tıpkı sıradan bir program gibi",
               "Yanlış. Birçok meşru program geçici dosya kullanır; tek başına şüpheli değildir."),
              ("Bir alt süreç başlatıp onun işini bitirmesini ve kapanmasını sakin biçimde beklemek",
               "Yanlış. Alt süreç başlatmak çok yaygındır; tek başına bir şey kanıtlamaz."),
          ], dogru=0),
          ("Tek başına zararsız olan davranışlar var; hangi ikisi birlikte alarm zilini çaldırır?",
           "Kalıcılık ve beklenmeyen dış bağlantı: Cilt 6'daki kalıcılık ile Cilt 2'deki ağ gözlemini hatırla.",
           "Doğru şık 'kendini başlangıca ekle + bilinmeyen adrese bağlan' bileşimini anlatan şık."),
          puan=30, baslik="Şüpheli birleşim"),
]

SEVIYE = Seviye(
    kimlik="c17b02",
    cilt=17,
    bolum=2,
    baslik="Statik ve Dinamik Analiz",
    brifing="""
**<<musteri>>** olay müdahale ekibi bir adım ileri gitti: **<<pc>>** bilgisayarından üç dosya (hepsi ZARARSIZ eğitim örneği) ve izole
bir ortamda üretilmiş kurgusal bir sandbox raporu geldi. <<hikaye>>

Deniz: "Önce dosyaları çalıştırmadan konuşturalım: gerçekten ne oldukları, içlerinde okunur bir şey var mı. Sonra sandbox raporu bize
çalışırken ne yaptığını söylesin." Selin: "Ve unutma, bu araçların hepsi sana tanıdık: `file`, `grep`, `base64`, ağ gözlemi.
Yeni bir beceri değil, var olanların bir düşman örneğine uygulanması." Mert: "Dosyanın adına değil içeriğine güven."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Statik analiz zararlıyı çalıştırmadan konuşturur: `file` gerçek türü söyler, `strings` gömülü metni çıkarır, base64 gibi basit
kodlamalar saniyeler içinde çözülür. Dinamik analiz ise davranışı gösterir: hangi adrese bağlandı, hangi dosyayı oluşturdu,
nasıl kalıcı oldu. Saldırgan açısından kodlama ve paketleme analistin işini yavaşlatır ama durdurmaz. Savunma dersi: iki
yaklaşımı birlikte kullan, bulduğun adres, dosya ve davranışları not et: bunlar bir sonraki bölümde **göstergelere (IOC)** ve
tespit kurallarına dönüşecek.
""",
    gercek_hayat="""
- **Uzantı yalan söyler:** Pek çok kimlik avı ve zararlı kampanyasında masum görünen uzantılı ya da sıkıştırılmış dosyalar
  kullanılır; bu yüzden güvenlik ekipleri dosyanın gerçek türünü içeriğine bakarak (`file`, sihirli baytlar) belirler.
- **Önleme / tespit:** Dosya türüne göre posta ağ geçidinde engelleme, bilinmeyen dosyaların otomatik sandbox'a gönderilmesi,
  EDR'ın yeni oluşan kalıcılık girdilerini (başlangıç klasörü, zamanlanmış görev) ve alışılmadık dış bağlantıları alarm yapması.
  Kodlanmış (base64) metinlerdeki adres ve alan adları IOC listesine eklenir.
- **Sandbox sınırı:** Bazı zararlılar sanal ortamda çalıştıklarını fark edince davranışlarını değiştirir; bu yüzden sandbox raporu
  statik analiz ve ağ kayıtlarıyla birlikte değerlendirilir.
""",
    sure_hedef_dk=30,
)
