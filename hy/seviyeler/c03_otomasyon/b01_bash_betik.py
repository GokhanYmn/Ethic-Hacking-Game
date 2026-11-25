"""Cilt 3 · Bölüm 1 — Bash ile Betik Yazmak.

Beceri: shebang, chmod +x, değişkenler (ve `=` etrafında boşluk tuzağı), $1 $# $0,
`if [ -z ]` ile kullanım mesajı + `exit 1`, `-f`/`-d` testleri, `for` + `seq`.

Oyuncu dört küçük betik yazar (selam.sh, logsay.sh, ipler.sh, varmi.sh); `cevap <no>`
yazınca oyun betiği farklı girdilerle (lab klasörleri, geçici klasörler, eksik argüman)
çalıştırıp çıktısını denetler. Vakalar: farklı müşterilerin "her sabah elle yapılan" log
kontrolleri.
"""
from __future__ import annotations

import base64
import random
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from hy.motor.kontrol import Baglam, Bayrak, Secmeli, Sayi, Sonuc, norm
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri

VAKALAR = [
    {
        "kod": "kuzgun", "log_kok": "depo_loglari", "sunucular": ("kzg-depo", "kzg-takip"),
        "yedek_kok": "gece_yedekleri", "yedek_ek": "depo_db", "ag": "10.30.8",
        "olay": "Depo panelinde kimsenin hatırlamadığı bir sevkiyat iptali görülmüş. Serdar Bey "
                "o günden beri her sabah iki sunucunun log klasörünü elle sayıp yedeklerin "
                "alınıp alınmadığına tek tek bakıyormuş.",
        "tuzak": ["katalog_eski.txt", "logrotate.conf"],
    },
    {
        "kod": "pazarix", "log_kok": "web_kayitlari", "sunucular": ("pzx-web01", "pzx-odeme"),
        "yedek_kok": "yedekler", "yedek_ek": "siparis_db", "ag": "10.0.12",
        "olay": "Kampanya haftası başlıyor ve geçen yıl sipariş sayfası çöktüğünde kimse hangi "
                "logun nerede olduğunu bulamamış. Tuncay Bey her sabah log sayımı ve yedek "
                "kontrolü istiyor ama bunu hep elle yapıyor.",
        "tuzak": ["urun_katalog.txt", "blog_yazilari.txt"],
    },
    {
        "kod": "medora", "log_kok": "portal_loglari", "sunucular": ("medora-portal", "medora-pacs"),
        "yedek_kok": "yedek_arsivi", "yedek_ek": "randevu_db", "ag": "172.16.20",
        "olay": "Bir hasta, randevu sayfasında başka birinin bilgilerini gördüğünü bildirmiş. "
                "Dr. Aslı Hanım, olay sonrası incelemede logların eksiksiz tutulduğundan emin "
                "olmak istiyor; şimdilik her sabah klasörleri elle sayıyorlar.",
        "tuzak": ["doktor_katalogu.txt", "logrotate.conf"],
    },
    {
        "kod": "yesiltepe", "log_kok": "ebelediye_log", "sunucular": ("ytb-ebelediye", "ytb-vezne"),
        "yedek_kok": "yedekler", "yedek_ek": "borc_db", "ag": "192.168.40",
        "olay": "Borç sorgulama sayfası geçen hafta birkaç dakikalığına çöktü ve o saatin logu "
                "kayıp çıktı. Nurcan Hanım artık her sabah log ve yedek kontrolü istiyor; ekip "
                "bunu elle, sıkılarak yapıyor.",
        "tuzak": ["ihale_katalogu.txt", "logrotate.conf"],
    },
]

LOG_ADLARI = ["access", "error", "auth", "app", "cron", "mail", "kern", "daemon", "audit", "api"]


def _arg_sorusu(rng, m: dict, v: dict) -> tuple:
    """`$#` sorusu için (komut satırı, argüman sayısı, tırnaksız kelime sayısı)."""
    sablonlar = [
        (f'./not_al.sh "{m["ad"]}" acil {rng.randint(2, 9)}', 3),
        (f"./tara.sh {v['ag']}.{rng.randint(2, 250)} 22 80 443", 4),
        (f'./yedekle.sh /var/www /etc "{v["sunucular"][0]} gece yedegi"', 3),
        (f"./rapor.sh {m['alan']} kritik", 2),
        (f'./bildir.sh "{m["kisi"].split(" (")[0]}" {m["alan"]} "port 22 acik"', 3),
        (f"./kontrol.sh {v['sunucular'][0]} {v['sunucular'][1]} {v['ag']}.1 {v['ag']}.2 hizli", 5),
    ]
    komut, n = rng.choice(sablonlar)
    tirnaksiz = len(komut.replace('"', "").split()) - 1
    return komut, n, tirnaksiz


def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    gun = u.gun(rng)
    s1, s2 = v["sunucular"]
    klasorler = {}
    for sunucu in (s1, s2):
        n_log = rng.randint(3, 9)
        adlar = rng.sample(LOG_ADLARI, n_log)
        tuzak = [f"{rng.choice(adlar)}.log.{rng.randint(1, 4)}", f"{rng.choice(adlar)}.log.gz"]
        tuzak = rng.sample(tuzak + list(v["tuzak"]), rng.randint(2, 4))
        klasorler[sunucu] = {"log": [a + ".log" for a in adlar], "tuzak": sorted(set(tuzak))}
    yedek = f"{gun:%Y-%m-%d}_{v['yedek_ek']}.tar.gz"
    komut, arg_n, tirnaksiz = _arg_sorusu(rng, m, v)
    return {
        "vaka": f"{m['ad']} — her sabahki elle log kontrolünü betiğe dökmek",
        "musteri": m,
        "v": v,
        "klasorler": klasorler,
        "yedek": yedek,
        "arg_tirnaksiz": tirnaksiz,
        "metin": {
            "musteri": m["ad"], "kisi": m["kisi"], "olay": v["olay"], "kod": m["kod"],
            "log_kok": v["log_kok"], "s1": s1, "s2": s2, "yedek_kok": v["yedek_kok"],
            "yedek": yedek, "ag": v["ag"], "arg_komut": komut, "alan": m["alan"],
        },
        "cevaplar": {
            "bayrak": u.bayrak(rng, "nobet_devri"),
            "arg_sayisi": arg_n,
        },
    }


ILK_SH = """#!/bin/bash
# ilk.sh — ilk betiğin
echo "Merhaba, hacker."
echo "Bugün: $(date +%d.%m.%Y)"
echo "Bu betiği çalıştıran kullanıcı: $(whoami)"
"""

ARGUMANLAR_SH = """#!/bin/bash
# argumanlar.sh — betiğe verilen argümanlar nereye gider?
echo "Betiğin adı (\\$0)        : $0"
echo "Birinci argüman (\\$1)    : $1"
echo "İkinci argüman (\\$2)     : $2"
echo "Argüman sayısı (\\$#)     : $#"
"""

KULLANIM_SH = """#!/bin/bash
# kullanim.sh — her düzgün betiğin başındaki kalıp
if [ -z "$1" ]; then
    echo "Kullanım: $0 <hedef>"
    exit 1
fi
echo "Hedef işleniyor: $1"
"""

SABLON_SH = """#!/bin/bash
# sablon.sh — kendi betiklerin için iskelet (kopyala: cp ornekler/sablon.sh yeni.sh)

# 1) Girdi kontrolü: eksikse kullanım mesajı ve hata koduyla çık
if [ -z "$1" ]; then
    echo "Kullanım: $0 <arguman>"
    exit 1
fi

# 2) Argümanı anlamlı bir değişkene al (= etrafında BOŞLUK YOK)
hedef="$1"

# 3) Asıl iş
echo "[*] İşleniyor: $hedef"
"""


def _nobetci(s: dict) -> str:
    kodlu = base64.b64encode(s["cevaplar"]["bayrak"].encode()).decode()
    return f"""#!/bin/bash
# nobetci.sh — nöbet devri kontrolü (Mert Y.)
# Not: geçen ay biri izinleri bozmuş, düzeltmeyi unutmayın.
if [ -z "$1" ]; then
    echo "Kullanım: $0 <musteri_kodu>"
    echo "Kodlar için: cat musteriler.txt"
    exit 1
fi
if [ "$1" != "{s['musteri']['kod']}" ]; then
    echo "[-] '$1' bu haftanın müşterisi değil. Brifingi tekrar oku."
    exit 2
fi
echo "[+] Nöbet devri onaylandı: {s['musteri']['ad']}"
echo "[+] Devir kodu: $(echo '{kodlu}' | base64 -d)"
"""


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    m = s["musteri"]
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} — sabah kontrolü laboratuvarı\n\n"
          f"{v['log_kok']}/   : iki sunucunun log klasörlerinin kopyası\n"
          f"{v['yedek_kok']}/ : gece yedekleri\n"
          "ornekler/    : eğitimde kullanılan örnek betikler\n"
          "araclar/     : Mert'in bıraktığı betikler\n\n"
          "Kendi betiklerini bu klasöre (lab'ın köküne) yaz: selam.sh, logsay.sh, ipler.sh, varmi.sh\n")
    u.yaz(lab / "ornekler" / "ilk.sh", ILK_SH, mod=0o644)
    u.yaz(lab / "ornekler" / "argumanlar.sh", ARGUMANLAR_SH, mod=0o755)
    u.yaz(lab / "ornekler" / "kullanim.sh", KULLANIM_SH, mod=0o755)
    u.yaz(lab / "ornekler" / "sablon.sh", SABLON_SH, mod=0o644)
    for sunucu, k in s["klasorler"].items():
        for ad in k["log"]:
            u.yaz(lab / v["log_kok"] / sunucu / ad, f"{sunucu} {ad} kaydı\n")
        for ad in k["tuzak"]:
            u.yaz(lab / v["log_kok"] / sunucu / ad, f"{ad}\n")
    yk = lab / v["yedek_kok"]
    u.yaz(yk / s["yedek"], "yedek arşivi (laboratuvar kopyası)\n")
    u.yaz(yk / "eski" / "OKUBENI.txt", "Eski yedekler arşive taşındı.\n")
    u.yaz(yk / "yedek_listesi.txt", f"{s['yedek']}\n")
    kodlar = ["pazarix", "medora", "ferahbank", "kuzgun", "yesiltepe", "paramix", "atolye"]
    satirlar = [f"{k:<10} {musteri(k)['ad']}" for k in kodlar]
    u.yaz(lab / "musteriler.txt", "# kod      müşteri\n" + "\n".join(satirlar) + "\n")
    u.yaz(lab / "araclar" / "nobetci.sh", _nobetci(s), mod=0o644)


# ---------------------------------------------------------------- referans çözümler

SELAM_SH = """#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: $0 <ad>"
    exit 1
fi
echo "Merhaba, $1"
"""

LOGSAY_SH = """#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: $0 <klasor>"
    exit 1
fi
if [ ! -d "$1" ]; then
    echo "Hata: $1 diye bir klasör yok."
    exit 1
fi
sayi=0
for dosya in "$1"/*.log; do
    if [ -f "$dosya" ]; then
        sayi=$((sayi + 1))
    fi
done
echo "$sayi log dosyası var"
"""

IPLER_SH = """#!/bin/bash
if [ $# -ne 3 ]; then
    echo "Kullanım: $0 <ag_oneki> <ilk> <son>   (örnek: $0 10.0.0 1 5)"
    exit 1
fi
onek="$1"
for i in $(seq "$2" "$3"); do
    echo "$onek.$i"
done
"""

VARMI_SH = """#!/bin/bash
if [ -z "$1" ]; then
    echo "Kullanım: $0 <dosya>"
    exit 1
fi
if [ -f "$1" ]; then
    echo "bulundu"
else
    echo "yok"
fi
"""


def _md(betik: str, ad: str) -> str:
    return f"Örnek bir `{ad}`:\n\n```\n{betik.rstrip()}\n```\n\nKaydet, `chmod +x {ad}` yap ve `./{ad}` ile kendin de dene."


# ---------------------------------------------------------------- denetimler

def _yakin(mesaj: str) -> Sonuc:
    return Sonuc(False, mesaj, yakin=True)


def _selam_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return _yakin(hata)
    rng = random.Random()
    adlar = [rng.choice(["Deniz", "Selin", "Mert"]), rng.choice(["Şule", "Çağrı", "Gökçe", "Ilgın", "Ömer"])]
    for ad in adlar:
        c = calistir(ad)
        cokme = calistir.cokme(c)
        if cokme:
            return Sonuc(False, f"`{calistir.goster(ad)}` çalışırken: {cokme}")
        cikti = norm(c.stdout)
        if re.search(r"merhaba,?\s+" + re.escape(norm(ad)), cikti):
            if c.kod != 0:
                return _yakin(f"Selamı doğru yazdın ama çıkış kodu {c.kod}. Başarılı çalışmada betik 0 ile "
                              "bitmeli; sondaki gereksiz bir `exit 1` olabilir mi?")
            continue
        if "$1" in c.stdout:
            return _yakin("Çıktıda `$1` harfi harfine görünüyor. Tek tırnak içinde değişkenler açılmaz: "
                          "`echo \"Merhaba, $1\"` gibi çift tırnak kullan.")
        if "merhaba" in cikti:
            return _yakin(f"`{calistir.goster(ad)}` çalıştırınca \"Merhaba, {ad}\" bekliyordum. Merhaba "
                          "yazıyorsun ama verdiğim adı değil; birinci argüman `$1`'dedir." + bt.ozet(c))
        return Sonuc(False, f"`{calistir.goster(ad)}` çalıştırınca \"Merhaba, {ad}\" satırını bekliyordum."
                     + bt.ozet(c))
    return Sonuc(True, "Betiğin argümansız çalışınca kullanım mesajı verip 1 ile çıkıyor, adla "
                       "çalışınca selamlıyor. Bu iki parça, yazacağın her aracın iskeleti olacak.")


def _sayi_son_satir(c: bt.Cikti, yol: str) -> list:
    satirlar = [s for s in c.stdout.replace(yol, " ").splitlines() if s.strip()]
    return bt.sayilar(satirlar[-1]) if satirlar else []


def _logsay_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return _yakin(hata)
    olmayan = str(Path(tempfile.gettempdir()) / f"hy_olmayan_{random.randint(1000, 9999)}")
    c = calistir(olmayan)
    if c.zaman_asimi or c.hata:
        return Sonuc(False, calistir.cokme(c) or "Betik çalışmadı.")
    if c.kod == 0:
        return _yakin("Var olmayan bir klasör verdiğimde betiğin 0 koduyla (başarı) bitti. Klasörün varlığını "
                      "`[ ! -d \"$1\" ]` ile kontrol et; yoksa bir hata mesajı yazıp `exit 1` ile çık."
                      + bt.ozet(c))
    s = b.senaryo
    lab_klasor = Path(b.lab) / s["v"]["log_kok"] / s["v"]["sunucular"][0]
    gecici = Path(tempfile.mkdtemp(prefix="hy_logsay_"))
    try:
        rng = random.Random()
        adlar = rng.sample(["uygulama", "hata", "erisim", "guvenlik", "sistem", "odeme", "kargo", "randevu"],
                           rng.randint(2, 6))
        for ad in adlar:
            (gecici / f"{ad}.log").write_text("x\n")
        for ad in rng.sample(["eski.log.gz", "erisim.log.old", "katalog.txt", "notlar.txt", "blog.md"], 3):
            (gecici / ad).write_text("x\n")
        for klasor in (lab_klasor, gecici):
            if not klasor.is_dir():
                return Sonuc(False, f"{klasor} klasörü yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
            dosyalar = [p for p in klasor.iterdir() if p.is_file()]
            beklenen = sum(1 for p in dosyalar if p.name.endswith(".log"))
            icinde_log = sum(1 for p in dosyalar if "log" in p.name)
            c = calistir(str(klasor))
            cokme = calistir.cokme(c)
            if cokme:
                return Sonuc(False, f"`{calistir.goster(klasor)}` çalışırken: {cokme}")
            sayilar = _sayi_son_satir(c, str(klasor))
            if beklenen in sayilar:
                continue
            if not sayilar:
                return _yakin(f"`{calistir.goster(klasor)}` çıktısının son satırında bir sayı bulamadım. "
                              "Sonucu en sonda yaz, örn. `echo \"$sayi log dosyası var\"`." + bt.ozet(c))
            if icinde_log in sayilar and icinde_log != beklenen:
                return _yakin(f"{icinde_log} saydın ama sadece adı `.log` ile BİTEN {beklenen} dosya var. "
                              "`eski.log.gz`, `x.log.1` ya da `katalog.txt` gibi adında \"log\" geçenleri "
                              "de saymışsın. Desen `*.log` olmalı (grep kullanıyorsan `'\\.log$'`).")
            if len(dosyalar) in sayilar:
                return _yakin(f"Klasördeki bütün dosyaları ({len(dosyalar)}) saymışsın; sadece `.log` ile "
                              f"bitenler ({beklenen}) sayılmalı.")
            if klasor == gecici:
                return _yakin(f"Lab klasöründe doğru saydın ama farklı bir klasörde ({beklenen} log dosyası "
                              f"olan) {sayilar[-1]} dedin. Klasör yolunu sabit yazmış olabilir misin? "
                              "Hep `$1`'i kullan.")
            return Sonuc(False, f"`{klasor.name}` klasöründe {beklenen} tane .log dosyası var, betiğin "
                         f"{sayilar[-1]} dedi." + bt.ozet(c))
    finally:
        shutil.rmtree(gecici, ignore_errors=True)
    return Sonuc(True, "logsay.sh hem eksik argümanı hem olmayan klasörü yakalıyor, `.log` dosyalarını da "
                       "doğru sayıyor. Sabah işinin yarısı artık tek komut.")


def _ipler_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    ag = b.senaryo["v"]["ag"]
    hata = bt.kullanim_denetle(calistir, ag)
    if hata:
        return _yakin(hata + "\n    (Burada sadece ağ önekini verdim; üç argüman gelmediyse kullanım mesajı "
                             "bekliyorum. `$#` ile argüman sayısını kontrol et.)")
    rng = random.Random()
    denemeler = [(ag, rng.randint(1, 5), rng.randint(6, 12)),
                 (f"10.{rng.randint(1, 250)}.{rng.randint(1, 250)}", rng.randint(20, 40), rng.randint(42, 50))]
    onceki = None
    for onek, bas, son in denemeler:
        beklenen = [f"{onek}.{i}" for i in range(bas, son + 1)]
        c = calistir(onek, bas, son)
        cokme = calistir.cokme(c)
        if cokme:
            return Sonuc(False, f"`{calistir.goster(onek, bas, son)}` çalışırken: {cokme}")
        bulunan = bt.ipler(c.stdout)
        if bulunan == beklenen or (sorted(bulunan) == sorted(beklenen) and len(set(bulunan)) == len(bulunan)):
            onceki = bulunan
            continue
        nasil = calistir.goster(onek, bas, son)
        if not bulunan and ("$onek" in c.stdout or "$1" in c.stdout or "$i" in c.stdout):
            return _yakin("Çıktıda değişken adları harfi harfine görünüyor (`$1`, `$i`...). Tek tırnak içinde "
                          "değişkenler açılmaz; çift tırnak kullan: `echo \"$onek.$i\"`.")
        if onceki is not None and bulunan == onceki:
            return _yakin("İkinci denemede farklı argümanlar verdim ama aynı IP'leri yazdın. Değerleri sabit "
                          "yazmış olabilir misin? `$1`, `$2`, `$3`'ü kullan.")
        if bulunan == beklenen[:-1]:
            return _yakin(f"`{nasil}` son IP'yi ({beklenen[-1]}) yazmadı. `seq {bas} {son}` iki ucu da dahil "
                          "eder; döngünün bitişini kontrol et.")
        if bulunan == beklenen[1:]:
            return _yakin(f"`{nasil}` ilk IP'yi ({beklenen[0]}) atladı. Başlangıç değeri `$2` olmalı.")
        return Sonuc(False, f"`{nasil}` çalıştırınca {beklenen[0]} ile {beklenen[-1]} arasındaki "
                     f"{len(beklenen)} IP'yi bekliyordum; betiğin {len(bulunan)} IP yazdı." + bt.ozet(c))
    return Sonuc(True, "ipler.sh doğru çalışıyor. Bir sonraki bölümde bu döngünün içine bir bağlantı "
                       "denemesi koyacaksın ve elinde gerçek bir keşif aracı olacak.")


def _varmi_denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return _yakin(hata)
    s = b.senaryo
    yk = Path(b.lab) / s["v"]["yedek_kok"]
    var = yk / s["yedek"]
    if not var.is_file():
        return Sonuc(False, f"{var} dosyası yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    yok = yk / f"{random.randint(2027, 2030)}-01-01_{s['v']['yedek_ek']}.tar.gz"
    klasor = yk / "eski"
    for yol, istenen in ((var, "bulundu"), (yok, "yok"), (klasor, "yok")):
        c = calistir(str(yol))
        cokme = calistir.cokme(c)
        if cokme:
            return Sonuc(False, f"`{calistir.goster(yol)}` çalışırken: {cokme}")
        cikti = norm(c.stdout)
        buldu = "bulundu" in cikti
        yok_dedi = bool(re.search(r"\byok\b", cikti))
        if istenen == "bulundu" and buldu and not yok_dedi:
            continue
        if istenen == "yok" and yok_dedi and not buldu:
            continue
        if yol == klasor and buldu:
            return _yakin(f"`{klasor.name}` bir KLASÖR ama betiğin \"bulundu\" dedi. `-e` her türlü yolu kabul "
                          "eder; `-f` sadece normal dosya için doğru döner. `[ -f \"$1\" ]` kullan.")
        if yol == var:
            return Sonuc(False, f"Var olan bir dosyayı ({var.name}) verdim; sadece \"bulundu\" yazmalıydın."
                         + bt.ozet(c))
        return Sonuc(False, f"Olmayan bir dosya verdim ({yol.name}); sadece \"yok\" yazmalıydın." + bt.ozet(c))
    return Sonuc(True, "varmi.sh doğru: dosya varsa \"bulundu\", yoksa ya da klasörse \"yok\". Yedek "
                       "kontrolü artık tek satır.")


def _arg_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + 1:
        return "Betiğin kendi adını da saymış olabilirsin; `$0` argüman sayısına (`$#`) dahil değildir."
    if n == b.senaryo["arg_tirnaksiz"] and n != beklenen:
        return "Tırnak içindeki boşluklu metin tek bir argümandır; tırnakları hesaba kat."
    return None


# ---------------------------------------------------------------- test çözücüsü

def coz(lab: Path, s: dict) -> dict:
    """Oyuncuyu taklit eder: referans betikleri lab'a yazar, Mert'in betiğini düzeltip çalıştırır."""
    for ad, metin in (("selam.sh", SELAM_SH), ("logsay.sh", LOGSAY_SH), ("ipler.sh", IPLER_SH),
                      ("varmi.sh", VARMI_SH)):
        bt.betik_yaz(lab / ad, metin)
    kod = subprocess.run(["bash", "-c", "grep -v '^#' musteriler.txt | grep -i '" + s["musteri"]["ad"].split()[0]
                          + "' | awk '{print $1}'"], cwd=lab, capture_output=True, text=True).stdout.split()[0]
    cikti = subprocess.run(["bash", "-c", f"chmod +x araclar/nobetci.sh && ./araclar/nobetci.sh {kod}"],
                           cwd=lab, capture_output=True, text=True).stdout
    bayrak = re.search(r"FLAG\{[^}]+\}", cikti).group(0)
    from hy.motor.kontrol import Baglam as B
    secmeli = {no: SEVIYE.gorevler[no - 1].kontrol.cevabi_goster(B(s, lab, no))[0] for no in (7, 8)}
    # $# sorusu: komutu argümanları sayan küçük bir betikle gerçekten çalıştır
    komut = s["metin"]["arg_komut"]
    ad = komut.split()[0]
    bt.betik_yaz(lab / ".arg_say" / ad[2:], '#!/bin/bash\necho "$#"\n')
    arg_n = subprocess.run(["bash", "-c", komut], cwd=lab / ".arg_say", capture_output=True, text=True).stdout.strip()
    shutil.rmtree(lab / ".arg_say", ignore_errors=True)
    return {1: "", 2: "", 3: "", 4: "", 5: bayrak, 6: arg_n, **secmeli}


# ---------------------------------------------------------------- eğitim

ADIMLAR = [
    Adim("Betik: komutların bir dosyada dizilmiş hali", """
Cilt 1'de komutları tek tek yazdın. Aynı komutları bir dosyaya alt alta yazıp tek seferde
çalıştırırsan elinde bir **betik** (script) olur. Mert'in sözüyle: "Bir şeyi üçüncü kez
elle yapıyorsan, o iş bir betik olmak istiyor demektir."

Laboratuvarındaki ilk örneğe bak:
""", komut="cat ornekler/ilk.sh", sonra="""
İlk satır `#!/bin/bash` **shebang**'tir: işletim sistemine "bu dosyayı bash ile çalıştır"
der. `$(date ...)` ise bir komutun çıktısını metnin içine gömer; buna **komut ikamesi**
(command substitution) denir.
"""),
    Adim("Çalıştırma izni", """
Bir dosyayı `./dosya` diye çalıştırmak için **çalıştırma izni** (x) gerekir; yoksa
"Permission denied" alırsın (Cilt 1, Bölüm 5). `./` ise "bu klasördeki dosya" demektir;
Linux, PATH dışındaki programları sen açıkça göstermeden çalıştırmaz.
""", komut="chmod +x ornekler/ilk.sh && ./ornekler/ilk.sh", sonra="""
`&&` "soldaki başarılıysa sağdakini çalıştır" demektir. Kendi betiklerinde de sıra hep
budur: yaz, `chmod +x`, `./betik.sh` ile dene.
"""),
    Adim("Değişkenler ve boşluk tuzağı", """
Bash'te değişken `ad="deger"` diye atanır, `$ad` diye kullanılır. Kural katıdır: **eşittir
işaretinin iki yanında boşluk olmaz.** Yanlışını bilerek dene:
""", komut='ad = "veli"', sonra="""
Bash, `ad = "veli"` satırını "`ad` adlı bir komutu `=` ve `veli` argümanlarıyla çalıştır"
diye okudu ve `ad: command not found` dedi. Doğrusu `ad="veli"`. Bu hatayı ilk
betiklerinde mutlaka yapacaksın; mesajı tanıman yeter.
"""),
    Adim("Argümanlar: $1, $# ve $0", """
İyi araçlar girdiyi dışarıdan alır. Komut satırında betiğin adından sonra yazdıkların
sırayla `$1`, `$2`... olur. `$#` kaç argüman verildiğini, `$0` betiğin kendi adını
söyler. Örnek betik bunları ekrana basıyor:
""", komut="./ornekler/argumanlar.sh <<alan>> 443", sonra="""
`$#` 2 çıktı: betiğin adı (`$0`) sayılmaz. Tırnak içindeki boşluklu bir metin
(`"Kuzgun Lojistik"`) **tek** argümandır.
"""),
    Adim("Kullanım mesajı ve çıkış kodu", """
Her düzgün betik, girdisi eksikse ne beklediğini söyler ve **sıfırdan farklı bir çıkış
koduyla** biter. `[ -z "$1" ]` "birinci argüman boş mu?" diye sorar. Son çalışan komutun
çıkış kodu `$?` içindedir:
""", komut='./ornekler/kullanim.sh; echo "çıkış kodu: $?"', sonra="""
Kod 1 çıktı: "hata". Sıfır "başarı" demektir. `cat ornekler/kullanim.sh` ile kalıba bak;
yazacağın her betik bununla başlayacak. Sık kullanılan testler: `-z` (boş mu), `-n` (dolu
mu), `-f` (dosya var mı), `-d` (klasör var mı), `"$a" = "$b"` (metin eşit mi), `-eq`
(sayı eşit mi), `-ne` (sayı farklı mı). `$#` ile birleşince: `if [ $# -ne 3 ]; then`.
"""),
    Adim("Döngü ve seq", """
Otomasyonun kalbi döngüdür. `seq 1 5` 1'den 5'e (**ikisi de dahil**) sayı üretir;
`for` her birini sırayla `$i`'ye koyar:
""", komut='for i in $(seq 1 5); do echo "<<ag>>.$i"; done', sonra="""
**Hacker gözüyle:** "Tek hedef için çalışan komutu al, bir `for` döngüsüne koy, 254 hedefe
uygula." Pek çok basit tarama aracının özü budur. Bir sonraki bölümde bu döngünün içine
bir bağlantı denemesi koyacaksın.
"""),
    Adim("Dosya ve klasör testleri", """
`-d` klasörün, `-f` normal bir dosyanın varlığını sınar. `-e` ise ikisini ayırmaz, her türlü
yol için doğrudur. `<<log_kok>>` klasörü var mı?
""", komut='[ -d <<log_kok>> ] && echo "klasör var" || echo "klasör yok"', sonra="""
`A && B || C` kısa bir if/else'tir. Betiklerde okunurluk için uzun `if ... then ... else
... fi` biçimini tercih et; `-d` ile `-f` arasındaki farkı da görevlerde arayacağım.
"""),
    Adim("Betiği nasıl yazacaksın, oyun nasıl deneyecek?", """
Betiği `nano selam.sh` ile yaz (Ctrl+O kaydet, Enter, Ctrl+X çık). Hazır iskelet
istersen `cp ornekler/sablon.sh selam.sh` ile kopyala ve düzenle. Sonra `chmod +x selam.sh`
ve `./selam.sh` ile **önce kendin** dene.

Saha görevinde `cevap 1` yazdığında oyun lab'daki `selam.sh`'ı bulur ve farklı girdilerle
çalıştırır: argümansız, farklı adlarla, bazen senin hiç görmediğin geçici klasörlerle.
Yani cevabı ezberleyemezsin; betiğin gerçekten doğru çalışmalı. Bir sorun olursa ne
gördüğünü ve neyi beklediğini söyler. İskelete bir göz at:
""", komut="cat ornekler/sablon.sh"),
]


# ---------------------------------------------------------------- görevler

GOREVLER = [
    Gorev("Isınma: `selam.sh` adında bir betik yaz. Bir adı argüman olarak alıp `Merhaba, <ad>` "
          "yazsın. Argüman verilmezse `Kullanım: ...` mesajı basıp **1** koduyla çıksın.",
          bt.BetikKontrol("selam.sh", _selam_denetle, _md(SELAM_SH, "selam.sh")),
          ("İki parça var: önce argüman boş mu diye bak, sonra selamla.",
           "Boşluk testi `[ -z \"$1\" ]`; içindeyse `echo \"Kullanım: $0 <ad>\"` ve `exit 1`. Selam için "
           "`echo \"Merhaba, $1\"`.",
           "İskelet:\n\n```\n#!/bin/bash\nif [ -z \"$1\" ]; then\n    echo \"Kullanım: ...\"\n    "
           "exit ...\nfi\necho \"Merhaba, ...\"\n```\n\nSonra `chmod +x selam.sh` ve `./selam.sh Deniz` ile dene."),
          puan=30, baslik="İlk betik"),
    Gorev("<<kisi>> her sabah log klasörlerini elle sayıyor. `logsay.sh` yaz: (1) argümansız "
          "çalışınca kullanım mesajı + `exit 1`; (2) verilen klasör yoksa hata mesajı + `exit 1`; "
          "(3) klasördeki adı **`.log` ile biten** dosyaların sayısını çıktının **son satırına** "
          "yazsın. Kendin `./logsay.sh <<log_kok>>/<<s1>>` ile dene.",
          bt.BetikKontrol("logsay.sh", _logsay_denetle, _md(LOGSAY_SH, "logsay.sh")),
          ("Klasörde adında \"log\" geçen ama `.log` ile bitmeyen dosyalar da var. Önce `ls -la "
           "<<log_kok>>/<<s1>>` ile bak.",
           "Klasör kontrolü `[ ! -d \"$1\" ]`. Sayım için ya `for dosya in \"$1\"/*.log` döngüsünde bir sayaç "
           "(`sayi=$((sayi + 1))`) ya da `ls \"$1\" | grep -c '\\.log$'`.",
           "İskelet:\n\n```\n#!/bin/bash\nif [ -z \"$1\" ]; then ... exit 1; fi\nif [ ! -d \"$1\" ]; then "
           "echo \"Hata: ...\"; exit 1; fi\nsayi=$(ls \"$1\" | grep -c '...')\necho \"$sayi log dosyası var\"\n```"),
          puan=50, baslik="Log sayacı"),
    Gorev("Keşif hazırlığı: `ipler.sh` yaz. Üç argüman alsın: ağ öneki, ilk ve son sayı. "
          "`./ipler.sh <<ag>> 3 7` çalışınca `<<ag>>.3`'ten `<<ag>>.7`'ye kadar her IP'yi ayrı satıra "
          "yazsın (iki uç dahil). Üç argüman gelmezse kullanım mesajı + `exit 1`.",
          bt.BetikKontrol("ipler.sh", _ipler_denetle, _md(IPLER_SH, "ipler.sh")),
          ("Argüman SAYISINI kontrol etmen gerekiyor; `$1`'in boş olup olmadığı yetmez.",
           "`if [ $# -ne 3 ]; then` ile başla. Döngü `for i in $(seq \"$2\" \"$3\")`.",
           "İskelet:\n\n```\n#!/bin/bash\nif [ $# -ne 3 ]; then ... exit 1; fi\nonek=\"$1\"\nfor i in "
           "$(seq ...); do\n    echo \"$onek.$i\"\ndone\n```"),
          puan=40, baslik="IP üreteci"),
    Gorev("Yedek kontrolü: `varmi.sh` yaz. Bir dosya yolunu argüman alsın; o yolda **normal bir "
          "dosya** varsa `bulundu`, yoksa `yok` yazsın (klasörler dosya sayılmaz). Argümansızsa "
          "kullanım mesajı + `exit 1`. Dene: `./varmi.sh <<yedek_kok>>/<<yedek>>`",
          bt.BetikKontrol("varmi.sh", _varmi_denetle, _md(VARMI_SH, "varmi.sh")),
          ("Eğitimdeki test operatörlerinden biri tam olarak \"normal dosya var mı\" diye sorar.",
           "`-f` kullan; `-e` klasörlere de \"var\" der.",
           "İskelet:\n\n```\n#!/bin/bash\nif [ -z \"$1\" ]; then ... fi\nif [ -f \"$1\" ]; then\n    echo ...\n"
           "else\n    echo ...\nfi\n```"),
          puan=40, baslik="Var mı yok mu"),
    Gorev("Mert'in bıraktığı `araclar/nobetci.sh` betiği \"bozuk\" diye şikâyet var. Çalıştır, "
          "kullanım mesajının ne istediğini oku ve doğru argümanla çalıştırıp verdiği devir kodunu "
          "(bayrağı) gönder.",
          Bayrak("bayrak"),
          ("Önce çalıştırmayı dene: `./araclar/nobetci.sh`. Hata mesajı sana ilk sorunu söyleyecek.",
           "\"Permission denied\" çalıştırma izninin olmadığını söyler: `chmod +x`. Sonra kullanım mesajına göre "
           "bu haftanın müşteri kodunu `musteriler.txt`'de bul.",
           "`chmod +x araclar/nobetci.sh`, ardından `./araclar/nobetci.sh <kod>`. Kod, <<musteri>> satırının "
           "ilk sütunu."),
          puan=40, baslik="Bozuk betik"),
    Gorev("Bir betik şu komutla çalıştırılıyor:\n\n```\n<<arg_komut>>\n```\n\nBetiğin içinde `$#` kaç olur?",
          Sayi("arg_sayisi", sik_hatalar=_arg_hata),
          ("`$#` argüman sayısıdır. Betiğin adı bir argüman mı?",
           "Komut adından sonraki parçaları say; çift tırnak içindeki boşluklu metin tek parçadır.",
           "`./ornekler/argumanlar.sh` ile kendin dene: aynı argümanları ona ver ve `$#` satırını oku."),
          puan=25, baslik="$# kaç?"),
    Gorev("Yeni stajyer betiğine `hedef = \"<<alan>>\"` yazmış ve `hedef: command not found` "
          "hatası almış. Neden?",
          Secmeli([
              ("Bash, `hedef`'i komut, gerisini argüman sanıyor",
               "Doğru. `=` etrafında boşluk olunca Bash `hedef`'i komut, `=` ve değeri argüman sanır. "
               "Doğrusu `hedef=\"...\"`."),
              ("Bash'te değişken adları büyük harfle yazılmak zorunda",
               "Hayır; küçük harfli değişkenler sorunsuz çalışır. Sorun boşluklarda."),
              ("Değişken değerleri çift tırnak yerine tek tırnakla yazılmalı",
               "Tırnak türü burada sorun değil; `hedef=\"x\"` de `hedef='x'` de çalışır."),
              ("Değişkeni kullanmadan önce `export` ile tanımlamak gerekiyor",
               "`export` değişkeni alt süreçlere aktarır; atama için gerekmez."),
          ]),
          ("Hata mesajı `hedef`'in ne olduğunu sandığını söylüyor.",
           "Bash bir satırın ilk kelimesini neyin adı olarak okur?",
           "Eğitimdeki `ad = \"veli\"` denemesini hatırla."),
          puan=20, baslik="Boşluk tuzağı"),
    Gorev("Kullanım mesajını bastıktan sonra neden `exit 1` yazarız?",
          Secmeli([
              ("0 dışı kod \"hata\" demektir; çağıran betik bunu anlar",
               "Doğru. `./betik.sh && sonraki` zincirinde betik 1 ile biterse sonraki çalışmaz; otomasyonun "
               "temeli budur."),
              ("`exit 1` yazılmazsa kullanım mesajı ekranda hiç görünmez",
               "Mesaj `echo` ile zaten basılır. `exit 1` betiği durdurur ve hata kodunu bildirir."),
              ("Betiğin bir sonraki çalıştırmada aynı argümanı hatırlamasını sağlar",
               "Betikler çalıştırmalar arasında bir şey hatırlamaz; çıkış kodu sadece o çalışmanın sonucudur."),
              ("`exit 1` betiği bir saniye bekletip sonra kendiliğinden kapatır",
               "Bekleme yapmaz; betiği hemen sonlandırır ve 1 kodunu döndürür."),
          ]),
          ("Eğitimde `echo $?` ile neyi gördün?",
           "0 başarı, 0 dışı her şey hata. Bunu kim okur?",
           "Bir betiğin sonucunu başka bir betik ya da `&&` zinciri çıkış kodundan anlar."),
          puan=20, baslik="Çıkış kodu"),
]


SEVIYE = Seviye(
    kimlik="c03b01",
    cilt=3,
    bolum=1,
    baslik="Bash ile Betik Yazmak",
    brifing="""
Mert kahvesini masana bırakıp ekranını sana çeviriyor: "**<<musteri>>**'den <<kisi>>
aradı. <<olay>>"

"Bu işi betiğe çevireceğiz. Ama önce temel: shebang, çalıştırma izni, argüman, kullanım
mesajı, döngü. Bunlar oturmadan yazdığın her betik bir gün seni gece yarısı yarı yolda
bırakır. Bir de `araclar/` altına benim eski bir betiğimi koydum; birisi bozmuş, bakarsın."

Selin kapıdan ekliyor: "Bu cilt boyunca araçlarını sen yazacaksın, oyun da onları
deneyecek. `cevap` dediğinde betiğin senin hiç görmediğin girdilerle çalıştırılır;
ezber cevap işe yaramaz."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Bash, saldırganın sızdığı hemen her Linux makinede bulduğu dildir: orada Python olmayabilir
ama bash neredeyse her zaman vardır. Bu yüzden "tek hedefte çalışan komutu döngüye koy"
becerisi hem keşifte hem sızma sonrası işlerde seni nmap'siz, Python'suz bir makinede bile
ayakta tutar. Savunma tarafında aynı beceri sabah kontrollerini, yedek denetimini ve log
sayımını insan hatasından kurtarır. İki tarafın ortak dersi: girdiyi doğrula (`-z`, `-d`,
`-f`), değişkeni tırnakla, hatada sıfırdan farklı kodla çık.
""",
    gercek_hayat="""
- **Shellshock (2014):** Bash'in ortam değişkenlerindeki fonksiyon tanımlarını işlerken
  arkalarına eklenen komutları da çalıştırdığı ortaya çıktı (CVE-2014-6271). CGI betikleri
  üzerinden pek çok web sunucusunda uzaktan komut çalıştırmaya yol açtı. Bash'in her yerde
  olması, açığının da her yerde olması demekti.
- **Boş değişken felaketi:** 2015'te Linux için Steam istemcisinin bir betiği
  `rm -rf "$STEAMROOT/"*` satırını, değişken boş kaldığında da çalıştırdı ve bazı
  kullanıcıların dosyalarını sildi. Bu bölümdeki `[ -z "$1" ]` kontrolü tam olarak bu tür
  kazaları önlemek içindir.
- **Elindekiyle yaşamak (living off the land):** Olay müdahale raporlarında saldırganların
  zararlı yazılım indirmek yerine sistemde zaten bulunan bash, PowerShell gibi araçlarla
  çalıştığı sıkça anlatılır; iz bırakmamanın yolu budur. Savunmacının bash'i iyi okuması da
  bu yüzden şarttır.
""",
    sure_hedef_dk=45,
)
