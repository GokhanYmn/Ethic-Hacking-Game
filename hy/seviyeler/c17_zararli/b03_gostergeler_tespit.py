"""Cilt 17 · Bölüm 3 — Göstergeler, Tespit ve Lab.

Beceri: kurgusal bir analiz özetinden IOC (ihlal göstergesi) listesi ÇIKARMAK (zararlının kendi ürettiği adresler ve
dosyalar; meşru trafik IOC değildir), kurgusal proxy/DNS/dosya loglarında bu IOC'leri aramak ve basit bir tespit kuralı
YAZMAK (yanlış alarm üretmeyen, hepsini yakalayan). İmza tabanlı ve davranış tabanlı tespit farkını anlamak.

Vakalar: Ferah Bank, Kuzgun Lojistik, Medora Sağlık, Paramix. Her şey kurgusal ve düz metindir; zararlı kod yoktur.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Durum, Kume, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c17_zararli.ortak import hex_, sec_doldur, sh, sha256, vaka_sec

ALAN_ETIKETLERI = ["guncelleme-merkezi", "bulut-senkron", "surucu-destek", "hizmet-aktarici", "yardimci-servis"]
KAYNAKLAR = {"dns": "dns.log", "proxy": "proxy.log", "dosya": "dosya_olaylari.log"}
BENIGN_DOSYALAR = ["/home/{k}/belgeler/rapor.docx", "/var/log/sistem.log", "/tmp/oturum_{x}.tmp",
                   "/home/{k}/indirilenler/liste.pdf", "/home/{k}/.cache/onbellek_{x}.dat"]


def _ip_cakisir(a: str, b: str) -> bool:
    return a.startswith(b) or b.startswith(a)


def uret(rng):
    v = vaka_sec(rng)
    gun = u.gun(rng)
    t = gun + timedelta(hours=rng.randint(8, 12), minutes=rng.randint(0, 40))
    domain = rng.choice(ALAN_ETIKETLERI) + f"{rng.randint(1, 9)}.lab"
    ip = u.dis_ip(rng)
    sahte_komsu = ip.rsplit(".", 1)[0] + "." + next(str(n) for n in rng.sample(range(2, 254), 40)
                                                    if not _ip_cakisir(str(n), ip.rsplit(".", 1)[1]))
    ntp_ip, guncel_ip, portal_ip = u.dis_ip(rng), u.dis_ip(rng), u.dis_ip(rng)
    while len({ip, sahte_komsu, ntp_ip, guncel_ip, portal_ip}) < 5 or any(
            _ip_cakisir(x.rsplit(".", 1)[1], ip.rsplit(".", 1)[1]) and x.rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]
            for x in (ntp_ip, guncel_ip, portal_ip)):
        ntp_ip, guncel_ip, portal_ip = u.dis_ip(rng), u.dis_ip(rng), u.dis_ip(rng)
    port = rng.randint(20000, 45000)
    kalici = f"sistem_yardimcisi_{hex_(rng, 4)}.desktop"
    ornek_hash = sha256(f"ZARARSIZ EGITIM ORNEGI {hex_(rng, 24)}".encode())
    ntp_alan = "ntp.kurum.lab"
    guncel_alan = f"guncelleme.{v['alan']}"
    portal_alan = f"portal.{v['alan']}"
    # makineler
    n = 8
    sonlar = rng.sample(range(10, 90), n)
    cihazlar = [(f"10.20.{rng.randint(1, 9)}.{s}", f"{v['pc']}-{i + 1:02d}") for i, s in enumerate(sonlar)]
    bulasik = rng.sample(cihazlar, 3)
    dosya_makine = bulasik[0]
    # --- proxy.log
    proxy = []
    gurultu = [(ntp_alan, ntp_ip, 443), (guncel_alan, guncel_ip, 443), (portal_alan, portal_ip, 443)]
    for _ in range(46):
        c = rng.choice(cihazlar)
        a, i, p = rng.choice(gurultu)
        proxy.append((rng.randint(0, 3000), c[0], i, p, a, rng.choice([200, 200, 304]), rng.randint(200, 9000)))
    ioc_proxy = 0
    for c in bulasik:
        for _ in range(rng.randint(2, 4)):
            proxy.append((rng.randint(0, 3000), c[0], ip, port, domain, 200, rng.randint(100, 900)))
            ioc_proxy += 1
    for _ in range(2):   # aynı /24'te meşru bir adres (gevşek kalıpları yakalamak için)
        c = rng.choice(cihazlar)
        proxy.append((rng.randint(0, 3000), c[0], sahte_komsu, 443, f"cdn.{v['alan']}", 200, rng.randint(200, 900)))
    proxy.sort()
    # --- dns.log
    dns = []
    for _ in range(42):
        c = rng.choice(cihazlar)
        dns.append((rng.randint(0, 3000), c[0], rng.choice([ntp_alan, guncel_alan, portal_alan, f"cdn.{v['alan']}"])))
    n_dns = 0
    for c in bulasik:
        for _ in range(rng.randint(1, 3)):
            dns.append((rng.randint(0, 3000), c[0], domain))
            n_dns += 1
    dns.sort()
    # --- dosya olayları
    dosya = []
    for _ in range(30):
        c = rng.choice(cihazlar)
        sablon = rng.choice(BENIGN_DOSYALAR)
        dosya.append((rng.randint(0, 3000), c[1], "/".join(sablon.format(k="kullanici", x=hex_(rng, 4)).split("/"))))
    dosya.append((rng.randint(0, 3000), dosya_makine[1], f"/home/kullanici/.config/autostart/{kalici}"))
    dosya.sort()
    return {
        "vaka": f"{v['ad']} — IOC çıkarma ve tespit kuralı",
        "v": v, "t": t, "domain": domain, "ip": ip, "port": port, "kalici": kalici, "hash": ornek_hash,
        "ntp": (ntp_alan, ntp_ip), "guncel": (guncel_alan, guncel_ip), "portal": (portal_alan, portal_ip),
        "komsu": sahte_komsu, "cihazlar": cihazlar, "proxy": proxy, "dns": dns, "dosya": dosya,
        "bulasik": [c[0] for c in bulasik], "dosya_ip": dosya_makine[0],
        "metin": {"musteri": v["ad"], "pc": v["pc"], "hikaye": v["hikaye"], "ntp_ip": ntp_ip},
        "cevaplar": {"bulasik": [c[0] for c in bulasik], "dns_sayisi": n_dns, "dosya_ip": dosya_makine[0],
                     "_ioc_proxy": ioc_proxy},
    }


def _zaman(s, saniye) -> str:
    return f"{s['t'] + timedelta(seconds=saniye):%Y-%m-%d %H:%M:%S}"


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    u.yaz(lab / "OKUBENI.txt",
          f"{v['ad']} — {v['pc']} makineleri için KURGUSAL analiz özeti ve loglar. Hiçbir dosya zararlı değildir.\n"
          "Selin'den not: Bir zararlıyı analiz ettik. Şimdi çıkan göstergelerle kurumun loglarında iz sürüp bir tespit kuralı yazacaksın.\n")
    u.yaz(lab / "analiz" / "ozet.txt",
          "ANALİZ ÖZETİ (kurgusal sandbox + statik analiz sonucu)\n\n"
          "Zararlı örneğin KENDİ ürettiği göstergeler:\n"
          f"  alan adı : {s['domain']}\n"
          f"  IP       : {s['ip']}\n"
          f"  port     : {s['port']}\n"
          f"  sha256   : {s['hash']}\n"
          f"  dosya    : {s['kalici']}\n\n"
          "Analiz sırasında görülen MEŞRU trafik (IOC DEĞİL, sandbox'ın kendi trafiği):\n"
          f"  [meşru] alan adı : {s['ntp'][0]}   IP: {s['ntp'][1]}   (saat eşitleme)\n"
          f"  [meşru] alan adı : {s['guncel'][0]}   IP: {s['guncel'][1]}   (işletim sistemi güncellemesi)\n"
          f"  [meşru] alan adı : {s['portal'][0]}   IP: {s['portal'][1]}   (kurum portalı)\n")
    u.yaz(lab / "ioc_bicimi.txt",
          "IOC dosyası biçimi (ioc.txt, bu klasörde oluştur)\n"
          "  Her satır:  tür: değer          Türler: alan, ip, sha256, dosya\n"
          "  Örnek (başka bir vakadan, KURGUSAL):\n"
          "    alan: ornek-baska.lab\n"
          "  Kural: yalnızca zararlının KENDİ ürettiği göstergeler yazılır; meşru trafik IOC değildir.\n")
    u.yaz(lab / "kural_bicimi.txt",
          "Basit tespit kuralı biçimi (kural.txt, bu klasörde oluştur)\n"
          "  ad: <kısa ad>\n"
          "  kaynak: dns | proxy | dosya        (hangi logda aranacak: dns.log, proxy.log, dosya_olaylari.log)\n"
          "  ara: <metin>                       (satırda büyük/küçük harf fark etmeksizin geçmesi gereken metin)\n"
          "  esik: <sayı>                       (en az kaç satır eşleşirse alarm)\n"
          "İyi kural: bütün zararlı satırları yakalar (kaçırmaz), meşru satırlarda alarm vermez (yanlış alarm yok).\n")
    u.yaz(lab / "envanter" / "cihazlar.txt",
          "# ip hostname\n" + "".join(f"{ip} {ad}\n" for ip, ad in s["cihazlar"]))
    u.yaz(lab / "loglar" / "proxy.log",
          "# zaman kaynak_ip -> hedef_ip:port hedef_alan durum bayt   (KURGUSAL proxy logu)\n" +
          "".join(f"{_zaman(s, z)} {src} -> {d}:{p} {a} {k} {b}\n" for z, src, d, p, a, k, b in s["proxy"]))
    u.yaz(lab / "loglar" / "dns.log",
          "# zaman kaynak_ip sorgu alan tür   (KURGUSAL DNS logu)\n" +
          "".join(f"{_zaman(s, z)} {src} sorgu {a} A\n" for z, src, a in s["dns"]))
    u.yaz(lab / "loglar" / "dosya_olaylari.log",
          "# zaman hostname olay yol   (KURGUSAL dosya olayı logu)\n" +
          "".join(f"{_zaman(s, z)} {h} DOSYA_OLUSTU {y}\n" for z, h, y in s["dosya"]))


def coz(lab: Path, s: dict) -> dict:
    sh("alan=$(grep -m1 'alan adı' analiz/ozet.txt | awk '{print $NF}'); "
       "ip=$(grep -m1 'IP ' analiz/ozet.txt | awk '{print $NF}'); "
       "h=$(grep -m1 'sha256' analiz/ozet.txt | awk '{print $NF}'); "
       "f=$(grep -m1 'dosya ' analiz/ozet.txt | awk '{print $NF}'); "
       "printf 'alan: %s\\nip: %s\\nsha256: %s\\ndosya: %s\\n' $alan $ip $h $f > ioc.txt", lab)
    ip = sh("grep '^ip:' ioc.txt | awk '{print $2}'", lab)
    alan = sh("grep '^alan:' ioc.txt | awk '{print $2}'", lab)
    dosya = sh("grep '^dosya:' ioc.txt | awk '{print $2}'", lab)
    bulasik = sh(f"grep -F '{ip}:' loglar/proxy.log | awk '{{print $3}}' | sort -u | tr '\\n' ' '", lab)
    dns_n = sh(f"grep -c -F '{alan}' loglar/dns.log", lab)
    host = sh(f"grep -F '{dosya}' loglar/dosya_olaylari.log | awk '{{print $3}}'", lab)
    dip = sh(f"awk -v h={host} '$2==h {{print $1}}' envanter/cihazlar.txt", lab)
    sh(f"printf 'ad: zararli_alan_dns\\nkaynak: dns\\nara: {alan}\\nesik: 1\\n' > kural.txt", lab)
    return sec_doldur({2: bulasik, 3: dns_n, 4: dip}, GOREVLER, lab, s)


# ----------------------------------------------------------------------------- durum kontrolleri

def _oku(b, ad: str):
    for d in (b.lab, b.calisma_dizini):
        if d and (Path(d) / ad).is_file():
            return (Path(d) / ad).read_text(encoding="utf-8", errors="replace")
    return None


def _anahtar_deger(metin: str) -> list:
    sonuc = []
    for satir in metin.splitlines():
        if ":" in satir and not satir.lstrip().startswith("#"):
            k, _, d = satir.partition(":")
            sonuc.append((k.strip().lower(), d.strip()))
    return sonuc


def _ioc_kontrol(b) -> Sonuc:
    metin = _oku(b, "ioc.txt")
    if metin is None:
        return Sonuc(False, "`ioc.txt` bulunamadı. Bu klasörde oluştur (`ioc_bicimi.txt` biçimine bak).")
    s = b.senaryo
    kv = _anahtar_deger(metin)
    degerler = {k: [d.lower() for kk, d in kv if kk == k] for k in ("alan", "ip", "sha256", "dosya")}
    eksik = []
    if s["domain"].lower() not in degerler["alan"]:
        eksik.append("`alan:` satırında zararlının alan adı yok")
    if s["ip"] not in degerler["ip"]:
        eksik.append("`ip:` satırında zararlının IP'si yok")
    if s["hash"].lower() not in degerler["sha256"]:
        eksik.append("`sha256:` satırında örneğin özeti yok")
    meşru = [s["ntp"][0], s["ntp"][1], s["guncel"][0], s["guncel"][1], s["portal"][0], s["portal"][1]]
    gurultu = [m for m in meşru if m.lower() in metin.lower()]
    if gurultu:
        return Sonuc(False, f"Listede meşru bir adres var: {gurultu[0]}. IOC yalnızca zararlının **kendi** ürettiği göstergelerdir.",
                     yakin=True)
    if eksik:
        return Sonuc(False, "Eksik: " + "; ".join(eksik) + ".", yakin=len(eksik) < 3)
    return Sonuc(True)


def _satirlar(b, kaynak: str) -> list:
    yol = b.lab / "loglar" / KAYNAKLAR[kaynak]
    return [x for x in yol.read_text(encoding="utf-8").splitlines() if x and not x.startswith("#")]


def _ioc_satiri(s, kaynak: str, satir: str) -> bool:
    if kaynak == "dns":
        return s["domain"] in satir
    if kaynak == "proxy":
        return f"{s['ip']}:" in satir
    return s["kalici"] in satir


def _kural_kontrol(b) -> Sonuc:
    metin = _oku(b, "kural.txt")
    if metin is None:
        return Sonuc(False, "`kural.txt` bulunamadı. Bu klasörde oluştur (`kural_bicimi.txt` biçimine bak).")
    kv = dict(_anahtar_deger(metin))
    for k in ("ad", "kaynak", "ara", "esik"):
        if not kv.get(k):
            return Sonuc(False, f"`{k}:` satırı eksik ya da boş.")
    kaynak = kv["kaynak"].lower()
    if kaynak not in KAYNAKLAR:
        return Sonuc(False, "`kaynak` şunlardan biri olmalı: dns, proxy, dosya.")
    try:
        esik = int(kv["esik"])
    except ValueError:
        return Sonuc(False, "`esik` bir sayı olmalı.")
    ara = kv["ara"].lower()
    if len(ara) < 4:
        return Sonuc(False, "`ara` metni çok kısa; çok sayıda satırla eşleşir.")
    s = b.senaryo
    satirlar = _satirlar(b, kaynak)
    beklenen = {i for i, x in enumerate(satirlar) if _ioc_satiri(s, kaynak, x)}
    eslesen = {i for i, x in enumerate(satirlar) if ara in x.lower()}
    fazla = eslesen - beklenen
    if fazla:
        ornek = satirlar[sorted(fazla)[0]]
        return Sonuc(False, f"Yanlış alarm: kural meşru bir satırla da eşleşiyor ({len(fazla)} satır), örn.: {ornek}", yakin=True)
    if not eslesen:
        return Sonuc(False, f"Kural `{kaynak}` logunda hiçbir zararlı satırı yakalamıyor.")
    if eslesen != beklenen:
        return Sonuc(False, f"Kural {len(eslesen)} zararlı satırı yakalıyor ama {len(beklenen)} tane var; bir kısmını kaçırıyor.",
                     yakin=True)
    if esik < 1 or esik > len(beklenen):
        return Sonuc(False, f"`esik` {esik}: bu logda yalnızca {len(beklenen)} zararlı satır var; alarm hiç üretilmez ya da anlamsız.")
    return Sonuc(True)


def _bulasik_hata(g, beklenen, b):
    s = b.senaryo
    if s["ip"].lower() in g:
        return "Bu, zararlının **sunucu** IP'si. Sorulan, ona bağlanan **iç** makinelerin IP'leri (`->` işaretinin solundakiler)."
    return None


def _dns_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == b.senaryo["cevaplar"]["_ioc_proxy"]:
        return "Bu proxy logundaki bağlantı sayısı olabilir. Soru **DNS** sorgularını soruyor (`loglar/dns.log`)."
    return None


ADIMLAR = [
    Adim("IOC: ihlal göstergesi", """
Analiz bittiğinde elinde **IOC** (Indicator of Compromise, ihlal göstergesi) denen bulgular olur: zararlının bağlandığı alan adı ve IP,
oluşturduğu dosya adı, örneğin hash'i. IOC'ler doğrudan savunmaya dönüşür: SIEM ve IDS kurallarına eklenir, böylece aynı zararlı
**başka bir makinede** de yakalanır. Tek bir analiz, tüm kurumu koruyan bir kural üretir.

Analiz özetine bak:
""", komut="cat analiz/ozet.txt", sonra="""
Dikkat: Özette iki grup adres var. Zararlının **kendi** ürettikleri IOC'dir; sandbox'ın kendi (saat eşitleme, güncelleme gibi) **meşru**
trafiği IOC değildir. Meşru bir adresi IOC listesine eklemek, yanlış alarm yağmuruna ve gerçek hizmetlerin engellenmesine yol açar.
"""),
    Adim("IOC listesi yazmak", """
IOC listesi basit bir metin dosyasıdır: her satırda `tür: değer`. Bir dosyaya satır eklemek için `echo ... >> dosya` kullanılır
(`>` dosyayı sıfırlar, `>>` sonuna ekler). Biçimi oku:
""", komut="cat ioc_bicimi.txt"),
    Adim("Logda iz sürmek: proxy", """
Kurumun proxy logunda zararlının IP'sine kim bağlanmış? `grep -F` metni olduğu gibi arar (nokta `.` düzenli ifadede özel karakter,
`-F` ile değil). Önce logun biçimine bak:
""", komut="head -5 loglar/proxy.log"),
    Adim("Kim bağlanmış?", """
Aşağıdaki komut örnek bir **meşru** hedefe bağlanan iç makineleri sayar. Aynısını zararlının IP'siyle sen yapacaksın:
""", komut="grep -F '<<ntp_ip>>:' loglar/proxy.log | awk '{print $3}' | sort | uniq -c", sonra="""
Zararlının IP'sini ararken `IP:` biçiminde (iki nokta üst üste ile birlikte) ara; yoksa `203.0.113.7` gibi bir IP'nin başka bir adresin
(`203.0.113.70`) içinde de geçtiğini yanlışlıkla eşleştirirsin. Zaman iki sütun (tarih ve saat) olduğu için kaynak IP üçüncü sütundadır: `awk '{print $3}'` onu alır.
"""),
    Adim("DNS ve dosya olayları", """
Aynı IOC'yi diğer kaynaklarda da ara: DNS logunda alan adını kaç kez sorgulayan olmuş, dosya olayı logunda zararlının oluşturduğu
dosya hangi makinede görülmüş? Cihaz envanteri hostname ile IP'yi eşler:
""", komut="head -5 loglar/dns.log && head -5 loglar/dosya_olaylari.log && head -5 envanter/cihazlar.txt"),
    Adim("Basit tespit kuralı", """
Bir kural, bir logda belirli bir metni arar ve yeterince satır eşleşirse alarm üretir. İyi kural **iki şeyi** yapar: zararlı satırların
hepsini yakalar (kaçırmaz) ve meşru satırlarda alarm vermez (yanlış alarm yok). Biçim:
""", komut="cat kural_bicimi.txt", sonra="""
Kuralı yazmadan önce kalıbının kaç satırı yakaladığını `grep -c -i 'kalıp' loglar/dns.log` ile sına: sayı, beklediğin zararlı satır
sayısıyla aynı olmalı. Kalıp çok genelse (örn. `.lab`) her satırı yakalar, çok özelse bazılarını kaçırır.
"""),
    Adim("İmza mı, davranış mı?", """
Hash, alan adı, IP gibi göstergeler bir **imzadır**: yalnızca bilinen zararlıyı yakalar; saldırgan yeni varyantta alan adını ya da dosya
adını değiştirir. **Davranış tabanlı** tespit ise "hangi zararlı olursa olsun" şüpheli bir davranışa bakar: örneğin bir süreç kendini
başlangıca ekleyip bilinmeyen bir adrese bağlanıyorsa şüphelidir (EDR sistemlerinin yaptığı budur).

**Hacker gözüyle:** İmza kolay ve hızlıdır ama kısa ömürlüdür; davranış kuralı daha zahmetlidir ama yeni zararlıları da yakalar. İyi
savunma ikisini birlikte kullanır.
"""),
]

GOREVLER = [
    Gorev("`analiz/ozet.txt` içindeki zararlının **kendi** göstergelerini (alan adı, IP, sha256) bu klasörde `ioc.txt` olarak yaz. "
          "Biçim: her satır `tür: değer` (`alan:`, `ip:`, `sha256:`; istersen `dosya:`). **Meşru** trafik IOC listesine girmemeli. "
          "Bitince `cevap 1` yaz.",
          Durum(_ioc_kontrol, "ioc.txt: alan, ip, sha256 (+dosya); meşru adresler yok"),
          ("Özette iki bölüm var: zararlının kendi ürettikleri ve sandbox'ın meşru trafiği. Hangisini listeleyeceksin?",
           "Dosya oluşturmak için `echo 'alan: ...' >> ioc.txt` komutunu satır satır tekrarla ya da `nano ioc.txt` kullan.",
           "Satırlar şöyle: `alan: <özetteki alan adı>`, `ip: <özetteki IP>`, `sha256: <özetteki hash>`, `dosya: <özetteki dosya>`."),
          puan=45, baslik="IOC listesi"),
    Gorev("`loglar/proxy.log` içinde **zararlının sunucu IP'sine bağlanan iç makinelerin IP adreslerini** yaz.",
          Kume("bulasik", tur="ip", bicim="IP'ler, virgülle ayrılmış", sik_hatalar=_bulasik_hata),
          ("Önce `ioc.txt`'ye yazdığın IP'yi kullanarak logda ara.",
           "`grep -F '<IP>:' loglar/proxy.log`: `IP:` biçiminde ara; yanlışlıkla başka bir adresin içinde eşleşmesin.",
           "`... | awk '{print $3}' | sort -u`: zaman iki sütun olduğundan kaynak (iç) IP üçüncü sütundadır."),
          puan=40, baslik="Bulaşık makineler"),
    Gorev("`loglar/dns.log` içinde zararlının **alan adı kaç kez sorgulanmış**?",
          Sayi("dns_sayisi", sik_hatalar=_dns_hata),
          ("Aranacak şey özetteki zararlı alan adı; log DNS sorgularını tutuyor.",
           "`grep -c -F '<alan adı>' loglar/dns.log`",
           "Komutun çıktısındaki sayı cevaptır."),
          puan=30, baslik="DNS sorguları"),
    Gorev("`loglar/dosya_olaylari.log` içinde zararlının oluşturduğu dosya hangi makinede görüldü? Makinenin **IP adresini** yaz "
          "(hostname → IP eşlemesi `envanter/cihazlar.txt` içinde).",
          IP("dosya_ip"),
          ("Önce dosya adını log'da ara; hostname üçüncü sütundadır (tarih ve saat ilk iki sütun).",
           "`grep -F '<dosya adı>' loglar/dosya_olaylari.log` hostname'i verir; sonra `grep <hostname> envanter/cihazlar.txt` ile IP'yi bul.",
           "`awk -v h=<hostname> '$2==h {print $1}' envanter/cihazlar.txt`"),
          puan=40, baslik="Dosyanın düştüğü makine"),
    Gorev("Zararlının **IOC'sini yakalayan bir tespit kuralı** yaz: bu klasörde `kural.txt` oluştur (`kural_bicimi.txt` biçimi). "
          "Kural, seçtiğin logdaki **bütün** zararlı satırları yakalasın ve **hiçbir meşru satırda** alarm vermesin. "
          "Bitince `cevap 5` yaz.",
          Durum(_kural_kontrol, "kural.txt: ad, kaynak: dns, ara: <zararlı alan adı>, esik: 1"),
          ("En kolay kaynak hangisi? Zararlının alan adı DNS logunda satırlarını net işaretler.",
           "Kalıbını `grep -c -i 'kalıp' loglar/dns.log` ile sına: sayı, önceki görevde bulduğun zararlı satır sayısıyla aynı olmalı.",
           "`printf 'ad: zararli_alan\\nkaynak: dns\\nara: <alan adı>\\nesik: 1\\n' > kural.txt` (alan adını kendin yaz)."),
          puan=50, baslik="Tespit kuralı yaz"),
    Gorev("IOC'leri SIEM ve IDS kurallarına eklemek **ne sağlar**?",
          Secmeli([
              ("Aynı zararlının başka yerde ya da başka zamanda ortaya çıkmasını yakalamayı",
               "Doğru. Tek bir analizden çıkan gösterge, aynı zararlıyı her yerde arayabilmeni sağlar."),
              ("Zararlının yazarını otomatik olarak tespit edip yakalamayı ve hemen cezalandırmayı",
               "Yanlış. IOC bir tespit aracıdır; kişiyi tanımlamak adli ve hukuki bir süreçtir."),
              ("Zararlının yeni ve bilinmeyen varyantlarını da hiçbir imza gerekmeden yakalamayı",
               "Yanlış. IOC bilinen göstergeleri arar; yeni varyantlar için davranış tabanlı tespit gerekir."),
              ("Bilgisayarları zararlıya karşı tümden bağışık yapmayı ve bulaşmayı kökten önlemeyi",
               "Yanlış. IOC bir tespit ve izleme aracıdır; bağışıklık vermez."),
          ], dogru=0),
          ("IOC bir kez bulunuyor; sonra ne yaparsın?",
           "Göstergeyi bir kurala koyduğunda hangi sorunun cevabını otomatik bulursun: 'Bu iz başka yerde de var mı?'",
           "Doğru şık, aynı zararlıyı başka yerde de yakalamayı söyleyen şık."),
          puan=25, baslik="IOC ne sağlar"),
    Gorev("İmza tabanlı tespitin (hash, alan adı) **sınırı nedir** ve davranış tabanlı tespit bunu nasıl aşar?",
          Secmeli([
              ("İmza yalnızca bilineni yakalar; davranış tabanlı tespit yenileri de yakalar",
               "Doğru. Hash ya da adres değişince imza etkisizleşir; davranış ise değişmez."),
              ("İmza çok yavaş çalışır; davranış tabanlı tespit ise çok daha hızlı ve hafif çalışır",
               "Yanlış. Asıl fark hız değil, kapsamdır: bilinen mi, davranış mı?"),
              ("İmza yalnızca Windows'ta çalışır; davranış tabanlı tespit ise yalnızca Linux içindir",
               "Yanlış. İkisi de farklı işletim sistemlerinde kullanılır."),
              ("İmza yanlış alarm üretmez, davranış tabanlı tespit sürekli üretir ve bu yüzden kullanılmaz",
               "Yanlış. Davranış tabanlı tespit (EDR) yaygın kullanılır; yanlış alarm yönetimi onun parçasıdır."),
          ], dogru=0),
          ("Saldırgan yeni bir varyantta neyi değiştirir: davranışı mı, göstergeleri mi?",
           "Hash'i bir bayt değiştirerek nasıl farklı yaparsın? Peki zararlının yaptığı iş değişir mi?",
           "Doğru şık, imzanın bilineni yakaladığını, davranışın yeni olanı da yakaladığını söyleyen şık."),
          puan=30, baslik="İmza ve davranış"),
    Gorev("Aşağıdakilerden hangisi **davranış tabanlı** bir tespit kuralıdır?",
          Secmeli([
              ("Süreç kendini başlangıca ekleyip görülmemiş bir alan adına bağlanırsa alarm üret",
               "Doğru. Hangi program olduğuna değil ne yaptığına bakar; yeni zararlılar da bu kalıba girer."),
              ("Dosyanın sha256 özeti, bilinen zararlılar listesindeki bir hash'e birebir eşitse alarm üret",
               "Yanlış. Bu bir imza kuralıdır: yalnızca bilinen dosyayı yakalar."),
              ("DNS'te bilinen zararlı listesindeki bir alan adı sorgulanırsa her seferinde alarm üret",
               "Yanlış. Bu bir gösterge (IOC) kuralıdır; yeni alan adında çalışmaz."),
              ("Bütün `.lab` uzantılı alan adı sorgularını engelle ve bunların her biri için alarm üret",
               "Yanlış. Bu çok genel bir engeldir ve meşru trafiği de keser; davranışa bakmaz."),
          ], dogru=0),
          ("Kural hangi program olduğunu mu soruyor, ne yaptığını mı?",
           "EDR sistemleri tek bir imzaya değil, bir dizi davranışa bakar: kalıcılık + bilinmeyen bağlantı gibi.",
           "Doğru şık, programın yaptığı iş birleşimine (kalıcılık + bilinmeyen adrese bağlanma) bakan şık."),
          puan=25, baslik="Davranış kuralı"),
]

SEVIYE = Seviye(
    kimlik="c17b03",
    cilt=17,
    bolum=3,
    baslik="Göstergeler, Tespit ve Lab",
    brifing="""
Analiz bitti ve **<<musteri>>** için şimdi asıl iş başlıyor: bu zararlı **başka makinelerde de var mı**? <<hikaye>>

Deniz: "Elimde analiz özeti ve üç log var: proxy, DNS, dosya olayları. Sandbox'ın kendi meşru trafiğini IOC sanma; yanlış alarm
bütün SOC'u yorar." Selin: "Önce IOC listesini çıkar, sonra bulaşık makineleri bul, sonra aynı şeyin tekrar olmasını
yakalayacak basit bir kural yaz." Mert: "Tek bir zararlıyı analiz edip bütün kurumu koruyan bir kural üretmek, mavi takımın en tatmin edici işi."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Zararlı analizi bir son değil, bir başlangıçtır: çıkan göstergeler (IOC) loglarda iz sürmeni ve bulaşık makineleri bulmanı sağlar;
aynı göstergeler kurallara dönüşünce kurumun geri kalanını korur. Saldırgan açısından göstergeler kolay değiştirilebilir; bu
yüzden imza tabanlı kural kısa ömürlüdür. Savunma dersi: IOC'leri çıkarırken meşru trafiği karıştırma (yanlış alarm), kuralı
önce loglarda sına, ve imzaya ek olarak davranış tabanlı tespiti de kullan.
""",
    gercek_hayat="""
- **IOC paylaşımı:** Güvenlik ekipleri ve CERT'ler analiz ettikleri zararlıların göstergelerini (alan adı, IP, hash) birbirleriyle
  paylaşır; bu göstergeler SIEM, IDS ve EDR kurallarına eklenerek aynı kampanyanın başka kurumlarda yakalanmasını sağlar.
- **Önleme / tespit:** IOC tabanlı kurallar hızlı ve ucuzdur ama kısa ömürlüdür; saldırganlar alan adı ve IP'leri sık değiştirir. EDR gibi
  davranış tabanlı çözümler (kalıcılık, alışılmadık bağlantı, olağandışı süreç zincirleri) imzadan bağımsız çalışır. Kurallar
  üretime almadan önce geçmiş loglarda sınanır; böylece meşru trafikte yanlış alarm üretmedikleri doğrulanır.
- **Finans sektörü:** Bankacılık truva atları ve fidye yazılımları finansal kuruluşların başlıca tehditleri arasındadır; bunları
  analiz edip tespit kuralına dönüştürebilen bir olay müdahale ekibi büyük değer taşır.
""",
    sure_hedef_dk=35,
)
