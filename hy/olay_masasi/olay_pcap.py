"""Olay Masası — Paket Analizi: tcpdump Çıktısında Saldırıyı Okumak (PCAP).

Savunmacı ve kurgusaldır: gerçek ağ trafiği yoktur, `yakalama.txt` dosyası `tcpdump -nn -r`
çıktısının sahte (üretilmiş) bir kopyasıdır. Dış IP'ler belgelendirme amaçlı TEST-NET bloklarındandır.
Dosyaya üç saldırı türünden biri gömülür: C2 beacon (düzenli aralıklı küçük paketler), veri sızıntısı
(büyük giden transfer) ya da port tarama (tek kaynaktan çok sayıda hedef porta SYN). Gürültü olarak
normal HTTP/DNS trafiği ve yem (decoy) trafikler vardır.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. `uret` ve `yaz`, aynı
`_akis(alt)` ile veriyi yeniden üretir (`_tohum` motor tarafından ezildiği için ayrı anahtar).
"""
from __future__ import annotations

import random
import subprocess
from pathlib import Path

from hy.motor.kontrol import IP, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur

TURLER = ["beacon", "exfil", "tarama"]
TUR_AD = {"beacon": "C2 beacon (komuta-kontrol sinyali)", "exfil": "veri sızıntısı (exfiltration)",
          "tarama": "port tarama"}

SENARYOLAR = [
    {"tur": "beacon", "musteri": "Yıldız Hastaneleri", "sektor": "özel hastane", "kisi": "BT müdürü Orhan Bey",
     "hikaye": "Poliklinik sekreterinin bilgisayarı yavaşladı ve antivirüs sessizce kapandı."},
    {"tur": "beacon", "musteri": "Kervan Lojistik", "sektor": "lojistik şirketi", "kisi": "Sistem yöneticisi Ferda Hanım",
     "hikaye": "Depo ofisindeki bir PC gece boyunca kapatılmasına rağmen ağ ışığı yanıp sönüyor."},
    {"tur": "exfil", "musteri": "Pınar Hukuk Bürosu", "sektor": "hukuk bürosu", "kisi": "Yönetici ortak Kemal Bey",
     "hikaye": "Müvekkil dosyalarının tutulduğu sunucudan, mesai dışında internet hattı tamamen doldu."},
    {"tur": "exfil", "musteri": "Nehir Tasarım Atölyesi", "sektor": "mimarlık ofisi", "kisi": "Ofis müdürü Tuba Hanım",
     "hikaye": "Proje çizimlerinin olduğu paylaşım klasörünün hattı gece yarısı beklenmedik biçimde şişti."},
    {"tur": "tarama", "musteri": "Anadolu Enerji Dağıtım", "sektor": "enerji dağıtım şirketi",
     "kisi": "Güvenlik sorumlusu Cenk Bey",
     "hikaye": "Güvenlik duvarı, internetten gelen ve bir sunucunun tüm kapılarını yoklayan bir hareket bildirdi."},
    {"tur": "tarama", "musteri": "Boğaz Sigorta", "sektor": "sigorta şirketi", "kisi": "SOC analisti Duygu Hanım",
     "hikaye": "Dışa açık bir sunucu için, kısa sürede çok sayıda 'bağlantı reddedildi' kaydı birikti."},
]

AC_PORTLAR = [22, 21, 3389, 445, 3306, 8080, 5900]
C2_PORTLAR = [8443, 4444, 8080, 1337, 9001]
SIZ_PORTLAR = [443, 8443, 2222, 21, 9000]

SORU = {
    "beacon": {
        "sayi": "Saldırgan IP'sine ele geçirilmiş makineden giden **beacon paketi** (iç makineden dış IP'ye giden, "
                "veri taşıyan küçük paket) kaç tane? (Sunucudan dönen yanıtları sayma.)",
        "hedef": "Beacon'ı gönderen, yani **ele geçirilmiş iç makinenin IP adresi** hangisi?",
        "port": "Beacon paketleri saldırganın hangi **portuna** gidiyor?",
        "saat": "Saldırgana giden **ilk beacon paketinin** saat ve dakikası nedir? (SS:DD biçimi)",
    },
    "exfil": {
        "sayi": "İç makineden saldırgan IP'sine giden paketlerin `length` değerlerini topla: saldırgana "
                "toplam **kaç bayt veri** gitti?",
        "hedef": "Veriyi dışarı gönderen **iç makinenin IP adresi** hangisi?",
        "port": "Veri, saldırgan IP'sinin hangi **portuna** gönderiliyor?",
        "saat": "Saldırgan IP'siyle **ilk temasın** (ilk paketin) saat ve dakikası nedir? (SS:DD biçimi)",
    },
    "tarama": {
        "sayi": "Saldırgan toplam **kaç farklı hedef porta** SYN gönderdi? (Yeniden gönderilen aynı port "
                "bir kez sayılır.)",
        "hedef": "Taranan **iç makinenin IP adresi** hangisi?",
        "port": "Taramada hedefte **açık bulunan** (SYN/ACK, yani `Flags [S.]` ile cevap veren) port hangisi?",
        "saat": "Saldırganın **ilk SYN paketinin** saat ve dakikası nedir? (SS:DD biçimi)",
    },
}

DESEN = {
    "beacon": "Beacon: aynı dış IP'ye düzenli aralıklarla giden küçük paketler.",
    "exfil": "Veri sızıntısı: tek bir dış IP'ye giden büyük hacimli (uzun) paketler.",
    "tarama": "Port tarama: tek bir kaynaktan aynı hedefin çok sayıda farklı portuna SYN.",
}
KANIT = {
    "beacon": "Tek bir dış IP'ye, aynı küçük boyutta ve düzenli aralıkla paket gidiyor: bu insan değil makine ritmidir.",
    "exfil": "İç makineden tek bir dış IP'ye dev bir bayt hacmi gidiyor; normal gezinti bu kadar yükleme yapmaz.",
    "tarama": "Tek dış kaynak, aynı hedefin yüzlerce farklı portuna SYN yolluyor; çoğu RST ile reddediliyor.",
}

MUDAHALE = {
    "beacon": [
        ("Ele geçirilmiş makineyi ağdan izole et, saldırgan IP'sini engelle, makinede zararlıyı ara ve o "
         "makinenin parolalarını yenile",
         "Doğru. Kaynak (makine) ve kanal (IP) birlikte kesilmeli; yoksa zararlı başka adrese geçer."),
        ("Yalnızca saldırgan IP'sini engelle, makineye dokunma",
         "Eksik. Zararlı makinede kalır; saldırgan başka bir adresten yeniden bağlanır."),
        ("Paketler çok küçük, önemsiz sayılır; yok say",
         "Yanlış. Düzenli küçük paketler tam da beacon'ın imzasıdır; yok saymak saldırgana zaman verir."),
        ("Şirketin tüm internetini süresiz kapat",
         "Aşırı. İş durur; oysa tek makineyi izole etmek yeterli ve çok daha hızlıdır."),
    ],
    "exfil": [
        ("Saldırgan IP'sine giden bağlantıyı hemen kes, makineyi izole et, neyin gittiğini belirle ve "
         "kişisel veri varsa ihlal bildirimi sürecini (KVKK) başlat",
         "Doğru. Önce kanamayı durdur, sonra kapsamı belirle ve yasal bildirim yükümlülüklerini yönet."),
        ("Transfer bitene kadar bekle, sonra logları temizle",
         "Yanlış. Beklemek daha çok veri kaybettirir; logları silmek de kanıtı yok eder."),
        ("Saldırgan IP'sine kendi aracınla karşı saldırı yap",
         "Yanlış ve yasadışı. Karşı saldırı (hack-back) izinsiz erişimdir; davayı da zayıflatır."),
        ("Trafik şifreli olabilir, içeriğe bakılamaz diye görmezden gel",
         "Yanlış. İçerik görünmese bile hacim, hedef ve zamanlama bir sızıntıyı ele verir."),
    ],
    "tarama": [
        ("Kaynak IP'yi engelle ya da hız sınırla, açık bulunan portun gerçekten gerekli ve güncel olduğunu "
         "denetle, o porta gelen giriş denemelerini izlemeye al",
         "Doğru. Tarama keşiftir, asıl tehlike açık portun arkasındaki hizmettir; onu sertleştir ve izle."),
        ("Tarama zararsız bir yoklamadır; hiçbir şey yapma",
         "Yanlış. Tarama genelde saldırının ilk adımıdır; açık port bulunduysa sıradaki adım sömürüdür."),
        ("Taranan tüm portları kör biçimde kapat",
         "Aşırı. Gerekli hizmetler de kesilir; yalnızca gereksiz portlar kapatılmalı, gerekliler korunmalı."),
        ("Saldırgana karşı tarama ve saldırı başlat",
         "Yanlış ve yasadışı. Karşı saldırı izinsiz erişimdir; savunmacının işi izlemek ve engellemektir."),
    ],
}


class DinSecmeli(Secmeli):
    """Doğru şık senaryoya göre değişen çoktan seçmeli (şıklar `uretici(senaryo)` ile gelir)."""

    def __init__(self, uretici):
        super().__init__([("", "")])
        self.uretici = uretici

    def _ayarla(self, b):
        self.secenekler, self.dogru = self.uretici(b.senaryo)

    def ek_metin(self, b):
        self._ayarla(b)
        return super().ek_metin(b)

    def dogrula(self, girdi, b):
        self._ayarla(b)
        return super().dogrula(girdi, b)

    def cevabi_goster(self, b):
        self._ayarla(b)
        return super().cevabi_goster(b)


def _tur_secenekleri(s):
    tur = s["cevaplar"]["tur_kodu"]
    sec = []
    for t in TURLER:
        sec.append((TUR_AD[t], ("Doğru. " + KANIT[t]) if t == tur else
                    f"Hayır. {DESEN[t]} Veride bu deseni göremiyorsun; aralıklara, `length` değerlerine ve "
                    "port çeşitliliğine bak."))
    return sec, TURLER.index(tur)


def _mudahale_secenekleri(s):
    return MUDAHALE[s["cevaplar"]["tur_kodu"]], 0


def _zaman(t: float) -> str:
    t = max(t, 0.0)
    return f"{int(t) // 3600:02d}:{int(t) % 3600 // 60:02d}:{int(t) % 60:02d}.{int((t % 1) * 1_000_000):06d}"


def _akis(alt: int) -> dict:
    """Alt-tohumdan tüm yakalamayı ve cevapları deterministik üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    tur = sen["tur"]
    iclr = [f"10.20.0.{n}" for n in rng.sample(range(10, 250), 6)]
    dns = "10.20.0.2"
    sunucu = f"10.20.0.{rng.randint(251, 253)}"
    dis = u.benzersiz(rng, u.dis_ip, 6)
    sald, web = dis[0], dis[1:5]
    visitor = dis[5]
    t0 = rng.randint(9, 15) * 3600 + rng.randint(0, 3599)
    ev: list = []

    def tcp(t, s, sp, d, dp, fl, ln):
        ack = f", ack {rng.randint(1, 4_000_000_000)}" if "." in fl else ""
        ev.append((t, f"{_zaman(t)} IP {s}.{sp} > {d}.{dp}: Flags [{fl}], seq {rng.randint(1, 4_000_000_000)}"
                      f"{ack}, win 64240, length {ln}"))

    def eph():
        return rng.randint(32768, 60999)

    def dns_sorgu(t, c, ad):
        sp, q = eph(), rng.randint(1000, 60000)
        ev.append((t, f"{_zaman(t)} IP {c}.{sp} > {dns}.53: {q}+ A? {ad}. ({len(ad) + 14})"))
        ev.append((t + 0.02, f"{_zaman(t + 0.02)} IP {dns}.53 > {c}.{sp}: {q} 1/0/0 A {rng.choice(web)} "
                             f"({len(ad) + 30})"))

    cevap = {}
    # ---------------- saldırı
    if tur == "beacon":
        kurban = rng.choice(iclr)
        aralik = rng.choice([30, 45, 60, 90])
        n = rng.randint(70, 120)
        port = rng.choice(C2_PORTLAR)
        bas = t0 + rng.randint(120, 900)
        for i in range(n):
            t = bas + i * aralik + rng.uniform(0, 2)
            sp = eph()
            tcp(t, kurban, sp, sald, port, "P.", rng.randint(40, 60))
            tcp(t + rng.uniform(0.04, 0.2), sald, port, kurban, sp, "P.", rng.randint(16, 24))
        # yem: başka istemci bir yazılım sunucusuna 10 dakikada bir küçük paket (meşru güncelleme kontrolü)
        diger = rng.choice([c for c in iclr if c != kurban])
        for i in range((n * aralik) // 600):
            tcp(bas + i * 600 + rng.uniform(0, 5), diger, eph(), web[0], 443, "P.", rng.randint(50, 70))
        # yem: düzensiz küçük paketler
        for _ in range(rng.randint(10, 20)):
            tcp(rng.uniform(t0, bas + n * aralik), rng.choice(iclr), eph(), web[1], 80, "P.", rng.randint(70, 90))
        bitis = bas + n * aralik + 600
        cevap = {"saldirgan": sald, "sayi": n, "hedef": kurban, "port": port,
                 "saat": _zaman(bas)[:5], "alt_sayi": 2 * n, "kurban": kurban}
    elif tur == "exfil":
        kurban = rng.choice(iclr)
        n = rng.randint(90, 180)
        port = rng.choice(SIZ_PORTLAR)
        bas = t0 + rng.randint(300, 1200)
        sp = eph()
        tcp(bas, kurban, sp, sald, port, "S", 0)
        tcp(bas + 0.05, sald, port, kurban, sp, "S.", 0)
        tcp(bas + 0.1, kurban, sp, sald, port, ".", 0)
        t = bas + 0.2
        toplam = 0
        for i in range(n):
            ln = rng.choice([1448] * 8 + [1200, 900])
            toplam += ln
            tcp(t, kurban, sp, sald, port, "P.", ln)
            if i % 2:
                tcp(t + 0.02, sald, port, kurban, sp, ".", 0)
            t += rng.uniform(0.02, 1.2)
        # yem 1: başka istemci büyük dosya indiriyor (gelen yön)
        indiren = rng.choice([c for c in iclr if c != kurban])
        isp = eph()
        for _ in range(rng.randint(100, 160)):
            tcp(rng.uniform(bas, t), web[0], 443, indiren, isp, "P.", 1448)
        # yem 2: başka istemci bulut yedeğine orta boy yükleme yapıyor (<90 paket)
        yukleyen = rng.choice([c for c in iclr if c != kurban])
        ysp = eph()
        yb = rng.uniform(t0, bas)
        for i in range(rng.randint(30, 45)):
            tcp(yb + i * 0.4, yukleyen, ysp, web[1], 443, "P.", 1448)
        bitis = t + 600
        cevap = {"saldirgan": sald, "sayi": toplam, "hedef": kurban, "port": port,
                 "saat": _zaman(bas)[:5], "alt_sayi": n, "kurban": kurban}
    else:
        n = rng.randint(120, 380)
        acik = rng.choice(AC_PORTLAR)
        havuz = list(range(1, 1025)) + [3306, 5432, 6379, 8080, 8443, 9200, 27017]
        portlar = set(rng.sample(havuz, n))
        portlar.add(acik)
        portlar = list(portlar)
        rng.shuffle(portlar)
        n = len(portlar)
        bas = t0 + rng.randint(300, 1200)
        sp = rng.randint(40000, 60000)
        t = bas
        syn_toplam = 0

        def syn(p, t):
            tcp(t, sald, sp, sunucu, p, "S", 0)
            if p == acik:
                tcp(t + 0.0005, sunucu, p, sald, sp, "S.", 0)
                tcp(t + 0.001, sald, sp, sunucu, p, "R", 0)
            else:
                tcp(t + 0.0005, sunucu, p, sald, sp, "R.", 0)

        for p in portlar:
            syn(p, t)
            syn_toplam += 1
            t += rng.uniform(0.001, 0.03)
        for p in rng.sample(portlar, rng.randint(5, 12)):      # yeniden gönderimler
            t += rng.uniform(0.5, 2.0)
            syn(p, t)
            syn_toplam += 1
        # yem: normal ziyaretçi sunucunun 80/443 portuna defalarca bağlanıyor
        for _ in range(rng.randint(30, 60)):
            tv = rng.uniform(t0, t + 600)
            vp = eph()
            tcp(tv, visitor, vp, sunucu, rng.choice([80, 443]), "S", 0)
            tcp(tv + 0.03, sunucu, 443, visitor, vp, "S.", 0)
        bitis = t + 600
        cevap = {"saldirgan": sald, "sayi": n, "hedef": sunucu, "port": acik,
                 "saat": _zaman(bas)[:5], "alt_sayi": syn_toplam, "kurban": sunucu}

    # ---------------- gürültü: normal HTTP/DNS
    tum = iclr
    for _ in range(rng.randint(200, 280)):
        t = rng.uniform(t0, bitis)
        c, sv, dp, sp = rng.choice(tum), rng.choice(web), rng.choice([80, 443, 443]), eph()
        tcp(t, c, sp, sv, dp, "S", 0)
        tcp(t + 0.03, sv, dp, c, sp, "S.", 0)
        tcp(t + 0.06, c, sp, sv, dp, "P.", rng.randint(300, 600))
        for k in range(rng.randint(1, 3)):
            tcp(t + 0.1 + k * 0.01, sv, dp, c, sp, "P.", 1448)
    for _ in range(rng.randint(60, 100)):
        dns_sorgu(rng.uniform(t0, bitis), rng.choice(tum),
                  rng.choice(["www.haber-sitesi.lab", "mail.posta-ag.lab", "cdn.sunucu-agi.lab",
                              "guncelleme.os-ag.lab", "bulut.depo-ag.lab"]))

    ev.sort(key=lambda x: x[0])
    cevap["tur_kodu"] = tur
    cevap["tur"] = TUR_AD[tur]
    return {"sen": sen, "satirlar": [s for _, s in ev], "cevap": cevap}


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen, c = v["sen"], v["cevap"]
    q = SORU[c["tur_kodu"]]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — paket yakalama analizi",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "sayi_soru": q["sayi"], "hedef_soru": q["hedef"],
                  "port_soru": q["port"], "saat_soru": q["saat"]},
        "cevaplar": {"saldirgan": c["saldirgan"], "tur": c["tur"], "tur_kodu": c["tur_kodu"],
                     "sayi": c["sayi"], "hedef": c["hedef"], "port": c["port"], "saat": c["saat"],
                     "alt_sayi": c["alt_sayi"]},
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    u.yaz(lab / "yakalama.txt", "\n".join(v["satirlar"]) + "\n")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _ip_hata(g, beklenen, b):
    if g.startswith("10.20."):
        return "Bu iç ağdaki bir makine. Saldırgan, ağın **dışındaki** IP'dir (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)."
    return None


def _hedef_hata(g, beklenen, b):
    if g == b.senaryo["cevaplar"]["saldirgan"]:
        return "Bu saldırganın dış IP'si. Burada **iç ağdaki** (10.20.0.x) makineyi soruyoruz."
    return None


def _sayi_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == int(b.senaryo["cevaplar"]["alt_sayi"]) and n != beklenen:
        tur = b.senaryo["cevaplar"]["tur_kodu"]
        return {"beacon": "Bu, iki yönün toplamı: sunucudan dönen yanıtları da saymışsın. Yalnızca iç makineden giden paketleri say.",
                "exfil": "Bu paket SAYISI; bayt istiyoruz. Her paketin `length` değerini topla.",
                "tarama": "Bu, SYN satırı sayısı; yeniden gönderilen portlar iki kez sayılmış. Farklı portları say (`sort -u`)."}[tur]
    return None


def coz(lab: Path, s: dict) -> dict:
    # tcpdump satırı: $1 zaman, $3 kaynak.ip.port, $5 hedef.ip.port:, $7 bayrak (ör. [S],), $NF uzunluk
    prs = ("/Flags/ {n=split($3,a,\".\"); sip=a[1]\".\"a[2]\".\"a[3]\".\"a[4]; d=$5; sub(/:$/,\"\",d); "
           "split(d,b,\".\"); dip=b[1]\".\"b[2]\".\"b[3]\".\"b[4]; dp=b[5]; fl=$7; len=$NF; ")
    ara = ("awk '" + prs + "if (fl==\"[S],\") {k=sip\" \"dip\" \"dp; if (!(k in g)) {g[k]=1; c[sip]++}}} "
           "END{for (i in c) print c[i], i}' yakalama.txt | sort -rn | head -1")
    sayi, ip = (_sh(ara, lab).split() + ["0", ""])[:2]
    if int(sayi) > 50:                                   # tarama: çok porta SYN yollayan tek kaynak
        saldirgan = ip
        hedef = _sh("awk '" + prs + f"if (sip==\"{ip}\" && fl==\"[S],\") print dip}}' yakalama.txt "
                    "| sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
        port = _sh("awk '" + prs + f"if (sip==\"{hedef}\" && dip==\"{ip}\" && fl==\"[S.],\") print a[5]}}' "
                   "yakalama.txt | head -1", lab)
    else:
        iceriden = "sip ~ /^10\\.20\\./ && dip !~ /^10\\.20\\./"
        top = _sh("awk '" + prs + f"if ({iceriden} && len>0) s[sip\" \"dip\" \"dp]+=len}} "
                  "END{for (i in s) print s[i], i}' yakalama.txt | sort -rn | head -1", lab).split()
        if top and int(top[0]) > 100000:                 # sızıntı: tek dış IP'ye devasa bayt hacmi
            sayi, hedef, saldirgan, port = top[0], top[1], top[2], top[3]
        else:                                            # beacon: en çok küçük paket giden dış IP
            kucuk = _sh("awk '" + prs + f"if ({iceriden} && len>0 && len<100) q[sip\" \"dip\" \"dp]++}} "
                        "END{for (i in q) print q[i], i}' yakalama.txt | sort -rn | head -1", lab).split()
            sayi, hedef, saldirgan, port = kucuk[0], kucuk[1], kucuk[2], kucuk[3]
    saat = _sh(f"grep -m1 '{saldirgan}' yakalama.txt | cut -c1-5", lab)
    cozum = {1: saldirgan, 2: "", 3: sayi, 4: hedef, 5: port, 6: saat, 7: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("`yakalama.txt` içinde saldırıyı yürüten **saldırgan (dış) IP adresi** hangisi? Şüphe: bir "
          "iç makineye düzenli sinyal yolluyor, büyük veri çekiyor ya da çok porta SYN gönderiyor olabilir.",
          IP("saldirgan", sik_hatalar=_ip_hata),
          ("Normal trafik çok çeşitli adreslerle olur. Saldırı, **tek bir dış IP** etrafında ağır ya da düzenli "
           "bir iz bırakır: çok sayıda paket, çok bayt ya da çok port.",
           "Kaynak ve hedef IP'yi ayırmak için son noktadan sonrasını (portu) at: `awk '{print $3,$5}'` ile "
           "başla, `sort | uniq -c | sort -rn` ile en sık geçenleri gör. `length` değerlerine de bak (satırın sonu).",
           "Dış IP'ler `192.0.2.`, `198.51.100.` ya da `203.0.113.` ile başlar; iç ağ `10.20.0.`. "
           "`grep -v ' 10.20.0.2.53 '` ile DNS gürültüsünü ele; sonra dış IP başına paket/bayt say."),
          puan=15, baslik="Saldırgan IP"),
    Gorev("Bu yakalamadaki saldırının **türü** nedir?",
          DinSecmeli(_tur_secenekleri),
          ("Üç desen var: **beacon** (düzenli aralıkla küçük paketler), **sızıntı** (tek yöne giden büyük hacim), "
           "**tarama** (tek kaynak, çok hedef port).",
           "Saldırgan IP'sine ait satırlara bak: `grep <ip> yakalama.txt | head -20`. Aralıklar eşit mi? "
           "`length` büyük mü? Hedef port hep aynı mı yoksa sürekli değişiyor mu?",
           "Zaman damgaları eşit aralıklıysa beacon; `length` 1448 gibi büyük ve hep aynı yöne ise sızıntı; "
           "hedef port her satırda değişiyor ve çoğuna `R.` (reddedildi) dönüyorsa tarama."),
          puan=15, baslik="Saldırı türü"),
    Gorev("<<sayi_soru>>",
          Sayi("sayi", sik_hatalar=_sayi_hata),
          ("Önce saldırgan IP'sine ait satırları süz, sonra hangi yönün/alanın sayılacağına karar ver.",
           "Sayı için `awk`: satır sayısı `END{print NR}`; bayt toplamı `{s+=$NF} END{print s}`; "
           "farklı port için `sort -u | wc -l`. Portu ayırmak için adresi `.` ile böl: `split($5,b,\".\")`.",
           "Örnek kalıplar: `grep -c '<iç-ip>\\.[0-9]* > <dış-ip>\\.' yakalama.txt` (belli yöndeki satırlar) ya da "
           "`awk '$3 ~ /^<dış-ip>/ {print $5}' yakalama.txt | sort -u | wc -l` (farklı hedef)."),
          puan=20, baslik="Sayı / hacim"),
    Gorev("<<hedef_soru>>",
          IP("hedef", sik_hatalar=_hedef_hata),
          ("İç ağ adresleri `10.20.0.` ile başlar. Saldırgan IP'sinin karşı tarafında hangi iç makine var?",
           "Saldırgan IP'sini içeren satırlarda öbür adresi oku: `grep <dış-ip> yakalama.txt | awk '{print $3,$5}' "
           "| sort | uniq -c | sort -rn | head`.",
           "Sonuçta `10.20.0.x.<port>` biçiminde görünür; en sık geçen iç adres cevaptır (son noktadan sonraki "
           "port kısmını cevaba yazma)."),
          puan=15, baslik="İç hedef makine"),
    Gorev("<<port_soru>>",
          Sayi("port"),
          ("Port, adresin sonundaki sayıdır: `10.20.0.5.443` içindeki `443` gibi.",
           "İlgili satırları süz ve portu ayır: `awk '{print $5}' ... | cut -d. -f5 | sort | uniq -c | sort -rn`.",
           "Sızıntı/beacon için saldırgana giden satırların hedef portu hep aynıdır. Tarama için `grep 'Flags \\[S\\.\\]'` "
           "ile SYN/ACK dönen satırı ara: hedefin kendi portu `.`'den sonra, `>`'dan ÖNCE yazar."),
          puan=15, baslik="Port"),
    Gorev("<<saat_soru>>",
          Metin("saat", bicim="SS:DD, örn. 13:05"),
          ("Satırın başındaki zaman damgası `SS:DD:SS.mikrosaniye` biçimindedir; yalnız saat ve dakika istiyoruz.",
           "Saldırgan IP'sini içeren ilk satırı al: `grep -m1 <dış-ip> yakalama.txt`.",
           "`grep -m1 <dış-ip> yakalama.txt | cut -c1-5` — satırın ilk 5 karakteri saat:dakikadır."),
          puan=10, baslik="Başlangıç saati"),
    Gorev("Bulgularınla şimdi **en doğru müdahale** hangisi?",
          DinSecmeli(_mudahale_secenekleri),
          ("Hem kanalı hem kaynağı düşün; hukuka uygun ve ölçülü kal.",
           "Doğru cevap, saldırı türüne özgü bir sonraki adımı da içerir: izolasyon, kapsam belirleme ya da sertleştirme.",
           "Karşı saldırı (hack-back) ve 'yok say' her zaman yanlıştır; aşırı geniş kesintiler de öyle."),
          puan=20, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_pcap",
    cilt=2,
    bolum=119,
    baslik="Paket Analizi: tcpdump Çıktısında Saldırıyı Okumak",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<kisi>> anlatıyor: <<hikaye>>
Ağ ekibi hattan bir kayıt aldı ve `tcpdump -nn -r` ile metne döktü: `yakalama.txt`."

"Her satır bir paket: `zaman IP kaynak.port > hedef.port: Flags [..], seq, win, length N`. Adreslerin
sonundaki son sayı **port**, `length` paketin veri uzunluğu. `[S]` bağlantı isteği (SYN), `[S.]` kabul,
`[R.]` ret, `[P.]` veri. İç ağ `10.20.0.x`; dışarıdakiler belgelendirme blokları (`192.0.2.x` gibi), yani
kurgusal. Dosyada normal web ve DNS trafiği var; ama bir yerde bir saldırı gizli. Kim yapıyor, hangi
türde, ne kadar, hangi makineye? Bul ve müdahale yolunu seç."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Paket yakalamada üç klasik imza var. **Beacon:** aynı dış IP'ye eşit aralıklı, hep aynı boyda küçük paketler
(insan tıklaması düzensizdir, zararlı bir saat gibi çalışır). **Sızıntı:** iç makineden tek bir dış adrese
giden, indirme değil yükleme yönünde büyük bayt hacmi. **Tarama:** tek kaynaktan aynı hedefin yüzlerce
farklı portuna SYN; kapalı portlar `R.` ile reddedilir, açık olan `S.` ile cevap verip kendini ele verir.
Savunmacı bu üçünü aynı soruyla ayırır: **kim, kime, kaç kez, ne kadar büyük, hangi aralıkla?** Sonra
kaynağı izole eder, kanalı keser, kapsamı belirler.
""",
    gercek_hayat="""
- **C2 beaconing:** Cobalt Strike gibi saldırı çerçeveleri, ele geçirilmiş makineyi komuta sunucusuna düzenli
  aralıklarla yoklatır; "sleep" ve "jitter" ayarlarıyla ritmi bozmaya çalışırlar, savunmacılar da bu
  düzenliliği istatistikle yakalar. 2020 Aralık'ta ortaya çıkan SolarWinds / SUNBURST vakasında zararlı,
  yaklaşık iki hafta bekledikten sonra dışarıyla konuşmaya başlıyordu; ritim ve zamanlama bu yüzden önemliydi.
- **Veri sızıntısı ve tünelleme:** Veri bazen HTTP/HTTPS içinde, bazen DNS sorgularına gömülerek (DNS
  tünelleme) çıkarılır; hacim ve hedef analizi bu kanalları da ele verir. 2017'deki Equifax ihlalinde saldırgan
  veriyi uzun süre şifreli kanaldan çıkardı; trafiği inceleyen cihazın sertifikasının süresinin dolmuş olması
  izlemeyi kör etmişti.
- **Port tarama:** Shodan ve Censys gibi servisler interneti sürekli tarar, saldırganlar da aynısını kendi
  araçlarıyla yapar. 2016'daki Mirai botnet'i, internetteki cihazların Telnet portlarını tarayıp zayıf
  parolaları deneyerek yayıldı.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c02b06",),
)
