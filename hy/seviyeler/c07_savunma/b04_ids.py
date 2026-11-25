"""Cilt 7 · Bölüm 4 — Saldırı Tespiti: IDS ve IPS.

Beceri: Suricata `eve.json` biçimindeki (kurgusal) alarm satırlarını okumak ve saymak, gerçek
saldırıyı yanlış pozitiften (izinli tarayıcı/yedek) ayırmak, bir imza kuralının eşiğini okumak,
bir pcap'te SYN taramasının izini sürmek. İmza ve anomali kavramları.

Vakalar: banka DMZ'si, hastane ağı, lojistik deposu. Her vakada yanlış pozitif kaynağı farklıdır
(zafiyet tarayıcı, ağ izleme, yedek sunucusu). Saldırı içeriği yok: alarm satırlarında yalnızca iz
olarak metin geçer (`UNION SELECT` gibi).
"""
from __future__ import annotations

import json
import random
import re
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import IP, Kume, Secmeli, Sayi
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import ag
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c07_savunma.ortak import sec_doldur, sh

SIDLER = {
    9000001: ("LAB SYN port taraması (çok sayıda farklı porta SYN)", "Attempted Information Leak", 2),
    9000002: ("LAB Nikto web tarayıcı User-Agent", "Web Application Attack", 2),
    9000003: ("LAB URI içinde UNION SELECT", "Web Application Attack", 1),
    9000004: ("LAB olağandışı büyük giden aktarım", "Potentially Bad Traffic", 3),
    9000005: ("LAB SSH parola deneme eşiği", "Attempted Administrator Privilege Gain", 2),
}

VAKALAR = [
    {
        "ad": "Ferah Bank — internet şubesi DMZ'si", "kod": "ferahbank", "ag": "10.30.0", "klasor": "ids_kayitlari",
        "tarayici": "haftalık zafiyet tarayıcısı (Pazar 02:00 taraması)", "ikinci": "ağ izleme sunucusu (sağlık kontrolleri)",
        "sahne": "Gece yarısı internet şubesi önündeki IDS onlarca alarm üretti; nöbetçi analist hangisinin gerçek olduğunu ayıramıyor.",
        "ikinci_hedef": "izleme bulutu",
    },
    {
        "ad": "Medora Sağlık — hastane ağı", "kod": "medora", "ag": "10.40.0", "klasor": "sensor_cikti",
        "tarayici": "ağ envanter tarayıcısı (BT ekibinin aylık taraması)", "ikinci": "yedekleme sunucusu (gece yedeği)",
        "sahne": "Hastanenin yeni IDS sensörü ilk haftasında bir alarm yağmuru çıkardı; yönetim 'bunların hepsi saldırı mı?' diye soruyor.",
        "ikinci_hedef": "bulut yedek hizmeti",
    },
    {
        "ad": "Kuzgun Lojistik — depo ağı", "kod": "kuzgun", "ag": "10.50.0", "klasor": "suricata_log",
        "tarayici": "depo stok sayım cihazlarını arayan envanter tarayıcısı", "ikinci": "depo kamerası yedek sunucusu (gece aktarımı)",
        "sahne": "Depo ağındaki sensör, iki gündür sürekli alarm veriyor; bir de tuhaf bir trafik yakalaması alındı.",
        "ikinci_hedef": "uzak arşiv depolaması",
    },
]


def _eve(t, event_type, src, sport, dst, dport, rng, **ek) -> dict:
    d = {"timestamp": f"{t:%Y-%m-%dT%H:%M:%S}.{rng.randint(0, 999999):06d}+0300", "flow_id": rng.randint(10**15, 10**16 - 1),
         "in_iface": "eth0", "event_type": event_type, "src_ip": src, "src_port": sport, "dest_ip": dst,
         "dest_port": dport, "proto": "TCP"}
    d.update(ek)
    return d


def _alarm(t, sid, src, sport, dst, dport, rng, http=None) -> dict:
    imza, kat, sev = SIDLER[sid]
    d = _eve(t, "alert", src, sport, dst, dport, rng,
             alert={"action": "allowed", "gid": 1, "signature_id": sid, "rev": rng.randint(1, 3), "signature": imza,
                    "category": kat, "severity": sev})
    if http:
        d["http"] = http
    return d


def uret(rng):
    v = rng.choice(VAKALAR)
    m = musteri(v["kod"])
    for _ in range(200):               # en çok alarm veren imza tek olsun
        a1, f1 = rng.randint(3, 5), rng.randint(5, 9)
        n_nikto, n_union, n_ssh, f2 = rng.randint(2, 4), rng.randint(2, 4), rng.randint(2, 4), rng.randint(6, 12)
        sayac = {9000001: a1 + f1, 9000002: n_nikto, 9000003: n_union, 9000004: f2, 9000005: n_ssh}
        if sorted(sayac.values())[-1] > sorted(sayac.values())[-2]:
            break
    saldirgan = u.dis_ip(rng)
    web = u.ic_ip(rng, v["ag"])
    tarayici = u.ic_ip(rng, v["ag"].rsplit(".", 1)[0] + ".9")
    ikinci = u.ic_ip(rng, v["ag"].rsplit(".", 1)[0] + ".2")
    bulut = u.dis_ip(rng)
    while bulut == saldirgan:
        bulut = u.dis_ip(rng)
    tohum = rng.randint(1, 10**6)
    n_syn, n_ssh_esik, n_buyuk = rng.randint(15, 40), rng.randint(5, 10), rng.choice([500, 800, 1000, 1500])
    acik = sorted(rng.sample([22, 80, 443, 3306, 8080, 8443, 25, 445], rng.randint(2, 4)))
    diger = [21, 23, 53, 110, 111, 135, 139, 143, 993, 1433, 3389, 5432, 1723, 5900, 9200]
    portlar = sorted(set(acik) | set(rng.sample(diger, rng.randint(12, 15))))
    # alarm olayları: (saniye ofseti, sid, kaynak, ...) yaz() içinde zamanlanır
    return {
        "vaka": v["ad"], "v": v, "m": m, "sayac": sayac, "saldirgan": saldirgan, "web": web, "tarayici": tarayici,
        "ikinci": ikinci, "bulut": bulut, "tohum": tohum, "portlar": portlar, "acik": acik,
        "a1": a1, "f1": f1, "f2": f2, "n_nikto": n_nikto, "n_union": n_union, "n_ssh": n_ssh,
        "esikler": {"syn": n_syn, "ssh": n_ssh_esik, "buyuk": n_buyuk},
        "metin": {"musteri": m["ad"], "ids": v["klasor"], "sahne": v["sahne"], "tarayici": v["tarayici"], "ikinci": v["ikinci"]},
        "cevaplar": {
            "toplam": sum(sayac.values()), "sid": max(sayac, key=sayac.get), "ip": saldirgan,
            "fp": f1 + f2, "esik": n_syn, "acik": acik,
        },
    }


def _eve_satirlari(s: dict) -> list:
    rng = random.Random(s["tohum"])
    m = s["m"]
    bas = u.gun(rng) + timedelta(hours=rng.randint(0, 3), minutes=rng.randint(0, 59))
    olaylar = []
    zaman = lambda g=3600 * 6: bas + timedelta(seconds=rng.randint(0, g))      # noqa: E731
    sp = lambda: rng.randint(32768, 60999)                                      # noqa: E731
    web, sal = s["web"], s["saldirgan"]
    yerel_ag = s["v"]["ag"]
    for _ in range(s["a1"]):
        olaylar.append(_alarm(zaman(), 9000001, sal, sp(), web, rng.choice(s["portlar"]), rng))
    for _ in range(s["f1"]):
        olaylar.append(_alarm(zaman(), 9000001, s["tarayici"], sp(), f"{yerel_ag}.{rng.randint(10, 60)}", rng.choice(s["portlar"]), rng))
    for _ in range(s["n_nikto"]):
        olaylar.append(_alarm(zaman(), 9000002, sal, sp(), web, 80, rng,
                              {"hostname": m["alan"], "url": rng.choice(["/", "/admin/", "/.git/HEAD", "/backup.zip"]),
                               "http_user_agent": u.ARAC_UA["Nikto"], "http_method": "GET", "status": 404}))
    for _ in range(s["n_union"]):
        olaylar.append(_alarm(zaman(), 9000003, sal, sp(), web, 80, rng,
                              {"hostname": m["alan"], "url": m["id_sayfa"] + "-1+UNION+SELECT+1,2,3--",
                               "http_user_agent": rng.choice(u.TARAYICI_UA), "http_method": "GET", "status": 200}))
    for _ in range(s["f2"]):
        olaylar.append(_alarm(zaman(), 9000004, s["ikinci"], sp(), s["bulut"], 443, rng))
    for _ in range(s["n_ssh"]):
        olaylar.append(_alarm(zaman(), 9000005, sal, sp(), web, 22, rng))
    for _ in range(rng.randint(14, 22)):                      # alarm olmayan olaylar (bilerek aynı IP'lerden de)
        kaynak = rng.choice([sal, s["tarayici"], s["ikinci"], u.dis_ip(rng), u.dis_ip(rng), f"{yerel_ag}.{rng.randint(20, 80)}"])
        olaylar.append(_eve(zaman(), "flow", kaynak, sp(), web, rng.choice([80, 443, 22]), rng,
                            app_proto=rng.choice(["http", "tls", "ssh"]),
                            flow={"pkts_toserver": rng.randint(2, 40), "pkts_toclient": rng.randint(1, 40), "bytes_toserver": rng.randint(200, 9000)}))
    for _ in range(rng.randint(6, 10)):
        olaylar.append(_eve(zaman(), "dns", f"{yerel_ag}.{rng.randint(20, 80)}", sp(), f"{yerel_ag}.53", 53, rng,
                            dns={"type": "query", "rrname": rng.choice(["www.", "mail.", "vpn."]) + m["alan"], "rrtype": "A"}))
    olaylar.sort(key=lambda d: d["timestamp"])
    return [json.dumps(d, separators=(",", ":"), ensure_ascii=False) for d in olaylar]


def _kurallar(s: dict) -> str:
    e = s["esikler"]
    return (
        "# Yerel kural dosyası (Suricata sözdizimi; kurgusal, lab için sadeleştirilmiş)\n"
        f'alert tcp any any -> $HOME_NET any (msg:"{SIDLER[9000001][0]}"; flags:S; threshold:type both, track by_src, '
        f"count {e['syn']}, seconds 10; classtype:attempted-recon; sid:9000001; rev:2;)\n"
        f'alert http any any -> $HTTP_SERVERS any (msg:"{SIDLER[9000002][0]}"; flow:established,to_server; '
        'http.user_agent; content:"Nikto"; nocase; classtype:web-application-attack; sid:9000002; rev:1;)\n'
        f'alert http any any -> $HTTP_SERVERS any (msg:"{SIDLER[9000003][0]}"; http.uri; content:"UNION"; nocase; '
        'content:"SELECT"; nocase; distance:0; classtype:web-application-attack; sid:9000003; rev:3;)\n'
        f'alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"{SIDLER[9000004][0]}"; dsize:>{e["buyuk"]}; '
        "threshold:type threshold, track by_src, count 50, seconds 60; classtype:bad-unknown; sid:9000004; rev:1;)\n"
        f'alert tcp any any -> $HOME_NET 22 (msg:"{SIDLER[9000005][0]}"; flags:S; threshold:type both, track by_src, '
        f"count {e['ssh']}, seconds 60; classtype:attempted-admin; sid:9000005; rev:1;)\n"
    )


def _pcap(s: dict) -> ag.Pcap:
    rng = random.Random(s["tohum"] + 7)
    v = s["v"]
    p = ag.Pcap(yerel=f"{v['ag']}.0/24", ag_gecidi=f"{v['ag']}.1")
    t = u.gun(rng).timestamp() + 3600 * rng.randint(1, 5)
    web, sal = s["web"], s["saldirgan"]
    istemci = u.ic_ip(rng, v["ag"])
    while istemci in (web, f"{v['ag']}.1"):
        istemci = u.ic_ip(rng, v["ag"])
    for i in range(2):                                         # meşru istemci oturumları (SYN-ACK gürültüsü)
        o = p.tcp_oturum(istemci, 40000 + i, web, 443 if i else 80, t=t + i * 3)
        o.el_sikis()
        o.istemci(ag.http_istek("GET", "/", s["m"]["alan"]))
        o.sunucu(ag.http_yanit(200, "<h1>Merhaba</h1>"))
        o.kapat()
    p.syn_tarama(sal, web, s["portlar"], acik=set(s["acik"]), t=t + 20)
    p.tls_oturumu(istemci, u.dis_ip(rng), t=t + 40, r=rng)
    return p


def yaz(lab: Path, s: dict) -> None:
    k = lab / s["v"]["klasor"]
    m = s["m"]
    u.yaz(k / "eve.json", "\n".join(_eve_satirlari(s)) + "\n")
    u.yaz(k / "kurallar.rules", _kurallar(s))
    u.yaz(k / "izinli_kaynaklar.txt",
          "# IP adresi  açıklama (BT ekibi tarafından onaylı kaynaklar)\n"
          f"{s['tarayici']}  {s['v']['tarayici']}\n{s['ikinci']}  {s['v']['ikinci']}\n")
    _pcap(s).kaydet(k / "yakalama.pcap")
    u.yaz(lab / "OKUBENI.txt",
          f"{m['ad']} IDS çıktıları ({s['v']['klasor']}/). KURGUSAL.\n"
          f"Deniz'den not: {s['v']['sahne']}\n"
          f"eve.json: sensörün olay günlüğü. kurallar.rules: yerel imza kuralları. yakalama.pcap: aynı ağın trafik kaydı.\n")


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    s = b.senaryo
    if n > beklenen:
        return "`eve.json` içinde alarm olmayan olaylar da var (flow, dns). Sadece `\"event_type\":\"alert\"` olanları say."
    return None


def _sid_hata(g, beklenen, b):
    if re.fullmatch(r"\d+", g) and int(g) not in SIDLER:
        return "Bu bir imza numarası değil. `signature_id` alanındaki 7 haneli sayıyı yaz (9000...)."
    return None


def _fp_hata(g, beklenen, b):
    s = b.senaryo
    try:
        n = int(g)
    except ValueError:
        return None
    if n == s["f1"] or n == s["f2"]:
        return "İzinli kaynaklardan biri için saymışsın; iki izinli kaynak var, ikisinin alarmlarını topla."
    if n > beklenen:
        return "Alarm olmayan (flow/dns) olayları da saymış olabilirsin; sadece `\"event_type\":\"alert\"` satırlarını say."
    return None


def _ip_hata(g, beklenen, b):
    s = b.senaryo
    if g in (s["tarayici"], s["ikinci"]):
        return "Bu IP `izinli_kaynaklar.txt` içinde, yani BT ekibinin kendi aracı. Gerçek saldırgan listede olmayan IP."
    return None


def coz(lab: Path, s: dict) -> dict:
    k = s["v"]["klasor"]
    eve = f"{k}/eve.json"
    toplam = sh(f"grep -c '\"event_type\":\"alert\"' {eve}", lab)
    sid = sh(f"grep -o '\"signature_id\":[0-9]*' {eve} | sort | uniq -c | sort -rn | head -1 | awk '{{print $2}}' | cut -d: -f2", lab)
    izinli = f"<(awk '!/^#/ {{print $1}}' {k}/izinli_kaynaklar.txt)"
    ip = sh(f"grep 'signature_id\":9000001' {eve} | grep -o '\"src_ip\":\"[^\"]*\"' | cut -d'\"' -f4 | sort -u | grep -vxFf {izinli}", lab)
    fp = sh(f"grep '\"event_type\":\"alert\"' {eve} | grep -cFf <(awk '!/^#/ {{print \"\\\"src_ip\\\":\\\"\"$1\"\\\"\"}}' {k}/izinli_kaynaklar.txt)", lab)
    esik = sh(f"grep 'sid:9000001' {k}/kurallar.rules | grep -o 'count [0-9]*' | cut -d' ' -f2", lab)
    acik = sh(f"tcpdump -nn -r {k}/yakalama.pcap 'dst host {ip} and tcp[13] = 18' 2>/dev/null | awk '{{print $3}}' | awk -F. '{{print $NF}}' | sort -un", lab).split()
    return sec_doldur({1: toplam, 2: sid, 3: ip, 4: fp, 5: esik, 6: " ".join(acik)}, GOREVLER, lab, s)


ADIMLAR = [
    Adim("IDS ve IPS: izler mi, durdurur mu?", """
Loglar olanı kaydeder; **IDS** (saldırı tespit sistemi) saldırıyı *olurken* yakalayıp alarm verir.
**IPS** (saldırı önleme sistemi) bir adım ileri gider: yakaladığını *engeller*. Fark basit: IDS "bir
saldırı görüyorum" der, IPS "görüyorum ve durduruyorum" der. Yaygın açık kaynak araçlar Snort ve
**Suricata** (ağ), Zeek (ağ analizi) ve Wazuh'tur (ana makine).

<<sahne>> Sensörün çıktılarını (kurgusal) klasörde buldun:
""", komut="ls -l <<ids>>"),
    Adim("eve.json: sensörün olay defteri", """
Suricata her olayı `eve.json` dosyasına, **satır başına bir JSON** olarak yazar. Alarm dışında
akış (flow) ve DNS gibi olaylar da vardır. İlk iki satıra bak:
""", komut="head -n 2 <<ids>>/eve.json", sonra="""
Alanlar: `timestamp` (zaman), `event_type` (olay türü: alert, flow, dns), `src_ip`/`dest_ip`
(kaynak/hedef), `alert.signature_id` (imza numarası), `alert.signature` (imza adı), `alert.severity`
(önem: 1 en yüksek). Alarm olmayan satırlar da dosyada durur; sadece alarm saymak için
`"event_type":"alert"` ile süzmelisin.
"""),
    Adim("Sadece alarmları saymak", """
`grep -c` eşleşen satırları sayar. Tırnaklar JSON'un parçası olduğu için kalıba dahil:
""", komut="grep -c '\"event_type\":\"alert\"' <<ids>>/eve.json", sonra="""
Dosyadaki toplam satır sayısı (`wc -l`) bundan fazladır; farkı alarm olmayan olaylar yapar. "Kaç alarm var?"
sorusuna doğru cevap, yanlış cevabın 'satır sayısı' olduğu klasik bir tuzaktır.
"""),
    Adim("İmza bazında sayım", """
Cilt 1'deki `sort | uniq -c` kalıbı burada da çalışır. Hangi imza kaç kez tetiklenmiş?
""", komut="grep -o '\"signature\":\"[^\"]*\"' <<ids>>/eve.json | sort | uniq -c | sort -rn", sonra="""
En çok alarm veren imza **en tehlikeli olan değildir**. Genellikle bir yanlış pozitif kaynağı
(zamanlanmış bir tarama, bir yedek) en çok gürültüyü yapar. Alarm sayısı, tehlike ölçüsü değildir.
"""),
    Adim("Bir kuralın neyi yakaladığını okumak", """
**İmza tabanlı** tespit, bilinen saldırıların parmak izini arar: hızlıdır, kesindir, ama yalnızca
bilinen saldırıyı yakalar. Bir kural şöyle okunur: `alert` (alarm ver) `tcp` (protokol) `any any
-> $HOME_NET any` (kimden kime), parantez içinde `msg` (mesaj), `flags:S` (yalnızca SYN paketleri),
`threshold` (eşik: kaç olay, kaç saniyede) ve `sid` (imza numarası). Yerel kurallara bak:
""", komut="cat <<ids>>/kurallar.rules", sonra="""
İlk kuralı oku: bir kaynak IP **10 saniyede `count` değerinden çok sayıda SYN** gönderirse alarm. Bu,
Cilt 4'te nmap `-sS` taramasının imzasıdır. Eşik düşük olursa meşru trafikte de alarm çıkar; yüksek
olursa yavaş tarama gözden kaçar. Eşik ayarı savunmanın zanaatıdır.
"""),
    Adim("Gerçek mi, yanlış mı? İzinli kaynaklar", """
**Yanlış pozitif** (false positive), sensörün alarm verdiği ama saldırı olmayan olaydır. BT ekibi
<<tarayici>> ve <<ikinci>> gibi kendi araçlarını çalıştırır; bunlar da saldırgan gibi görünür. Onaylı
kaynak listesi:
""", komut="cat <<ids>>/izinli_kaynaklar.txt", sonra="""
Bir analistin işi: alarmı **bağlama oturtmak**. "Bu IP listede mi? Bu saatte bu işi bekliyor muyduk?"
Listede olmayan bir IP'den gelen aynı alarm, gerçek pozitiftir (true positive). Aynı imza,
iki ayrı IP, iki ayrı sonuç.
"""),
    Adim("Aynı ağın trafik kaydı: pcap", """
IDS alarmı ile ham trafiği yan yana koymak kesin bilgi verir. Cilt 2'deki `tcpdump -nn -r` ile
yakalamanın ilk paketlerine bak:
""", komut="tcpdump -nn -r <<ids>>/yakalama.pcap -c 8", sonra="""
Bir **SYN taramasında** saldırgan çok sayıda farklı porta tek paketlik SYN gönderir. Port
**kapalıysa** hedef `RST` (Flags [R.]) döner; **açıksa** `SYN-ACK` (Flags [S.]) döner. Yani SYN-ACK
yanıtının geldiği portlar açık portlardır. SYN-ACK paketi için bayrak bayt'ı (`tcp[13]`) 18'dir:
`tcpdump -nn -r DOSYA 'tcp[13] = 18'`.
"""),
    Adim("Hacker gözüyle: IDS'ten kaçmak", """
**Hacker gözüyle:** Cilt 4'te nmap `-sS` taramasının neden `-sT`'den daha sessiz olduğunu görmüştün.
IDS tam bu farkı yakalamaya çalışır: kısa sürede çok SYN, bir tarama imzasıdır. Saldırgan
"düşük ve yavaş" giderek (taramayı saatlere yayarak), trafiği şifreleyerek ya da bilinen araç
imzalarından kaçınarak kaçmaya çalışır. Savunmacı imzaları günceller ve **anomali tabanlı**
tespitle ("normalin dışı ne?") yakalamayı dener. İki taraf sürekli bir kedi-fare oyunundadır; bu
yüzden IDS tek başına yetmez, katmanlar şart. Şimdi görevlere geç.
"""),
]

GOREVLER = [
    Gorev("`<<ids>>/eve.json` içinde toplam kaç **alarm** (event_type alert) var?",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Dosyada alarm olmayan olaylar da var (flow, dns).",
           "Satırların `\"event_type\":\"alert\"` içerenlerini say.",
           "`grep -c '\"event_type\":\"alert\"' <<ids>>/eve.json`"),
          puan=25, baslik="Alarm sayısı"),
    Gorev("En çok alarm üreten imzanın **numarası** (signature_id, 9000... ile başlayan) nedir?",
          Sayi("sid", sik_hatalar=_sid_hata),
          ("Her alarmın bir `signature_id` alanı var; hangisi en çok geçiyor?",
           "`grep -o` ile sadece `signature_id` alanını çek, `sort | uniq -c | sort -rn` ile say.",
           "`grep -o '\"signature_id\":[0-9]*' <<ids>>/eve.json | sort | uniq -c | sort -rn | head -3`; üstteki satırın sayısı."),
          puan=30, baslik="En gürültülü imza"),
    Gorev("`SYN port taraması` imzasını (sid 9000001) tetikleyen kaynak IP'ler arasında, "
          "**`izinli_kaynaklar.txt` listesinde olmayan** (gerçek saldırgan) IP hangisi?",
          IP("ip", sik_hatalar=_ip_hata),
          ("Aynı imza birden fazla IP'den tetiklenmiş; bazılarını BT ekibi kendi çalıştırıyor.",
           "9000001 alarmlarının `src_ip` değerlerini tekilleştir, sonra onaylı IP'leri çıkar.",
           "`grep 'signature_id\":9000001' <<ids>>/eve.json | grep -o '\"src_ip\":\"[^\"]*\"' | sort -u` ile adayları gör; izinli listede olmayanı seç."),
          puan=40, baslik="Gerçek pozitif"),
    Gorev("Onaylı (izinli) kaynakların ürettiği **toplam alarm** sayısı kaç? Bunlar yanlış pozitiftir. "
          "(Sadece alarmları say, alarm olmayan olayları değil.)",
          Sayi("fp", sik_hatalar=_fp_hata),
          ("İki onaylı IP var; ikisinin de alarm üreten satırlarını say.",
           "Önce sadece alarm satırlarını süz, sonra `izinli_kaynaklar.txt` içindeki IP'leri içerenleri say.",
           "`grep '\"event_type\":\"alert\"' <<ids>>/eve.json | grep -c -e IP1 -e IP2` (IP'ler listede)."),
          puan=40, baslik="Yanlış pozitifler"),
    Gorev("`kurallar.rules` içinde sid **9000001** (SYN port taraması) kuralı, kaç SYN'de alarm veriyor "
          "(`threshold` içindeki `count` değeri)?",
          Sayi("esik"),
          ("Kuralları sid numarasına göre bul; eşik, `threshold` ifadesinin içinde.",
           "`grep 'sid:9000001' <<ids>>/kurallar.rules` sadece o kuralı verir.",
           "`count` kelimesinden sonraki sayı cevaptır: `grep -o 'count [0-9]*'` ile çıkarabilirsin."),
          puan=30, baslik="Kural eşiği"),
    Gorev("`<<ids>>/yakalama.pcap` içinde saldırganın taradığı portlardan hangileri **açık**? (Saldırgana "
          "SYN-ACK ile cevap veren portlar.) Port numaralarını virgülle yaz.",
          Kume("acik", tur="sayi", bicim="port numaraları, virgülle ayrılmış"),
          ("Açık port SYN-ACK döndürür, kapalı port RST döndürür.",
           "Hedefin saldırgana gönderdiği SYN-ACK paketlerini süzmen gerek: `tcp[13] = 18` ve hedef adres saldırgan.",
           "`tcpdump -nn -r <<ids>>/yakalama.pcap 'dst host SALDIRGAN_IP and tcp[13] = 18'` çıktısında kaynak adresin son noktasından sonraki sayı porttur."),
          puan=50, baslik="Açık portlar"),
    Gorev("Daha önce **hiç görülmemiş** yeni bir saldırı türünü yakalama şansı en yüksek olan tespit yaklaşımı hangisidir?",
          Secmeli([
              ("Anomali tabanlı tespit: normalin dışına çıkan davranışı işaretler, ama yanlış alarm üretebilir",
               "Doğru. Anomali tespiti bilinen imza gerektirmez; bedeli yanlış pozitiflerdir."),
              ("İmza tabanlı tespit: imza listesinde olmayan saldırıyı da parmak izinden tanır",
               "Yanlış. İmza tabanlı tespit yalnızca bilinen, imzası yazılmış saldırıları yakalar."),
              ("Yalnızca güvenlik duvarı: açık olmayan her porta gelen paket zaten saldırıdır",
               "Yanlış. Güvenlik duvarı kural eşleştirir; yeni bir saldırı türünü tanıma yeteneği yoktur."),
              ("Bir saldırının yamasının beklenmesi: yama çıkmadan hiçbir yeni saldırı yoktur",
               "Yanlış. Yeni saldırılar yamadan önce de görülür; tespit yama beklemez."),
          ], dogru=0),
          ("İmza = bilinen parmak izi. Bilinmeyeni neyle yakalarsın?",
           "'Normal'in ne olduğunu öğrenip sapmayı arayan yöntem hangisi?",
           "Anomali tabanlı tespit yeni saldırıları yakalayabilir; bedeli yanlış alarmdır."),
          puan=20, baslik="İmza ve anomali"),
    Gorev("Bir IPS, izinli zafiyet tarayıcısının (BT ekibinin kendi aracı) IP'sini yanlışlıkla engellerse ne olur?",
          Secmeli([
              ("Meşru iş kesilir (tarama ya da yedek yapılamaz); çözüm izinli kaynakları istisna listesine almak",
               "Doğru. IPS yanlış pozitifte iş kesintisine yol açar; bu yüzden izinli kaynaklar için istisna/ayar şarttır."),
              ("Hiçbir şey olmaz; IPS'nin engellediği trafik zaten sadece saldırı olabilir",
               "Yanlış. IPS de yanılabilir; meşru bir aracı engellemek, yanlış pozitifin doğrudan sonucudur."),
              ("Sensör kendiliğinden kapanır ve bütün ağ trafiğini serbest bırakır",
               "Yanlış. Bir kuralın yanlış engellemesi sensörü kapatmaz; sadece o trafiği keser."),
              ("Saldırgan otomatik olarak yakalanır, çünkü engellenen her IP sonunda saldırgandır",
               "Yanlış. Engellenen IP'nin saldırgan olduğunun garantisi yoktur; bu kez kendi aracımız engellendi."),
          ], dogru=0),
          ("IDS yalnızca izler; IPS ise bir şeyi *durdurur*. Yanlış durdurursan?",
           "Engellenen aracın ne yaptığını düşün: tarama, yedek, sağlık kontrolü.",
           "IPS'in bedeli, yanlış pozitifin gerçek iş kesintisine dönüşmesidir."),
          puan=20, baslik="IPS riski"),
]


def _kapanis():
    return """
Aynı port taraması imzası iki ayrı IP'den tetiklendi: biri BT ekibinin kendi aracıydı, biri saldırgan.
Sayıya bakan analist yanılır; bağlama (izinli kaynak listesi, saat, hedef) bakan doğrusunu görür.
Saldırgan açısından ders: tarama hızını düşürmek ya da trafiği şifrelemek imzayı atlatabilir, çünkü
imza yalnızca bildiğini tanır. Savunma dersi: eşikleri ve izinli kaynakları düzenli güncelle,
anomali tespitini imza tespitiyle birlikte kullan ve bir IDS'in alarmını mutlaka ikinci bir kaynakla
(log, pcap) doğrula.
"""


SEVIYE = Seviye(
    kimlik="c07b04",
    cilt=7,
    bolum=4,
    baslik="Saldırı Tespiti: IDS ve IPS",
    brifing="""
Deniz Kara iki monitör arasında dönüyor: "**<<musteri>>**'nin sensörü bir yığın alarm yazdı. <<sahne>>
Alarm yağmurunda gerçek saldırıyı bulmak, samanlıkta iğne aramak gibi."

Deniz klasörü sana uzatıyor: "`eve.json` sensörün defteri, `kurallar.rules` yerel imzalar,
`izinli_kaynaklar.txt` BT ekibinin kendi araçları, `yakalama.pcap` aynı ağın trafiği. Sorular: kaç alarm,
kim gerçek, kim yanlış alarm, kural neyi yakalıyor ve saldırgan hangi kapıları açık buldu?"
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Equifax 2017:** Kamuya açık soruşturma raporlarına göre, ağ trafiğini inceleyen bir güvenlik
  cihazının sertifikası uzun süre yenilenmediği için trafik büyük ölçüde incelenemedi ve saldırı
  aylarca fark edilmedi. Ders: tespit araçlarının **çalışır durumda olduğunu** düzenli doğrulamak,
  onları kurmak kadar önemlidir.
- **Target 2013:** Güvenlik ürünleri saldırıya ilişkin alarmlar üretmişti ama alarmlar yeterince
  aksiyona çevrilmedi. Alarm yağmurunda gerçek sinyali ayıklamak (yanlış pozitifleri eleyip
  kritiklere öncelik vermek) bu bölümdeki beceridir.
- **Port taraması ve eşik ayarı:** Hemen her IDS'te port tarama kuralı bulunur ve en sık yanlış
  alarm kaynağı, kurumun kendi zafiyet tarayıcıları ve izleme araçlarıdır. Bu kaynakları kural
  yazarken istisna listesine almak (suppress) ve taramaları önceden duyurmak olağan pratiktir.
""",
    sure_hedef_dk=40,
)
