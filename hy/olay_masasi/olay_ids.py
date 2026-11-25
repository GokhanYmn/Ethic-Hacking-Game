"""Olay Masası — Alarm Ayıklama Masası.

Her vakada bir IDS'in (Suricata `eve.json` biçiminde, kurgusal imzalarla) alarm kayıtları:
gürültücü bir iç güvenlik tarayıcısı, bir izleme sunucusu, dışarıdan sessiz ama kritik bir
saldırgan ve birkaç yoklayıcı. Analist yanlış pozitifleri ayıklayıp gerçek tehdidi bulur.
Hiçbir saldırı yükü yoktur; yalnızca alarm kayıtları vardır. Dış IP'ler TEST-NET'tir.
"""
from __future__ import annotations

import json
import subprocess
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Sayi, Sonuc
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

IMZA = {
    2100001: ("LAB SCAN Nmap betik motoru taraması", "Attempted Information Leak", 2),
    2100002: ("LAB SCAN Güvenlik tarayıcısı User-Agent", "Attempted Information Leak", 3),
    2100003: ("LAB WEB Olası SQL enjeksiyon denemesi", "Web Application Attack", 1),
    2100004: ("LAB POLICY SSH sürüm sorgusu", "Misc activity", 3),
    2100010: ("LAB POLICY SNMP sorgusu", "Misc activity", 3),
    2100011: ("LAB POLICY ICMP yoklama", "Misc activity", 3),
    2100020: ("LAB SCAN Tekil port taraması", "Attempted Information Leak", 3),
    2100021: ("LAB WEB Olası dizin gezinme", "Web Application Attack", 2),
    2100022: ("LAB SSH kaba kuvvet denemesi", "Attempted User Privilege Gain", 2),
    2100023: ("LAB SCAN ICMP tarama", "Attempted Information Leak", 3),
    2100030: ("LAB WEB Yönetim paneli yetkisiz erişim", "Attempted Administrator Privilege Gain", 1),
}
PORT = {2100001: 80, 2100002: 443, 2100003: 80, 2100004: 22, 2100010: 161, 2100011: 0, 2100020: 8080,
        2100021: 80, 2100022: 22, 2100023: 0, 2100030: 443}
IC_RE = r"^(10\.|192\.168\.|172\.16\.)"


def uret(rng):
    m = musteri_sec(rng)
    ag = rng.choice(["192.168.10", "10.0.0", "10.10.5", "172.16.4"])
    hedef = f"{ag}.{rng.randint(10, 40)}"
    tarayici = f"{ag}.{rng.randint(100, 199)}"
    izleme = f"{ag}.{rng.randint(200, 250)}"
    a1, a2 = u.benzersiz(rng, u.dis_ip, 2)
    yoklayicilar = u.benzersiz(rng, u.dis_ip, rng.randint(2, 3), {a1, a2})
    olaylar = []   # (ip, sid)
    # iç tarayıcı: baskın imza rastgele
    sidler = rng.sample([2100001, 2100002, 2100003, 2100004], 4)
    for sid, n in zip(sidler, (rng.randint(12, 18), rng.randint(5, 9), rng.randint(3, 4), rng.randint(1, 2))):
        olaylar += [(tarayici, sid)] * n
    for sid in (2100010, 2100011):
        olaylar += [(izleme, sid)] * rng.randint(2, 4)
    # dış gürültücü (keşif): baskın imza belirgin
    s1, s2, s3 = rng.sample([2100020, 2100021, 2100022], 3)
    for sid, n in zip((s1, s2, s3), (rng.randint(7, 10), rng.randint(3, 5), rng.randint(2, 3))):
        olaylar += [(a1, sid)] * n
    # dışarıdan sessiz ama kritik
    olaylar += [(a2, 2100003)] * rng.randint(2, 3) + [(a2, 2100030)] * rng.randint(1, 2)
    for ip in yoklayicilar:
        olaylar.append((ip, 2100023))
    rng.shuffle(olaylar)
    t0 = u.gun(rng).replace(hour=rng.randint(0, 5))
    zamanlar = u.zamanlar(rng, t0, len(olaylar) + 25, 5, 240)
    # akış/dns gürültüsü
    gurultu = [("flow" if rng.random() < .7 else "dns") for _ in range(25)]
    sirali = []
    kalan_g = list(gurultu)
    idx = sorted(rng.sample(range(len(olaylar) + 25), 25))
    oi = 0
    for i, t in enumerate(zamanlar):
        if i in idx:
            tip = kalan_g.pop()
            ip = rng.choice([u.dis_ip(rng), u.ic_ip(rng, ag)])
            ev = {"timestamp": _zaman(t, rng), "flow_id": rng.randint(10 ** 12, 10 ** 13), "in_iface": "eth0",
                  "event_type": tip, "src_ip": ip, "src_port": rng.randint(1024, 65000),
                  "dest_ip": hedef, "dest_port": 53 if tip == "dns" else rng.choice([80, 443, 22]), "proto": "TCP"}
        else:
            ip, sid = olaylar[oi]
            oi += 1
            ad, kat, sev = IMZA[sid]
            ev = {"timestamp": _zaman(t, rng), "flow_id": rng.randint(10 ** 12, 10 ** 13), "in_iface": "eth0",
                  "event_type": "alert", "src_ip": ip, "src_port": rng.randint(1024, 65000),
                  "dest_ip": hedef, "dest_port": PORT[sid], "proto": "TCP",
                  "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1, "signature": ad,
                            "category": kat, "severity": sev}}
        sirali.append(json.dumps(ev, ensure_ascii=False, separators=(",", ":")))
    sayac = {}
    for ip, sid in olaylar:
        sayac[sid] = sayac.get(sid, 0) + 1
    ham_top = max(sayac, key=sayac.get)
    fp = {tarayici, izleme}
    gercek = {}
    for ip, sid in olaylar:
        if ip not in fp:
            gercek[sid] = gercek.get(sid, 0) + 1
    gercek_top = max(gercek, key=gercek.get)
    dis_say = {}
    for ip, sid in olaylar:
        if ip not in fp:
            dis_say[ip] = dis_say.get(ip, 0) + 1
    # a2'nin kronolojik ilk severity-1 alarmı
    ilk_kat = None
    oi = 0
    for i in range(len(zamanlar)):
        if i in idx:
            continue
        ip, sid = olaylar[oi]
        oi += 1
        if ip == a2 and IMZA[sid][2] == 1:
            ilk_kat = IMZA[sid][1]
            break
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — IDS alarm kayıtları",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "sunucu": m["sunucu"],
                  "hikaye": m["hikaye"], "hedef": hedef},
        "cevaplar": {"toplam": len(olaylar), "ham_imza": ham_top, "fp": sum(1 for ip, _ in olaylar if ip in fp),
                     "dis_ip": [a1], "kritik_ip": [a2], "gercek_imza": gercek_top,
                     "kategori": [ilk_kat]},
        "_eve": "\n".join(sirali) + "\n",
        "_bilinen": f"{tarayici}  nessus-tarama   haftalık güvenlik taraması (BT onaylı)\n"
                    f"{izleme}  izleme-sunucusu  ağ izleme (SNMP/ICMP yoklaması normaldir)\n",
        "_fp_ipler": sorted(fp),
        "_dis": a1,
    }


def _zaman(t, rng):
    return f"{t:%Y-%m-%dT%H:%M:%S}.{rng.randint(0, 999999):06d}+0300"


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "alarmlar" / "eve.json", s["_eve"])
    u.yaz(lab / "alarmlar" / "bilinen_yerel.txt", s["_bilinen"])


def _engel(b) -> Sonuc:
    yol = b.lab / "engel_listesi.txt"
    if not yol.exists():
        return Sonuc(False, "`engel_listesi.txt` yok. Engellenecek IP'yi bu dosyaya yaz.")
    from hy.motor.kontrol import IP_DESENI
    ipler = set(IP_DESENI.findall(yol.read_text(encoding="utf-8")))
    kritik = b.senaryo["cevaplar"]["kritik_ip"][0]
    if set(b.senaryo["_fp_ipler"]) & ipler:
        return Sonuc(False, "Listede BT'nin onayladığı bir iç sistem var; kendi tarayıcını engellersen güvenlik "
                            "taramaları ve izleme durur.")
    if kritik not in ipler:
        return Sonuc(False, "Listede gerçek tehdit olan IP yok: severity 1 alarm veren dış IP'yi yaz.",
                     yakin=bool(ipler))
    return Sonuc(True, "Engel listesi hazır. Gerçek ağda bu IP'yi güvenlik duvarına da eklerdin.")


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _toplam_hata(g, beklenen, b):
    n = b.senaryo["_eve"].count("\n")
    if int(g) == n:
        return "Bu, dosyadaki tüm satırlar. Akış (flow) ve DNS kayıtları alarm değil; sadece `\"event_type\":\"alert\"`."
    return None


def _ip_hata(g, beklenen, b):
    if g in b.senaryo["_fp_ipler"]:
        return "Bu IP `bilinen_yerel.txt` listesinde: BT'nin onayladığı iç sistem, yanlış pozitif."
    return None


def coz(lab: Path, s: dict) -> dict:
    toplam = _sh("grep -c '\"event_type\":\"alert\"' alarmlar/eve.json", lab)
    ham = _sh("grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -o '\"signature_id\":[0-9]*' | sort | uniq -c "
              "| sort -rn | head -1 | awk -F: '{print $2}'", lab)
    liste = "awk '{print \"\\\"src_ip\\\":\\\"\" $1 \"\\\"\"}' alarmlar/bilinen_yerel.txt"
    fp = _sh(f"grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -c -F -f <({liste})", lab)
    dis = _sh(f"grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -v -F -f <({liste}) "
              "| grep -o '\"src_ip\":\"[0-9.]*\"' | cut -d'\"' -f4 | grep -vE '^(10|192\\.168|172\\.16)\\.' "
              "| sort | uniq -c | sort -rn | head -1 | awk '{print $2}'", lab)
    kritik = _sh(f"grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -v -F -f <({liste}) "
                 "| grep '\"severity\":1[,}]' | grep -o '\"src_ip\":\"[0-9.]*\"' | cut -d'\"' -f4 | sort -u", lab)
    gercek = _sh(f"grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -v -F -f <({liste}) "
                 "| grep -o '\"signature_id\":[0-9]*' | sort | uniq -c | sort -rn | head -1 | awk -F: '{print $2}'", lab)
    kat = _sh("grep '\"src_ip\":\"" + kritik + "\"' alarmlar/eve.json | grep '\"severity\":1[,}]' | head -1 "
              "| python3 -m json.tool | grep '\"category\"' | cut -d'\"' -f4", lab)
    _sh(f"echo {kritik} > engel_listesi.txt", lab)
    return {1: toplam, 2: ham, 3: fp, 4: dis, 5: kritik, 6: gercek, 7: "", 8: kat}


GOREVLER = [
    Gorev("`alarmlar/eve.json` dosyasında kaç **alarm** (`alert`) kaydı var? (akış ve DNS kayıtları alarm değildir)",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Dosyada her satır bir JSON olay; ama hepsi alarm değil.",
           "Her satırda `\"event_type\":\"...\"` var; alarmlarda değer `alert`.",
           "`grep -c '\"event_type\":\"alert\"' alarmlar/eve.json`"),
          puan=15, baslik="Toplam alarm"),
    Gorev("En çok tekrar eden imzanın kimliği (`signature_id`) nedir? (tüm alarmlar dahil)",
          Sayi("ham_imza"),
          ("Her alarmın bir `signature_id` numarası var; aynı numaranın kaç kez geçtiğini say.",
           "`grep -o` ile sadece `\"signature_id\":NUMARA` kısmını çıkar, sırala, `uniq -c` ile say.",
           "`grep -o '\"signature_id\":[0-9]*' alarmlar/eve.json | sort | uniq -c | sort -rn | head -3`"),
          puan=15, baslik="En sık imza"),
    Gorev("`alarmlar/bilinen_yerel.txt` BT'nin onayladığı iç sistemleri listeliyor. Bu IP'lerden gelen alarmlar "
          "**yanlış pozitif**. Kaç alarm yanlış pozitif?",
          Sayi("fp"),
          ("Önce listedeki IP'leri oku, sonra bu IP'lerin `src_ip` olduğu alarmları say.",
           "`grep` ile her IP'yi `\"src_ip\":\"IP\"` biçiminde ara (tırnaklar 10.0.0.5 ile 10.0.0.50'yi karıştırmanı önler).",
           "`grep '\"event_type\":\"alert\"' alarmlar/eve.json | grep -c -e '\"src_ip\":\"IP1\"' -e '\"src_ip\":\"IP2\"'`"),
          puan=20, baslik="Yanlış pozitif"),
    Gorev("Yanlış pozitifleri çıkardıktan sonra, **dışarıdan** (iç ağ dışından) gelen ve **en çok alarm üreten** "
          "IP hangisi?",
          Metin("dis_ip", bicim="bir IP adresi", sik_hatalar=_ip_hata),
          ("İç ağ adresleri 10., 192.168. ya da 172.16. ile başlar; dışarıdakiler değil.",
           "Yanlış pozitifleri `grep -v` ile at, kalanlarda `src_ip` değerlerini say.",
           "`... | grep -o '\"src_ip\":\"[0-9.]*\"' | sort | uniq -c | sort -rn`"),
          puan=20, baslik="En gürültülü dış IP"),
    Gorev("Yanlış pozitifleri çıkardıktan sonra **severity 1** (en yüksek önem) alarm veren IP hangisi? "
          "(Suricata'da 1 en kritik, 3 en düşüktür)",
          Metin("kritik_ip", bicim="bir IP adresi", sik_hatalar=_ip_hata),
          ("`severity` alarmın `alert` bölümünde bir sayı: 1 en yüksek önemdir.",
           "`grep '\"severity\":1[,}]'` severity 1 alarmları süzer; yanlış pozitifleri unutma.",
           "En çok alarm üreten IP ile en kritik alarmı veren IP aynı olmak zorunda değil."),
          puan=25, baslik="Kritik tehdit"),
    Gorev("Yanlış pozitifler çıkarıldığında **en çok tekrar eden imzanın kimliği** (`signature_id`) nedir?",
          Sayi("gercek_imza"),
          ("Görev 2'nin aynısı, ama önce yanlış pozitifleri atmalısın.",
           "İç tarayıcının gürültüsü sıralamayı bozuyordu; onsuz sıralama değişir.",
           "`grep -v` ile iki yerel IP'yi at, `signature_id` değerlerini say, sırala."),
          puan=20, baslik="Gerçek en sık imza"),
    Gorev("Görev 5'teki IP'yi `engel_listesi.txt` dosyasına yaz (`echo IP > engel_listesi.txt`). "
          "Bitince `cevap 7` yaz.",
          Durum(_engel, "echo <severity-1 IP> > engel_listesi.txt"),
          ("Dosya henüz yok; bir yönlendirme (`>`) ile oluşturabilirsin.",
           "`echo 203.0.113.9 > engel_listesi.txt` biçiminde, kendi bulduğun IP ile.",
           "Listeye yanlış pozitif bir iç IP'yi yazma; güvenlik taramaları durur."),
          puan=20, baslik="Engelle"),
    Gorev("Görev 5'teki IP'nin **ilk severity-1 alarmının** `category` (kategori) değeri ne? "
          "(satırı okunur görmek için `python3 -m json.tool` kullan)",
          Metin("kategori", bicim="kategori adı (İngilizce)"),
          ("Satırı süz, tek bir satır al, JSON biçimlendiriciden geçir.",
           "`grep IP alarmlar/eve.json | grep '\"severity\":1[,}]' | head -1 | python3 -m json.tool`",
           "Çıktıdaki `alert` bölümünde `category` alanı var."),
          puan=15, baslik="Alarm kategorisi"),
]

SEVIYE = Seviye(
    kimlik="olay_ids",
    cilt=1,
    bolum=95,
    baslik="Alarm Ayıklama Masası",
    brifing="""
Deniz Kara başını ekrandan kaldırmadan konuşuyor: "**<<musteri>>** (<<sektor>>) ağındaki IDS
bütün gece alarm üretti. <<hikaye>> <<kisi>> **<<sunucu>>** önündeki sensörün kaydını
`alarmlar/eve.json` olarak gönderdi; BT'nin tanıdığı iç sistemler `bilinen_yerel.txt`'de."

"Alarm sayısına bakıp panik yapma: çoğu gürültü. Önce yanlış pozitifleri ayıkla, sonra dışarıdan
gerçekten tehdit olanı bul. Unutma, en çok alarm veren her zaman en tehlikeli değildir."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
IDS çok konuşur; analistin işi sinyali gürültüden ayırmaktır. Haftalık güvenlik taraması gibi
bilinen kaynakları listeleyip ayıklamak, alarm yorgunluğunu azaltır. Sonra bakılacak şey hacim
değil önemdir: sessizce birkaç kritik alarm üreten bir IP, gürültülü bir yoklayıcıdan çok daha
tehlikelidir. Bu eleme bir betikte tutulursa her sabah beş dakikada yapılır.
""",
    gercek_hayat="""
- **Alarm yorgunluğu:** Büyük bir perakende zincirinin 2013'teki ihlalinde güvenlik ürünü gerçek
  saldırı alarmını üretmiş, ama alarm bol gürültü arasında kaybolmuş ve işlem görmemiştir.
  Önlem: bilinen kaynakları ayıklayan kurallar, alarmları önemine göre sıralayan bir panel ve
  kritik alarm için ayrı bildirim.
- **Tarayıcı beyaz listesi:** Kurumsal ağlarda zafiyet tarayıcısı IP'leri IDS kurallarında bilinçli
  olarak işaretlenir; böylece hem taramalar sorunsuz çalışır hem de dışarıdan gelen aynı imzalı
  trafik gözden kaçmaz.
""",
    sure_hedef_dk=20,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b04",),
)
