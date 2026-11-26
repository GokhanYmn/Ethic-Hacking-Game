"""Olay Masası — Güvenlik Duvarı Kural Denetimi.

Her vakada başka bir müşterinin güvenlik duvarı kural listesi (`kurallar.txt`) gelir. Listede
tohumdan türeyen dört tür hata saklıdır: internete açık hassas port, "her şeye izin"
kuralı, önündeki geniş kural yüzünden hiç çalışmayan (gölgelenmiş) kural ve ACCEPT varsayılan
politika. Oyuncu kural dosyasını `awk` ve `grep` ile denetler. Sadece savunma: dosya okunur,
hiçbir sisteme dokunulmaz.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Kume, Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

HASSAS = [22, 3389, 5432, 3306, 6379]
AG_HAVUZU = ["192.168.1", "192.168.10", "10.0.0", "10.10.5", "172.16.4"]
SIRALAMA_SIFIR = "0.0.0.0/0"


def uret(rng):
    m = musteri_sec(rng)
    srv = u.ic_ip(rng, "10.50.0")
    admin, diger = rng.sample(AG_HAVUZU, 2)
    portlar = rng.sample(HASSAS, len(HASSAS))
    n_acik = rng.randint(1, 2)
    acik, kapali = portlar[:n_acik], portlar[n_acik:]
    politika = rng.choice(["ACCEPT", "DROP"])

    # Hatalı olmayan (yanıltıcı) kurallar
    havuz = [
        f"ACCEPT tcp {SIRALAMA_SIFIR} {srv} 443",
        f"ACCEPT tcp {SIRALAMA_SIFIR} {srv} 80",
        f"ACCEPT tcp {diger}.0/24 {srv} {rng.choice(HASSAS)}",
        f"DROP tcp {SIRALAMA_SIFIR} {srv} {rng.choice(kapali)}",
        f"DROP all {u.dis_ip(rng)}/32 any any",
        f"ACCEPT udp {diger}.0/24 {srv} 53",
        f"ACCEPT icmp {SIRALAMA_SIFIR} {srv} any",
    ]
    govde = rng.sample(havuz, rng.randint(5, 7))
    govde += [f"ACCEPT tcp {SIRALAMA_SIFIR} {srv} {p}" for p in acik]
    rng.shuffle(govde)

    genis = f"ACCEPT tcp {admin}.0/24 any any"
    golge = f"DROP tcp {admin}.{rng.randint(2, 254)}/32 {srv} {rng.choice(HASSAS)}"
    g_yer = rng.randint(0, len(govde))
    govde.insert(g_yer, genis)
    govde.insert(rng.randint(g_yer + 1, len(govde)), golge)
    govde.append(f"ACCEPT all {SIRALAMA_SIFIR} any any")   # her şeye izin: en sonda, her şeyi geçersiz kılar

    satirlar = [f"{i} {k}" for i, k in enumerate(govde, 1)]
    acik_satir = {f"ACCEPT tcp {SIRALAMA_SIFIR} {srv} {p}" for p in acik}
    acik_no = [i for i, k in enumerate(govde, 1) if k in acik_satir]
    golge_no = govde.index(golge) + 1
    kural_metni = (
        f"# {m['ad']} - {m['sunucu']} ({srv}) INPUT zinciri\n"
        f"POLITIKA {politika}\n"
        "# NO EYLEM PROTO KAYNAK HEDEF PORT\n" + "\n".join(satirlar) + "\n"
    )
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — {m['sunucu']} güvenlik duvarı",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "sunucu": m["sunucu"], "kisi": m["kisi"],
                  "hikaye": m["hikaye"]},
        "cevaplar": {
            "acik_portlar": sorted(acik),
            "hepsi_no": len(govde),
            "golge_no": golge_no,
            "politika": [politika],
            "toplam": len(acik) + 2,
        },
        "_kurallar": kural_metni,
        "_acik_no": acik_no,
    }


def yaz(lab: Path, s: dict) -> None:
    u.yaz(lab / "kurallar.txt", s["_kurallar"])


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _hepsi_hata(g, beklenen, b):
    if int(g) in b.senaryo["_acik_no"]:
        return "Bu kural tek bir hassas portu açıyor; sorulan, **kaynak, hedef, port ve protokolün hepsi** serbest olan kural."
    return None


def _golge_hata(g, beklenen, b):
    if int(g) == b.senaryo["cevaplar"]["hepsi_no"]:
        return ("Bu kural herkese açık ama gölgelenmiş değil: en sonda ve kendinden önce onu kapatan kural yok. "
                "Gölgelenen, önündeki geniş bir kural yüzünden hiç eşleşemeyen DAHA DAR kuraldır.")
    return None


def _politika_hata(g, beklenen, b):
    if g in ("dogru", "doğru", "evet", "hayır", "hayir"):
        return "Politikanın adını yaz: `ACCEPT` ya da `DROP`."
    return None


def Secmeli_cevap(s, lab):
    return SEVIYE.gorevler[5].kontrol.cevabi_goster(Baglam(s, lab, 6))[0]


def coz(lab: Path, s: dict) -> dict:
    portlar = _sh("awk '$2==\"ACCEPT\" && $4==\"0.0.0.0/0\" && $6 ~ /^(22|3389|5432|3306|6379)$/ {print $6}' "
                  "kurallar.txt | sort -un | tr '\\n' ' '", lab)
    hepsi = _sh("awk '$2==\"ACCEPT\" && $3==\"all\" && $4==\"0.0.0.0/0\" && $5==\"any\" && $6==\"any\" "
                "{print $1}' kurallar.txt", lab)
    golge = _sh("awk '$2==\"ACCEPT\" && $4 ~ /\\/24$/ && $5==\"any\" && $6==\"any\" "
                "{split($4,a,\".\"); g[a[1]\".\"a[2]\".\"a[3]]=1} "
                "$4 ~ /\\/32$/ {split($4,a,\".\"); if ((a[1]\".\"a[2]\".\"a[3]) in g) print $1}' kurallar.txt", lab)
    politika = _sh("awk '$1==\"POLITIKA\" {print $2}' kurallar.txt", lab)
    n_acik = len(portlar.split())
    toplam = n_acik + len(hepsi.split()) + len(golge.split())
    return {1: portlar, 2: hepsi, 3: golge, 4: politika, 5: toplam, 6: Secmeli_cevap(s, lab)}


GOREVLER = [
    Gorev("`kurallar.txt` içinde **internetten (0.0.0.0/0) gelen** trafiğe **ACCEPT** veren ve hassas bir "
          "yönetim/veritabanı portunu (22, 3389, 5432, 3306, 6379) açan kurallar var. Açık hassas portların "
          "hepsini yaz.",
          Kume("acik_portlar", tur="sayi", bicim="boşlukla ayrılmış port numaraları"),
          ("Kural satırında eylem 2., kaynak 4., port 6. alan. Kaynağı 0.0.0.0/0 ve eylemi ACCEPT olanları süz.",
           "Süzdüklerinin portuna bak; yalnızca 22, 3389, 5432, 3306, 6379 sayılır. 443/80 web için normaldir.",
           "`awk '$2==\"ACCEPT\" && $4==\"0.0.0.0/0\" {print $1, $6}' kurallar.txt` — sonra hassas portları seç."),
          puan=15, baslik="Açık hassas port"),
    Gorev("**Her şeye izin veren** (proto, kaynak, hedef ve port hepsi serbest) ACCEPT kuralının sıra numarası kaç?",
          Sayi("hepsi_no", sik_hatalar=_hepsi_hata),
          ("Böyle bir kuralda kaynak, hedef ve port 'herkes/her yer' anlamına gelir.",
           "Proto `all`, kaynak `0.0.0.0/0`, hedef ve port `any` olan ACCEPT satırı.",
           "`awk '$2==\"ACCEPT\" && $3==\"all\" && $5==\"any\" && $6==\"any\" {print $1}' kurallar.txt`"),
          puan=15, baslik="Her şeye izin"),
    Gorev("Bir kural **gölgelenmiş**: önündeki geniş bir kural aynı trafiği zaten yakaladığı için hiç çalışmıyor. "
          "Gölgelenen (daha dar) kuralın sıra numarası kaç?",
          Sayi("golge_no", sik_hatalar=_golge_hata),
          ("Güvenlik duvarı kuralları yukarıdan aşağıya okur; ilk eşleşen kazanır. Üstteki geniş kural alttakini yutar.",
           "Kaynağı bir /24 ağ olan ve hedef/port `any` olan kuralı bul; sonra o ağın içindeki tek bir ana makine (/32) için yazılmış, ondan SONRA gelen kurala bak.",
           "`awk '$4 ~ /\\/24$/ && $5==\"any\" {print $1, $4}' kurallar.txt` ve `awk '$4 ~ /\\/32$/ {print $1, $4}' kurallar.txt` çıktılarını karşılaştır."),
          puan=20, baslik="Gölge kural"),
    Gorev("Dosyadaki **varsayılan politika** (hiçbir kurala uymayan trafiğe ne yapılacağı) nedir? "
          "`ACCEPT` ya da `DROP` yaz. (Güvenli olan hangisi?)",
          Metin("politika", bicim="ACCEPT ya da DROP", sik_hatalar=_politika_hata),
          ("Politika satırı dosyanın başında; kural satırlarından farklı bir sözcükle başlar.",
           "`POLITIKA` ile başlayan satırın ikinci alanı.",
           "`awk '$1==\"POLITIKA\" {print $2}' kurallar.txt` — güvenli olan DROP'tur (varsayılan reddet)."),
          puan=15, baslik="Varsayılan politika"),
    Gorev("Toplam kaç **riskli kural** var? (İnternete açık hassas port kuralları + her şeye izin kuralı + "
          "gölgelenmiş kural; politika satırını sayma.)",
          Sayi("toplam"),
          ("Önceki üç görevin cevaplarını topla: kaç hassas port kuralı, kaç her-şeye-izin, kaç gölge kural.",
           "Açık hassas port sayısı + 1 (her şeye izin) + 1 (gölgelenmiş).",
           "Her kural ayrı satır olduğu için aynı satırı iki kez sayma; hassas port görevindeki port sayısı = o kural sayısı."),
          puan=15, baslik="Riskli kural sayısı"),
    Gorev("Bulgularını yönetime raporluyorsun. **En kritik** bulgu hangisi?",
          Secmeli([
              ("Her şeye izin veren `ACCEPT all 0.0.0.0/0 any any` kuralı",
               "Doğru. Tek satır bütün koruma mantığını boşa çıkarır: internetten her porta erişim açılır."),
              ("Gölgelenmiş tek bir DROP kuralı",
               "Önemli bir hijyen sorunu ama tek bir ana makineyi etkiler; her şeye izin kadar kritik değil."),
              ("Dosyanın başındaki yorum satırlarının eksik olması",
               "Yorum satırları belgelemedir; güvenlik açığı yaratmaz."),
              ("Kural sayısının fazla olması",
               "Kalabalık kural listesi bakım yükü getirir ama tek başına açık değildir."),
          ], dogru=0),
          ("Bir kuralın etkisi, kaç kaynağa, hedefe ve porta izin verdiğiyle ölçülür.",
           "Hangi bulgu **her** kaynağın **her** porta ulaşmasına izin veriyor?",
           "Her şeye izin kuralı diğer bütün DROP/ACCEPT inceliklerini anlamsız kılar."),
          puan=15, baslik="En kritik bulgu"),
]

SEVIYE = Seviye(
    kimlik="olay_firewall",
    cilt=7,
    bolum=106,
    baslik="Güvenlik Duvarı Kural Denetimi",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) aradı. <<hikaye>>
<<kisi>> bize **<<sunucu>>** sunucusunun güvenlik duvarı kural listesini gönderdi: `kurallar.txt`."

"Kurallar yukarıdan aşağıya okunur, ilk eşleşen kazanır. Bu listeyi denetle: internete açılmış
hassas port var mı, her şeye izin veren kural var mı, bir kural diğerinin gölgesinde mi kalmış,
varsayılan politika güvenli mi? Sadece oku ve raporla, hiçbir şeyi değiştirme."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Güvenlik duvarı hijyeninin dört kuralı: **varsayılan reddet** (politika DROP, izinler tek tek
açılır), **en az açıklık** (yönetim ve veritabanı portları internete değil, yalnızca bilinen
ağlara), **kural hijyeni** (her şeye izin kuralı hiçbir zaman kalıcı olmamalı, geçici açılan
kural not ve bitiş tarihiyle gelmeli) ve **gölge kural denetimi** (dar bir kuralın önüne geniş
bir kural eklendiğinde dar kuralın hâlâ çalışıp çalışmadığı düzenli olarak sınanmalı).
""",
    gercek_hayat="""
- **Açık RDP/3389 ve fidye yazılımı:** Fidye çetelerinin en sık giriş yollarından biri,
  internete açık bırakılmış Uzak Masaüstü (3389) portudur. Saldırganlar sızan ya da tahmin
  edilen parolayla doğrudan içeri girer; çok sayıda olayda ilk adım, "geçici" diye açılıp
  unutulan bir güvenlik duvarı kuralıdır.
- **Açık Redis/6379 ve Elasticsearch sızıntıları:** Kimlik doğrulamasız Redis ve Elasticsearch
  sunucularının internete açık bırakılması, milyonlarca kaydın ele geçirilmesine ya da verinin
  silinip fidye notu bırakılmasına yol açtı. Bu veri tabanları ağ içinde kalmak üzere
  tasarlanmıştı; tek bir fazla geniş kural onları herkese açtı.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b02",),
)
