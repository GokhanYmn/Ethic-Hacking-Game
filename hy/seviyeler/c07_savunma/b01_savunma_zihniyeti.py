"""Cilt 7 · Bölüm 1 — Savunma Zihniyeti ve Saldırı Zinciri.

Beceri: bir olayın kanıtlarını siber saldırı zincirinin (kill chain) aşamalarına ve MITRE ATT&CK
teknik koduna eşlemek, zincirin hangi halkada durduğunu söylemek, derinlemesine savunmada hangi
katmanın (önleme / tespit / kurtarma) eksik olduğunu bulmak.

Vakalar: üç ayrı kurgusal olay (e-ticaret, hastane, belediye). Her vakada zincir farklı bir
halkada durur ve içinde bir de alakasız (meşru) kayıt vardır.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from hy.motor.kontrol import Durum, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c07_savunma.ortak import Sira, ascii_norm, sec_doldur, sh

ASAMALAR = [
    ("kesif", "Keşif", "Hedefi haritalar (Cilt 4)", ["keşif", "kesif"]),
    ("ilk_erisim", "İlk erişim", "İçeri girer: açık, phishing, çalıntı parola (Cilt 5-6)",
     ["ilk erişim", "ilk erisim", "ilk_erisim"]),
    ("yer_edinme", "Yer edinme", "Kalıcılık sağlar: yeni hesap, zamanlanmış görev (Cilt 6)",
     ["yer edinme", "yer_edinme", "kalıcılık", "kalicilik"]),
    ("yetki_yukseltme", "Yetki yükseltme", "Root/admin olur (Cilt 6)",
     ["yetki yükseltme", "yetki yukseltme", "yetki_yukseltme"]),
    ("yanal_hareket", "Yanal hareket", "Diğer makinelere yayılır (Cilt 6)", ["yanal hareket", "yanal_hareket"]),
    ("hedefe_ulasma", "Hedefe ulaşma", "Veri çalar ya da şifreler",
     ["hedefe ulaşma", "hedefe ulasma", "hedefe_ulasma"]),
]
ALAKASIZ = ["alakasız", "alakasiz", "benign", "meşru", "mesru", "normal", "gürültü", "gurultu"]

MITRE = [
    ("T1595", "Active Scanning", "Hedefi etkin biçimde tarama (port/dizin taraması)"),
    ("T1190", "Exploit Public-Facing Application", "İnternete açık uygulamadaki zafiyeti kullanma"),
    ("T1566", "Phishing", "Oltalama e-postası ile içeri girme"),
    ("T1078", "Valid Accounts", "Geçerli (çalıntı/sızmış) hesap kullanma"),
    ("T1110", "Brute Force", "Parolayı deneme-yanılmayla bulma"),
    ("T1136", "Create Account", "Kalıcılık için yeni hesap oluşturma"),
    ("T1053", "Scheduled Task/Job", "Zamanlanmış görev/cron ile kalıcılık"),
    ("T1548", "Abuse Elevation Control Mechanism", "Yetki yükseltme mekanizmalarını kötüye kullanma (sudo, UAC)"),
    ("T1021", "Remote Services", "Uzak hizmetlerle (SSH, RDP) başka makineye geçme"),
    ("T1005", "Data from Local System", "Yerel sistemdeki veriyi toplama"),
    ("T1048", "Exfiltration Over Alternative Protocol", "Veriyi alışılmadık protokolle dışarı çıkarma"),
    ("T1486", "Data Encrypted for Impact", "Veriyi şifreleyip erişimi kesme (fidye)"),
    ("T1070", "Indicator Removal", "İz silme (logları temizleme)"),
]

KATMAN_HAVUZU = {
    "onleme": ["Çok faktörlü kimlik doğrulama (MFA)", "Güvenlik duvarı kural seti", "SSH sertleştirme", "Yama yönetimi süreci"],
    "tespit": ["Merkezi log toplama", "IDS alarmları", "Başarısız giriş alarm kuralı", "Dosya bütünlüğü izleme"],
    "kurtarma": ["Çevrimdışı yedek", "Yedekten geri dönüş testi", "Olay müdahale planı", "Kurtarma tatbikatı"],
}
KATMAN_ADI = {"onleme": "önleme", "tespit": "tespit", "kurtarma": "kurtarma"}

# Her vaka: aşama girdileri (aşama_no, MITRE kodu, kaynak, metin, kanıtı bulmak için anahtar kelime)
VAKALAR = [
    {
        "ad": "Pazarix — e-ticaret sitesinde sızma", "musteri": "Pazarix", "sektor": "e-ticaret",
        "klasor": "pazarix_olay",
        "sahne": "Kampanya haftasında web sunucusunda tuhaf hesap hareketleri görüldü. Deniz, gece nöbetinde "
                 "dağınık notları toplayıp sana yolladı.",
        "girdiler": [
            (0, "T1595", "güvenlik duvarı", "{ip} adresinden 3 dakikada 1.800 farklı URL istendi; araç imzası bir web tarayıcısı (Nikto).", "1\\.800"),
            (1, "T1190", "web sunucusu", "{ip} ürün sayfasında SQL hata sayfaları (HTTP 500) üretti; hemen ardından yönetici tablosu içeriğini döndüren bir yanıt gitti.", "SQL hata"),
            (2, "T1136", "auth.log", "Web sunucusunda 'servis_destek' adlı yeni bir yerel hesap oluşturuldu (useradd).", "servis_destek"),
            (3, "T1548", "sudo kaydı", "'servis_destek' hesabı parolasız sudo kuralıyla root kabuğu açtı.", "parolasız sudo"),
            (4, "T1021", "veritabanı sunucusu", "Web sunucusunun iç IP'sinden veritabanı sunucusuna SSH ile root girişi yapıldı; bu IP daha önce hiç bağlanmamıştı.", "veritabanı sunucusuna SSH"),
        ],
        "alakasiz": ("yedekleme sunucusu", "Gece 02:00 yedek işi başarıyla tamamlandı (her gün aynı saatte çalışır).", "yedek işi"),
    },
    {
        "ad": "Medora Sağlık — hastanede fidye olayı", "musteri": "Medora Sağlık", "sektor": "hastane",
        "klasor": "medora_olay",
        "sahne": "Hastanenin dosya sunucusundaki randevu kayıtları açılmıyor. Bilgi işlem müdürü Dr. Aslı "
                 "Hanım'ın ekibi olayı toparlamak için kayıt notlarını sana iletti.",
        "girdiler": [
            (0, "T1595", "güvenlik duvarı", "{ip} adresinden 40 farklı porta tek paketlik bağlantı denemesi geldi (port taraması).", "40 farklı porta"),
            (1, "T1078", "VPN geçidi", "'hemsire_vpn' hesabı {ip} adresinden gece 03:10'da tek denemede başarılı giriş yaptı; hesapta MFA yoktu ve kullanıcı o gün izinliydi.", "MFA yoktu"),
            (2, "T1053", "sunucu cron kaydı", "Root'a ait zamanlanmış görevler listesine kimsenin tanımadığı, her gece çalışan yeni bir görev eklendi.", "yeni bir görev"),
            (3, "T1548", "sudo kaydı", "VPN ile girilen servis hesabı sudo ile root kabuğu açtı; hesap bunu ilk kez yapıyor.", "root kabuğu açtı"),
            (4, "T1021", "alan denetleyicisi", "Ele geçirilen sunucudan uzak masaüstü (RDP) oturumu açıldı; kaynak makine normalde RDP kullanmaz.", "RDP"),
            (5, "T1486", "dosya sunucusu", "Dakikalar içinde 12.000 dosyanın uzantısı değişti ve her klasöre 'OKU_BENI' notu bırakıldı.", "12\\.000"),
        ],
        "alakasiz": ("bilgi işlem", "Gece yarısı planlı bakımda işletim sistemi güncellemeleri kuruldu ve sunucu yeniden başlatıldı.", "planlı bakım|planlı bakımda"),
    },
    {
        "ad": "Yeşiltepe Belediyesi — oltalama olayı", "musteri": "Yeşiltepe Belediyesi", "sektor": "belediye",
        "klasor": "yesiltepe_olay",
        "sahne": "İhale birimindeki bir bilgisayarda garip bir pencere çıktı. Olay erken fark edildi; senden "
                 "kayıtlara bakıp saldırganın nereye kadar geldiğini söylemeni istiyorlar.",
        "girdiler": [
            (0, "T1595", "web sunucusu", "{ip} belediye sitesindeki /ihale altındaki dizinleri bir tarama aracıyla (gobuster) yokladı.", "gobuster"),
            (1, "T1566", "e-posta ağ geçidi", "'İhale şartnamesi' konulu e-postadaki bağlantıya tıklayan personelin bilgisayarından, {ip} adresindeki sahte giriş sayfasına parola girildi.", "sahte giriş sayfası"),
            (2, "T1053", "uç nokta kaydı", "Aynı bilgisayarda her oturum açılışında çalışan yeni bir zamanlanmış görev bulundu.", "oturum açılışında"),
            (3, "T1548", "uç nokta kaydı", "Kullanıcı hesabı denetimi (UAC) uyarısı atlanarak yönetici yetkisine çıkıldı.", "UAC"),
        ],
        "alakasiz": ("muhasebe", "Maaş listesi ay sonunda her zamanki gibi 'maas.xlsx' adıyla bankaya e-postayla gönderildi.", "maas\\.xlsx"),
    },
]


def uret(rng):
    v = rng.choice(VAKALAR)
    ip = u.dis_ip(rng)
    kul = rng.choice(u.ISIMLER)
    t = datetime(2026, 1, 1, rng.randint(1, 5), rng.randint(0, 59), rng.randint(0, 59))
    ham = []                      # (zaman, asama_no|None, mitre, kaynak, metin, ara)
    for a, mitre, kaynak, metin, ara in v["girdiler"]:
        t += timedelta(minutes=rng.randint(9, 58), seconds=rng.randint(1, 59))
        ham.append((t, a, mitre, kaynak, metin.format(ip=ip, kul=kul), ara))
    k_kaynak, k_metin, k_ara = v["alakasiz"]
    tb = ham[0][0] + timedelta(minutes=rng.randint(5, 70), seconds=rng.randint(1, 59))
    ham.append((tb, None, "", k_kaynak, k_metin, k_ara))
    rng.shuffle(ham)
    girdiler = []
    for i, (z, a, mitre, kaynak, metin, ara) in enumerate(ham, 1):
        girdiler.append({"id": f"E{i}", "zaman": f"{z:%H:%M:%S}", "asama": a, "mitre": mitre,
                         "kaynak": kaynak, "metin": metin, "ara": ara, "t": z})
    zincir = sorted((g for g in girdiler if g["asama"] is not None), key=lambda g: g["t"])
    ilk = next(g for g in girdiler if g["asama"] == 1)
    benign = next(g for g in girdiler if g["asama"] is None)
    son_no = max(g["asama"] for g in girdiler if g["asama"] is not None)
    eslesme = {g["id"]: (ASAMALAR[g["asama"]][0] if g["asama"] is not None else "alakasiz") for g in girdiler}
    # envanter: bir katmanda aktif kontrol yok (sadece 'planlı' olan var)
    eksik = rng.choice(list(KATMAN_HAVUZU))
    envanter = []
    for katman, havuz in KATMAN_HAVUZU.items():
        secilen = rng.sample(havuz, 3)
        if katman == eksik:
            envanter += [(secilen[0], katman, "planli"), (secilen[1], katman, "iptal")]
        else:
            envanter += [(secilen[0], katman, "aktif"), (secilen[1], katman, "aktif"), (secilen[2], katman, "planli")]
    rng.shuffle(envanter)
    mitre_ara = {"T1190": "Exploit Public", "T1078": "Valid Accounts", "T1566": "Phishing"}[ilk["mitre"]]
    return {
        "vaka": v["ad"], "v": v, "girdiler": girdiler, "envanter": envanter, "ip": ip,
        "benign_ara": benign["ara"],
        "metin": {"musteri": v["musteri"], "klasor": v["klasor"], "sektor": v["sektor"], "sahne": v["sahne"]},
        "cevaplar": {
            "ilk_erisim": ilk["id"], "alakasiz": benign["id"], "mitre": ilk["mitre"],
            "son_asama": ASAMALAR[son_no][3], "zincir": [int(g["id"][1:]) for g in zincir],
            "eksik": [KATMAN_ADI[eksik], eksik, {"onleme": "önleyici", "tespit": "tespit edici", "kurtarma": "kurtarıcı"}[eksik]],
            "eslesme": eslesme, "ilk_ara": ilk["ara"], "mitre_ara": mitre_ara,
        },
    }


def yaz(lab: Path, s: dict) -> None:
    k = s["metin"]["klasor"]
    v = s["v"]
    satirlar = [f"OLAY NOTLARI — {v['musteri']} (KURGUSAL VAKA)",
                "Kayıtlar kaynağa göre dağınık toplandı; zaman sırasına dizilmemiştir.",
                "Biçim: numara | saat | kaynak | not", ""]
    for g in s["girdiler"]:
        satirlar.append(f"{g['id']} | {g['zaman']} | {g['kaynak']} | {g['metin']}")
    u.yaz(lab / "olay_notlari.txt", "\n".join(satirlar) + "\n")
    u.yaz(lab / "saldiri_zinciri.txt", "\n".join(f"{i}. {ad} — {ac}" for i, (_, ad, ac, _) in enumerate(ASAMALAR, 1)) + "\n")
    u.yaz(lab / "mitre_kisa_liste.txt", "MITRE ATT&CK kısa liste (lab için seçilmiş teknikler)\n"
          "kod | teknik adı | ne demek\n" + "\n".join(f"{c} | {a} | {t}" for c, a, t in MITRE) + "\n")
    u.yaz(lab / "savunma_envanteri.csv", "kontrol;katman;durum\n" + "\n".join(";".join(e) for e in s["envanter"]) + "\n")
    u.yaz(lab / "OKUBENI.txt",
          f"{v['musteri']} olay klasörü (kurgusal). Selin'den not: kanıt notlarını zincire oturtmadan "
          "önce her notun hangi kaynaktan geldiğine bak.\n"
          "Cevaplarını yazarken eslesme.txt dosyasını bu klasörde oluştur.\n")


def _stage_kodu(token: str):
    t = re.sub(r"[\s_\-]+", " ", ascii_norm(token)).strip()
    if t in {ascii_norm(x) for x in ALAKASIZ}:
        return "alakasiz"
    for kod, ad, _, varyant in ASAMALAR:
        if t in {re.sub(r"[\s_\-]+", " ", ascii_norm(x)) for x in varyant}:
            return kod
    return None


def _eslesme_kontrol(b) -> Sonuc:
    yol = None
    for d in (b.calisma_dizini, b.lab):
        if d and (Path(d) / "eslesme.txt").is_file():
            yol = Path(d) / "eslesme.txt"
            break
    if yol is None:
        return Sonuc(False, "`eslesme.txt` bulunamadı. Lab klasöründe oluştur; her satır: `E3 İlk erişim` gibi.")
    beklenen = b.senaryo["cevaplar"]["eslesme"]
    verilen = {}
    for ham in yol.read_text(errors="replace").splitlines():
        m = re.match(r"^\s*E?(\d+)\s*[:,=\-–—\s]+\s*(.+?)\s*$", ham, re.I)
        if m:
            verilen[f"E{int(m.group(1))}"] = _stage_kodu(m.group(2))
    if not verilen:
        return Sonuc(False, "Dosyada `E3 İlk erişim` biçiminde satır bulamadım.")
    eksik = [e for e in beklenen if e not in verilen]
    if eksik:
        return Sonuc(False, f"{len(beklenen)} kaydın hepsi eşlenmeli; eksik: {', '.join(sorted(eksik, key=lambda x: int(x[1:])))}.", yakin=True)
    yanlis = [e for e in beklenen if verilen[e] != beklenen[e]]
    if yanlis:
        e = sorted(yanlis, key=lambda x: int(x[1:]))[0]
        ipucu = "Alakasız (meşru) kayıt da var; ona `alakasız` yaz." if "alakasiz" in (beklenen[e], verilen[e]) else \
            "Saat sırasına ve kaydın ne yaptığına bak."
        return Sonuc(False, f"{len(yanlis)} satır yanlış, örneğin {e}. {ipucu}", yakin=len(yanlis) < len(beklenen))
    return Sonuc(True, "Hepsi doğru eşlendi.")


def coz(lab: Path, s: dict) -> dict:
    def id_bul(ara):
        return sh(f"grep -E '{ara}' olay_notlari.txt | head -1 | cut -d'|' -f1 | tr -d ' '", lab)
    ilk = id_bul(s["cevaplar"]["ilk_ara"])
    alakasiz = id_bul(s["benign_ara"])
    mitre = sh(f"grep '{s['cevaplar']['mitre_ara']}' mitre_kisa_liste.txt | cut -d'|' -f1 | tr -d ' '", lab)
    ad_komut = "sed 's/^[0-9]*\\. //; s/ —.*//' saldiri_zinciri.txt"
    son = sh("n=$(grep -c '^E[0-9]' olay_notlari.txt); n=$((n-1)); sed -n \"${n}p\" saldiri_zinciri.txt | "
             "sed 's/^[0-9]*\\. //; s/ —.*//'", lab)
    zincir = sh(f"grep '^E[0-9]' olay_notlari.txt | grep -Ev '{s['benign_ara']}' | sort -t'|' -k2,2 | cut -d'|' -f1 | tr -d 'E ' | tr '\\n' ' '", lab)
    eksik = sh("for k in onleme tespit kurtarma; do awk -F';' -v k=$k '$2==k && $3==\"aktif\"' savunma_envanteri.csv | grep -q . || echo $k; done", lab)
    n_zincir = len(s["cevaplar"]["zincir"])
    sh(f"grep '^E[0-9]' olay_notlari.txt | grep -Ev '{s['benign_ara']}' | sort -t'|' -k2,2 | cut -d'|' -f1 | tr -d ' ' "
       f"| paste -d' ' - <({ad_komut} | head -n {n_zincir}) > eslesme.txt; "
       f"grep '^E[0-9]' olay_notlari.txt | grep -E '{s['benign_ara']}' | cut -d'|' -f1 | tr -d ' ' | sed 's/$/ alakasiz/' >> eslesme.txt", lab)
    return sec_doldur({1: ilk, 2: alakasiz, 3: mitre, 4: son, 5: zincir, 6: eksik, 9: ""}, GOREVLER, lab, s)


def _zincir_hata(verilen, beklenen, b):
    benign = int(b.senaryo["cevaplar"]["alakasiz"][1:])
    if benign in verilen:
        return f"E{benign} zincirin parçası değil; o meşru bir kayıt. Onu çıkar."
    if verilen == sorted(verilen):
        return "Numara sırasına dizmişsin; ama E numaraları zaman sırası değil. `sort` ile saate göre sırala."
    return None


def _ilk_hata(g, beklenen, b):
    kod = {v: k for k, v in b.senaryo["cevaplar"]["eslesme"].items()}.get("kesif")
    if kod and norm_id(g) == norm_id(kod):
        return "O, zincirin en başındaki keşif kaydı. İlk erişim, saldırganın *içeri girdiği* andır."
    return None


def norm_id(x: str) -> str:
    return re.sub(r"^e", "", x.strip().lower())


ADIMLAR = [
    Adim("Saldırı zinciri: bir hikâyenin halkaları", """
Altı cilt boyunca saldırganın gözünden baktın. Şimdi masanın öbür tarafına, **mavi takıma**
(savunmacılara) geçiyorsun. Selin: "Savunma, rastgele önlemler yığmak değildir. Saldırganın
adımlarını bil, her adımı kırmaya çalış."

Çoğu saldırı **siber saldırı zinciri** (kill chain) denen öngörülebilir halkalardan geçer. Lab'da
bu zinciri bir dosyaya koydum:
""", komut="cat saldiri_zinciri.txt", sonra="""
Savunmanın amacı zinciri **mümkün olan en erken halkada kırmaktır.** Saldırgan ne kadar
ilerlerse zarar o kadar büyür.
"""),
    Adim("Elindeki kanıtlar: olay notları", """
<<musteri>> (<<sektor>>) vakasında kanıtlar farklı kaynaklardan dağınık geldi. <<sahne>>

Dosyadaki her satırın biçimi: `numara | saat | kaynak | not`. Önce hepsini oku:
""", komut="cat olay_notlari.txt", sonra="""
Dikkat: numaralar **zaman sırası değildir**; kayıtlar kaynağa göre toplandığı için karışık.
Bu bir tuzak değil, gerçek olaylarda da böyledir. İçlerinde bir de **alakasız (meşru)** kayıt var;
her şüpheli görünen şey saldırı değildir.
"""),
    Adim("Zamana göre sıralamak", """
Sıralama, olay incelemesinin ilk işidir. Satırları ikinci sütuna (saat) göre dizelim. `sort`'a
sütun ayırıcıyı `-t'|'`, anahtar sütunu `-k2,2` ile söylersin:
""", komut="sort -t'|' -k2,2 olay_notlari.txt", sonra="""
Şimdi hikâye okunuyor. Her kaydın hangi halkaya ait olduğunu *ne yaptığına* bakarak seçersin:
tarama keşiftir, içeri giriş ilk erişimdir, yeni hesap ya da zamanlanmış görev yer edinmedir.
"""),
    Adim("MITRE ATT&CK: ortak dil", """
Saldırganların yöntemlerini herkesin aynı adla andığı bir ortak sözlük var: **MITRE ATT&CK**,
gerçek saldırılardan derlenmiş, herkese açık bir teknikler bilgi tabanıdır. Her tekniğin bir
kodu vardır (`T1190` gibi). SOC (güvenlik operasyon merkezi) raporlarında "şu olay T1078'e
uyuyor" demek, bir paragraf yazmaktan hızlıdır.

Lab için seçilmiş kısa listeyi aç:
""", komut="cat mitre_kisa_liste.txt", sonra="""
Zincirin **halkaları** (keşif, ilk erişim...) saldırganın *amacıdır*; ATT&CK **teknikleri** o
amaca *nasıl* ulaştığını anlatır.
"""),
    Adim("Derinlemesine savunma", """
Tek bir güvenlik önlemine güvenmek kırılgandır. **Derinlemesine savunma** katman kurar; her
katman bir öncekinin başarısız olacağını varsayar. Üç tür katman düşün: **önleme** (içeri
sokma), **tespit** (içeri girdiyse fark et), **kurtarma** (zarar verdiyse geri dön).

Kurumun elindeki kontroller bu tabloda. Sadece `aktif` olanlar sayılır; "planlı" ya da
"iptal" olan bir kontrol bugün seni korumaz:
""", komut="cat savunma_envanteri.csv"),
    Adim("Kontrolleri saymak", """
Hangi katmanda kaç **aktif** kontrol var? `awk`'a `;` ile ayırmayı (`-F';'`) ve koşulu söylersin;
`sort | uniq -c` her katmanı sayar:
""", komut="awk -F';' '$3==\"aktif\" {print $2}' savunma_envanteri.csv | sort | uniq -c", sonra="""
Listede **hiç görünmeyen** katman, bu kurumda yok demektir. Boş bir katman, saldırganın o aşamada
engellenmeyeceği, fark edilmeyeceği ya da geri dönülemeyeceği anlamına gelir.
"""),
    Adim("Hacker gözüyle savunma", """
**Hacker gözüyle:** "Ben olsam nereden girerdim?" diyebilen savunmacı, kontrol listesini
körü körüne uygulayandan çok daha etkilidir. Bu yüzden iyi bir savunmacı saldırıyı da bilir:
iki tarafı da bilen kişiye **mor takım** (purple team) denir. Cilt 4-6'da öğrendiğin her
saldırı becerisi, bu cilttekilerin tam olarak nereye bakacağını söyler.

Şimdi görevlere geç: kanıtları zincire oturtacaksın. Cevaplarını `eslesme.txt` dosyasında da
isteyeceğim; bir dosyayı `printf`, `echo ... >> dosya` ya da `nano` ile yazabilirsin.
"""),
]

GOREVLER = [
    Gorev("`olay_notlari.txt` içinde saldırganın sisteme **ilk girdiği** anı gösteren kaydın numarasını yaz "
          "(örn. E4). Tarama, keşif sayılır; içeri girişi ara.",
          Metin("ilk_erisim", on_ekleri_at=("e",), sik_hatalar=_ilk_hata, bicim="kayıt numarası (örn. E4)"),
          ("Keşif saldırganın *bakmasıdır*; ilk erişim *girmesidir*. Girişi anlatan kaydı ara.",
           "Notlarda 'başarılı giriş', 'yanıt gitti', 'parola girildi' gibi bir ifade ara: içeri girişin işareti.",
           "`sort -t'|' -k2,2 olay_notlari.txt` ile zamana göre diz; taramadan hemen sonraki, içeri girişi anlatan satırın numarası."),
          puan=30, baslik="İlk erişim kaydı"),
    Gorev("Aynı notlarda saldırıyla **hiçbir ilgisi olmayan** (meşru, rutin) kaydın numarası hangisi?",
          Metin("alakasiz", on_ekleri_at=("e",), bicim="kayıt numarası (örn. E2)"),
          ("Saldırı kaydı zincirde bir işe yarar; meşru kayıt hiçbir halkaya uymaz.",
           "Rutin bir iş, planlı bakım ya da her gün aynı saatte olan bir şey arıyorsun.",
           "Notları saate göre dizdiğinde diğerleri bir hikâye oluşturur; hikâyeye uymayan tek satır cevaptır."),
          puan=25, baslik="Alakasız kayıt"),
    Gorev("`mitre_kisa_liste.txt` listesinden, **ilk erişim** kaydının karşılığı olan ATT&CK teknik kodunu yaz "
          "(T ile başlayan kod).",
          Metin("mitre", bicim="T1234 biçiminde kod"),
          ("İlk erişimin *nasıl* olduğuna bak: zafiyet mi, oltalama mı, çalıntı hesap mı?",
           "Listede her tekniğin yanında Türkçe bir açıklama var; kaydın anlattığına en çok uyanı seç.",
           "Kaydı bul, sonra `grep -i \"anahtar kelime\" mitre_kisa_liste.txt` ile uyan satırı çıkar; ilk sütun koddur."),
          puan=30, baslik="ATT&CK kodu"),
    Gorev("Saldırgan zincirin **en son hangi halkasına** ulaştı? (Notlardaki kanıtlara göre; halka adını yaz.)",
          Metin("son_asama", bicim="halka adı (örn. Yer edinme)"),
          ("Zincirde 6 halka var; saldırganın izini sürdüğün son halka hangisi?",
           "Alakasız kaydı çıkardıktan sonra kaç kayıt kaldı? Her kayıt bir halkadır ve halkalar sırayla ilerler.",
           "`saldiri_zinciri.txt` içindeki sıraya bak: kalan kayıt sayısı kaçsa, listenin o numaralı satırı cevaptır."),
          puan=30, baslik="Son halka"),
    Gorev("Alakasız kaydı çıkar, geri kalan kayıtları **saldırının gerçekleşme sırasına** diz (en erken olan başta). "
          "Cevap olarak E numaralarının sadece sayılarını sırayla yaz (örn. `3 1 2`).",
          Sira("zincir", sik_hatalar=_zincir_hata),
          ("Sıra kayıt numarasına değil, saate bağlı.",
           "`sort -t'|' -k2,2` saate göre dizer. Alakasız kaydı `grep -v` ile dışarıda bırakabilirsin.",
           "`grep '^E' olay_notlari.txt | grep -v \"ALAKASIZ_KAYDIN_BİR_KELİMESİ\" | sort -t'|' -k2,2 | cut -d'|' -f1`"),
          puan=40, baslik="Zincir sırası"),
    Gorev("`savunma_envanteri.csv` tablosuna göre bu kurumda **hiç aktif kontrolü olmayan** katman hangisi? "
          "(önleme, tespit ya da kurtarma)",
          Metin("eksik", bicim="önleme / tespit / kurtarma"),
          ("Sadece `aktif` yazanlar sayılır; 'planlı' ve 'iptal' sayılmaz.",
           "Her katman için `aktif` satırlarını ayrı ayrı say; biri sıfır çıkacak.",
           "`awk -F';' '$2==\"tespit\" && $3==\"aktif\"' savunma_envanteri.csv` boş dönerse eksik katman odur; üçünü de dene."),
          puan=30, baslik="Eksik katman"),
    Gorev("Savunmanın saldırı zincirine karşı asıl hedefi hangisidir?",
          Secmeli([
              ("Zinciri mümkün olan en erken halkada kırmak; çünkü saldırgan ilerledikçe zarar büyür",
               "Doğru. Keşif ve ilk erişimde durdurulan saldırı veriye hiç ulaşamaz."),
              ("Bütün bütçeyi son halkaya, yani veri çalınmasının önlenmesine harcamak; çünkü zarar orada oluşur",
               "Yanlış. Son halkaya gelen saldırgan çoktan içeride, yetkili ve zarar vermek üzeredir."),
              ("Her halkaya eşit sayıda kural yazıp zinciri eşit korumak; çünkü her halka aynı değerdedir",
               "Yanlış. Halkalar eşit değildir; erken halkada durdurmak çok daha ucuz ve etkilidir."),
              ("Saldırganın zinciri bitirmesini beklemek; çünkü tam kanıt ancak olay bitince toplanır",
               "Yanlış. Beklemek saldırganın zararını büyütür; kanıt, durdurarak da toplanır."),
          ], dogru=0),
          ("Zarar zincirin neresinde büyür?",
           "Bir halkada kırılan zincir, sonraki halkaları imkânsız kılar.",
           "En ucuz ve en etkili kırma noktası, saldırganın henüz uzağında olduğu en erken halkadır."),
          puan=20, baslik="Zinciri kırmak"),
    Gorev("Aşağıdakilerden hangisi **derinlemesine savunmayı** doğru anlatıyor?",
          Secmeli([
              ("Bir katmanın aşılacağı varsayılır; sertleştirme, loglama/alarm ve yedek gibi sonraki katmanlar devreye girer",
               "Doğru. Her katman bir öncekinin başarısız olacağını varsayar: kale duvarı, hendek, iç kule gibi."),
              ("Güvenlik duvarı yeterince güçlüyse sunucuda ayrıca log tutmaya ve yedek almaya gerek kalmaz",
               "Yanlış. Tek duvara güvenmek tam tersini yapmaktır; duvar aşılınca geriye hiçbir şey kalmaz."),
              ("Aynı türden iki ürünü üst üste koymak; örneğin iki güvenlik duvarı almak yeterli bir katmandır",
               "Yanlış. Aynı zafiyetten ikisi de etkilenir. Katmanlar *farklı türde* olmalı: önleme, tespit, kurtarma."),
              ("Bütün katmanları tek bir üründe toplamak; böylece yönetim kolaylaşır ve açık kalmaz",
               "Yanlış. Tek ürün tek hata noktasıdır; o bozulursa bütün katmanlar birlikte düşer."),
          ], dogru=0),
          ("Kale benzetmesini düşün: duvar, hendek, iç kule.",
           "Doğru cevap 'katmanların farklı türde olması ve birinin düşeceğinin baştan kabul edilmesi'ni söyler.",
           "Yanlış şıklardan üçü tek bir önleme/ürüne güveniyor; doğru olan, birden çok farklı katmanı birlikte kullanıyor."),
          puan=20, baslik="Derinlemesine savunma"),
    Gorev("`olay_notlari.txt` içindeki **her kaydı** bir halkaya eşle. Lab klasöründe `eslesme.txt` oluştur; "
          "her satır `E3 İlk erişim` gibi olsun (alakasız kayıt için `alakasız` yaz). Bitince `cevap 9`.",
          Durum(_eslesme_kontrol, "eslesme.txt dosyasında her kayıt için `E<no> <halka adı>` satırı olmalı"),
          ("Önce her kaydın halkasını belirle; sonra bir dosyaya satır satır yaz.",
           "`echo \"E1 Keşif\" >> eslesme.txt` ile satır ekleyebilir ya da `nano eslesme.txt` ile yazabilirsin.",
           "Zamana göre sıralı kayıt listesini çıkar (`sort -t'|' -k2,2`), `saldiri_zinciri.txt` halkaları ile yan yana koy ve sırayla yaz."),
          puan=50, baslik="Zincir eşlemesi"),
]


def _kapanis():
    return """
Saldırgan gözüyle zincir bir yol haritasıdır; savunmacı gözüyle ise bir **kesme planıdır**. Aynı
olayda keşif, ilk erişim ve yer edinme izlerinin hepsi kayıtlarda vardı: yani zinciri üç ayrı
yerde kırma şansın olmuştu. İyi savunmacı her halka için "burada beni ne fark ettirir, burada
ne durdurur" diye sorar. Saldırgan açısından ders: ne kadar çok halkayı sessiz geçerse, o kadar
az katmana yakalanır. Bu yüzden savunmada katmanlar farklı türde olmalı: önleme, tespit, kurtarma.
"""


SEVIYE = Seviye(
    kimlik="c07b01",
    cilt=7,
    bolum=1,
    baslik="Savunma Zihniyeti ve Saldırı Zinciri",
    brifing="""
Deniz Kara, mavi takımın sesi, kahve bardağıyla odaya giriyor: "Selin seni bana verdi. Bu cilt
masanın öbür tarafı: savunma." Önüne bir klasör bırakıyor: **<<musteri>>** (<<sektor>>) olayının
dağınık notları.

<<sahne>> Deniz: "Notlar karışık, bir de içlerinde alakasız bir satır var. Önce olayı zincire
oturt: saldırgan nerede başladı, nereye kadar geldi, hangi katman eksik? Sonra bunu ortak
dilde, MITRE ATT&CK koduyla yazalım."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Target 2013:** Saldırganlar, mağazaların ağına bir dış tedarikçinin (klima/ısıtma firması)
  kimlik bilgileriyle girdi; ağ iyi bölümlenmediği için kasa sistemlerine kadar ilerledi. Bu
  halkalar zincirin ilk erişim ve yanal hareket aşamalarıdır. Hem tedarikçi hesaplarını ve ağ
  bölümlemeyi (önleme) hem de alarmların gerçekten izlenmesini (tespit) isteyen vaka dersi bu.
- **Colonial Pipeline 2021:** Fidye saldırısının girişinin, çok faktörlü kimlik doğrulaması
  olmayan eski bir VPN hesabı olduğu kamuoyuna açıklandı. MFA ve kullanılmayan hesapların
  kapatılması ilk halkada zinciri kırabilirdi; bu bölümdeki "en erken halkada kır" ilkesi budur.
- **MITRE ATT&CK ve kill chain:** Kill chain kavramı Lockheed Martin araştırmacılarından gelir;
  ATT&CK herkese açık bir bilgi tabanıdır. SOC'ler alarmları ve tehdit raporlarını bu kodlarla
  etiketler, böylece "hangi teknikleri hiç görmüyoruz?" diye boşluk analizi yapabilirler.
""",
    sure_hedef_dk=30,
)
