"""Olay Masası — Zafiyet Önceliklendirme: Önce Neyi Kapatmalı?

TAMAMEN SAVUNMACI: oyuncu, bir kurumun güvenlik ekibindeki analisttir. Elinde bir zafiyet tarama raporu
vardır (`tarama_raporu.csv`); yama ekibinin zamanı kısıtlıdır, "önce neyi kapatalım?" sorusuna cevap
aranır. Tüm host, CVE numarası ve kurum kurgusaldır; gerçek zafiyet ya da sistem göstermez.

Önceliklendirme mantığı: internete açık + sömürü kodu (exploit) mevcut = ACİL katman. Katman içinde
sıra, "CVSS x iş kritikliği x açıklık x exploit" bağlam puanıyla belirlenir. Tuzaklar: en yüksek CVSS
(9.8) iç ağdaki, exploit'i olmayan bir bulgudur; orta CVSS'li ama internetten erişilen + exploit'i olan
bulgular daha önce gelir. Gürültü: düşük/bilgi seviyesi bulgular.

Bu bölüm Cilt 7 b06 (Zafiyet Yönetimi) konusunun uygulamalı tekrarıdır; eğitim içermez.

Determinizm: `uret` ağır veriyi sözlüğe gömmez; `_alt` alt-tohumunu saklar. Hem `uret` hem `yaz`
aynı `_akis(alt)` ile veriyi yeniden üretir. (`_tohum` motor tarafından ezildiği için ayrı anahtar.)
"""
from __future__ import annotations

import random
import subprocess
from pathlib import Path

from hy.motor.kontrol import Metin, Sayi, Secmeli
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c21_dolandiricilik.ortak import Dizi, sec_doldur

# host, servis, internete açık, iş kritikliği (1-5)
SENARYOLAR = [
    {"musteri": "Bereket Market Zinciri", "sektor": "perakende", "kisi": "BT güvenlik sorumlusu Selim Bey",
     "hikaye": "Kampanya haftası yaklaşırken haftalık zafiyet taraması 20'den fazla bulgu listeledi; yama "
               "ekibi bu hafta yalnızca birkaç sistemi kapatabilecek.",
     "hostlar": [
         ("bm-web01", "e-ticaret sitesi", 1, 4), ("bm-api01", "mobil uygulama API", 1, 5),
         ("bm-odeme-db", "ödeme veritabanı", 0, 5), ("bm-depo", "depo yönetim sistemi", 0, 3),
         ("bm-vpn", "uzaktan erişim geçidi", 1, 4), ("bm-yazici", "mağaza yazıcı sunucusu", 0, 1),
         ("bm-test", "test ortamı", 1, 1), ("bm-dosya", "dosya sunucusu", 0, 2)]},
    {"musteri": "Şifa Tıp Merkezi", "sektor": "sağlık", "kisi": "Bilgi işlem müdürü Dilek Hanım",
     "hikaye": "KVKK denetimi öncesi tarama sonuçları geldi. Hasta verisi tutan sistemler listede; hangisine "
               "ilk dokunulacağına karar vermek gerekiyor.",
     "hostlar": [
         ("sifa-portal", "hasta randevu portalı", 1, 4), ("sifa-hbys", "hasta kayıt sistemi", 0, 5),
         ("sifa-pacs", "tıbbi görüntü arşivi", 0, 5), ("sifa-vpn", "doktor uzaktan erişimi", 1, 5),
         ("sifa-wifi", "misafir Wi-Fi denetleyicisi", 1, 1), ("sifa-yazdir", "yazıcı yönetimi", 0, 1),
         ("sifa-mail", "e-posta sunucusu", 1, 3), ("sifa-dizin", "personel dizini", 0, 4)]},
    {"musteri": "Demirhan Enerji Dağıtım", "sektor": "enerji", "kisi": "Siber güvenlik şefi Ufuk Bey",
     "hikaye": "Yıllık sızma testi öncesi yapılan tarama, hem ofis hem saha ağında çok sayıda bulgu çıkardı. "
               "Bakım penceresi kısıtlı; önce neyi kapatalım diye soruluyor.",
     "hostlar": [
         ("dmh-musteri", "müşteri e-hizmet portalı", 1, 4), ("dmh-sayac", "sayaç veri toplama", 0, 5),
         ("dmh-scada", "saha izleme sunucusu", 0, 5), ("dmh-uzak", "uzaktan bakım geçidi", 1, 5),
         ("dmh-intranet", "kurum içi portal", 0, 2), ("dmh-web", "tanıtım sitesi", 1, 2),
         ("dmh-mail", "e-posta geçidi", 1, 3), ("dmh-yedek", "yedekleme sunucusu", 0, 3)]},
]

ACIL_CVSS = [5.3, 5.9, 6.5, 7.2, 7.5, 8.1, 8.8]
DUSUK_CVSS = [0.0, 2.1, 2.7, 3.1, 3.7, 4.3, 4.9]
ORTA_CVSS = [5.4, 6.1, 6.8, 7.1]


def _p(cvss: float, krit: int, acik: int, ex: int) -> int:
    return int(round(cvss * 10)) * krit * (2 if acik else 1) * (2 if ex else 1)


def _akis(alt: int) -> dict:
    """Alt-tohumdan tarama raporunu ve cevapları deterministik üretir."""
    rng = random.Random(alt)
    sen = rng.choice(SENARYOLAR)
    hostlar = sen["hostlar"]
    ic = [h for h in hostlar if not h[2]]
    dis = [h for h in hostlar if h[2]]
    for _ in range(500):
        satirlar = []       # (host, servis, cvss, acik, exploit, krit)

        def ekle(h, cvss, ex):
            satirlar.append((h[0], h[1], cvss, h[2], ex, h[3]))

        # tuzaklar: CVSS yüksek ama acil değil
        ekle(rng.choice([h for h in ic if h[3] >= 4]), 9.8, 0)
        ekle(rng.choice(ic), 9.1, 1)
        ekle(rng.choice(dis), 9.0, 0)
        for _ in range(rng.randint(0, 2)):
            ekle(rng.choice(hostlar), rng.choice([9.3, 9.4, 9.6]), 0)
        # acil katman: internete açık + exploit var
        n_acil = rng.randint(5, 6)
        for _ in range(n_acil):
            ekle(rng.choice(dis), rng.choice(ACIL_CVSS), 1)
        # gürültü
        for _ in range(rng.randint(10, 13)):
            h = rng.choice(hostlar)
            ex = 1 if (not h[2] and rng.random() < 0.25) else 0
            ekle(h, rng.choice(DUSUK_CVSS), ex)
        for _ in range(2):
            ekle(rng.choice(hostlar), rng.choice(ORTA_CVSS), 0)
        rng.shuffle(satirlar)
        puanlar = sorted((_p(c, k, a, e) for _, _, c, a, e, k in satirlar if a and e), reverse=True)
        if len(set(puanlar[:5])) < 5:
            continue
        break
    cves = u.benzersiz(rng, lambda r: f"CVE-2026-{r.randint(1000, 9999)}", len(satirlar))
    rows = []
    for i, ((host, servis, cvss, a, e, k), cve) in enumerate(zip(satirlar, cves), 1):
        rows.append({"id": f"b{i:02d}", "host": host, "servis": servis, "cve": cve, "cvss": cvss,
                     "acik": a, "ex": e, "krit": k})
    for r in rows:
        r["acil"] = int(bool(r["acik"] and r["ex"]))
        r["p"] = _p(r["cvss"], r["krit"], r["acik"], r["ex"])
    sirali = sorted(rows, key=lambda r: (-r["acil"], -r["p"], r["id"]))
    cvss_sirali = sorted(rows, key=lambda r: (-r["cvss"], r["id"]))
    return {
        "sen": sen, "rows": rows, "sirali": sirali, "cvss_ilk": cvss_sirali[0],
        "acil_sayi": sum(r["acil"] for r in rows),
        "yuksek_acil_degil": sum(1 for r in rows if r["cvss"] >= 9.0 and not r["acil"]),
    }


def uret(rng):
    alt = rng.randint(10_000_000, 999_999_999)
    v = _akis(alt)
    sen = v["sen"]
    return {
        "vaka": f"{sen['musteri']} ({sen['sektor']}) — zafiyet önceliklendirme",
        "metin": {"musteri": sen["musteri"], "sektor": sen["sektor"], "kisi": sen["kisi"],
                  "hikaye": sen["hikaye"], "bulgu_sayisi": len(v["rows"])},
        "cevaplar": {
            "ilk_cve": [v["sirali"][0]["cve"]],
            "cvss_host": [v["cvss_ilk"]["host"]],
            "acil": v["acil_sayi"],
            "sira": [r["id"] for r in v["sirali"][:4]],
            "yuksek": v["yuksek_acil_degil"],
        },
        "_alt": alt,
    }


def yaz(lab: Path, s: dict) -> None:
    v = _akis(s["_alt"])
    u.yaz(lab / "tarama_raporu.csv",
          "id,host,servis,cve,cvss,internete_acik,exploit_var,is_kritikligi\n"
          + "".join(f"{r['id']},{r['host']},{r['servis']},{r['cve']},{r['cvss']:.1f},"
                    f"{'evet' if r['acik'] else 'hayir'},{'evet' if r['ex'] else 'hayir'},{r['krit']}\n"
                    for r in v["rows"]))


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _ilk_cve_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    if g == v["cvss_ilk"]["cve"].casefold():
        return ("Bu, en yüksek CVSS'li bulgunun CVE'si. Ama CVSS tek başına öncelik değildir: o bulgu "
                "internete açık mı, exploit'i var mı, bak.")
    return None


def _sira_hata(verilen, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    cv = [r["id"] for r in v["cvss_sirali"]] if "cvss_sirali" in v else \
        [r["id"] for r in sorted(v["rows"], key=lambda r: (-r["cvss"], r["id"]))]
    if verilen == cv[:len(beklenen)]:
        return "Bu sıra yalnızca CVSS'ye göre dizilmiş. Önce acil katmanı (internete açık + exploit) ayır."
    if sorted(verilen) == sorted(beklenen):
        return "Doğru dört bulgu ama sıra yanlış: acil katmanda bağlam puanı (CVSS x kritiklik) sırayı belirler."
    return None


def _acil_hata(g, beklenen, b):
    v = _akis(b.senaryo["_alt"])
    try:
        n = int(g)
    except ValueError:
        return None
    if n == sum(1 for r in v["rows"] if r["acik"]):
        return "Bu, yalnızca internete açık olanların sayısı. Acil için exploit'in de var olması gerekir."
    if n == sum(1 for r in v["rows"] if r["ex"]):
        return "Bu, yalnızca exploit'i olanların sayısı. Acil için bulgunun internete açık da olması gerekir."
    return None


def coz(lab: Path, s: dict) -> dict:
    siralama = ("awk -F, 'NR>1{a=($6==\"evet\");e=($7==\"evet\");"
                "p=int($5*10+0.5)*$8*(a?2:1)*(e?2:1);print (a&&e)\",\"p\",\"$1}' tarama_raporu.csv "
                "| sort -t, -k1,1nr -k2,2nr -k3,3")
    ilk_id = _sh(siralama + " | head -1 | cut -d, -f3", lab)
    ilk_cve = _sh(f"awk -F, -v i='{ilk_id}' '$1==i{{print $4}}' tarama_raporu.csv", lab)
    cvss_host = _sh("awk -F, 'NR>1' tarama_raporu.csv | sort -t, -k5,5nr -k1,1 | head -1 | cut -d, -f2", lab)
    acil = _sh("awk -F, 'NR>1 && $6==\"evet\" && $7==\"evet\"' tarama_raporu.csv | wc -l", lab)
    sira = _sh(siralama + " | head -4 | cut -d, -f3 | tr '\\n' ' '", lab)
    yuksek = _sh("awk -F, 'NR>1 && $5+0>=9.0 && !($6==\"evet\" && $7==\"evet\")' tarama_raporu.csv | wc -l", lab)
    cozum = {1: ilk_cve, 2: cvss_host, 3: acil, 4: sira, 5: yuksek, 6: ""}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


GOREVLER = [
    Gorev("`tarama_raporu.csv` zafiyet tarama çıktısı (`id,host,servis,cve,cvss,internete_acik,exploit_var,"
          "is_kritikligi`; <<bulgu_sayisi>> bulgu). Öncelik mantığı: **internete açık + exploit (sömürü kodu) "
          "var + iş açısından kritik** sistem önce kapanır. Tek bir bulguyla başlayacak olsak, **en yüksek "
          "öncelikli** bulgunun CVE numarası hangisi?",
          Metin("ilk_cve", sik_hatalar=_ilk_cve_hata, bicim="CVE-2026-xxxx"),
          ("Önce acil olanları ayır: `internete_acik` ve `exploit_var` ikisi de `evet` olan satırlar.",
           "Filtre: `awk -F, '$6==\"evet\" && $7==\"evet\"' tarama_raporu.csv`. Kalanlar arasında CVSS (5. alan) "
           "ile `is_kritikligi`'ni (8. alan) çarpıp en büyüğünü seç.",
           "Puan: `awk -F, '$6==\"evet\" && $7==\"evet\" {print $5*$8, $1, $4}' tarama_raporu.csv | sort -nr "
           "| head -1` — çıkan satırın son alanı CVE."),
          puan=15, baslik="En öncelikli bulgu"),
    Gorev("Şimdi tam tersini sor: raporda **en yüksek CVSS puanına** sahip bulgu hangi **host**'ta?",
          Metin("cvss_host", bicim="host adı"),
          ("CVSS 5. sütunda. Sayısal olarak büyükten küçüğe sırala.",
           "`sort -t, -k5 -nr` virgülle ayrılmış 5. alana göre sayısal ters sıralar; başlık satırını `tail -n +2` "
           "ile atla.",
           "`tail -n +2 tarama_raporu.csv | sort -t, -k5 -nr | head -1 | cut -d, -f2`. Çıkan hostun "
           "`internete_acik` ve `exploit_var` değerlerine de bak: bu bulgu gerçekten acil mi?"),
          puan=10, baslik="En yüksek CVSS"),
    Gorev("Kaç bulgu **acil**? (Acil: hem **internete açık** hem de **exploit'i var**.)",
          Sayi("acil", sik_hatalar=_acil_hata),
          ("İki koşul da aynı anda sağlanmalı: 6. alan (internete_acik) ve 7. alan (exploit_var).",
           "`awk -F, '$6==\"evet\" && $7==\"evet\"' tarama_raporu.csv` bu satırları süzer; başlık satırı "
           "koşulu zaten sağlamaz.",
           "`awk -F, '$6==\"evet\" && $7==\"evet\"' tarama_raporu.csv | wc -l`"),
          puan=10, baslik="Acil bulgu sayısı"),
    Gorev("Yama ekibinin ilk **dört** bulguyu kapatacak zamanı var. Önceliklendirme sırasıyla (önce acil "
          "katman; katman içinde **CVSS x iş kritikliği** puanı büyük olan önde) ilk dört bulgunun "
          "**id**'lerini yaz.",
          Dizi("sira", sik_hatalar=_sira_hata, bicim="id'ler sırayla, boşlukla ayrılmış (örn. b03 b11 b07 b02)"),
          ("Önce acil olmayanları ele: önde olmaları için hem internete açık hem exploit'li olmaları gerekir.",
           "Her satır için puan hesapla: `awk -F, '$6==\"evet\" && $7==\"evet\" {print $5*$8, $1}' "
           "tarama_raporu.csv | sort -nr` — puan büyük olan önce.",
           "`awk -F, '$6==\"evet\" && $7==\"evet\" {print $5*$8, $1}' tarama_raporu.csv | sort -nr | head -4` "
           "— ikinci sütundaki id'leri sırayla yaz."),
          puan=25, baslik="Önceliklendirme sırası"),
    Gorev("**CVSS puanı 9.0 veya üstü** olduğu halde **acil olmayan** kaç bulgu var? (Yüksek puan tek başına "
          "acillik demek değildir; bu tuzakları say.)",
          Sayi("yuksek"),
          ("CVSS 5. alan; ondalıklı sayıyı sayıya çevirmek için awk'da `$5+0` kullan.",
           "Koşul: `$5+0>=9.0` VE acil değil. Acil değil = `!($6==\"evet\" && $7==\"evet\")`.",
           "`awk -F, 'NR>1 && $5+0>=9.0 && !($6==\"evet\" && $7==\"evet\")' tarama_raporu.csv | wc -l`"),
          puan=15, baslik="Yüksek CVSS ama acil değil"),
    Gorev("Yönetim sorar: \"Neden en yüksek CVSS'li bulguyu değil de CVSS'i daha düşük bir bulguyu "
          "önce kapatıyoruz?\" **Doğru gerekçe** hangisi?",
          Secmeli([
              ("Yüksek CVSS'li ama iç ağdaki ve exploit'i olmayan bulgu, kimsenin ulaşamadığı bir kapıdır; orta "
               "CVSS'li ama internetten erişilen ve exploit'i olan bulgu ise şu an kullanılabilir. Önce "
               "saldırganın gerçekten sömürebileceği olanı kapatırız",
               "Doğru. Risk = etki x ulaşılabilirlik x sömürülebilirlik. CVSS yalnızca teknik ciddiyeti "
               "ölçer; internete açık ve exploit'i hazır bir bulgu fiilen saldırı altındadır."),
              ("Raporları her zaman CVSS puanına göre büyükten küçüğe sıralamak en adil ve en güvenli yöntemdir",
               "Yanlış. Yalnızca CVSS'ye göre sıralamak bağlamı yok sayar: erişilemeyen 9.8 önce yamalanır, "
               "internetteki sömürülen 6.5 bekler. Gerçek risk ters yönde artar."),
              ("İnternete açık sistemler önemsizdir, çünkü güvenlik duvarı zaten her şeyi engeller",
               "Yanlış. İnternete açık servis, tanımı gereği güvenlik duvarının dışarıya bilerek açtığı "
               "kapıdır; saldırganın ilk denediği yer burasıdır."),
              ("Exploit'i olan bulgular eskidir; önemli olan yeni çıkan bulgulardır, bu yüzden CVE numarası "
               "en yeni olan önce yamalanır",
               "Yanlış. Exploit'in olması, saldırganın hazır silahı olduğu anlamına gelir; bulgunun yeni ya da "
               "eski olması önceliği belirlemez."),
          ]),
          ("Bir bulgunun risk olması için saldırganın ona ULAŞABİLMESİ ve onu SÖMÜREBİLMESİ gerekir.",
           "CVSS teknik ciddiyeti ölçer; internete açıklık, exploit varlığı ve iş kritikliği ise bağlamdır.",
           "Doğru cevap bağlamı (açıklık + exploit) CVSS'nin önüne koyar; yalnızca puana göre sıralamayı "
           "reddeder."),
          puan=25, baslik="Doğru önceliklendirme mantığı"),
]

SEVIYE = Seviye(
    kimlik="olay_zafiyet",
    cilt=7,
    bolum=120,
    baslik="Zafiyet Önceliklendirme: Önce Neyi Kapatmalı?",
    brifing="""
Selin Aksoy sana bir dosya yolluyor: "**<<musteri>>** (<<sektor>>) bizden yardım istedi. <<hikaye>>
<<kisi>> tarama çıktısını `tarama_raporu.csv` olarak gönderdi: her satır bir zafiyet bulgusu; hangi host,
hangi servis, CVE numarası, CVSS puanı (zafiyetin teknik ciddiyeti, 0-10), internete açık mı, bilinen bir
exploit'i (sömürü kodu) var mı ve sistem iş için ne kadar kritik (1-5)."

"Bu veri kurgusal, güvenle oku. Yama ekibinin zamanı sınırlı; hepsini birden kapatamayız. Sadece CVSS'ye
bakarsak yanılırız: erişilemeyen bir kapıyla internetteki açık kapı aynı değil. Sen bağlamı kat, acil
olanı ayır ve sırayı çıkar."
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Hacker Gözüyle: Saldırgan CVSS puanına değil, ulaşabildiği ve sömürebildiği kapıya bakar. Önceliklendirme
sorusu hep aynıdır: bu bulgu internetten erişilebiliyor mu, hazır bir exploit var mı, vurulursa iş ne
kaybeder? Bu üçüne "evet" diyen bulgu listenin başındadır; iç ağda, exploit'i olmayan 9.8 ise planlı
yama penceresine bırakılabilir (yine de unutulmaz, çünkü iç ağa giren saldırgan onu da kullanır). Savunma
tarafında: varlık envanterini güncel tut, tarama çıktısını bağlamla zenginleştir, acil katman için kısa bir
yama süresi (SLA) belirle ve yama gelene kadar geçici önlem (erişimi kapatmak, sanal yama) uygula.
""",
    gercek_hayat="""
- **Bilinen sömürülen zafiyetler listesi (KEV):** ABD siber güvenlik kurumu CISA, 3 Kasım 2021'de
  "Known Exploited Vulnerabilities" kataloğunu yayımladı; yalnızca gerçekten saldırıda kullanıldığı
  doğrulanan açıkları içerir ve federal kurumlara bu açıkları süre sınırı içinde kapatma zorunluluğu getirir.
  **Exploit'i var mı sorusu, CVSS'den daha güçlü bir önceliklendirme işaretidir.**
- **Yama gecikmesi bedeli:** 2017'deki Equifax veri ihlalinde kullanılan Apache Struts açığı
  (CVE-2017-5638) için yama, saldırıdan aylar önce, Mart 2017'de yayımlanmıştı; ihlal aynı yılın Mayıs
  ayında başladı. Yamanın var olması yetmez, uygulanması gerekir.
- **Bağlamlı önceliklendirme:** EPSS (açığın yakın zamanda sömürülme olasılığını tahmin eden açık skor)
  ve KEV gibi kaynaklar, birçok güvenlik ekibinin CVSS'nin üstüne ek sinyal olarak kullandığı yöntemlerdir.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c07b06",),
)
