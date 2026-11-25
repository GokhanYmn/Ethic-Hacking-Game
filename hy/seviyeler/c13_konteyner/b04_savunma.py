"""Cilt 13 · Bölüm 4 — Konteyner Savunması ve Lab.

Beceri: kurgusal bir küme denetim çıktısını (FAIL maddeleri), iş yükü ve namespace listelerini okuyup
riskleri saptamak; eksik bir NetworkPolicy'yi (varsayılan reddet) yazmak; her FAIL bulgusunu beş
savunma ilkesinden biriyle eşleştiren bir sertleştirme planı hazırlamak. `cevap <no>` dosyaların son
halini kontrol eder (Durum görevleri). Hiçbir kümeye bağlanılmaz.

Vakalar: e-ticaret, hastane, fintech, lojistik. FAIL maddeleri, iş yükleri ve eksik NetworkPolicy'li
namespace her vakada farklıdır.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c13_konteyner.ortak import sec_doldur, sh, sirket_sec

ILKELER = ["en-az-ayricalik", "kucuk-yuzey", "tarama", "rbac", "izole-ag"]
MADDELER = [
    ("5.2.1", "Ayrıcalıklı (privileged) konteynerlerin kabulü en aza indirilmeli", "en-az-ayricalik"),
    ("5.2.6", "Konteynerler root kullanıcıyla çalıştırılmamalı", "en-az-ayricalik"),
    ("5.1.1", "cluster-admin rolünün kullanımı en aza indirilmeli", "rbac"),
    ("5.1.3", "Rollerde joker (*) kullanılmamalı", "rbac"),
    ("5.3.2", "Her namespace'te varsayılan reddeden bir NetworkPolicy bulunmalı", "izole-ag"),
    ("5.4.1", "İmajlar yayından önce zafiyet taramasından geçmeli", "tarama"),
    ("5.4.2", "Çalışan imajlar düzenli aralıklarla yeniden taranmalı", "tarama"),
    ("5.5.1", "İmajlarda gereksiz araçlar (kabuk, paket yöneticisi) bulunmamalı", "kucuk-yuzey"),
    ("5.6.2", "Temel imaj olarak minimal imajlar tercih edilmeli", "kucuk-yuzey"),
]
GECEN = ["API sunucusunda anonim erişim kapalı", "etcd verisi şifreli saklanıyor", "Denetim günlüğü açık",
         "Kubelet yetkilendirmesi etkin"]
NAMESPACELER = ["uretim", "odeme", "test", "izleme", "ci", "arayuz"]
SAHNE = {
    "pazarix": "Pazarix'in kümesi için kapanış denetimi yapıldı; yönetim 'ne yapmalıyız?' diye soruyor.",
    "medora": "Medora Sağlık'ın küme denetimi tamamlandı; bulgular KVKK raporuna girecek.",
    "paramix": "Paramix'in PCI denetçisi, küme sertleştirme planınızı görmek istiyor.",
    "kuzgun": "Kuzgun Lojistik'in küme yöneticisi, denetim sonuçlarını önceliklendirmekte zorlanıyor.",
}


def uret(rng):
    sk = sirket_sec(rng)
    fail = rng.sample(MADDELER, 5)
    while len({m[2] for m in fail}) < 4 or not any(m[0] == "5.3.2" for m in fail):
        fail = rng.sample(MADDELER, 5)
    gecen = [m for m in MADDELER if m not in fail]
    nsler = rng.sample(NAMESPACELER, 4)
    np_var = {n: rng.random() < 0.5 for n in nsler}
    np_var[nsler[0]], np_var[nsler[1]] = True, False       # en az bir evet, en az iki hayır
    np_var[nsler[2]] = False
    hedef = rng.choice([n for n in nsler if not np_var[n]])
    yukler = []
    ad_havuzu = [f"{sk['servisler'][i]}" for i in range(5)]
    for i in range(rng.randint(8, 9)):
        yukler.append((f"{ad_havuzu[i % 5]}-{i + 1}", rng.choice(nsler), rng.random() < 0.3, rng.random() < 0.5))
    if not any(y[2] for y in yukler):
        a = yukler[0]
        yukler[0] = (a[0], a[1], True, a[3])
    return {
        "vaka": f"{sk['ad']} — küme sertleştirme planı",
        "sirket": sk, "fail": fail, "gecen": gecen, "nsler": nsler, "np_var": np_var, "hedef": hedef, "yukler": yukler,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "hedef": hedef},
        "cevaplar": {
            "fail": [m[0] for m in fail],
            "ayricalikli": sum(1 for y in yukler if y[2]),
            "np_yok": [n for n in nsler if not np_var[n]],
        },
    }


def yaz(lab: Path, s: dict) -> None:
    k = lab / "konteyner/denetim"
    satirlar = [f"# {s['sirket']['ad']} — küme denetim çıktısı (KURGUSAL; madde numaraları uydurmadır)"]
    tum = [("PASS", m[0], m[1]) for m in s["gecen"]] + [("FAIL", m[0], m[1]) for m in s["fail"]]
    tum += [("PASS", f"1.{i + 1}.1", t) for i, t in enumerate(GECEN)]
    tum.sort(key=lambda x: [int(p) for p in x[1].split(".")])
    satirlar += [f"[{d}] {no}  {t}" for d, no, t in tum]
    u.yaz(k / "denetim_ciktisi.txt", "\n".join(satirlar) + "\n")
    u.yaz(k / "is_yukleri.csv", "ad,namespace,privileged,root\n" +
          "".join(f"{a},{n},{'evet' if p else 'hayir'},{'evet' if r else 'hayir'}\n" for a, n, p, r in s["yukler"]))
    u.yaz(k / "namespaces.csv", "namespace,networkpolicy\n" +
          "".join(f"{n},{'evet' if s['np_var'][n] else 'hayir'}\n" for n in s["nsler"]))
    var = next(n for n in s["nsler"] if s["np_var"][n])
    u.yaz(k / "ornek-networkpolicy.yaml", f"""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: varsayilan-reddet
  namespace: {var}
spec:
  podSelector: {{}}
  policyTypes:
    - Ingress
""")
    u.yaz(k / "sertlestirme_plani.txt",
          "# Her FAIL maddesi için hangi savunma ilkesine ait olduğunu yaz (madde | ilke).\n"
          "# İlkeler: en-az-ayricalik, kucuk-yuzey, tarama, rbac, izole-ag\n" +
          "".join(f"{m[0]} | \n" for m in s["fail"]))


def _plan_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "konteyner/denetim/sertlestirme_plani.txt"
    if not yol.is_file():
        return Sonuc(False, "`sertlestirme_plani.txt` yok.")
    eslesme = {}
    for ham in yol.read_text(encoding="utf-8", errors="replace").splitlines():
        if ham.strip().startswith("#"):
            continue
        m = re.match(r"^\s*(\S+)\s*\|\s*(\S*)\s*$", ham)
        if m:
            eslesme[m.group(1)] = m.group(2).lower()
    for no, text, ilke in s["fail"]:
        if no not in eslesme or not eslesme[no]:
            return Sonuc(False, f"`{no}` maddesi için ilke yazılmamış (`{no} | ilke` biçimi).")
        if eslesme[no] not in ILKELER:
            return Sonuc(False, f"`{no}` için yazdığın `{eslesme[no]}` beş ilkeden biri değil: {', '.join(ILKELER)}.", yakin=True)
    for no, text, ilke in s["fail"]:
        if eslesme[no] != ilke:
            return Sonuc(False, f"`{no}` ({text}) için `{eslesme[no]}` yazmışsın; bu madde başka bir ilkeye ait. Maddenin ne istediğine bak.", yakin=True)
    return Sonuc(True, "Her bulgu doğru savunma ilkesine eşlendi; plan hazır.")


def _np_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    ns = s["hedef"]
    yol = b.lab / f"konteyner/denetim/networkpolicy-{ns}.yaml"
    if not yol.is_file():
        return Sonuc(False, f"`konteyner/denetim/networkpolicy-{ns}.yaml` dosyası yok. Örnek dosyayı kopyalayıp `{ns}` için düzenle.")
    m = yol.read_text(encoding="utf-8", errors="replace")
    if not re.search(r"^kind:\s*NetworkPolicy\s*$", m, re.M):
        return Sonuc(False, "`kind: NetworkPolicy` yok.")
    if not re.search(rf"^\s+namespace:\s*{re.escape(ns)}\s*$", m, re.M):
        return Sonuc(False, f"`metadata.namespace` `{ns}` olmalı (örnekteki namespace'te kalmış olabilir).", yakin=True)
    if not re.search(r"^\s+podSelector:\s*\{\s*\}\s*$", m, re.M):
        return Sonuc(False, "`podSelector: {}` olmalı: boş seçici namespace'teki **bütün** pod'lara uygulanır.", yakin=True)
    if not re.search(r"^\s+-\s*Ingress\s*$", m, re.M):
        return Sonuc(False, "`policyTypes` içinde `Ingress` yok; gelen trafik kısıtlanmıyor.", yakin=True)
    if re.search(r"^\s+ingress:", m, re.M):
        return Sonuc(False, "Dosyada bir `ingress:` kuralı var: bu, kural kadar trafiğe **izin verir**. Varsayılan reddet için hiç `ingress:` kuralı olmamalı.", yakin=True)
    return Sonuc(True, f"`{ns}` için varsayılan reddet NetworkPolicy hazır: gelen trafik, açıkça izin verilmedikçe engelleniyor.")


def coz(lab: Path, s: dict) -> dict:
    k = "konteyner/denetim"
    fail = sh(f"grep '^\\[FAIL\\]' {k}/denetim_ciktisi.txt | awk '{{print $2}}' | tr '\\n' ' '", lab)
    priv = sh(f"awk -F, '$3==\"evet\"' {k}/is_yukleri.csv | wc -l", lab)
    nsler = sh(f"awk -F, '$2==\"hayir\" {{print $1}}' {k}/namespaces.csv | tr '\\n' ' '", lab)
    sh(f"sed 's/namespace: .*/namespace: {s['hedef']}/' {k}/ornek-networkpolicy.yaml > {k}/networkpolicy-{s['hedef']}.yaml", lab)
    plan = []
    for ham in (lab / k / "denetim_ciktisi.txt").read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\[FAIL\]\s+(\S+)\s+(.*)$", ham)
        if not m:
            continue
        t = m.group(2).lower()
        if "privileged" in t or "root" in t:
            ilke = "en-az-ayricalik"
        elif "cluster-admin" in t or "joker" in t:
            ilke = "rbac"
        elif "networkpolicy" in t:
            ilke = "izole-ag"
        elif "tarama" in t:
            ilke = "tarama"
        else:
            ilke = "kucuk-yuzey"
        plan.append(f"{m.group(1)} | {ilke}")
    (lab / k / "sertlestirme_plani.txt").write_text("# plan\n" + "\n".join(plan) + "\n", encoding="utf-8")
    return sec_doldur({1: fail, 2: priv, 3: nsler, 4: "", 5: "", 6: "", 7: "", 8: ""}, GOREVLER, lab, s)


def _fail_hata(g, beklenen, b):
    verilen = set(g.split())
    gecen = {m[0] for m in b.senaryo["gecen"]}
    if verilen & gecen:
        return "Listende denetimi GEÇEN (`[PASS]`) bir madde var. Yalnızca `[FAIL]` olanlar."
    return None


def _priv_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Fazla saymışsın. Yalnızca üçüncü sütun (`privileged`) `evet` olmalı; basit bir `grep evet`, `root` sütunundaki `evet`'leri de sayar."
    return None


ADIMLAR = [
    Adim("Beş savunma ilkesi", """
Konteyner ve Kubernetes savunmasının özeti beş ilkedir:

- **en-az-ayricalik:** `privileged` yok, docker.sock bağlama, root olmayan kullanıcı.
- **kucuk-yuzey:** minimal imaj, gereksiz araç yok.
- **tarama:** imajları ve kümeyi sürekli tara.
- **rbac:** her kimliğe minimum Kubernetes yetkisi.
- **izole-ag:** pod'lar arası trafiği kısıtla (NetworkPolicy).

**<<musteri>>**. <<sahne>> Elindeki ilk dosya, kümenin denetim çıktısı:
""", komut="cat konteyner/denetim/denetim_ciktisi.txt", sonra="""
`[PASS]` geçen, `[FAIL]` kalan maddelerdir. Savunma planı, her FAIL maddesini bir ilkeye ve bir eyleme
bağlamaktır. (Madde numaraları bu lab için uydurmadır.)
"""),
    Adim("FAIL maddelerini süzmek", """
`grep` ile yalnızca başarısız olanları listele:
""", komut="grep '^\\[FAIL\\]' konteyner/denetim/denetim_ciktisi.txt", sonra="""
Her satırın metni, hangi ilkeyi ihlal ettiğini söyler: "privileged/root" en az ayrıcalık,
"cluster-admin/joker" RBAC, "NetworkPolicy" izole ağ, "tarama" tarama, "gereksiz araçlar/minimal"
küçük yüzey.
"""),
    Adim("İş yükleri ve ayrıcalık", """
Denetim maddeleri genel; asıl risk hangi iş yükünün ne yaptığıdır. İş yükü listesine bak:
""", komut="cat konteyner/denetim/is_yukleri.csv", sonra="""
`privileged=evet` olan iş yükleri bir konteyner kaçışının en kısa yoludur. Saymak için üçüncü
sütunu süz: `awk -F, '$3=="evet"' konteyner/denetim/is_yukleri.csv | wc -l`. Yalnızca üçüncü sütun
önemli; `root` sütunundaki `evet`'ler başka bir risktir.
"""),
    Adim("İzole ağ: NetworkPolicy", """
Varsayılan olarak Kubernetes'te her pod her pod'la konuşabilir. Bir pod ele geçirilirse saldırgan
komşu pod'lara kolayca ulaşır. **NetworkPolicy**, pod'lar arası trafiği kısıtlar. En güvenli başlangıç:
**varsayılan reddet** (`podSelector: {}` ve hiç `ingress:` kuralı yok): bütün pod'lara gelen trafik
engellenir, sonra yalnızca gerekenlere izin verilir. Hangi namespace'lerde bir NetworkPolicy var?
""", komut="cat konteyner/denetim/namespaces.csv", sonra="""
Aşağıdaki örnek, `networkpolicy=evet` olan bir namespace'in varsayılan reddet politikasıdır:
`cat konteyner/denetim/ornek-networkpolicy.yaml`. Eksik namespace için aynısını kopyalayıp `namespace`
satırını değiştirirsin.
"""),
    Adim("Kendi laboratuvarın", """
Kubernetes güvenliğini öğrenmek için **kasıtlı savunmasız küme projeleri** vardır (örneğin
kube-goat). Bunları **kendi makinende** (minikube ya da kind ile) çalıştırıp bu cildin yanlış
yapılandırmalarını güvenle deneyebilirsin: gerçek bir kümeyi riske atmazsın ve Cilt 9'daki Docker
temelin üzerine kurulur. (Bu oyun içinde bir küme çalıştırmıyoruz; yalnızca dosyaları okuyup düzeltiyoruz.)

**Hacker gözüyle:** Konteyner ve Kubernetes güvenliği DevOps ile güvenliğin kesiştiği yerdir
(DevSecOps). Kod ve altyapı yazabilen biri, kaçışın ve yanlış yapılandırmanın nereden geldiğini daha
derin anlar; bu kesişim, güvenlik alanında en çok aranan becerilerden biridir.
"""),
]

GOREVLER = [
    Gorev("`denetim_ciktisi.txt` içinde **`[FAIL]`** olan maddelerin numaralarını yaz.",
          Kume("fail", sik_hatalar=_fail_hata, bicim="madde numaraları, virgülle ayrılmış"),
          ("Başarısız maddeler satır başında `[FAIL]` ile işaretli.",
           "`grep '^\\[FAIL\\]' konteyner/denetim/denetim_ciktisi.txt`",
           "İkinci sütun madde numarası: `... | awk '{print $2}'`"),
          puan=30, baslik="FAIL maddeleri"),
    Gorev("`is_yukleri.csv` içinde **ayrıcalıklı (`privileged=evet`)** kaç iş yükü var?",
          Sayi("ayricalikli", sik_hatalar=_priv_hata),
          ("Üçüncü sütuna bak.",
           "`awk -F, '$3==\"evet\"'` ile süz, satırları say.",
           "`awk -F, '$3==\"evet\"' konteyner/denetim/is_yukleri.csv | wc -l`"),
          puan=20, baslik="Ayrıcalıklı iş yükleri"),
    Gorev("**NetworkPolicy'si olmayan** namespace'lerin adlarını yaz.",
          Kume("np_yok", bicim="namespace adları, virgülle ayrılmış"),
          ("`namespaces.csv`'de ikinci sütun.",
           "Değeri `hayir` olan satırların ilk sütunu.",
           "`awk -F, '$2==\"hayir\" {print $1}' konteyner/denetim/namespaces.csv`"),
          puan=30, baslik="Korumasız namespace'ler"),
    Gorev("`<<hedef>>` namespace'i için **varsayılan reddet** NetworkPolicy yaz: "
          "`konteyner/denetim/networkpolicy-<<hedef>>.yaml` (örnek dosyayı kopyalayıp düzenleyebilirsin). "
          "Bitince `cevap 4`.",
          Durum(_np_kontrol, "kind: NetworkPolicy; namespace; podSelector: {}; policyTypes: Ingress; ingress: kuralı yok"),
          ("Örnek dosya zaten var; yalnızca namespace farklı.",
           "`sed` ile namespace satırını değiştirip yeni bir dosyaya yönlendir.",
           "`sed 's/namespace: .*/namespace: <<hedef>>/' konteyner/denetim/ornek-networkpolicy.yaml > konteyner/denetim/networkpolicy-<<hedef>>.yaml`"),
          puan=50, baslik="NetworkPolicy yaz"),
    Gorev("`sertlestirme_plani.txt` dosyasını doldur: her FAIL maddesinin yanına (`madde | ilke`) ait olduğu "
          "savunma ilkesini yaz (`en-az-ayricalik`, `kucuk-yuzey`, `tarama`, `rbac`, `izole-ag`). "
          "Bitince `cevap 5`.",
          Durum(_plan_kontrol, "her FAIL maddesi için doğru ilke"),
          ("Her maddenin metni hangi ilkeyi ihlal ediyor?",
           "privileged/root → en-az-ayricalik; cluster-admin/joker → rbac; NetworkPolicy → izole-ag; tarama → tarama; araç/minimal imaj → kucuk-yuzey.",
           "`nano konteyner/denetim/sertlestirme_plani.txt` ile her satırın `|` işaretinden sonrasını doldur."),
          puan=50, baslik="Sertleştirme planı"),
    Gorev("Kasıtlı savunmasız bir Kubernetes lab'ı (örneğin kube-goat) neden güvenli bir öğrenme yoludur?",
          Secmeli([
              ("Kendi makinende çalışır; gerçek kümeyi riske atmadan yanlışları deneyebilirsin",
               "Doğru. Hata yapma özgürlüğü, kendi izole ortamında öğrenmenin faydasıdır."),
              ("Çünkü bu lab'lar gerçek şirketlerin üretim kümelerine bağlıdır ve onların verisiyle çalışır",
               "Yanlış. Gerçek bir kuruma bağlı olmak yasadışıdır; lab'lar kendi ortamında çalışır."),
              ("Çünkü bu lab'lar hiç yanlış yapılandırma içermez ve yalnızca doğru ayarları gösterir",
               "Yanlış. Tam tersine, kasıtlı olarak savunmasızdırlar; amaç öğrenmektir."),
              ("Çünkü bu lab'lar internete açık bir kamu kümesinde kimin eriştiğini herkese gösterir",
               "Yanlış. Kendi makinende çalışırlar; kamuya açık bir küme gerekmez."),
          ], dogru=0),
          ("Lab'ı nerede çalıştırırsın?",
           "Gerçek bir kuruma zarar verme riski var mı?",
           "Kendi makinen, izole, kasıtlı savunmasız."),
          puan=20, baslik="Güvenli lab"),
    Gorev("'DevSecOps' neden bu kitabın temalarının doğal bir birleşimidir?",
          Secmeli([
              ("Geliştirme (DevOps) ile güvenliği birleştirir; kitabın kod, altyapı ve güvenlik temaları orada buluşur",
               "Doğru. Konteyner ve altyapıyı kodla yöneten biri güvenlik açığının kaynağını da daha derin anlar."),
              ("Çünkü yalnızca güvenlik görevlilerinin kod yazması gerektiğini ve yazılımcıların güvenliğe karışmaması gerektiğini söyler",
               "Yanlış. DevSecOps tam tersine ekipleri birleştirir."),
              ("Çünkü yalnızca ağ kablolaması ve fiziksel güvenlik üzerine kuruludur",
               "Yanlış. DevSecOps kod, otomasyon ve altyapı güvenliğiyle ilgilidir."),
              ("Çünkü bu terim yalnızca bir antivirüs ürününün ticari adıdır ve kitabın konusu değildir",
               "Yanlış. DevSecOps bir yaklaşımdır, bir ürün adı değil."),
          ], dogru=0),
          ("Dev + Sec + Ops: hangi üç dünya?",
           "Kitap kod, altyapı ve güvenlik üstüne kurulu.",
           "Geliştirme ile güvenliğin kesişimi."),
          puan=20, baslik="DevSecOps"),
    Gorev("Bir **NetworkPolicy**, beş savunma ilkesinden hangisinin aracıdır?",
          Secmeli([
              ("İzole ağ: pod'lar arası trafiği kısıtlamak", "Doğru. NetworkPolicy tam olarak bunu yapar."),
              ("Tarama: imajlardaki zafiyetleri listelemek", "Yanlış. Tarama, imaj ve küme zafiyetlerini bulur; trafiği kısıtlamaz."),
              ("RBAC: kimin ne yapabileceğini sınırlamak", "Yanlış. RBAC kimlik ve yetkilerle ilgilidir; ağ trafiğiyle değil."),
              ("Küçük yüzey: imajdaki gereksiz araçları silmek", "Yanlış. Bu imaj içeriğiyle ilgilidir, ağ trafiğiyle değil."),
          ], dogru=0),
          ("NetworkPolicy neyi kısıtlar?",
           "Pod'lar arası konuşmayı.",
           "İzole ağ."),
          puan=20, baslik="NetworkPolicy ilkesi"),
]


def _kapanis():
    return """
Konteyner ve Kubernetes savunması beş ilkeye iner: en az ayrıcalık, küçük yüzey, tarama, sıkı RBAC ve
izole ağ. Hepsi bilinir; çoğu kurum kolaylık için erteler. Saldırgan bu ihmalleri arar, sen kapatırsın:
bir denetim çıktısındaki her FAIL maddesini bir ilkeye ve somut bir düzeltmeye bağla, eksik
NetworkPolicy'leri yaz, düzeltmeyi uyguladıktan sonra aynı denetimi tekrar çalıştırıp maddenin
gerçekten PASS olduğunu doğrula ve her şeyi kendi izole lab'ında önce dene.
"""


SEVIYE = Seviye(
    kimlik="c13b04",
    cilt=13,
    bolum=4,
    baslik="Konteyner Savunması ve Lab",
    brifing="""
Selin son dosyayı veriyor: "**<<musteri>>**. <<sahne>> Elimizde kümenin denetim çıktısı, iş yükü
listesi ve namespace tablosu var. Yönetime bir **sertleştirme planı** sunacağız: hangi bulgu hangi
ilkeye ait, hangi namespace korumasız ve onun için bir NetworkPolicy yazalım."

Deniz ekliyor: "Plan hazır olunca ben her ilke için bir alarm kuralı yazacağım. Hangi bulgu hangi
ilkeye giriyor, bilmem lazım."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Kıyaslama rehberleri:** CIS Kubernetes Benchmark ve CIS Docker Benchmark gibi herkese açık rehberler,
  bu bölümdeki denetim maddelerinin gerçek karşılıklarını içerir; açık kaynak araçlar bu rehberlere
  karşı kümeyi otomatik denetleyebilir.
- **NetworkPolicy'nin değeri:** Varsayılan olarak Kubernetes'te pod'lar birbirleriyle konuşabilir; bu
  yüzden bir pod'un ele geçirilmesi komşu pod'lara yayılmayı kolaylaştırır. Kubernetes'in kendi
  belgeleri, ağı varsayılan reddet ile başlatıp gerekeni açmayı önerir.
- **Tespit ve önleme:** Admission denetimleri ile kuralları dağıtımdan önce uygulamak, kümeyi düzenli
  taramak, imajları CI'da taramak ve NetworkPolicy/RBAC değişikliklerini denetim günlüğünden izlemek
  en yaygın uygulamalardır. Bu adımlar Mirai gibi "varsayılan ayarlarla bırakılan sistemler"
  olaylarındaki dersin konteyner dünyasındaki karşılığıdır: varsayılan güvenli değildir.
""",
    sure_hedef_dk=35,
)
