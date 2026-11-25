"""Cilt 13 · Bölüm 3 — Kubernetes Güvenliği.

Beceri: kurgusal RBAC ve Pod YAML dosyalarında aşırı yetkiyi (`*` kuralları, cluster-admin'e bağlı
ServiceAccount), hostPath bağlamayı, privileged ve ServiceAccount token'ının gereksiz bağlanmasını
bulmak ve dosyaları düzeltmek. `cevap <no>` dosyaların son halini kontrol eder (Durum görevleri).
PyYAML yoktur; ayrıştırma satır tabanlıdır. Hiçbir kümeye bağlanılmaz.

Vakalar: e-ticaret, hastane, fintech, lojistik. Rol/hesap adları, hangi pod'un hangi riski taşıdığı
ve aşırı yetkili ServiceAccount'un kimliği her vakada değişir.
"""
from __future__ import annotations

import re
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c13_konteyner.ortak import sec_doldur, sh, sirket_sec

ROL_ADLARI = ["ci-genis-yetki", "dagitim-her-sey", "platform-genis"]
SA_ADLARI = ["eski-dagitim", "yedek-hesap", "ilk-kurulum", "test-ekibi"]
SAHNE = {
    "pazarix": "Pazarix, siparişlerini bir Kubernetes kümesine taşıdı; ilk güvenlik incelemesi bu hafta.",
    "medora": "Medora Sağlık'ın küme yöneticisi 'bir pod ele geçirilirse ne olur?' sorusuna cevap bulamıyor.",
    "paramix": "Paramix'in PCI denetçisi, kümedeki servis hesaplarının yetkilerini listelemek istiyor.",
    "kuzgun": "Kuzgun Lojistik'te geçici olarak verilmiş bir küme yetkisinin hiç kaldırılmadığı fark edildi.",
}
NS = "uretim"


def uret(rng):
    sk = sirket_sec(rng)
    sv = sk["servisler"]
    rol = rng.choice(ROL_ADLARI)
    sa = rng.choice(SA_ADLARI)
    admin = f"{rng.choice(u.ISIMLER)}.admin"
    podlar = rng.sample(sv[:4], 3)                  # [temiz, loglu hostPath, tam yetkili]
    return {
        "vaka": f"{sk['ad']} — Kubernetes denetimi",
        "sirket": sk, "rol": rol, "sa": sa, "admin": admin, "podlar": podlar,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "rol": rol, "sa": sa, "ns": NS,
                  "pod_yetkili": podlar[2]},
        "cevaplar": {"clusteradmin": [admin, sa], "joker_rol": rol, "hostpath": [podlar[1], podlar[2]]},
    }


def _rbac(s: dict) -> str:
    on = s["sirket"]["on"]
    return f"""apiVersion: v1
kind: ServiceAccount
metadata:
  name: {s['sa']}
  namespace: {NS}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: izleyici
  namespace: {NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {on}-izleme-oku
rules:
  - apiGroups: [""]
    resources: ["pods", "nodes"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {s['rol']}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ci-yetki-baglantisi
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {s['rol']}
subjects:
  - kind: ServiceAccount
    name: ci-hesabi
    namespace: {NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: yonetici-baglantisi
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
  - kind: User
    name: {s['admin']}
    apiGroup: rbac.authorization.k8s.io
  - kind: ServiceAccount
    name: {s['sa']}
    namespace: {NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: izleme-baglantisi
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: {on}-izleme-oku
subjects:
  - kind: ServiceAccount
    name: izleyici
    namespace: {NS}
"""


def _pod(s: dict, ad: str, tur: str) -> str:
    on = s["sirket"]["on"]
    ust = f"""apiVersion: v1
kind: Pod
metadata:
  name: {ad}-pod
  namespace: {NS}
spec:
"""
    if tur == "temiz":
        return ust + f"""  serviceAccountName: izleyici
  automountServiceAccountToken: false
  containers:
    - name: uygulama
      image: {on}/{ad}:1.4
      securityContext:
        runAsNonRoot: true
"""
    if tur == "log":
        return ust + f"""  serviceAccountName: izleyici
  containers:
    - name: uygulama
      image: {on}/{ad}:1.4
      securityContext:
        runAsNonRoot: true
      volumeMounts:
        - name: loglar
          mountPath: /var/log/host
          readOnly: true
  volumes:
    - name: loglar
      hostPath:
        path: /var/log
"""
    return ust + f"""  serviceAccountName: {s['sa']}
  containers:
    - name: uygulama
      image: {on}/{ad}:1.4
      securityContext:
        privileged: true
      volumeMounts:
        - name: ana-disk
          mountPath: /host
  volumes:
    - name: ana-disk
      hostPath:
        path: /
"""


def yaz(lab: Path, s: dict) -> None:
    k = lab / "konteyner/k8s"
    u.yaz(k / "rbac.yaml", _rbac(s))
    for ad, tur in zip(s["podlar"], ["temiz", "log", "tam"]):
        u.yaz(k / f"pod-{ad}.yaml", _pod(s, ad, tur))
    u.yaz(k / "gereksinim.txt",
          f"`{s['rol']}` rolünü kullanan CI hesabı (`ci-hesabi`) yalnızca `{NS}` kümesindeki pod'ları\n"
          "LİSTELEMEK, GÖRMEK ve pod loglarını OKUMAK zorundadır. Başka hiçbir kaynağa ya da eyleme ihtiyacı yoktur.\n"
          f"`{s['sa']}` ServiceAccount'u artık kullanılmıyor; yalnızca yönetici kullanıcısı cluster-admin kalmalı.\n"
          f"`pod-{s['podlar'][2]}.yaml` yalnızca bir uygulama çalıştırıyor; ana makine diskine ya da ayrıcalığa ihtiyacı yok.\n")


def _belgeler(metin: str) -> list:
    return [d for d in re.split(r"^---\s*$", metin, flags=re.M) if d.strip()]


def _meta_ad(d: str):
    m = re.search(r"^  name:\s*(\S+)", d, re.M)
    return m.group(1) if m else None


def _kind(d: str):
    m = re.search(r"^kind:\s*(\S+)", d, re.M)
    return m.group(1) if m else None


def _liste(x: str) -> list:
    return [p.strip().strip("\"'") for p in x.split(",") if p.strip()]


def _rol_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "konteyner/k8s/rbac.yaml"
    if not yol.is_file():
        return Sonuc(False, "`rbac.yaml` yok.")
    doc = next((d for d in _belgeler(yol.read_text(encoding="utf-8")) if _kind(d) == "ClusterRole" and _meta_ad(d) == s["rol"]), None)
    if doc is None:
        return Sonuc(False, f"`{s['rol']}` rolü silinmiş. Rolü silme (CI hesabı çalışamaz), kurallarını daralt.")
    kurallar = re.findall(r"apiGroups:\s*\[(.*?)\]\s*\n\s+resources:\s*\[(.*?)\]\s*\n\s+verbs:\s*\[(.*?)\]", doc)
    if not kurallar:
        return Sonuc(False, "Kural biçimi bozulmuş. Her kural `apiGroups`, `resources`, `verbs` satırlarını (köşeli parantezli liste) içermeli.")
    kapsam = set()
    for ag, kay, fiil in kurallar:
        ag, kay, fiil = _liste(ag), _liste(kay), _liste(fiil)
        if "*" in ag or "*" in kay or "*" in fiil:
            return Sonuc(False, "Hâlâ bir `*` (joker) var: apiGroups, resources ya da verbs içinde. Hepsi tek tek yazılmalı.", yakin=True)
        fazla_kay = set(kay) - {"pods", "pods/log"}
        if fazla_kay:
            return Sonuc(False, f"Gerekmeyen kaynak(lar): {', '.join(sorted(fazla_kay))}. Yalnızca pod'lar ve pod logları.", yakin=True)
        fazla_fiil = set(fiil) - {"get", "list", "watch"}
        if fazla_fiil:
            return Sonuc(False, f"Gerekmeyen eylem(ler): {', '.join(sorted(fazla_fiil))}. CI hesabı yalnızca okuyacak.", yakin=True)
        for r in kay:
            for f in fiil:
                kapsam.add((r, f))
    if ("pods", "get") not in kapsam or ("pods", "list") not in kapsam or ("pods/log", "get") not in kapsam:
        return Sonuc(False, "Gereksinim: pod'ları listelemek (`list`), görmek (`get`) ve logları (`pods/log`) okumak (`get`). Eksik kalmış.", yakin=True)
    return Sonuc(True, "Rol daraldı: yalnızca pod'ları ve loglarını okuyabiliyor; jokersiz.")


def _baglanti_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "konteyner/k8s/rbac.yaml"
    if not yol.is_file():
        return Sonuc(False, "`rbac.yaml` yok.")
    doc = next((d for d in _belgeler(yol.read_text(encoding="utf-8")) if _kind(d) == "ClusterRoleBinding" and _meta_ad(d) == "yonetici-baglantisi"), None)
    if doc is None:
        return Sonuc(False, "`yonetici-baglantisi` bağlantısını silmişsin; yönetici kullanıcının yetkisini de kaybedersin. Yalnızca ServiceAccount öznesini çıkar.")
    ozneler = re.findall(r"- kind:\s*(\w+)\s*\n\s+name:\s*(\S+)", doc)
    if "cluster-admin" not in doc:
        return Sonuc(False, "`roleRef` içindeki `cluster-admin`'i değiştirmişsin; yönetici kullanıcı artık yetkisiz. Sorun rol değil, ona bağlı **ServiceAccount**.")
    if any(k == "ServiceAccount" for k, _ in ozneler):
        ad = next(a for k, a in ozneler if k == "ServiceAccount")
        return Sonuc(False, f"`{ad}` ServiceAccount'u hâlâ cluster-admin'e bağlı. Uygulama hesapları kümenin tamamını yönetmemeli.", yakin=True)
    if ("User", s["admin"]) not in ozneler:
        return Sonuc(False, f"Yönetici kullanıcıyı (`{s['admin']}`) da çıkarmışsın; yalnızca ServiceAccount öznesi gitmeli.", yakin=True)
    izle = next((d for d in _belgeler(yol.read_text(encoding="utf-8")) if _meta_ad(d) == "izleme-baglantisi"), "")
    if "izleyici" not in izle:
        return Sonuc(False, "`izleme-baglantisi` bağlantısındaki meşru `izleyici` öznesini de silmişsin; yalnızca cluster-admin'e bağlı hesabı çıkar.", yakin=True)
    return Sonuc(True, "cluster-admin artık yalnızca yönetici kullanıcıya bağlı; ServiceAccount çıkarıldı.")


def _pod_kontrol(b: Baglam) -> Sonuc:
    s = b.senaryo
    ad = s["podlar"][2]
    yol = b.lab / f"konteyner/k8s/pod-{ad}.yaml"
    if not yol.is_file():
        return Sonuc(False, f"`pod-{ad}.yaml` yok.")
    m = yol.read_text(encoding="utf-8")
    if "kind: Pod" not in m or "image:" not in m:
        return Sonuc(False, "Pod tanımı bozulmuş (`kind: Pod` ya da `image:` yok). Yalnızca riskli ayarları kaldır.")
    if re.search(r"privileged:\s*true", m):
        return Sonuc(False, "Hâlâ `privileged: true`. Konteynere ana makine yetkisi verme.", yakin=True)
    if "hostPath" in m:
        return Sonuc(False, "Hâlâ bir `hostPath` bağı var: pod ana makinenin diskine erişir. Hem `volumes` girdisini hem `volumeMounts` girdisini kaldır.", yakin=True)
    if re.search(r"^\s+(volumeMounts|volumes):\s*$", m, re.M) and not re.search(r"^\s+(volumeMounts|volumes):\s*\n\s+-", m, re.M):
        return Sonuc(False, "Boş bir `volumes:`/`volumeMounts:` anahtarı kalmış; öğesi olmayan anahtarı da sil.", yakin=True)
    if "/host" in m:
        return Sonuc(False, "`/host` bağ noktası hâlâ duruyor; bağ girdisini tamamen kaldır.", yakin=True)
    if not re.search(r"^  automountServiceAccountToken:\s*false\b", m, re.M):
        return Sonuc(False, "`automountServiceAccountToken: false` yok. Pod, API sunucusuna erişmesi gerekmeyen bir uygulama; token'ı gereksiz yere bağlama (`spec:` altına, 2 boşlukla).", yakin=True)
    if not re.search(r"runAsNonRoot:\s*true", m):
        return Sonuc(False, "`securityContext` içinde `runAsNonRoot: true` yok; konteyner root olarak çalışabilir.", yakin=True)
    return Sonuc(True, "Pod artık ayrıcalıksız, ana makine diski bağlı değil, token bağlanmıyor ve root olmayan kullanıcıyla çalışıyor.")


def coz(lab: Path, s: dict) -> dict:
    k = "konteyner/k8s"
    ca = sh(r"""awk 'BEGIN{RS="---"} /name: cluster-admin/ {print}' konteyner/k8s/rbac.yaml | grep -E '^    name:' | awk '{print $2}' | tr '\n' ' '""", lab)
    joker = sh(r"""awk 'BEGIN{RS="---"} index($0, "[\"*\"]") {print}' konteyner/k8s/rbac.yaml | grep -m1 '^  name:' | awk '{print $2}'""", lab)
    hp = sh(r"""grep -l hostPath konteyner/k8s/pod-*.yaml | xargs -n1 basename | sed 's/^pod-//;s/.yaml$//' | tr '\n' ' '""", lab)
    # düzeltmeler
    sh(f"sed -i 's/apiGroups: \\[\"\\*\"\\]/apiGroups: [\"\"]/; s/resources: \\[\"\\*\"\\]/resources: [\"pods\", \"pods\\/log\"]/; "
       f"s/verbs: \\[\"\\*\"\\]/verbs: [\"get\", \"list\"]/' {k}/rbac.yaml", lab)
    sil = f"  - kind: ServiceAccount\n    name: {s['sa']}\n    namespace: {NS}\n---\n"
    f_ = lab / k / "rbac.yaml"
    f_.write_text(f_.read_text(encoding="utf-8").replace(sil, "---\n", 1), encoding="utf-8")
    p = f"{k}/pod-{s['podlar'][2]}.yaml"
    sh(f"sed -i '/volumeMounts:/,$d' {p}; sed -i 's/privileged: true/runAsNonRoot: true/' {p}; "
       f"sed -i 's/^spec:/spec:\\n  automountServiceAccountToken: false/' {p}", lab)
    return sec_doldur({1: "", 2: ca, 3: joker, 4: hp, 5: "", 6: "", 7: ""}, GOREVLER, lab, s)


def _ca_hata(g, beklenen, b):
    verilen = set(g.split())
    if "izleyici" in verilen or "ci-hesabi" in verilen:
        return "Listende cluster-admin'e **bağlı olmayan** bir hesap var. Yalnızca `roleRef` içinde `cluster-admin` yazan bağlantının özneleri."
    return None


ADIMLAR = [
    Adim("Kubernetes'in parçaları", """
**Kubernetes** (K8s), yüzlerce konteyneri yöneten bir orkestrasyon sistemidir. Güçlüdür ama karmaşıktır;
karmaşıklık yanlış yapılandırma demektir.

- **Pod:** bir ya da birkaç konteynerin en küçük birimi.
- **Node:** pod'ların çalıştığı makine (ana makine).
- **API Server:** kümenin beyni; bütün kontrol buradan geçer.
- **RBAC:** kim neye erişebilir (K8s'in IAM'i).
- **Secret:** parola/anahtar saklama (varsayılan olarak zayıf korunur).

**<<musteri>>**. <<sahne>> Elindeki dosyalar: bir `rbac.yaml` ve üç Pod tanımı. (Kümeye bağlanmayacaksın;
dosyaları okuyup düzelteceksin.)
""", komut="ls konteyner/k8s"),
    Adim("RBAC: Role, ClusterRole, Binding", """
RBAC üç parçadan oluşur: **Role/ClusterRole** (hangi kaynak üzerinde hangi eylemlere izin), **özne**
(kullanıcı ya da ServiceAccount) ve bunları bağlayan **RoleBinding/ClusterRoleBinding**. Kurallarda `*`
bir joker: her kaynak, her eylem. Dosyayı oku:
""", komut="cat konteyner/k8s/rbac.yaml", sonra="""
Bu, Cilt 11 ve 12'deki en az yetki temasının Kubernetes karşılığıdır. `ClusterRole` bütün küme için,
`Role` yalnızca bir namespace için geçerlidir.
"""),
    Adim("Joker kuralları bulmak", """
Bir kuralda `apiGroups`, `resources`, `verbs` üçü de `["*"]` ise o kimlik **kümenin tamamında her şeyi**
yapabilir. Joker içeren satırları bul:
""", komut="grep -n '\"\\*\"' konteyner/k8s/rbac.yaml", sonra="""
Satır numarasından yukarı doğru çıkıp hangi rolün kuralı olduğunu bul. `grep -n 'name:\\|\"\\*\"'` rol
adlarıyla jokerleri yan yana gösterir.
"""),
    Adim("cluster-admin: kümenin tam sahibi", """
`cluster-admin`, kümede her şeyi yapma yetkisidir. Bir **ServiceAccount**'a (bir uygulamanın kimliği)
bağlanmışsa, o pod'u ele geçiren saldırgan kümenin tamamını ele geçirir. `roleRef`'te `cluster-admin`
yazan bağlantıyı ve **özneleri** (`subjects`) oku:
""", komut="grep -n -A12 'name: yonetici-baglantisi' konteyner/k8s/rbac.yaml", sonra="""
`kind: User` bir insan yöneticidir; `kind: ServiceAccount` bir uygulama kimliğidir. Uygulama
hesaplarının cluster-admin'de işi yoktur.
"""),
    Adim("Pod'lar: hostPath, privileged, token", """
Üç risk:

- **hostPath:** ana makinenin bir dizinini pod'a bağlar. `/` bağlanırsa pod ana makinenin tüm diskini
  görür.
- **privileged:** konteynere ana makine yetkisi verir (Bölüm 1).
- **ServiceAccount token'ı:** Kubernetes her pod'a, API sunucusuyla konuşabilen bir token'ı varsayılan
  olarak bağlar. Pod'un API'ye ihtiyacı yoksa bu gereksiz bir kapıdır (`automountServiceAccountToken: false`).

Hangi pod'larda `hostPath` var?
""", komut="grep -n 'hostPath' konteyner/k8s/pod-*.yaml", sonra="""
`path:` satırı hangi ana makine dizininin bağlandığını söyler. Salt okunur bir log dizini bile
ana makineyle ilişkidir, ama `/` ile aynı tehlikede değildir. Yine de hostPath bir **escape yolu**dur.
"""),
    Adim("Pod'dan cluster hakimiyetine", """
Saldırgan bir pod'u ele geçirdiğinde sıradaki hedefi **kümenin tamamıdır**: pod'un token'ı ve RBAC
boşluklarıyla yetki yükseltir. Bu, AD'deki domain hakimiyetine çok benzer: bir kullanıcıdan Domain
Admin'e giden yol. Pod ne kadar az yetkiliyse ve token ne kadar azsa, o yol o kadar kısalır.
Hangi pod hangi ServiceAccount'u kullanıyor?
""", komut="grep -n 'serviceAccountName\\|automount' konteyner/k8s/pod-*.yaml", sonra="""
Bir pod, **cluster-admin'e bağlı** bir ServiceAccount kullanıyorsa o pod'un ele geçirilmesi doğrudan
küme hakimiyetidir.
"""),
]

GOREVLER = [
    Gorev("Pod, Node ve API Server arasındaki ilişkiyi en doğru anlatan cümle hangisi?",
          Secmeli([
              ("Pod en küçük birimdir, Node makinedir, API Server kümenin kontrol merkezidir",
               "Doğru. Kontrol API Server'dan geçer; pod'lar node'larda çalışır."),
              ("API Server pod'ların içinde çalışan bir konteyner uygulamasıdır ve her node'un yerine geçer",
               "Yanlış. API Server kümenin kontrol bileşenidir; bir pod içindeki uygulama değildir."),
              ("Node bir pod'un içindeki tek konteynerin adıdır, pod ise node'un yapılandırma dosyasıdır",
               "Yanlış. Roller ters: pod konteynerleri taşır, node pod'ları barındıran makinedir."),
              ("Pod yalnızca ağ trafiğini izler, node ise parolaları saklar ve API Server'ı yedekler",
               "Yanlış. Bu görevler pod, node ve API Server'ın tanımı değil."),
          ], dogru=0),
          ("Pod'lar nerede çalışır?",
           "Kümeyi kim yönetir?",
           "Pod = en küçük birim; Node = makine; API Server = kontrol merkezi."),
          puan=20, baslik="Pod, Node, API Server"),
    Gorev("**cluster-admin** rolüne bağlı özneleri (kullanıcı ve ServiceAccount adları) yaz.",
          Kume("clusteradmin", sik_hatalar=_ca_hata, bicim="özne adları, virgülle ayrılmış"),
          ("`roleRef` içinde `cluster-admin` yazan bağlantıyı bul.",
           "`grep -n -A12 'name: yonetici-baglantisi' konteyner/k8s/rbac.yaml`: `subjects` altındaki adlar.",
           "Kullanıcı adı ve ServiceAccount adı: iki özne var. Başka bağlantıların öznelerini yazma."),
          puan=40, baslik="cluster-admin özneleri"),
    Gorev("Hangi **ClusterRole**'de hem `resources`, hem `verbs`, hem `apiGroups` için `*` (joker) var? "
          "Rolün adını yaz.",
          Metin("joker_rol", bicim="rol adı"),
          ("Joker `[\"*\"]` biçiminde yazılmış.",
           "`grep -n 'name:\\|\"\\*\"' konteyner/k8s/rbac.yaml` ile rol adlarını ve jokerleri yan yana gör.",
           "Üç satırlık `[\"*\"]` kümesinin hemen üstündeki `name:` satırı."),
          puan=30, baslik="Jokerli rol"),
    Gorev("Hangi pod'ların tanımında **hostPath** var? Pod dosya adlarındaki servis adlarını yaz "
          "(`pod-` ve `.yaml` olmadan).",
          Kume("hostpath", bicim="servis adları, virgülle ayrılmış"),
          ("`grep -n hostPath konteyner/k8s/pod-*.yaml`",
           "Çıktıdaki dosya adlarına bak.",
           "`grep -l hostPath konteyner/k8s/pod-*.yaml` yalnızca dosya adlarını verir."),
          puan=30, baslik="hostPath pod'lar"),
    Gorev("`<<rol>>` rolünü **daralt**: `gereksinim.txt`'e göre yalnızca pod'ları ve pod loglarını "
          "listeleyip okusun (`get`, `list`); hiçbir joker kalmasın. Bitince `cevap 5`.",
          Durum(_rol_kontrol, "apiGroups [\"\"], resources [pods, pods/log], verbs [get, list]"),
          ("Üç satır var; her birindeki `*` yerine gerekeni yaz.",
           "`apiGroups: [\"\"]` çekirdek API grubudur. Loglar `pods/log` ayrı bir kaynaktır.",
           "`sed -i 's/apiGroups: \\[\"\\*\"\\]/apiGroups: [\"\"]/; s/resources: \\[\"\\*\"\\]/resources: [\"pods\", \"pods\\/log\"]/; s/verbs: \\[\"\\*\"\\]/verbs: [\"get\", \"list\"]/' konteyner/k8s/rbac.yaml`"),
          puan=50, baslik="Rolü daralt"),
    Gorev("`yonetici-baglantisi` bağlantısından **`<<sa>>` ServiceAccount'unu çıkar**; yönetici kullanıcı "
          "cluster-admin olarak kalsın. Bitince `cevap 6`.",
          Durum(_baglanti_kontrol, "cluster-admin'in subjects listesinden ServiceAccount çıkar"),
          ("Silinecek şey yalnızca üç satırlık bir özne.",
           "`- kind: ServiceAccount`, altındaki `name:` ve `namespace:` satırları.",
           "`nano konteyner/k8s/rbac.yaml` ile bu üç satırı sil; `izleme-baglantisi`'ndaki ServiceAccount'a dokunma."),
          puan=40, baslik="Aşırı yetkili hesabı çıkar"),
    Gorev("`pod-<<pod_yetkili>>.yaml` pod'unu düzelt: `privileged` yerine `runAsNonRoot: true`, `hostPath` "
          "bağını (hem `volumeMounts` hem `volumes`) kaldır, `spec` altına `automountServiceAccountToken: false` "
          "ekle. Bitince `cevap 7`.",
          Durum(_pod_kontrol, "privileged→runAsNonRoot, hostPath yok, automountServiceAccountToken: false"),
          ("Dört ayrı değişiklik: privileged, hostPath/volumeMounts, token, root.",
           "`volumeMounts:` satırından dosyanın sonuna kadar silmek hostPath bağını kaldırır. Boş anahtar bırakma.",
           "`sed -i '/volumeMounts:/,$d' DOSYA; sed -i 's/privileged: true/runAsNonRoot: true/' DOSYA; sed -i 's/^spec:/spec:\\n  automountServiceAccountToken: false/' DOSYA`"),
          puan=50, baslik="Pod'u sertleştir"),
    Gorev("RBAC, bu kitabın hangi temasının Kubernetes karşılığıdır?",
          Secmeli([
              ("Cilt 11-12'deki en az yetki ve IAM temasının",
               "Doğru. RBAC, K8s'te kimin neye erişebileceğini belirler; bulutta IAM, AD'de grup yetkileri neyse odur."),
              ("Cilt 2'deki ARP ve alt ağ maskesi konusunun",
               "Yanlış. ARP yerel ağ adreslemesidir; RBAC erişim yetkileriyle ilgilidir."),
              ("Cilt 5'teki yalnızca SQL enjeksiyonu konusunun",
               "Yanlış. SQL enjeksiyonu bir uygulama zafiyetidir; RBAC bir yetkilendirme modelidir."),
              ("Cilt 3'teki bash döngülerinin",
               "Yanlış. Bash döngüleri otomasyon konusudur, yetkilendirme değil."),
          ], dogru=0),
          ("RBAC = kim neye erişebilir?",
           "Bulutta bunu hangi sistem yapıyordu?",
           "IAM / en az yetki."),
          puan=20, baslik="RBAC karşılığı"),
    Gorev("Bir pod'u ele geçiren saldırgan neden bütün kümeyi hedefler ve bu AD'deki neye benzer?",
          Secmeli([
              ("Pod'dan yetki yükseltip küme hakimiyetini hedefler; AD'deki domain hakimiyetine benzer",
               "Doğru. Tek bir pod'dan başlayıp yetki zincirini izleyerek küme yöneticisi olmaya çalışır."),
              ("Çünkü tüm pod'lar aynı konteyneri paylaşır; bu da AD'deki bir yazıcı sürücüsüne benzer",
               "Yanlış. Pod'lar ayrı çalışır; benzetme yazıcı sürücüsüyle değil yetki zinciriyle kurulur."),
              ("Çünkü pod'lar yalnızca tek bir ağ kablosunu paylaşır ve bu AD'deki parola politikasına benzer",
               "Yanlış. Tehlike ortak kablo değil, token ve RBAC yetkileridir."),
              ("Çünkü bir pod ele geçirilince bütün kümenin internet bağlantısı kendiliğinden kesilir",
               "Yanlış. Böyle bir otomatik tepki yok; saldırgan yetkisini artırmaya çalışır."),
          ], dogru=0),
          ("Pod'un token'ı ve RBAC yetkileri nereye açılır?",
           "AD'de bir kullanıcıdan Domain Admin'e giden yolu hatırla.",
           "Yetki yükseltip küme hakimiyetine ulaşmak."),
          puan=20, baslik="Pod'dan küme hakimiyetine"),
]


def _kapanis():
    return """
Kubernetes bu kitabın her temasının buluştuğu yerdir: ağ, kimlik, en az yetki, konteyner kaçışı ve
yanlış yapılandırma. Saldırgan bir pod'dan başlar, token ve RBAC boşluklarıyla yetki yükseltir ve küme
hakimiyetine ulaşır; aynı AD'de bir kullanıcıdan Domain Admin'e giden yol gibi. Savunma dersi: jokerli
rolleri ve cluster-admin'e bağlı ServiceAccount'ları düzenli tara, pod'larda `privileged`, `hostPath`
ve gereksiz token bağlamayı kapat, değişiklikten sonra uygulamanın çalışmaya devam ettiğini doğrula
ve basitliği koru: K8s'i güvenli yapmanın en büyük zorluğu karmaşıklığıdır.
"""


SEVIYE = Seviye(
    kimlik="c13b03",
    cilt=13,
    bolum=3,
    baslik="Kubernetes Güvenliği",
    brifing="""
Selin kubeconfig yerine dosyalar uzatıyor: "**<<musteri>>**. <<sahne>> Elimizde kümenin `rbac.yaml`
dosyası ve üç Pod tanımı var. Kümeye bağlanmayacağız; her şey dosyada. Üç şeye bak: jokerli rol,
cluster-admin'e bağlı bir ServiceAccount ve bir pod'da ana makine diskinin bağlanması."

Mert ekliyor: "Eğer ele geçirilen pod `<<sa>>` hesabıyla çalışıyorsa, saldırgan kümenin sahibi olur.
Önce onu kes."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Yaygın K8s bulguları:** Kubernetes güvenlik denetimlerinde aşırı yetkili RBAC rolleri,
  cluster-admin'e bağlı ServiceAccount'lar, `privileged` pod'lar ve `hostPath` bağları en sık
  raporlanan yapılandırma sorunları arasındadır; CIS Kubernetes Benchmark bu konuları açıkça ele alır.
- **Açık API sunucusu ve panolar:** Kubernetes panosunun ya da API sunucusunun kimlik doğrulaması
  olmadan internete açık bırakıldığı olaylar güvenlik araştırmalarında defalarca anlatılmıştır; bu
  yüzden bu bölümdeki "kim neye erişir" sorusu hem iç hem dış saldırgan için geçerlidir.
- **Tespit ve önleme:** Admission denetleyicileri (örneğin Pod Security standartları) `privileged` ve
  `hostPath` kullanan pod'ları dağıtımdan önce reddedebilir; RBAC taramaları jokerli rolleri ve
  cluster-admin bağlantılarını listeler; denetim günlükleri alışılmadık ServiceAccount etkinliğini
  yakalar.
""",
    sure_hedef_dk=40,
)
