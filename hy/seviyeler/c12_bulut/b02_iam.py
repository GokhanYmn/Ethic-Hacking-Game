"""Cilt 12 · Bölüm 2 — Kimlik ve Erişim (IAM).

Beceri: kurgusal IAM politika dosyalarında `*` yetkilerini ve yetki yükselten izinleri bulmak,
MFA'sız yöneticileri saptamak, koda gömülü sızmış anahtarı bulmak ve politikayı **daraltıp**
MFA'yı açarak düzeltmek. `cevap <no>` dosyaların son halini kontrol eder (Durum görevleri).

Vakalar: e-ticaret, hastane, fintech, lojistik, banka. Yönetici politikalarının adları, kullanıcılar
ve anahtarın saklandığı dosya her vakada farklıdır. Anahtarlar ve hesap numaraları tamamen kurgusaldır.
"""
from __future__ import annotations

import json
import string
from pathlib import Path

from hy.motor.kontrol import Baglam, Durum, Kume, Metin, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import uretec as u
from hy.seviyeler.c12_bulut.ortak import json_satirli, json_yaz, liste, py, sec_doldur, sh, sirket_sec

ADMIN_ADLARI = ["yonetici-tam-erisim", "tam-yetki", "platform-admin", "eski-devops-tam", "her-sey-serbest"]
SAHNE = {
    "pazarix": "Pazarix'in bir geliştiricisi 'ben yönetici değilim ama her şeyi silebiliyorum' diye şaka yaptı; Selin şaka olmadığını biliyor.",
    "medora": "Medora Sağlık'ta hasta dosyalarının tutulduğu hesapta kimin neye yetkisi olduğu kimse tarafından bilinmiyor.",
    "paramix": "Paramix'in üye işyeri verisi bulutta; denetçi 'en az yetki kanıtınız nedir?' diye soruyor.",
    "kuzgun": "Kuzgun Lojistik'te depo yazılımını kuran firmaya verilen geçici yetki hiç kaldırılmamış.",
    "ferahbank": "Ferah Bank'ın bulut ekibi, kıdemli yöneticilerden birinin hesabında MFA olmadığını fark etti.",
}
DOSYALAR = ["config.py", "deploy.sh", "notlar.txt"]


def _anahtar(rng) -> str:
    return "AKIALAB" + "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(13))


def _gizli(rng) -> str:
    return "LAB" + "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(30))


def uret(rng):
    sk = sirket_sec(rng)
    on = sk["on"]
    kova = f"{on}-{rng.choice(['rapor', 'uygulama', 'belge', 'yukleme'])}-verisi"
    adminler = rng.sample(ADMIN_ADLARI, 2)
    pol = {
        adminler[0]: [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        adminler[1]: [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}],
        "acil-durum-engeli": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
        "destek-ekibi": [{"Effect": "Allow", "Action": ["ec2:DescribeInstances", "iam:CreatePolicyVersion", "iam:PassRole"],
                          "Resource": "*"}],
        "uygulama-kova-okuma": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        "rapor-okuma": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{on}-raporlar/*"}],
    }
    isimler = [f"{a}.{b}" for a, b in zip(rng.sample(u.ISIMLER, 8), rng.sample(
        ["yilmaz", "kaya", "demir", "celik", "sahin", "arslan", "dogan", "kilic"], 8))]
    admin_idx = rng.sample(range(8), 3)
    mfasiz_admin = rng.sample(admin_idx, 2)          # 3 yöneticiden 2'si MFA'sız
    kullanicilar = []
    for i, ad in enumerate(isimler):
        if i in admin_idx:
            politikalar = [adminler[admin_idx.index(i) % 2]]
        elif i % 3 == 0:
            politikalar = ["rapor-okuma"]
        elif i % 3 == 1:
            politikalar = ["destek-ekibi"] if i == 4 else ["uygulama-kova-okuma"]
        else:
            politikalar = ["rapor-okuma"]
        mfa = False if i in mfasiz_admin else (rng.random() < 0.6 or i in admin_idx)
        kullanicilar.append({"ad": ad, "mfa": mfa, "politikalar": politikalar, "konsol": True})
    admin_kullanici = [k["ad"] for k in kullanicilar if any(p in adminler for p in k["politikalar"])]
    mfasiz = [k["ad"] for k in kullanicilar if k["ad"] in admin_kullanici and not k["mfa"]]
    dosya = rng.choice(DOSYALAR)
    return {
        "vaka": f"{sk['ad']} — IAM denetimi",
        "sirket": sk, "kova": kova, "pol": pol, "kullanicilar": kullanicilar, "adminler": adminler,
        "admin_kullanici": admin_kullanici, "mfasiz": mfasiz,
        "anahtar": _anahtar(rng), "gizli": _gizli(rng), "dosya": dosya,
        "metin": {"musteri": sk["ad"], "sahne": SAHNE[sk["kod"]], "kova": kova, "onek": on},
        "cevaplar": {"tam": adminler, "mfasiz": mfasiz, "yukselten": "destek-ekibi", "sizinti": dosya},
    }


def yaz(lab: Path, s: dict) -> None:
    k = lab / "bulut/iam"
    for ad, stm in s["pol"].items():
        u.yaz(k / f"politikalar/{ad}.json", json_yaz({"Version": "2012-10-17", "Statement": stm}))
    u.yaz(k / "kullanicilar.json", json_satirli({"hesap": "123456789012 (kurgusal)"}, {"kullanicilar": s["kullanicilar"]}))
    u.yaz(k / "gereksinim.txt",
          f"Muhasebe raporu servisi (`uygulama-kova-okuma` politikasını kullanır) yalnızca şunu yapmalı:\n"
          f"- `{s['kova']}` kovasındaki nesneleri OKUMAK (s3:GetObject)\n"
          f"- `{s['kova']}` kovasının içeriğini LİSTELEMEK (s3:ListBucket)\n"
          "Başka bir kovaya ya da başka bir eyleme ihtiyacı YOKTUR.\n"
          f"İpucu: kova kaynağı `arn:aws:s3:::{s['kova']}`, içindeki nesneler `arn:aws:s3:::{s['kova']}/*`.\n")
    d = k / "depo_kopyasi"
    u.yaz(d / "README.md", "# Rapor servisi\nKurulum için deploy.sh çalıştırın. Anahtarlar ortam değişkeninden okunmalıdır.\n")
    u.yaz(d / ".env.ornek", "AWS_ACCESS_KEY_ID=AKIA_BURAYA_ANAHTAR_YAZ\nAWS_SECRET_ACCESS_KEY=BURAYA_GIZLI_ANAHTAR_YAZ\n")
    icerik = {
        "config.py": f'# rapor servisi ayarları\nKOVA = "{s["kova"]}"\nAWS_ANAHTAR = "{s["anahtar"]}"\nAWS_GIZLI = "{s["gizli"]}"\n',
        "deploy.sh": f'#!/bin/bash\n# hızlı dağıtım (TODO: anahtarı ortam değişkenine taşı)\nexport AWS_ACCESS_KEY_ID={s["anahtar"]}\nexport AWS_SECRET_ACCESS_KEY={s["gizli"]}\n./baslat.sh\n',
        "notlar.txt": f'yedek anahtar (silmeyi unutma):\n{s["anahtar"]} / {s["gizli"]}\n',
    }
    temiz = {
        "config.py": f'# rapor servisi ayarları\nKOVA = "{s["kova"]}"\nAWS_ANAHTAR = None  # ortamdan okunur\n',
        "deploy.sh": "#!/bin/bash\n# anahtarlar ortamdan gelir\n./baslat.sh\n",
        "notlar.txt": "yapılacaklar: rapor biçimini güncelle\n",
    }
    for ad in DOSYALAR:
        u.yaz(d / ad, icerik[ad] if ad == s["dosya"] else temiz[ad])


def _politika(yol: Path):
    try:
        return json.loads(yol.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as e:
        return None, f"`{yol.name}` geçerli JSON değil ({e}). `python3 -m json.tool {yol.name}` ile doğrula."


def _daralt(b: Baglam) -> Sonuc:
    yol = b.lab / "bulut/iam/politikalar/uygulama-kova-okuma.json"
    d, hata = _politika(yol)
    if hata:
        return Sonuc(False, hata)
    stm = d.get("Statement", [])
    stm = stm if isinstance(stm, list) else [stm]
    izin = [x for x in stm if x.get("Effect") == "Allow"]
    eylemler = {e for x in izin for e in liste(x.get("Action", []))}
    kaynaklar = [r for x in izin for r in liste(x.get("Resource", []))]
    kova = b.senaryo["kova"]
    if any(e == "*" or e.endswith(":*") for e in eylemler):
        return Sonuc(False, "Hâlâ joker (`*`) içeren bir eylem var (`s3:*` gibi). Yalnızca gereken eylemleri tek tek yaz.", yakin=True)
    if "*" in kaynaklar or any(kova not in r for r in kaynaklar) or not kaynaklar:
        return Sonuc(False, f"Kaynak hâlâ çok geniş. Yalnızca `{kova}` kovasını gösteren ARN'ler olmalı.", yakin=True)
    kucuk = {e.lower() for e in eylemler}
    fazla = sorted(kucuk - {"s3:getobject", "s3:listbucket"})
    if fazla:
        return Sonuc(False, f"Gereksinim dosyasında olmayan eylem(ler) var: {', '.join(fazla)}. En az yetki: yalnızca gerekeni ver.", yakin=True)
    if not {"s3:getobject", "s3:listbucket"} <= kucuk:
        return Sonuc(False, "Servis okumak ve listelemek zorunda: `s3:GetObject` ve `s3:ListBucket` ikisi de olmalı, yoksa uygulama çalışmaz.", yakin=True)
    return Sonuc(True, "Politika daraldı: yalnızca tek kovada okuma ve listeleme; uygulama çalışmaya devam eder.")


def _mfa(b: Baglam) -> Sonuc:
    s = b.senaryo
    yol = b.lab / "bulut/iam/kullanicilar.json"
    d, hata = _politika(yol)
    if hata:
        return Sonuc(False, hata)
    kay = {k.get("ad"): k for k in d.get("kullanicilar", [])}
    if set(kay) != {k["ad"] for k in s["kullanicilar"]}:
        return Sonuc(False, "Kullanıcı satırı silinmiş ya da eklenmiş. Hesapları silme, sadece `mfa` değerini düzelt.")
    hala = [a for a in s["mfasiz"] if kay[a].get("mfa") is not True]
    if hala:
        return Sonuc(False, f"Şu yöneticilerde MFA hâlâ kapalı: {', '.join(hala)}.", yakin=True)
    return Sonuc(True, "Bütün yönetici hesaplarında MFA açık.")


def coz(lab: Path, s: dict) -> dict:
    j = "import json,glob,os" + chr(10)
    tam = py(j + "for f in sorted(glob.glob('bulut/iam/politikalar/*.json')):\n d=json.load(open(f))\n"
             " for x in d['Statement']:\n  a=x['Action'] if isinstance(x['Action'],list) else [x['Action']]\n"
             "  r=x['Resource'] if isinstance(x['Resource'],list) else [x['Resource']]\n"
             "  if x['Effect']=='Allow' and '*' in a and '*' in r: print(os.path.basename(f)[:-5])\n", lab).split()
    mfasiz = py(j + f"T=set({tam!r});d=json.load(open('bulut/iam/kullanicilar.json'))\n"
                "print(' '.join(k['ad'] for k in d['kullanicilar'] if set(k['politikalar'])&T and not k['mfa']))", lab)
    yuk = sh("grep -l 'iam:CreatePolicyVersion' bulut/iam/politikalar/*.json | xargs -n1 basename | sed 's/.json$//'", lab)
    sizinti = sh("grep -rlE 'AKIA[A-Z0-9]{16}' bulut/iam/depo_kopyasi", lab)
    # düzeltmeler
    kova = s["kova"]
    py(j + f"f='bulut/iam/politikalar/uygulama-kova-okuma.json';d=json.load(open(f));"
       f"d['Statement']=[{{'Effect':'Allow','Action':['s3:GetObject','s3:ListBucket'],'Resource':['arn:aws:s3:::{kova}','arn:aws:s3:::{kova}/*']}}];"
       "json.dump(d,open(f,'w'),indent=2)", lab)
    for a in s["mfasiz"]:
        sh(f"sed -i '/\"ad\": \"{a}\"/ s/\"mfa\": false/\"mfa\": true/' bulut/iam/kullanicilar.json", lab)
    return sec_doldur({1: " ".join(tam), 2: mfasiz, 3: yuk, 4: sizinti, 5: "", 6: ""}, GOREVLER, lab, s)


def _tam_hata(g, beklenen, b):
    if "acil-durum-engeli" in g.split():
        return "`acil-durum-engeli` bir **Deny** (reddet) politikası: `*` yazsa da yetki vermez, tersine her şeyi engeller. Yetki veren (`Allow`) olanlara bak."
    return None


def _mfa_hata(g, beklenen, b):
    verilen = set(g.split())
    yoneticisiz = {k["ad"].lower() for k in b.senaryo["kullanicilar"] if k["ad"] not in b.senaryo["admin_kullanici"] and not k["mfa"]}
    if verilen & yoneticisiz:
        return "MFA'sız ama **yönetici olmayan** bir hesabı da yazmışsın. Bu görev yalnızca tam yetkili (yönetici) hesapları soruyor; önceliğin onlar."
    return None


ADIMLAR = [
    Adim("Bulutta her şey bir kimliktir", """
Bulutta fiziksel sınır yoktur; bir kaynağa kimin ne yapabileceğini belirleyen tek şey **IAM**
(kimlik ve erişim yönetimi) politikalarıdır. Bu yüzden IAM, bulut güvenliğinin kalbidir. Saldırgan
"sunucuya girmez", bir **kimliği** ele geçirir (anahtar, token, rol) ve o kimliğin yetkisi kadar her
şeyi yapar.

**<<musteri>>**. <<sahne>> Politikalar JSON dosyaları. Önce bir tanesine bak:
""", komut="python3 -m json.tool bulut/iam/politikalar/rapor-okuma.json", sonra="""
Bir politikanın dört parçası: `Effect` (Allow ya da Deny), `Action` (yapılabilecek eylem),
`Resource` (hangi kaynak üzerinde) ve `Version`. `rapor-okuma` örneği **iyi** bir politikadır:
tek eylem, tek kaynak.
"""),
    Adim("Joker: * yetkisi", """
`*` bir **joker**dir (her şey demek). `"Action": "*"` her eylemi, `"Resource": "*"` her kaynağı
kapsar. İkisi birlikte **tam yetki** (admin) demektir. Kolaylık için yazılır ama bir kimlik
ele geçirilirse saldırgan her şeyi yapabilir. Tüm politikalarda `*` arayalım:
""", komut="grep -n '\"\\*\"' bulut/iam/politikalar/*.json", sonra="""
Dikkat: bir `*` her zaman tehlikeli değildir. `Effect: Deny` olan bir politikada joker, her şeyi
**yasaklar**. Etkiyi (`Effect`) ve iki jokeri birlikte oku.
"""),
    Adim("Yetki yükselten izinler", """
Bulutta yetki yükseltme genellikle bir IAM boşluğundan geçer: düşük yetkili bir kimliğin, **kendi
yetkisini artırabilecek** bir izne sahip olması. Örneğin yeni bir politika sürümü oluşturma
(`iam:CreatePolicyVersion`), bir kullanıcıya politika bağlama (`iam:AttachUserPolicy`) ya da bir
role bürünme/rol aktarma (`iam:PassRole`, `sts:AssumeRole`). Bu eylemlerin geniş kaynakta verilmesi,
tam yetkiye giden dolambaçlı bir yoldur (AD'deki BloodHound mantığının bulut karşılığı).
""", komut="grep -ln 'iam:' bulut/iam/politikalar/*.json", sonra="""
`iam:` ile başlayan eylemler **kimliğin kendisini** yönetir. Bir uygulamanın veya destek ekibinin
buna neredeyse hiç ihtiyacı olmaz.
"""),
    Adim("MFA'sız yöneticiler", """
**MFA** (çok faktörlü doğrulama), çalınan parolanın tek başına yetmemesini sağlar. Yönetici hesaplarda
MFA olmaması, parolası sızan bir kişinin tam yetki kazanması demektir. Kullanıcı kayıtlarında her
hesabın politikaları ve MFA durumu var:
""", komut="cat bulut/iam/kullanicilar.json", sonra="""
Hangi kullanıcıların tam yetkili politika taşıdığını, politika adlarını (önceki adımdan) kullanarak
bul. MFA'sız bir yönetici, MFA'sız sıradan bir kullanıcıdan çok daha acildir.
"""),
    Adim("Sızmış anahtarlar", """
Erişim anahtarları (access key) çoğu zaman koda ya da yapılandırmaya gömülür ve yanlışlıkla bir kod
deposuna yüklenir. Saldırganlar kod depolarını sürekli bu anahtarlar için tarar; sızan bir anahtar
dakikalar içinde denenebilir. Bu lab'daki kod deposu kopyasında anahtar kalıbını (`AKIA` ile başlayan
20 karakter) arayalım. (Anahtarlar kurgusaldır.)
""", komut="grep -rnE 'AKIA[A-Z0-9]{16}' bulut/iam/depo_kopyasi", sonra="""
Bir anahtar sızdıysa sıra: **önce anahtarı devre dışı bırak ve döndür (rotasyon)**, sonra kullanım
kayıtlarına bakıp kötüye kullanılıp kullanılmadığını incele, en son depodan temizle (geçmişte
kalacağı için tek başına yetmez). Kalıcı çözüm: anahtarı koda gömme; sır yönetimi servisi kullan.
"""),
    Adim("Politikayı daraltmak", """
En az yetki ilkesi: **gerekenin tamamını, ve yalnızca gerekeni** ver. Bir politikayı daraltırken
üç şeye bak: eylemleri tek tek yaz (joker kullanma), kaynağı belirle (ARN) ve uygulamanın çalışmaya
devam ettiğini doğrula. `gereksinim.txt` servisin gerçekte ne yaptığını söylüyor:
""", komut="cat bulut/iam/gereksinim.txt"),
]

GOREVLER = [
    Gorev("Hangi politikalar **tam yetki** (admin) verir? (`Effect: Allow` ve hem `Action` hem `Resource` `*`.) "
          "Dosya adlarını `.json` olmadan yaz.",
          Kume("tam", sik_hatalar=_tam_hata, bicim="politika adları, virgülle ayrılmış"),
          ("`*` geçen her politika admin değildir: `Effect`'e de bak.",
           "Önce `grep -n '\"\\*\"' bulut/iam/politikalar/*.json` ile `*` geçenleri bul, sonra Effect'i oku.",
           "Allow + Action `*` + Resource `*` olanlar. `Deny` olan bir tanesi var; onu alma."),
          puan=40, baslik="Tam yetkili politikalar"),
    Gorev("Tam yetkili bir politikası olup **MFA'sı kapalı** olan kullanıcıların adlarını yaz.",
          Kume("mfasiz", sik_hatalar=_mfa_hata, bicim="kullanıcı adları, virgülle ayrılmış"),
          ("İki koşul: yönetici ve MFA kapalı.",
           "`kullanicilar.json`'da önceki görevin politika adlarını taşıyan kullanıcılardan `\"mfa\": false` olanlar.",
           "`grep '\"mfa\": false' bulut/iam/kullanicilar.json` ile MFA'sızları listele, sonra politikasına bak."),
          puan=40, baslik="MFA'sız yönetici"),
    Gorev("Bir kimliğin **kendi yetkisini artırmasına** olanak veren (`iam:CreatePolicyVersion` içeren) "
          "politikanın adı nedir? (`.json` olmadan)",
          Metin("yukselten", bicim="politika adı"),
          ("`iam:` ile başlayan eylemleri ara.",
           "`grep -l 'iam:CreatePolicyVersion' bulut/iam/politikalar/*.json`",
           "Dosya adındaki `.json` uzantısını atarak yaz."),
          puan=30, baslik="Yetki yükselten politika"),
    Gorev("Kod deposu kopyasında **gerçek erişim anahtarı** bulunan dosyanın adı nedir? "
          "(`.env.ornek` yer tutucudur, gerçek anahtar değildir.)",
          Metin("sizinti", sadece_ad=True, bicim="dosya adı"),
          ("Anahtarların kalıbı sabit: `AKIA` ile başlayıp 16 harf/rakam.",
           "`grep -rnE 'AKIA[A-Z0-9]{16}' bulut/iam/depo_kopyasi` yer tutucuyu eleyecek şekilde kalıbı kullanır.",
           "Çıktıdaki dosya adını (yolun son parçasını) yaz."),
          puan=30, baslik="Sızmış anahtar"),
    Gorev("`uygulama-kova-okuma.json` politikasını **daralt**: yalnızca `<<kova>>` kovasında `s3:GetObject` "
          "ve `s3:ListBucket`. Bitince `cevap 5`.",
          Durum(_daralt, "Action: [s3:GetObject, s3:ListBucket]; Resource: kovanın ARN'leri"),
          ("Joker kalmasın: ne eylemde ne kaynakta.",
           "`gereksinim.txt` ARN biçimini veriyor: kova için `arn:aws:s3:::<<kova>>`, nesneler için `.../*`.",
           "`nano bulut/iam/politikalar/uygulama-kova-okuma.json` ile `Action` ve `Resource` alanlarını düzenle; sonra `python3 -m json.tool` ile doğrula."),
          puan=50, baslik="Politikayı daralt"),
    Gorev("MFA'sız yöneticilerin kullanıcı kayıtlarında `mfa` değerini `true` yap (gerçek hayatta bu, MFA'yı "
          "etkinleştirmenin dosyadaki yansımasıdır). Bitince `cevap 6`.",
          Durum(_mfa, "yöneticiler için \"mfa\": true"),
          ("Kullanıcı kayıtları tek satırlık; ilgili satırı bul.",
           "Değiştireceğin yalnızca önceki görevde bulduğun hesapların `mfa` değeri.",
           "`sed -i '/\"ad\": \"HESAP\"/ s/\"mfa\": false/\"mfa\": true/' bulut/iam/kullanicilar.json`"),
          puan=30, baslik="MFA'yı aç"),
    Gorev("Sızdığı anlaşılan bir erişim anahtarı için **ilk** yapılacak iş hangisidir?",
          Secmeli([
              ("Anahtarı hemen devre dışı bırakıp yenisini oluşturmak (rotasyon), sonra kayıtları incelemek",
               "Doğru. Sızan anahtar geçerli olduğu sürece kullanılabilir; önce kapıyı kapat."),
              ("Kod deposundaki dosyayı silip anahtarın artık güvende olduğunu varsaymak",
               "Yanlış. Depo geçmişinde kalır ve anahtar hâlâ geçerlidir; silmek yetmez."),
              ("Önce saldırgan kim diye kayıtlara bakmak, anahtara dokunmadan günlerce beklemek",
               "Yanlış. İnceleme önemli ama anahtar açıkken beklemek zararı büyütür."),
              ("Kullanıcının parolasını değiştirmek; anahtar parolaya bağlı olduğu için kendiliğinden geçersiz olur",
               "Yanlış. Erişim anahtarı paroladan bağımsızdır; ayrıca devre dışı bırakılmalıdır."),
          ], dogru=0),
          ("Sızan anahtar geçerli kaldıkça ne olur?",
           "Önce zararı durdur, sonra incele.",
           "Anahtarı devre dışı bırak ve döndür."),
          puan=20, baslik="İlk müdahale"),
    Gorev("'Bulutta her şey bir kimliktir' ifadesi neden bu kadar önemlidir?",
          Secmeli([
              ("Fiziksel sınır yoktur; erişimi yalnızca IAM politikaları belirler",
               "Doğru. Saldırgan sunucuya girmek yerine geçerli bir kimliği ele geçirir ve onun kadar yetkili olur."),
              ("Çünkü bulut sağlayıcıları yalnızca kimlik bilgilerini saklar ve kaynakları hiç tutmaz",
               "Yanlış. Kaynaklar sağlayıcıdadır; konu erişimi kimin belirlediğidir."),
              ("Çünkü bulutta kimlikler sadece faturalama için kullanılır ve güvenlikle ilgisi yoktur",
               "Yanlış. Kimlikler erişimin tek denetim noktasıdır."),
              ("Çünkü bulutta bir kimlik ele geçirilirse sağlayıcı tüm zararı otomatik olarak karşılar",
               "Yanlış. Paylaşılan sorumlulukta kimlik ve yapılandırma müşterinindir."),
          ], dogru=0),
          ("Bulutta bir kaynağa erişimi ne belirler?",
           "Kimlik ele geçirilirse ne olur?",
           "Erişimi yalnızca kimlik ve politikalar belirler."),
          puan=20, baslik="Her şey kimlik"),
]


def _kapanis():
    return """
Bulutta saldırgan çoğu zaman bir sunucuya "girmez"; geçerli bir kimliği ele geçirir ve meşru bir
kullanıcı gibi görünür. Bu yüzden iyi bir bulut savunması kimlik merkezlidir: jokersiz politikalar,
yetki yükselten izinlerin (`iam:*`) sıkı kontrolü, yöneticilerde zorunlu MFA, kodda anahtar yok, anahtar
rotasyonu ve "bu kimlik normalde böyle davranır mıydı?" diye soran anomali tespiti. Her düzeltmeden
sonra uygulamanın çalışmaya devam ettiğini doğrula.
"""


SEVIYE = Seviye(
    kimlik="c12b02",
    cilt=12,
    bolum=2,
    baslik="Kimlik ve Erişim (IAM)",
    brifing="""
Selin bulut denetim dosyasını masana bırakıyor: "**<<musteri>>**. <<sahne>> Elimizde IAM politika
dosyaları, kullanıcı listesi ve servisin kod deposunun bir kopyası var. Üç şeyi bul: jokerli
politikalar, MFA'sız yöneticiler ve sızmış anahtar. Sonra politikayı sen daralt."

Mert ekliyor: "Politikayı daraltırken uygulamayı bozarsan sabah ilk telefonu ben açarım."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis=_kapanis(),
    gercek_hayat="""
- **Sızmış anahtarlar:** Kod depolarına yanlışlıkla yüklenen bulut anahtarlarının kısa sürede
  başkalarınca denendiği, güvenlik raporlarında ve sağlayıcıların uyarılarında sık anılan bir
  durumdur. Pek çok sızma testi raporunda "koda gömülü kimlik bilgisi" bulgusu çok yaygındır.
- **Capital One 2019:** Kamuya açıklanan bilgilere göre saldırıda kullanılan rol gereğinden geniş
  yetkiliydi. Rol daha dar olsaydı, aynı yol çok daha az veriye açılırdı: en az yetki burada
  doğrudan zararı sınırlayan bir kontrol olurdu.
- **Tespit ve önleme:** Sağlayıcıların günlük hizmetleri (kim hangi API'yi çağırdı) alışılmadık
  kimlik davranışını yakalamak için kullanılır; ayrıca kod depoları için sır tarayıcıları ve
  yönetici hesaplar için zorunlu MFA, jokerli politikalar için otomatik denetim önerilir.
""",
    sure_hedef_dk=35,
)
