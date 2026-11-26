"""Olay Masası — Sızdırılmış Sır Taraması.

Her vakada başka bir müşteri ve başka bir sızıntı karışımı: bir kaynak kodu / ayar dökümünde
(`depo/`) AWS erişim anahtarı, düz parola, GitHub belirteci ve bazen bir özel anahtar gerçekten
sızmıştır; hangi dosyada hangi sır olduğu ve değerleri tohumdan gelir. Ayrıca korkutucu görünen
ama sır olmayan YEM satırlar vardır (kasa referansı, yer tutucu, ortam değişkeni okuma).
Oyuncu yalnızca dosyaları DENETLER; saldırı yok, ağ yok.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from hy.motor.kontrol import Baglam, Metin, Sayi, Secmeli, Sonuc, norm
from hy.motor.seviye import Gorev, Seviye
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri_sec

BUYUK = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALNUM = BUYUK + BUYUK.lower()
KARISIK = ALNUM + "+/"
DOSYALAR = ["config.py", ".env", "ayarlar.yml", "notlar.txt", "app.js", "deploy.sh"]
ANAHTAR_DOSYALARI = ["config.py", "notlar.txt", "deploy.sh"]
# Önem sırası: özel anahtar > aws > parola > token
TURLER = ["anahtar", "aws", "parola", "token"]
TUR_AD = {"anahtar": "Özel anahtar (private key)", "aws": "AWS erişim anahtarı",
          "parola": "Düz metin parola", "token": "GitHub erişim belirteci (token)"}


def _rastgele(rng, alfabe, n):
    return "".join(rng.choice(alfabe) for _ in range(n))


def _deger(rng, tur):
    if tur == "aws":
        return {"id": "AKIA" + _rastgele(rng, BUYUK, 16), "gizli": _rastgele(rng, KARISIK, 40)}
    if tur == "parola":
        return {"v": u.parola(rng)}
    if tur == "token":
        return {"v": "ghp_" + _rastgele(rng, ALNUM, 36)}
    return {"v": [_rastgele(rng, KARISIK, 64) for _ in range(rng.randint(4, 6))]}


def _anahtar_blogu(d, bicim):
    ust = bicim
    govde = "\n".join(d["v"])
    return f"-----BEGIN {ust} PRIVATE KEY-----\n{govde}\n-----END {ust} PRIVATE KEY-----\n"


def _gercek(dosya, ad, deger):
    k = ad.lower()
    if dosya == "config.py":
        return f'{ad} = "{deger}"'
    if dosya == ".env":
        return f"{ad}='{deger}'"
    if dosya == "ayarlar.yml":
        return f'{k}: "{deger}"'
    if dosya == "app.js":
        return f"const {k} = '{deger}';"
    if dosya == "deploy.sh":
        return f"export {ad}='{deger}'"
    return f"- {ad}='{deger}'  # geçici, sonra silinecek"


def _yem(rng, dosya, ad, kod):
    k = ad.lower()
    if dosya == "config.py":
        return rng.choice([f'{ad} = os.environ["{ad}"]', f'{ad} = os.getenv("{ad}")',
                           f'{ad} = "${{VAULT:{kod}/{k}}}"'])
    if dosya == ".env":
        return rng.choice([f"{ad}=${{VAULT:{kod}/{k}}}", f"{ad}=<buraya-koy>"])
    if dosya == "ayarlar.yml":
        return rng.choice([f"{k}: ${{VAULT:{kod}/{k}}}", f"{k}: <buraya-koy>"])
    if dosya == "app.js":
        return f"const {k} = process.env.{ad};"
    if dosya == "deploy.sh":
        return rng.choice([f'export {ad}="${{VAULT:{kod}/{k}}}"', f"export {ad}=<buraya-koy>"])
    return f"- {ad}: kasada ({kod}/{k}), buraya yazılmaz"


ADLAR = {"aws": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"), "parola": ("DB_PASSWORD",),
         "token": ("GITHUB_TOKEN",)}


def _token_yem(rng, dosya, kod):
    return _yem(rng, dosya, "GITHUB_TOKEN", kod).replace("<buraya-koy>", "ghp_<buraya-koy>")


def uret(rng):
    m = musteri_sec(rng)
    kod = m["kod"]
    anahtar_var = rng.random() < 0.6
    turler = ["aws", "parola", "token"] + (["anahtar"] if anahtar_var else [])

    yer = {}
    bos = list(DOSYALAR)
    if anahtar_var:
        yer["anahtar"] = rng.choice(ANAHTAR_DOSYALARI)
        bos.remove(yer["anahtar"])
    for t in ("aws", "parola", "token"):
        yer[t] = rng.choice(bos)
        bos.remove(yer[t])
    degerler = {t: _deger(rng, t) for t in turler}
    bicim = rng.choice(["RSA", "EC", "OPENSSH"])

    icerik = {}
    for d in DOSYALAR:
        satirlar = []
        if d == "config.py":
            satirlar += ["import os", "", f'APP_ADI = "{kod}-api"', 'DEBUG = False']
        elif d == ".env":
            satirlar += ["APP_ENV=production", f"DB_HOST={u.ic_ip(rng)}"]
        elif d == "ayarlar.yml":
            satirlar += [f"uygulama: {kod}-servis", "ortam: production"]
        elif d == "notlar.txt":
            satirlar += [f"{m['ad']} dağıtım notları", "- yük dengeleyici cuma gecesi yenilenecek"]
        elif d == "app.js":
            satirlar += ["const express = require('express');", f"const port = {rng.choice([3000, 8080, 8443])};"]
        else:
            satirlar += ["#!/bin/bash", "set -e"]
        # her tür için: bu dosyada gerçekse gerçek, değilse bazen yem
        for t in ("aws", "parola", "token"):
            adlar = ADLAR[t]
            if t in yer and yer[t] == d:
                if t == "aws":
                    satirlar.append(_gercek(d, adlar[0], degerler[t]["id"]))
                    satirlar.append(_gercek(d, adlar[1], degerler[t]["gizli"]))
                else:
                    satirlar.append(_gercek(d, adlar[0], degerler[t]["v"]))
            elif rng.random() < 0.55:
                if t == "token":
                    satirlar.append(_token_yem(rng, d, kod))
                else:
                    for ad in adlar:
                        satirlar.append(_yem(rng, d, ad, kod))
        if yer.get("anahtar") == d:
            blok = _anahtar_blogu(degerler["anahtar"], bicim).rstrip("\n")
            if d == "config.py":
                satirlar.append(f'DEPLOY_ANAHTARI = """\n{blok}\n"""')
            else:
                satirlar.append(blok)
        elif d == "notlar.txt" and rng.random() < 0.6:
            satirlar.append("- sunucu özel anahtarı sır kasasında, depoda tutulmaz")
        icerik[f"depo/{d}"] = "\n".join(satirlar) + "\n"

    kritik = next(t for t in TURLER if t in turler)
    return {
        "vaka": f"{m['ad']} ({m['sektor']}) — sızdırılmış sır taraması",
        "metin": {"musteri": m["ad"], "sektor": m["sektor"], "kisi": m["kisi"], "hikaye": m["hikaye"]},
        "cevaplar": {
            "aws_dosya": [yer["aws"], f"depo/{yer['aws']}"],
            "parola_dosya": [yer["parola"], f"depo/{yer['parola']}"],
            "toplam": len(turler),
            "kritik": kritik,
            "aws_on_ek": degerler["aws"]["id"][:8],
        },
        "_dosyalar": icerik,
    }


def yaz(lab: Path, s: dict) -> None:
    for yol, icerik in s["_dosyalar"].items():
        u.yaz(lab / yol, icerik)


class KritikSecmeli(Secmeli):
    """Doğru şık vakaya göre değişir: bulunan sır türleri içinde en kritik olan."""

    def _dogru(self, b: Baglam) -> int:
        return TURLER.index(b.senaryo["cevaplar"]["kritik"])

    def dogrula(self, girdi: str, b: Baglam) -> Sonuc:
        self.dogru = self._dogru(b)
        return super().dogrula(girdi, b)

    def cevabi_goster(self, b: Baglam) -> str:
        self.dogru = self._dogru(b)
        return super().cevabi_goster(b)

    def harf(self, b: Baglam) -> str:
        return "abcd"[self._sira(b).index(self._dogru(b))]


def _sh(komut: str, lab: Path) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True).stdout.strip()


def _toplam_hata(g, beklenen, b):
    if int(g) > beklenen:
        return ("Aynı dosyada iki satır sır olsa da dosya bir kez sayılır; `${VAULT:...}`, "
                "`<buraya-koy>` ve `os.environ[...]` da sır değildir.")
    return None


def coz(lab: Path, s: dict) -> dict:
    aws = _sh("grep -rlE 'AKIA[A-Z0-9]{16}' depo | head -1", lab)
    parola = _sh("grep -rliE \"password[\\\"']?[[:space:]]*[=:][[:space:]]*[\\\"'][^\\\"'$<]+[\\\"']\" depo | head -1", lab)
    toplam = _sh("( grep -rlE 'AKIA[A-Z0-9]{16}' depo; "
                 "grep -rliE \"password[\\\"']?[[:space:]]*[=:][[:space:]]*[\\\"'][^\\\"'$<]+[\\\"']\" depo; "
                 "grep -rlE 'ghp_[A-Za-z0-9]{36}' depo; "
                 "grep -rlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' depo ) | sort -u | wc -l", lab)
    anahtar = _sh("grep -rlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' depo | head -1", lab)
    kritik = "anahtar" if anahtar else "aws"
    ks = SEVIYE.gorevler[3].kontrol
    harf = "abcd"[ks._sira(Baglam({**s, "cevaplar": {**s["cevaplar"], "kritik": kritik}}, lab, 4))
                  .index(TURLER.index(kritik))]
    on_ek = _sh("grep -rhoE 'AKIA[A-Z0-9]{16}' depo | head -1 | cut -c1-8", lab)
    return {1: aws, 2: parola, 3: toplam, 4: harf, 5: on_ek, 6: SEVIYE.gorevler[5].kontrol.cevabi_goster(
        Baglam(s, lab, 6))[0]}


GOREVLER = [
    Gorev("`depo/` altındaki dosyalardan hangisinde **gerçek bir AWS erişim anahtarı** sızmış? "
          "(`${VAULT:...}`, `<buraya-koy>` ve `os.environ[...]` gerçek değer değildir) Dosya adını yaz.",
          Metin("aws_dosya", bicim="dosya adı", sadece_ad=True),
          ("AWS erişim anahtar kimlikleri belirli bir önekle başlar ve sabit uzunluktadır.",
           "`AKIA` ile başlar, ardından 16 büyük harf/rakam gelir. Gizli dosyalar (`.env`) için `-r` ile tüm dizine bak.",
           "`grep -rlE 'AKIA[A-Z0-9]{16}' depo`"),
          puan=20, baslik="Sızan AWS anahtarı"),
    Gorev("Hangi dosyada **düz metin (şifrelenmemiş) bir parola** gömülü? Dosya adını yaz.",
          Metin("parola_dosya", bicim="dosya adı", sadece_ad=True),
          ("Gerçek parola tırnak içinde, doğrudan yazılmış bir değerdir; ortam değişkeninden okunan ya da kasaya bağlı değer sır değildir.",
           "`password` kelimesini ara (büyük/küçük harf fark etmez) ve eşitlikten sonra gelen değere bak: tırnak içinde gerçek metin mi, yoksa `os.environ`/`${VAULT}`/`<...>` mı?",
           "`grep -rniE 'password' depo` ile adayları gör; sonra `grep -rliE \"password['\\\"]?\\s*[=:]\\s*['\\\"][^'\\\"$<]+['\\\"]\" depo`"),
          puan=20, baslik="Düz parola"),
    Gorev("Toplam kaç **dosyada gerçek bir sır** (AWS anahtarı, düz parola, `ghp_` belirteci ya da özel anahtar) var?",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Dört sır türünü ayrı ayrı ara, çıkan dosya adlarını birleştir.",
           "Her tür için `grep -rl` kullan: `AKIA...`, `password=...`, `ghp_...`, `-----BEGIN ... PRIVATE KEY-----`. Aynı dosya iki kez çıkabilir.",
           "Hepsinin çıktısını birleştirip `sort -u | wc -l` ile tekilleştir. Özel anahtar için: `grep -rlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' depo`"),
          puan=20, baslik="Etkilenen dosya sayısı"),
    Gorev("Bulduğun sızıntılar arasında **en kritik** sır türü hangisi? "
          "(Önem sırası: özel anahtar > AWS anahtarı > parola > token)",
          KritikSecmeli([(TUR_AD[t], "") for t in TURLER]),
          ("Özel anahtar bir sunucuya ya da kimliğe doğrudan erişim verir; en tehlikelisi odur. Depoda hiç özel anahtar yoksa sıradakine bak.",
           "Önce özel anahtar başlığını ara; yoksa bir sonraki türe geç. Sıra: özel anahtar > AWS > parola > token.",
           "`grep -rlE -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' depo` boş dönüyorsa en kritik tür AWS anahtarıdır; doluysa özel anahtardır."),
          puan=15, baslik="En kritik sır"),
    Gorev("Sızan AWS erişim anahtar kimliğinin **ilk 8 karakterini** yaz (`AKIA` ile başlayan kısım dahil).",
          Metin("aws_on_ek", bicim="8 karakter"),
          ("Anahtar kimliği 20 karakterdir; senden yalnızca başı isteniyor.",
           "Anahtarı yalnızca eşleşen kısmıyla yazdır: `grep -o`. Sonra ilk 8 karakteri kes.",
           "`grep -rhoE 'AKIA[A-Z0-9]{16}' depo | cut -c1-8`"),
          puan=15, baslik="Anahtar ön eki"),
    Gorev("AWS anahtarının depoda sızdığını doğruladın. Doğru müdahale hangisi?",
          Secmeli([
              ("Anahtarı hemen iptal et/döndür, sırrı git geçmişinden de temizle, sırları sır kasasına taşı",
               "Doğru. Sızan sır ele geçirilmiş sayılır: önce geçersiz kıl, sonra geçmişten sil ve kalıcı çözüm olarak kasaya taşı."),
              ("Dosyadan satırı silip yeni bir commit at",
               "Yetmez: anahtar git geçmişinde ve kopyalarda durur, hâlâ geçerlidir."),
              ("Depoyu gizli (private) yap ve anahtara dokunma",
               "Hayır. Depo bir an bile açık kaldıysa anahtar kopyalanmış olabilir; iptal edilmedikçe tehlike sürer."),
              ("Anahtar kötüye kullanılana kadar bekle",
               "Hayır. Beklemek saldırgana süre verir; sızan sır varsayılan olarak ele geçirilmiş sayılır."),
          ]),
          ("Sızan bir sırrı kimlerin görmüş olabileceğini bilemezsin.",
           "Sırrın geçerliliğini sonlandırmadan yapılan her temizlik yarım kalır.",
           "Sıra: iptal/döndür, geçmişten temizle, sır kasasına taşı."),
          puan=10, baslik="Doğru müdahale"),
]

SEVIYE = Seviye(
    kimlik="olay_sizinti",
    cilt=4,
    bolum=112,
    baslik="Sızdırılmış Sır Taraması",
    brifing="""
Deniz Kara ekranı sana çeviriyor: "**<<musteri>>** (<<sektor>>) bir kaynak kodu denetimi
istedi. <<hikaye>> <<kisi>> uygulamanın kod ve ayar dosyalarının dökümünü gönderdi."

"Dosyalar sende: `depo/` altında `config.py`, `.env`, `ayarlar.yml`, `notlar.txt`, `app.js`
ve `deploy.sh`. Saldırı yok, sadece kod denetimi: depoya sızmış gerçek sırları (gizli anahtar,
parola, belirteç) bulacaksın. Dikkat, `${VAULT:...}`, `<buraya-koy>` ve `os.environ[...]`
sır değil; kasaya bağlı ya da boş yer tutucular. Hangisi gerçekten sızmış?"
""",
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kod deposundaki sır, saldırganın en ucuz giriş kapısıdır. Dört alışkanlık çoğunu önler: sırları
kodda değil **sır kasasında** tut, **commit öncesi tarama** (git-secrets, trufflehog gibi) ile
sızmadan yakala, bir sır sızdıysa **anında döndür/iptal et** ve unutma: dosyadan silmek yetmez,
**git geçmişini de temizle**. Bu taramayı her commit'e bağlamak, sızıntıyı dışarı çıkmadan durdurur.
""",
    gercek_hayat="""
- **GitHub'da sızan anahtarlar:** Araştırmacılar herkese açık depolarda her gün binlerce
  erişim anahtarı ve belirteç bulur; otomatik botlar bir anahtarı yayınlandıktan dakikalar
  içinde yakalayıp kötüye kullanır.
- **Uber, 2016:** Mühendisler özel bir GitHub deposuna AWS erişim anahtarı koymuştu. Saldırgan
  bu kimlik bilgilerini bulup bulut depolamasındaki milyonlarca kullanıcı ve sürücü kaydına
  ulaştı. Anahtar kodda değil kasada olsaydı, ya da sızar sızmaz döndürülseydi, olay bu boyuta varmazdı.
""",
    sure_hedef_dk=15,
    tamamlama_bonusu=30,
    olay_masasi=True,
    on_kosul=("c04b05",),
)
