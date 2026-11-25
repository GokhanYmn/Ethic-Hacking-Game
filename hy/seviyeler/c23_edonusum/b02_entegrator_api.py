"""Cilt 23 · Bölüm 2 — Entegratör ve API Güvenliği.

Beceri: kurgusal UBL-TR benzeri e-fatura XML'lerinde üç tür tutarsızlığı otomatik yakalamak (satır toplamı
ile toplam tutarın uyuşmaması, siparişteki alıcıdan farklı alıcı, imza/hash uyuşmazlığı) ve kurgusal bir
entegratör API günlüğünde anahtar sızıntısını ve yetkisiz çağrıyı bulmak. Gerçek e-imza (XAdES) ya da mali
mühür burada yoktur: laboratuvarda imza, belgenin bazı alanlarından sha256 ile hesaplanan basit bir
"özet"tir. Amaç bütünlük mantığını kavramaktır.

Vakalar: Kuzgun Lojistik (navlun), Pazarix (toptan alım), Medora Sağlık (tıbbi sarf). Tüm taraflar,
VKN benzeri numaralar ve anahtarlar kurgusaldır ve geçersiz biçimdedir (KVKN-000123 gibi).
"""
from __future__ import annotations

import csv
import hashlib
import os
import random
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path

from hy.motor.kontrol import Baglam, IP, Metin, Sayi, Secmeli, Sonuc
from hy.motor.seviye import Adim, Gorev, Seviye
from hy.ortak import betik as bt
from hy.ortak import uretec as u
from hy.ortak.vakalar import musteri
from hy.seviyeler.c21_dolandiricilik.ortak import sec_doldur, sh

VAKALAR = [
    {"kod": "kuzgun", "tedarikci": "Kuzgun Lojistik", "kisi": "Serdar Bey",
     "alicilar": ["Yıldız Tekstil", "Bora Gıda", "Çınar Mobilya", "Doruk Otomotiv", "Elma Ambalaj", "Fidan Kimya"],
     "kalemler": ["İstanbul-Ankara navlun", "İzmir-Bursa navlun", "Depolama hizmeti (aylık)", "Soğuk zincir taşıma",
                  "Konteyner elleçleme"],
     "olay": "Kuzgun Lojistik'in entegratör üzerinden gönderdiği navlun faturalarından bazılarının müşteri kopyasıyla "
             "uyuşmadığı bildirildi; aynı hafta entegratör API'sinde olağandışı çağrılar da görüldü."},
    {"kod": "pazarix", "tedarikci": "Pazarix Toptan", "kisi": "Tuncay Bey",
     "alicilar": ["Gül Market", "Hilal Kafe", "Işık Kırtasiye", "Jale Butik", "Kaya Züccaciye", "Lale Çiçekçilik"],
     "kalemler": ["Toptan kahve çekirdeği", "Kâğıt bardak (koli)", "Ofis sarf malzemesi", "Ambalaj paketi", "Depo hizmeti"],
     "olay": "Pazarix'in toptan satış faturalarından bazılarında alıcı ya da tutar bilgisi şüpheli bulundu; entegratör "
             "API günlüğünde de bir anahtarın beklenmedik yerde göründüğü bildirildi."},
    {"kod": "medora", "tedarikci": "Medora Sağlık", "kisi": "Dr. Aslı Hanım",
     "alicilar": ["Ada Medikal", "Bahar Laboratuvar", "Cemre Eczanesi", "Derya Diyaliz", "Ekin Görüntüleme", "Fırat Ortopedi"],
     "kalemler": ["Tıbbi sarf malzeme seti", "Laboratuvar tetkik hizmeti", "Cihaz bakım hizmeti", "Steril eldiven (koli)",
                  "Hasta nakil hizmeti"],
     "olay": "Medora'nın tedarikçilerine kesilen e-faturalardan birkaçının alıcı ve tutar bilgisi ile sipariş kayıtları "
             "uyuşmuyor; entegratör API'sinde yetkisiz erişim şüphesi var."},
]

NS = ('xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" '
      'xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" '
      'xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2" '
      'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"')


def ozet(no: str, alici_vkn: str, alici_ad: str, odenecek: str) -> str:
    return hashlib.sha256(f"{no}|{alici_vkn}|{alici_ad}|{odenecek}".encode("utf-8")).hexdigest()


def _tl(kurus: int) -> str:
    return f"{kurus // 100}.{kurus % 100:02d}"


def _xml(f: dict) -> str:
    satir = "\n".join(
        f'  <cac:InvoiceLine>\n    <cbc:ID>{i}</cbc:ID>\n    <cbc:InvoicedQuantity unitCode="C62">{adet}</cbc:InvoicedQuantity>\n'
        f'    <cbc:LineExtensionAmount currencyID="TRY">{_tl(tutar)}</cbc:LineExtensionAmount>\n'
        f'    <cac:Item><cbc:Name>{ad}</cbc:Name></cac:Item>\n  </cac:InvoiceLine>'
        for i, (ad, adet, tutar) in enumerate(f["satirlar"], 1))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Invoice {NS}>
  <cbc:ProfileID>KURGUSAL-LAB</cbc:ProfileID>
  <cbc:ID>{f['no']}</cbc:ID>
  <cbc:IssueDate>{f['tarih']}</cbc:IssueDate>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="VKN">{f['ted_vkn']}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>{f['ted_ad']}</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:AccountingCustomerParty>
    <cac:Party>
      <cac:PartyIdentification><cbc:ID schemeID="VKN">{f['alici_vkn']}</cbc:ID></cac:PartyIdentification>
      <cac:PartyName><cbc:Name>{f['alici_ad']}</cbc:Name></cac:PartyName>
    </cac:Party>
  </cac:AccountingCustomerParty>
  <cac:TaxTotal><cbc:TaxAmount currencyID="TRY">{_tl(f['kdv'])}</cbc:TaxAmount></cac:TaxTotal>
  <cac:LegalMonetaryTotal>
    <cbc:LineExtensionAmount currencyID="TRY">{_tl(f['ara'])}</cbc:LineExtensionAmount>
    <cbc:AllowanceTotalAmount currencyID="TRY">{_tl(f['iskonto'])}</cbc:AllowanceTotalAmount>
    <cbc:PayableAmount currencyID="TRY">{_tl(f['odenecek'])}</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
{satir}
  <ds:Signature>
    <ds:SignedInfo><ds:DigestValue>{f['ozet']}</ds:DigestValue></ds:SignedInfo>
  </ds:Signature>
</Invoice>
"""


def _hesapla(f: dict) -> None:
    f["ara"] = sum(t for _, _, t in f["satirlar"])
    f["kdv"] = round((f["ara"] - f["iskonto"]) * 0.20)
    f["odenecek"] = f["ara"] - f["iskonto"] + f["kdv"]


def _imzala(f: dict) -> None:
    f["ozet"] = ozet(f["no"], f["alici_vkn"], f["alici_ad"], _tl(f["odenecek"]))


# ---------------------------------------------------------------- referans denetim (oyuncunun yazacağı mantık)

def _bul(k, yol):
    e = k.find(yol)
    return (e.text or "").strip() if e is not None else ""


def ref_kontrol(xml_metin: str, siparis: dict) -> set:
    k = ET.fromstring(xml_metin)
    no = _bul(k, "{*}ID")
    vkn = _bul(k, "{*}AccountingCustomerParty/{*}Party/{*}PartyIdentification/{*}ID")
    ad = _bul(k, "{*}AccountingCustomerParty/{*}Party/{*}PartyName/{*}Name")
    satirlar = sum(round(float(x.text) * 100) for x in k.findall("{*}InvoiceLine/{*}LineExtensionAmount"))
    ara = round(float(_bul(k, "{*}LegalMonetaryTotal/{*}LineExtensionAmount")) * 100)
    isk = round(float(_bul(k, "{*}LegalMonetaryTotal/{*}AllowanceTotalAmount")) * 100)
    odenecek_m = _bul(k, "{*}LegalMonetaryTotal/{*}PayableAmount")
    odenecek = round(float(odenecek_m) * 100)
    kdv = round(float(_bul(k, "{*}TaxTotal/{*}TaxAmount")) * 100)
    nedenler = set()
    if satirlar != ara or odenecek != ara - isk + kdv:
        nedenler.add("toplam")
    if siparis.get(no) != vkn:
        nedenler.add("alici")
    if ozet(no, vkn, ad, odenecek_m) != _bul(k, "{*}Signature/{*}SignedInfo/{*}DigestValue"):
        nedenler.add("imza")
    return nedenler


def klasor_uret(rng: random.Random, v: dict, n_toplam: int, n_alici: int, n_imza: int, n_toplam_dosya: int = 14) -> dict:
    """{dosyalar: {ad: xml}, siparis: {no: vkn}, beklenen: {ad: set}, no_of: {ad: no}, alici_no}"""
    gun = u.gun(rng)
    n = n_toplam_dosya
    nolar = list(dict.fromkeys(f"FTR2026{rng.randint(10**8, 10**9 - 1)}" for _ in range(n * 2)))[:n]
    vkn_of = {a: f"KVKN-{rng.randint(100, 999):06d}" for a in v["alicilar"]}
    ted_vkn = f"KVKN-{rng.randint(100, 999):06d}"
    faturalar = []
    for i, no in enumerate(nolar):
        alici = rng.choice(v["alicilar"])
        satirlar = [(rng.choice(v["kalemler"]), rng.randint(1, 12), rng.randint(40, 900) * 100 + rng.choice([0, 0, 50]))
                    for _ in range(rng.randint(2, 4))]
        f = {"no": no, "tarih": f"{gun - timedelta(days=rng.randint(0, 20)):%Y-%m-%d}", "ted_vkn": ted_vkn,
             "ted_ad": v["tedarikci"], "alici_vkn": vkn_of[alici], "alici_ad": alici, "satirlar": satirlar,
             "iskonto": rng.choice([0, 0, 0, 5000, 12000])}
        _hesapla(f)
        _imzala(f)
        faturalar.append(f)
    siparis = {f["no"]: f["alici_vkn"] for f in faturalar}
    idx = list(range(n))
    rng.shuffle(idx)
    atamalar = {}
    for _ in range(n_toplam):
        atamalar[idx.pop()] = rng.choice(["T1", "T1b"])
    for _ in range(n_alici):
        atamalar[idx.pop()] = "T2"
    for _ in range(n_imza):
        atamalar[idx.pop()] = rng.choice(["T3a", "T3b"])
    for i, t in atamalar.items():
        f = faturalar[i]
        if t == "T1":                                   # tutar imzadan ÖNCE değiştirilmiş: özet tutarlı, toplam tutmuyor
            f["odenecek"] += rng.randint(8, 60) * 1000
            _imzala(f)
        elif t == "T1b":                                # bir satır değiştirilmiş, başlık aynı kalmış
            ad, adet, tutar = f["satirlar"][0]
            f["satirlar"][0] = (ad, adet, tutar + rng.randint(5, 40) * 1000)
        elif t == "T2":                                 # alıcı imzadan ÖNCE değiştirilmiş: özet tutarlı, sipariş tutmuyor
            diger = rng.choice([a for a in v["alicilar"] if vkn_of[a] != f["alici_vkn"]])
            f["alici_vkn"], f["alici_ad"] = vkn_of[diger], diger
            _imzala(f)
        elif t == "T3a":                                # imzadan SONRA alıcı unvanı değiştirilmiş
            diger = rng.choice([a for a in v["alicilar"] if a != f["alici_ad"]])
            f["alici_ad"] = diger + " Ltd"
        else:                                           # imzadan SONRA tutarlar tutarlı biçimde şişirilmiş
            ad, adet, tutar = f["satirlar"][0]
            f["satirlar"][0] = (ad, adet, tutar + rng.randint(5, 40) * 10000)
            _hesapla(f)
    dosyalar, beklenen, no_of = {}, {}, {}
    adlar = [f"F-{i:03d}.xml" for i in range(1, n + 1)]
    for ad, f in zip(adlar, faturalar):
        dosyalar[ad] = _xml(f)
        no_of[ad] = f["no"]
        beklenen[ad] = ref_kontrol(dosyalar[ad], siparis)
    return {"dosyalar": dosyalar, "siparis": siparis, "beklenen": beklenen, "no_of": no_of, "atamalar": atamalar,
            "faturalar": faturalar}


def klasor_dogru_mu(k: dict, n_toplam, n_alici, n_imza) -> bool:
    say = {"toplam": 0, "alici": 0, "imza": 0}
    for ned in k["beklenen"].values():
        for x in ned:
            say[x] += 1
    return (say["toplam"], say["alici"], say["imza"]) == (n_toplam, n_alici, n_imza) and \
        all(len(x) <= 1 for x in k["beklenen"].values())


def klasor(rng, v, n_toplam, n_alici, n_imza, n=14):
    for _ in range(40):
        k = klasor_uret(rng, v, n_toplam, n_alici, n_imza, n)
        if klasor_dogru_mu(k, n_toplam, n_alici, n_imza):
            return k
    raise RuntimeError("tutarlı fatura klasörü üretilemedi")


# ---------------------------------------------------------------- API günlüğü

def api_logu(rng: random.Random, v: dict, k: dict) -> dict:
    gun = u.gun(rng)
    muk = [f"M-{rng.randint(1000, 9999)}" for _ in range(8)]
    muk = list(dict.fromkeys(muk))
    anahtar = {m: f"ak_live_{m.replace('-', '')}_{''.join(rng.choice('0123456789abcdef') for _ in range(6))}" for m in muk}
    satirlar = []

    def ekle(t, ip, key, sahip, yol, hedef, status):
        satirlar.append((t, f"{t:%Y-%m-%dT%H:%M:%S}+03:00 gw=ent01 ip={ip} key={key} sahip={sahip} {yol} hedef={hedef} status={status}"))

    ic = {m: f"10.40.{rng.randint(1, 9)}.{rng.randint(10, 250)}" for m in muk}
    for m in muk:
        for _ in range(rng.randint(8, 14)):
            t = gun + timedelta(seconds=rng.randint(7 * 3600, 20 * 3600))
            yol = rng.choice(["POST /v1/fatura/gonder", "GET /v1/fatura/durum", "GET /v1/fatura/liste", "POST /v1/irsaliye/gonder"])
            ekle(t, ic[m], anahtar[m], m, yol, m, 200)
    kurban = muk[0]
    hedef_muk = muk[1:]
    sald_ip = u.dis_ip(rng)
    sizan = anahtar[kurban]
    # anahtar bir hata ayıklama isteğinde URL'ye düşmüş
    t = gun + timedelta(hours=rng.randint(9, 16), minutes=rng.randint(0, 50))
    satirlar.append((t, f"{t:%Y-%m-%dT%H:%M:%S}+03:00 gw=ent01 ip={ic[kurban]} key=- sahip={kurban} "
                        f"GET /v1/fatura/liste?api_key={sizan}&debug=1 hedef={kurban} status=200"))
    # saldırgan: bu anahtarla başka mükelleflerin verisini çekiyor
    t = gun + timedelta(days=1, hours=rng.randint(1, 4), minutes=rng.randint(0, 50))
    n_yetkisiz = rng.randint(5, 9)
    for i in range(n_yetkisiz):
        t += timedelta(seconds=rng.randint(20, 150))
        ekle(t, sald_ip, sizan, kurban, "GET /v1/fatura/liste", rng.choice(hedef_muk), 200)
    n_red = rng.randint(2, 4)
    for _ in range(n_red):                         # engellenenler: yetkisiz ama başarısız
        t += timedelta(seconds=rng.randint(10, 60))
        ekle(t, sald_ip, sizan, kurban, "POST /v1/fatura/gonder", rng.choice(hedef_muk), 403)
    satirlar.sort(key=lambda x: x[0])
    return {"satirlar": [s for _, s in satirlar], "sizan": sizan, "son6": sizan[-6:], "n_yetkisiz": n_yetkisiz,
            "sald_ip": sald_ip, "n_red": n_red}


# ---------------------------------------------------------------- senaryo

def uret(rng):
    v = dict(rng.choice(VAKALAR))
    m = musteri(v["kod"])
    tohum = rng.randint(1, 10**9)
    n_t, n_i = rng.randint(2, 3), rng.randint(2, 3)
    k = klasor(random.Random(tohum), v, n_t, 1, n_i)
    log = api_logu(random.Random(tohum + 3), v, k)
    alici_ad = next(ad for ad, ned in k["beklenen"].items() if "alici" in ned)
    return {
        "vaka": f"{m['ad']} — e-fatura ve entegratör API incelemesi",
        "musteri": m, "v": v, "tohum": tohum, "n_t": n_t, "n_i": n_i, "n": len(k["dosyalar"]),
        "metin": {"musteri": m["ad"], "kisi": v["kisi"], "olay": v["olay"], "n_fatura": len(k["dosyalar"])},
        "cevaplar": {
            "toplam": n_t, "alici": k["no_of"][alici_ad], "imza": n_i,
            "son6": log["son6"], "yetkisiz": log["n_yetkisiz"], "ip": log["sald_ip"],
        },
        "_red": log["n_red"],
    }


def yaz(lab: Path, s: dict) -> None:
    v = s["v"]
    k = klasor(random.Random(s["tohum"]), v, s["n_t"], 1, s["n_i"])
    log = api_logu(random.Random(s["tohum"] + 3), v, k)
    for ad, metin in k["dosyalar"].items():
        u.yaz(lab / "faturalar" / ad, metin)
    u.yaz(lab / "siparisler.csv", "fatura_no,alici_vkn\n" + "\n".join(f"{no},{vkn}" for no, vkn in k["siparis"].items()) + "\n")
    u.yaz(lab / "api" / "entegrator_api.log", "\n".join(log["satirlar"]) + "\n")
    u.yaz(lab / "ornekler" / "xml_oku.py", XML_OKU_PY, mod=0o755)
    u.yaz(lab / "ornekler" / "ozet_hesapla.py", OZET_PY, mod=0o755)
    u.yaz(lab / "OKUBENI.txt",
          f"{s['musteri']['ad']} — e-fatura ve entegratör API incelemesi (kurgusal)\n\n"
          f"faturalar/F-001.xml ...   : {s['n']} e-fatura (kurgusal, UBL-TR benzeri)\n"
          "siparisler.csv           : sipariş sisteminde kayıtlı fatura no -> alıcı VKN\n"
          "api/entegrator_api.log   : entegratör ağ geçidinin API günlüğü\n\n"
          "Bu lab'daki imza (özet), gerçek e-imza değil, sadeleştirilmiş bir modeldir:\n"
          "    ozet = sha256( fatura_no | alici_vkn | alici_unvan | odenecek_tutar )   (| ile birleştirilmiş metin)\n"
          "    faturadaki <ds:DigestValue> değeri bu özetle aynı olmalıdır.\n\n"
          "Üç tutarsızlık türü:\n"
          "  toplam : satır tutarlarının toplamı başlıktaki LineExtensionAmount'a eşit değil\n"
          "           ya da PayableAmount != LineExtensionAmount - AllowanceTotalAmount + TaxAmount\n"
          "  alici  : faturadaki alıcı VKN'si, siparisler.csv'deki ile farklı\n"
          "  imza   : hesaplanan özet, faturadaki DigestValue ile farklı\n\n"
          "Kendi denetleyicini lab'ın köküne yaz: fatura_denetle.py\n"
          "Kullanım: python3 fatura_denetle.py <fatura_klasoru> <siparisler.csv>\n"
          "Çıktı   : sorunlu her dosya için bir satır: `F-005.xml toplam` (birden çok neden virgülle)\n")


XML_OKU_PY = r'''#!/usr/bin/env python3
# xml_oku.py — bir e-faturadan alanları okur (ElementTree). {*} her ad alanını (namespace) kabul eder.
import sys
import xml.etree.ElementTree as ET

kok = ET.parse(sys.argv[1]).getroot()
print("fatura no :", kok.find("{*}ID").text)
print("alıcı VKN :", kok.find("{*}AccountingCustomerParty/{*}Party/{*}PartyIdentification/{*}ID").text)
print("ödenecek  :", kok.find("{*}LegalMonetaryTotal/{*}PayableAmount").text)
satirlar = [x.text for x in kok.findall("{*}InvoiceLine/{*}LineExtensionAmount")]
print("satırlar  :", satirlar)
'''

OZET_PY = r'''#!/usr/bin/env python3
# ozet_hesapla.py — bir faturadaki özeti (DigestValue) yeniden hesaplar ve kayıtlı değerle karşılaştırır
import hashlib
import sys
import xml.etree.ElementTree as ET

k = ET.parse(sys.argv[1]).getroot()
no = k.find("{*}ID").text
vkn = k.find("{*}AccountingCustomerParty/{*}Party/{*}PartyIdentification/{*}ID").text
ad = k.find("{*}AccountingCustomerParty/{*}Party/{*}PartyName/{*}Name").text
tutar = k.find("{*}LegalMonetaryTotal/{*}PayableAmount").text
hesap = hashlib.sha256(f"{no}|{vkn}|{ad}|{tutar}".encode("utf-8")).hexdigest()
kayitli = k.find("{*}Signature/{*}SignedInfo/{*}DigestValue").text
print("hesaplanan:", hesap[:16], "...")
print("kayıtlı   :", kayitli[:16], "...")
print("sonuç     :", "AYNI" if hesap == kayitli else "FARKLI")
'''

DENETLE_PY = r'''#!/usr/bin/env python3
import csv
import hashlib
import sys
import xml.etree.ElementTree as ET
from decimal import Decimal
from pathlib import Path

if len(sys.argv) < 3:
    print(f"Kullanım: {sys.argv[0]} <fatura_klasoru> <siparisler.csv>")
    sys.exit(1)


def bul(kok, yol):
    e = kok.find(yol)
    return (e.text or "").strip() if e is not None else ""


with open(sys.argv[2], encoding="utf-8", newline="") as f:
    siparis = {r["fatura_no"]: r["alici_vkn"] for r in csv.DictReader(f)}

for yol in sorted(Path(sys.argv[1]).glob("*.xml")):
    kok = ET.parse(yol).getroot()
    no = bul(kok, "{*}ID")
    vkn = bul(kok, "{*}AccountingCustomerParty/{*}Party/{*}PartyIdentification/{*}ID")
    ad = bul(kok, "{*}AccountingCustomerParty/{*}Party/{*}PartyName/{*}Name")
    satirlar = sum(Decimal(x.text) for x in kok.findall("{*}InvoiceLine/{*}LineExtensionAmount"))
    ara = Decimal(bul(kok, "{*}LegalMonetaryTotal/{*}LineExtensionAmount"))
    iskonto = Decimal(bul(kok, "{*}LegalMonetaryTotal/{*}AllowanceTotalAmount"))
    odenecek_metin = bul(kok, "{*}LegalMonetaryTotal/{*}PayableAmount")
    kdv = Decimal(bul(kok, "{*}TaxTotal/{*}TaxAmount"))
    nedenler = []
    if satirlar != ara or Decimal(odenecek_metin) != ara - iskonto + kdv:
        nedenler.append("toplam")
    if siparis.get(no) != vkn:
        nedenler.append("alici")
    ozet = hashlib.sha256(f"{no}|{vkn}|{ad}|{odenecek_metin}".encode("utf-8")).hexdigest()
    if ozet != bul(kok, "{*}Signature/{*}SignedInfo/{*}DigestValue"):
        nedenler.append("imza")
    if nedenler:
        print(yol.name, ",".join(nedenler))
'''


# ---------------------------------------------------------------- denetim

def _dosya_say(c: bt.Cikti) -> dict:
    sonuc = {}
    for satir in c.stdout.splitlines():
        m = re.search(r"F-\d{3}\.xml", satir)
        if m:
            a = bt.ascii_kucuk(satir)
            sonuc[m.group(0)] = {x for x in ("toplam", "alici", "imza") if x in a}
    return sonuc


def _kontrol(calistir: bt.Calistirici, klasor_yolu: Path, siparis_yolu: Path, k: dict, goster: str) -> Sonuc | None:
    c = calistir(str(klasor_yolu), str(siparis_yolu))
    nasil = calistir.goster(goster)
    cokme = calistir.cokme(c)
    if cokme:
        return Sonuc(False, f"`{nasil}` çalışırken: {cokme}")
    bulunan = _dosya_say(c)
    beklenen = {ad: ned for ad, ned in k["beklenen"].items() if ned}
    if not bulunan and beklenen:
        return Sonuc(False, f"`{nasil}` çıktısında sorunlu dosya bulamadım. Her sorunlu dosyayı `F-005.xml toplam` "
                     "biçiminde bir satıra yaz." + bt.ozet(c), yakin=True)
    fazla = set(bulunan) - set(beklenen)
    eksik = set(beklenen) - set(bulunan)
    if fazla:
        ad = sorted(fazla)[0]
        ipucu = ""
        if any(f["iskonto"] > 0 for f in k["faturalar"]):
            ipucu = " İskontolu faturalar meşrudur: ödenecek tutar = ara toplam - iskonto + KDV."
        return Sonuc(False, f"`{nasil}`: {ad} sağlam bir fatura ama sorunlu demişsin ({len(fazla)} yanlış alarm)." + ipucu
                     + f" Sen `{', '.join(sorted(bulunan[ad])) or '-'}` dedin.", yakin=True)
    if eksik:
        ad = sorted(eksik)[0]
        ned = sorted(beklenen[ad])[0]
        yardim = {
            "toplam": "Satır tutarlarını toplayıp başlıktaki LineExtensionAmount ile, ödenecek tutarı da "
                      "`LineExtensionAmount - AllowanceTotalAmount + TaxAmount` ile karşılaştır.",
            "alici": "Faturadaki alıcı VKN'sini `siparisler.csv`'de fatura numarasına karşılık gelen VKN ile karşılaştır.",
            "imza": "`sha256(no|alici_vkn|alici_unvan|odenecek)` hesaplayıp `DigestValue` ile karşılaştır "
                    "(`ornekler/ozet_hesapla.py`).",
        }[ned]
        return Sonuc(False, f"`{nasil}`: {len(eksik)} sorunlu fatura kaçırılmış (örn. {ad}: `{ned}` kontrolü). {yardim}",
                     yakin=True)
    for ad, ned in beklenen.items():
        if bulunan[ad] != ned:
            return Sonuc(False, f"`{nasil}`: {ad} için neden `{', '.join(sorted(bulunan[ad])) or '-'}` yazmışsın, "
                         f"`{', '.join(sorted(ned))}` olmalı. Neden anahtar sözcükleri: toplam, alici, imza.", yakin=True)
    return None


def _denetle(b: Baglam, calistir: bt.Calistirici) -> Sonuc:
    s = b.senaryo
    hata = bt.kullanim_denetle(calistir)
    if hata:
        return Sonuc(False, hata, yakin=True)
    lab = Path(b.lab)
    if not (lab / "faturalar").is_dir():
        return Sonuc(False, f"{lab / 'faturalar'} yok. Lab'ı bozduysan `sifirla` ile yeniden kur.")
    k = klasor(random.Random(s["tohum"]), s["v"], s["n_t"], 1, s["n_i"])
    sonuc = _kontrol(calistir, lab / "faturalar", lab / "siparisler.csv", k, "faturalar siparisler.csv")
    if sonuc:
        return sonuc
    rng = random.Random()
    v = rng.choice(VAKALAR)
    yeni = klasor(rng, v, rng.randint(1, 3), rng.randint(1, 2), rng.randint(1, 3), rng.randint(10, 13))
    gecici = Path(tempfile.mkdtemp(prefix="hy_fatura_"))
    try:
        for ad, metin in yeni["dosyalar"].items():
            (gecici / ad).write_text(metin, encoding="utf-8")
        sip = gecici / "siparis.csv"
        sip.write_text("fatura_no,alici_vkn\n" + "\n".join(f"{n}={x}".replace("=", ",") for n, x in yeni["siparis"].items()) + "\n",
                       encoding="utf-8")
        sonuc = _kontrol(calistir, gecici, sip, yeni, f"{gecici} {sip}")
    finally:
        shutil.rmtree(gecici, ignore_errors=True)
    if sonuc:
        sonuc.mesaj += "\n    (Bu, hiç görmediğin yeni bir fatura klasörüydü; klasör ve sipariş dosyası argümandan gelmeli.)"
        return sonuc
    return Sonuc(True, "fatura_denetle.py hem lab klasöründe hem hiç görmediği yeni bir klasörde, iskontolu meşru faturaları "
                       "işaretlemeden, üç tutarsızlık türünü de doğru yakaladı. Bütünlük kontrolü tam olarak budur: "
                       "toplam, kayıtlı beklenti ve imza.")


def _toplam_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n > beklenen:
        return "Fazla: iskontolu faturalar meşrudur. Kural: ödenecek = ara toplam - iskonto + KDV, satırların toplamı başlığa eşit."
    return None


def _imza_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + b.senaryo["n_t"] or n == beklenen + b.senaryo["n_t"] + 1:
        return "Fazla: özeti ödenecek tutar üzerinden **belgedeki haliyle** hesapla; tutarı imzadan önce değiştirilmiş faturalarda özet tutarlıdır."
    return None


def _son6_hata(g, beklenen, b):
    if len(g) > 6 and g.endswith(beklenen.lower()):
        return "Fazla yazmışsın; sadece son 6 karakter."
    return None


def _yetkisiz_hata(g, beklenen, b):
    try:
        n = int(g)
    except ValueError:
        return None
    if n == beklenen + b.senaryo["_red"]:
        return "403 ile **engellenen** denemeleri de saymışsın. Soru başarılı (`status=200`) yetkisiz çağrıları soruyor."
    return None


def coz(lab: Path, s: dict) -> dict:
    bt.betik_yaz(lab / "fatura_denetle.py", DENETLE_PY)
    cikti = "python3 fatura_denetle.py faturalar siparisler.csv"
    toplam = sh(f"{cikti} | grep -c toplam", lab)
    imza = sh(f"{cikti} | grep -c imza", lab)
    dosya = sh(f"{cikti} | grep alici | awk '{{print $1}}'", lab)
    alici = sh(f"grep -o '<cbc:ID>[^<]*' faturalar/{dosya} | head -1 | cut -d'>' -f2", lab)
    son6 = sh("grep 'api_key=' api/entegrator_api.log | head -1 | grep -o 'api_key=[^& ]*' | cut -d= -f2 | rev | cut -c1-6 | rev", lab)
    yetkisiz = sh("awk '{for(i=1;i<=NF;i++){if($i ~ /^sahip=/)s=substr($i,7); if($i ~ /^hedef=/)h=substr($i,7); if($i ~ /^status=/)st=substr($i,8)} "
                  "if (s!=h && st==200) n++} END{print n+0}' api/entegrator_api.log", lab)
    ip = sh("awk '{for(i=1;i<=NF;i++){if($i ~ /^sahip=/)s=substr($i,7); if($i ~ /^hedef=/)h=substr($i,7); if($i ~ /^status=/)st=substr($i,8)} "
            "if (s!=h && st==200) print $3}' api/entegrator_api.log | sort | uniq -c | sort -rn | head -1 | awk '{print $2}' | cut -d= -f2", lab)
    cozum = {1: "", 2: toplam, 3: alici, 4: imza, 5: son6, 6: yetkisiz, 7: ip}
    return sec_doldur(cozum, SEVIYE.gorevler, lab, s)


ADIMLAR = [
    Adim("Bütünlük = üç kontrol", """
Selin: "Bir faturanın değiştirilip değiştirilmediğini anlamak için üç ayrı soruya bakarsın:
**1)** belgenin kendi içinde tutarlı mı (satırlar toplamı = toplam)? **2)** beklediğin alıcıya mı gidiyor
(siparişle uyuşuyor mu)? **3)** imzası (hash'i) belgenin içeriğiyle uyuşuyor mu?" Klasörün haritası:
""", komut="cat OKUBENI.txt"),
    Adim("Bir e-faturayı okumak", """
UBL-TR benzeri XML'de satırlar `cac:InvoiceLine` altında, toplamlar `cac:LegalMonetaryTotal` altında, alıcı
`cac:AccountingCustomerParty` altında. İlk faturanın ilk 22 satırı:
""", komut="head -22 faturalar/F-001.xml"),
    Adim("grep ile hızlı bakış", """
Önce komut satırı: ödenecek tutarların hepsini alt alta gör. `-h` dosya adını yazmaz:
""", komut="grep -h PayableAmount faturalar/*.xml | head -5", sonra="""
Tek tek okumak 14 faturada bile yorucu; gerçek hayatta binlercedir. İşi bir programa vereceğiz.
"""),
    Adim("Python ile XML okumak", """
`xml.etree.ElementTree` XML'i ağaç olarak okur. XML'in kendi ad alanları (`cbc:`, `cac:`) vardır; yolda
`{*}` yazmak her ad alanını kabul eder: `kok.find("{*}ID")`. Örnek betik:
""", komut="python3 ornekler/xml_oku.py faturalar/F-001.xml", sonra="""
Para tutarlarını karşılaştırırken `float` yerine `decimal.Decimal` kullanmak, ondalık yuvarlama
hatalarını önler. Finans yazılımında bu bir alışkanlık olmalı.
"""),
    Adim("İmza özeti nasıl hesaplanır?", """
Lab'daki "imza", belgenin dört alanından sha256 ile hesaplanan bir özet. Gerçek e-imza çok daha
karmaşıktır (sertifika, zaman damgası) ama fikir aynı: **içerik değişirse özet değişir**. Örnek betik, bir
faturanın özetini yeniden hesaplayıp kayıtlı değerle kıyaslıyor:
""", komut="python3 ornekler/ozet_hesapla.py faturalar/F-001.xml"),
    Adim("API günlüğü", """
Entegratör API'sinin günlüğünde her satır: zaman, istemci IP'si, kullanılan anahtar, anahtarın **sahibi**
olan mükellef ve istenen kaynağın **hedef** mükellefi. Normal bir çağrıda sahip ile hedef aynıdır:
""", komut="head -4 api/entegrator_api.log", sonra="""
Sahibi **başka** mükellef olan bir kaynağa başarılı bir çağrı (`status=200`) gördüğünde, bu bir **yetkilendirme
açığıdır** (BOLA): sistem anahtarın sahibini doğruladı ama o sahibin o kaynağa erişim yetkisi olup
olmadığını kontrol etmedi. Cilt 5'teki IDOR'un API hali.
"""),
    Adim("Anahtar nerede görünmemeli", """
API anahtarı bir **sırdır** ve yalnızca istek başlığında (header) taşınmalıdır. URL'ye (sorgu dizesine)
yazılırsa her proxy'nin, tarayıcı geçmişinin ve günlük dosyasının içinde düz metin kalır. Günlükte anahtar
URL'de görünen satırı ararken bir kalıp:
""", komut="grep -c 'api_key=' api/entegrator_api.log", sonra="""
**Hacker gözüyle:** Sızan bir anahtar, sahibinin kimliğiyle işlem yapma izni demektir. Saldırgan loglara
bakıp kullanılmış anahtarları toplar; savunmacı ise günlüklere anahtarı hiç yazmayarak (maskeleyerek) ve
sızanı hemen iptal ederek bu yüzeyi kapatır.
"""),
]

GOREVLER = [
    Gorev("`fatura_denetle.py` yaz: `python3 fatura_denetle.py <fatura_klasoru> <siparisler.csv>` klasördeki her XML'i "
          "üç kontrolden geçirsin (`OKUBENI.txt`'de tanımlı): **toplam**, **alici**, **imza**. Sorunlu her dosya için "
          "bir satır: `F-005.xml toplam` (birden çok neden varsa virgülle). Sağlam dosyalar yazılmasın; iskontolu "
          "faturalar meşrudur. Argümansızsa `Kullanım` mesajı ve `exit 1`. Oyun betiğini hiç görmediği yeni bir "
          "klasörle de deneyecek. Dene: `python3 fatura_denetle.py faturalar siparisler.csv`",
          bt.BetikKontrol("fatura_denetle.py", _denetle,
                          "Örnek `fatura_denetle.py`:\n\n```\n" + DENETLE_PY.rstrip() + "\n```", zaman_asimi=60),
          ("`ornekler/xml_oku.py` ve `ornekler/ozet_hesapla.py` iki kontrolün çekirdeğini içeriyor; birleştir ve "
           "`Path(klasor).glob('*.xml')` ile tüm dosyaları dolaş.",
           "Üç kontrol: satırlar toplamı (`findall('{*}InvoiceLine/{*}LineExtensionAmount')`) başlığa eşit mi ve "
           "`ödenecek == ara - iskonto + kdv` mi; `siparis[fatura_no] == alici_vkn` mi (`csv.DictReader` ile sözlük kur); "
           "`sha256(no|vkn|unvan|odenecek_metin) == DigestValue` mi.",
           "Her dosya için `nedenler = []` tut, kontrol başarısızsa `nedenler.append(\"toplam\")` vb.; sonda "
           "`if nedenler: print(yol.name, \",\".join(nedenler))`. Tutar karşılaştırması için `Decimal` kullan; özet için "
           "tutarı XML'deki **metin** haliyle (`odenecek_metin`) kullan."),
          puan=70, baslik="Fatura denetleyici"),
    Gorev("Aracının bulduğu sorunlu faturalardan kaçında **toplam tutarsızlığı** (`toplam`) var?",
          Sayi("toplam", sik_hatalar=_toplam_hata),
          ("Aracının çıktısında `toplam` nedenini sayabilirsin.",
           "`python3 fatura_denetle.py faturalar siparisler.csv | grep -c toplam`",
           "Aynı komut."),
          puan=20, baslik="Toplam uyuşmazlığı"),
    Gorev("Bir faturanın **alıcısı değiştirilmiş**: siparişteki alıcıdan farklı bir alıcıya kesilmiş. Bu faturanın "
          "numarası nedir? (Dosya adı değil, XML içindeki fatura numarası `FTR2026...`.)",
          Metin("alici", bicim="fatura numarası (FTR2026...)"),
          ("Aracının `alici` nedenini yazdığı dosyayı bul; sonra o XML'in içindeki ilk `<cbc:ID>` fatura numarasıdır.",
           "`python3 fatura_denetle.py faturalar siparisler.csv | grep alici`; ardından `grep '<cbc:ID>' faturalar/F-XXX.xml`.",
           "`grep -o '<cbc:ID>[^<]*' faturalar/F-XXX.xml | head -1` (F-XXX yerine dosyanı yaz)."),
          puan=25, baslik="Değişen alıcı"),
    Gorev("İmza (`DigestValue`) **uyuşmayan** kaç fatura var? Bunlar imzalandıktan **sonra** değiştirilmiş "
          "demektir.",
          Sayi("imza", sik_hatalar=_imza_hata),
          ("`imza` nedenli satırları say.",
           "`python3 fatura_denetle.py faturalar siparisler.csv | grep -c imza`",
           "Aynı komut."),
          puan=25, baslik="İmza uyuşmazlığı"),
    Gorev("`api/entegrator_api.log`: bir API anahtarı **URL içinde düz metin** olarak (`api_key=` parametresi) "
          "günlüğe düşmüş. Anahtarın **son 6 karakteri** nedir?",
          Metin("son6", sik_hatalar=_son6_hata, bicim="anahtarın son 6 karakteri"),
          ("Aradığın kalıp `api_key=`.",
           "`grep 'api_key=' api/entegrator_api.log`",
           "`grep -o 'api_key=[^& ]*' api/entegrator_api.log`; anahtar `&` işaretine ya da boşluğa kadar."),
          puan=30, baslik="Sızan anahtar"),
    Gorev("Bu anahtar saldırgan tarafından kullanılmış: **sahibi dışındaki** mükelleflerin kaynaklarına başarılı "
          "(`status=200`) kaç çağrı yapılmış? (`sahip=` ile `hedef=` farklı.)",
          Sayi("yetkisiz", sik_hatalar=_yetkisiz_hata),
          ("Her satırda `sahip=` ve `hedef=` alanları var; farklı olanları ve 200 dönenleri seç.",
           "Anahtarı kullanan satırlara bak: `grep '<anahtar>' api/entegrator_api.log`; sahip ile hedefi karşılaştır.",
           "`awk '{for(i=1;i<=NF;i++){if($i ~ /^sahip=/)s=substr($i,7); if($i ~ /^hedef=/)h=substr($i,7); if($i ~ /^status=/)"
           "st=substr($i,8)} if (s!=h && st==200) n++} END{print n+0}' api/entegrator_api.log`"),
          puan=35, baslik="Yetkisiz çağrılar"),
    Gorev("Bu yetkisiz çağrıların yapıldığı **IP adresi** hangisi?",
          IP("ip"),
          ("Yetkisiz çağrıların hepsi aynı kaynaktan gelmiş olabilir.",
           "Önceki görevde bulduğun satırların `ip=` alanına bak.",
           "Yetkisiz satırları süz ve her satırdaki `ip=` alanını oku (awk'ta üçüncü alan `$3`)."),
          puan=20, baslik="Saldırgan IP"),
    Gorev("\"Entegratörümüze güveniyoruz\" yaklaşımının asıl tehlikesi nedir?",
          Secmeli([
              ("Güven, bağlantı güvenliğini gevşetmenin mazereti olur; oysa zayıf halka tüm akışı riske atar",
               "Doğru. Entegratör çok sayıda mükellefin verisini işler; onu ele geçiren herkesin verisine ulaşabilir, bu "
               "yüzden güven kontrolün yerine geçmez."),
              ("Entegratörler her zaman kötü niyetlidir",
               "Mesele niyet değil; en iyi niyetli aracı da ele geçirilebilir ya da yanlış yapılandırılabilir."),
              ("Entegratör kullanmak yasaktır, belgeler doğrudan gönderilmelidir",
               "Entegratör kullanmak meşru ve yaygın bir yoldur; sorun güvenliğin denetlenmemesi."),
              ("Güven, API anahtarlarını gereksiz kılar",
               "Tam tersine: güvenin olduğu yerde bile her istek kimlik doğrulamalı ve yetkilendirilmeli."),
          ]),
          ("Zincirin en zayıf halkası kadar güçlü olduğunu hatırla.",
           "Güvenmek ile doğrulamak aynı şey değil.",
           "Cilt 19'daki üçüncü taraf zinciri riski."),
          puan=20, baslik="Güven tuzağı"),
    Gorev("Bir API anahtarının günlükte düz metin göründüğü anlaşıldı. **İlk** yapılacak doğru adım hangisi?",
          Secmeli([
              ("Anahtarı hemen iptal edip yenisini ver; günlüğü de maskele ve olası kullanımı incele",
               "Doğru. Sızan sır geçersiz kılınmadıkça kullanılmaya devam eder; ardından kaynak sorun giderilir."),
              ("Günlük dosyasını silip konuyu kapatmak",
               "Silmek anahtarın başkasında olabilecek kopyasını geçersiz kılmaz; üstelik delili de yok eder."),
              ("Yalnızca anahtar sahibine nazikçe dikkatli olmasını söylemek",
               "Uyarı yetmez; sır sızdıysa teknik olarak geçersiz kılınmalı."),
              ("Bir hafta beklemek ve yetkisiz çağrı olup olmadığına bakmak",
               "Beklemek saldırgana zaman verir; önce anahtarı kapat, sonra incele."),
          ]),
          ("Anahtar başkasının elinde olabilir mi?",
           "Sır sızdıysa onu hâlâ geçerli bırakmak ne demek?",
           "Cilt 12 sır yönetimi: sızdıysa iptal et ve yenile."),
          puan=20, baslik="Sızıntıya ilk adım"),
]

SEVIYE = Seviye(
    kimlik="c23b02",
    cilt=23,
    bolum=2,
    baslik="Entegratör ve API Güvenliği",
    brifing="""
**<<musteri>>**: <<olay>> <<kisi>> bir denetim istiyor.

Selin klasörü masaya bırakıyor: "<<n_fatura>> e-fatura, sipariş kayıtları ve entegratör API'sinin günlüğü.
Üç soru: hangi faturalar **kendi içinde tutarsız**, hangileri **siparişteki alıcıdan farklı**, hangilerinin
**imzası belgeyle uyuşmuyor**? Sonra API günlüğüne bakıp anahtar sızıntısı ya da yetkisiz çağrı var mı
bulacağız." Deniz ekliyor: "Elle bakmak mümkün değil. Bir denetleyici yaz." Mert: "İskontolu faturalara dikkat.
Meşru faturaya sahte alarm vermek de denetimin kalitesini düşürür."
""",
    adimlar=ADIMLAR,
    gorevler=GOREVLER,
    uret=uret,
    yaz=yaz,
    coz=coz,
    kapanis="""
Kendi denetleyicin e-faturalarda üç farklı kurcalama biçimini ayırt etti: imzadan **önce** değişen tutar (iç
tutarsızlık), imzadan **önce** değişen alıcı (sipariş uyuşmazlığı) ve imzadan **sonra** değişen içerik (özet
uyuşmazlığı). Üçü de aynı fikirle yakalanır: belgenin kendi içinde tutarlılığı, beklenen kayıtla uyum ve
imza. API günlüğünde ise bir anahtarın URL'de görünmesi ve sahibinin dışındaki kaynaklara başarılı çağrılar,
hem sır yönetimi hem yetkilendirme eksikliğini gösterdi. Savunma dersi: anahtar yalnızca başlıkta taşınır ve
günlüklerde maskelenir, her istekte kaynak düzeyinde yetki kontrol edilir ve entegratöre güven, denetimin yerine
geçmez.
""",
    gercek_hayat="""
- **Kimlik bilgisi sızıntısı:** Kod depolarında, günlüklerde ve hata ayıklama çıktılarında unutulan API
  anahtarları, pek çok sızma testi raporunda ve gerçek olaylarda tekrarlanan bir bulgudur (Capital One 2019
  olayı da bulut kimlik bilgilerine ve yanlış yapılandırılmış bir erişime dayanır). Tespit: günlüklerde ve
  depolarda gizli bilgi tarayıcıları; önlem: sırların başlıkta taşınması, günlükte maskelenmesi ve sızanın
  hemen iptal edilmesi.
- **Nesne düzeyinde yetkilendirme (BOLA/IDOR):** OWASP'ın API güvenliği listesinin başında yer alan açıklardan
  biridir: kimliği doğrulanmış bir istemci, başkasına ait kaynağa erişebilir. Tespit: günlükte "anahtar sahibi
  ile istenen kaynak sahibi farklı" kalıbı; önlem: her istekte kaynak sahipliğinin sunucuda denetlenmesi.
- **Belge bütünlüğü:** e-dönüşümde belgelerin elektronik imza ya da mali mühürle korunması, sonradan yapılan
  değişikliklerin fark edilmesini sağlar. Mevzuat ve teknik ayrıntılar GİB tarafından yönetilir ve değişebilir;
  bütünlüğü imza ile doğrulama ilkesi ise kalıcıdır.
""",
    sure_hedef_dk=50,
)
