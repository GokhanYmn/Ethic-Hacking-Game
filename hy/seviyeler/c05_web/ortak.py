"""Cilt 5 ortak yardımcıları (motoru değiştirmeden).

Bu cildin hedefi, oyunun kendi küçük web uygulamasıdır. Uygulama lab'da bir Python dosyasıdır
(`uygulama.py`) ve tek bir fonksiyon tanımlar:

    def isle(istek, db):  ->  (durum_kodu, başlıklar, gövde)

- `istek`: `Istek` nesnesi (method, path, sorgu, form, cerez, baslik, ip).
- `db`: sqlite3 bağlantısını saran küçük sarmalayıcı (`db.execute(sql, parametreler)`).

Servis (`servis_calis`) 127.0.0.1'de dinler ve `uygulama.py`'yi **dosya değişince yeniden yükler**:
oyuncu dosyayı düzeltip kaydettiğinde, sunucuyu yeniden başlatmadan curl ile düzeltmeyi görebilir.
Düzeltme görevlerinin kontrolü (`Deneme`) aynı dosyayı bir veritabanı kopyasıyla süreç içinde
yükler ve sahte isteklerle sınar; böylece sonuç ağa, porta ya da zamana bağlı olmaz.
"""
from __future__ import annotations

import contextlib
import dataclasses
import html
import http.client
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from hy.motor.kontrol import Sonuc
from hy.motor.servis import SessizIsleyici, calistir, http_sunucu

HTML = "text/html; charset=utf-8"


# ---------------------------------------------------------------- istek / yanıt

class Istek:
    """Uygulamanın gördüğü istek. Tüm değerler oyuncunun/istemcinin kontrolündedir."""

    def __init__(self, method="GET", path="/", sorgu=None, form=None, cerez=None, baslik=None,
                 ip="127.0.0.1"):
        self.method = method
        self.path = path
        self.sorgu = dict(sorgu or {})
        self.form = dict(form or {})
        self.cerez = dict(cerez or {})
        self.baslik = {k.lower(): v for k, v in (baslik or {}).items()}
        self.ip = ip


@dataclasses.dataclass
class Yanit:
    kod: int = 0
    basliklar: list = dataclasses.field(default_factory=list)
    govde: str = ""
    sql: list = dataclasses.field(default_factory=list)   # [(sorgu_metni, parametreler)]
    hata: str = ""                                        # uygulama istisna fırlattıysa

    def baslik(self, ad: str) -> str:
        ad = ad.lower()
        return ", ".join(v for k, v in self.basliklar if k.lower() == ad)

    @property
    def set_cerezler(self) -> list:
        return [v for k, v in self.basliklar if k.lower() == "set-cookie"]

    def cerez_degeri(self, ad: str) -> str:
        for sc in self.set_cerezler:
            ilk = sc.split(";", 1)[0]
            if "=" in ilk and ilk.split("=", 1)[0].strip() == ad:
                return ilk.split("=", 1)[1].strip()
        return ""

    @property
    def konum(self) -> str:
        return self.baslik("location")


def cerez_ayristir(ham: str) -> dict:
    sonuc = {}
    for parca in (ham or "").split(";"):
        if "=" in parca:
            k, v = parca.split("=", 1)
            sonuc[k.strip()] = v.strip()
    return sonuc


# ---------------------------------------------------------------- veritabanı

class DB:
    """sqlite3 bağlantısı için ince sarmalayıcı. Çalıştırılan her sorguyu kaydeder (kontrol için)."""

    def __init__(self, con: sqlite3.Connection, kayit: list | None = None):
        self.con = con
        self.kayit = kayit
        self.son_sql = ""

    def execute(self, sql: str, parametreler=()):
        self.son_sql = sql
        if self.kayit is not None:
            self.kayit.append((sql, tuple(parametreler)))
        return self.con.execute(sql, tuple(parametreler))


def db_olustur(yol: Path, sema: str, tablolar: dict) -> None:
    """`tablolar`: {tablo_adi: [satir_tuple, ...]}. Eski dosya silinir."""
    yol = Path(yol)
    yol.parent.mkdir(parents=True, exist_ok=True)
    yol.unlink(missing_ok=True)
    con = sqlite3.connect(str(yol))
    try:
        con.executescript(sema)
        for tablo, satirlar in tablolar.items():
            if satirlar:
                yer = ",".join("?" * len(satirlar[0]))
                con.executemany(f"INSERT INTO {tablo} VALUES ({yer})", satirlar)
        con.commit()
    finally:
        con.close()


def db_sorgu(yol: Path, sql: str, parametreler=()) -> list:
    """Lab veritabanından salt-okunur sorgu (kontroller için)."""
    con = sqlite3.connect(str(yol), timeout=5)
    try:
        return con.execute(sql, parametreler).fetchall()
    finally:
        con.close()


# ---------------------------------------------------------------- uygulamayı yükleme ve çalıştırma

def kaynak_yukle(yol: Path) -> dict:
    kaynak = Path(yol).read_text(encoding="utf-8")
    ad_alani = {"__name__": "uygulama", "__file__": str(yol)}
    exec(compile(kaynak, str(yol), "exec"), ad_alani)
    if not callable(ad_alani.get("isle")):
        raise RuntimeError("uygulama.py içinde `isle(istek, db)` fonksiyonu yok")
    return ad_alani


def hata_ozeti(e: BaseException) -> str:
    """Oyuncuya gösterilecek tek satırlık Python hatası (satır numarasıyla)."""
    if isinstance(e, SyntaxError):
        return f"SyntaxError: {e.msg} (uygulama.py, satır {e.lineno})"
    satir = ""
    for ayrinti in reversed(traceback.extract_tb(e.__traceback__)):
        if ayrinti.filename.endswith("uygulama.py"):
            satir = f" (uygulama.py, satır {ayrinti.lineno})"
            break
    tip = type(e).__name__ if type(e).__module__ == "builtins" else f"{type(e).__module__}.{type(e).__name__}"
    return f"{tip}: {e}{satir}"


def _cikti_duzenle(sonuc) -> tuple:
    if not isinstance(sonuc, tuple) or len(sonuc) not in (2, 3):
        raise TypeError("isle() (kod, başlıklar, gövde) ya da (kod, gövde) döndürmeli")
    if len(sonuc) == 2:
        kod, govde = sonuc
        basliklar = {}
    else:
        kod, basliklar, govde = sonuc
    if isinstance(basliklar, dict):
        basliklar = list(basliklar.items())
    else:
        basliklar = list(basliklar)
    if not any(k.lower() == "content-type" for k, _ in basliklar):
        basliklar.append(("Content-Type", HTML))
    if isinstance(govde, bytes):
        govde = govde.decode("utf-8", "replace")
    return int(kod), basliklar, str(govde)


def istek_calistir(isle, db_yolu: Path, istek: Istek, kayit: list | None = None) -> Yanit:
    """Tek isteği uygulamaya verir; istisnayı 500 sayfasına çevirir (gerçek sunucular gibi)."""
    con = sqlite3.connect(str(db_yolu), timeout=5, isolation_level=None)
    con.row_factory = sqlite3.Row
    sorgular = kayit if kayit is not None else []
    db = DB(con, sorgular)
    try:
        kod, basliklar, govde = _cikti_duzenle(isle(istek, db))
        return Yanit(kod, basliklar, govde, sorgular)
    except Exception as e:  # uygulama hatası = 500
        ayrinti = html.escape(hata_ozeti(e))
        sorgu = f"\nSorgu: {html.escape(db.son_sql)}" if db.son_sql else ""
        sayfa = (f"<html><body><h1>500 Sunucu Hatası</h1><pre>{ayrinti}{sorgu}</pre></body></html>\n")
        return Yanit(500, [("Content-Type", HTML)], sayfa, sorgular, hata=hata_ozeti(e))
    finally:
        con.close()


class Canli:
    """`uygulama.py` dosyası değişince yeniden yüklenen uygulama."""

    def __init__(self, yol: Path):
        self.yol = Path(yol)
        self._anahtar = None
        self._ad_alani = None
        self._hata = None
        self._kilit = threading.Lock()

    def isle(self):
        try:
            st = self.yol.stat()
            anahtar = (st.st_mtime_ns, st.st_size)
        except OSError as e:
            raise RuntimeError(f"uygulama.py okunamadı: {e}")
        with self._kilit:
            if anahtar != self._anahtar:
                self._anahtar = anahtar
                try:
                    self._ad_alani = kaynak_yukle(self.yol)
                    self._hata = None
                except Exception as e:
                    self._ad_alani = None
                    self._hata = e
            if self._hata is not None:
                raise self._hata
            return self._ad_alani["isle"]


def uygulama_isleyici(lab: Path, sunucu_adi: str = "pylab/1.0"):
    """HTTP işleyici sınıfı: istekleri lab'daki uygulama.py'ye verir."""
    lab = Path(lab)
    canli = Canli(lab / "uygulama.py")
    db_yolu = lab / "uygulama.db"

    class Isleyici(SessizIsleyici):
        server_version = sunucu_adi
        protocol_version = "HTTP/1.0"

        def _ele_al(self):
            u = urlsplit(self.path)
            sorgu = dict(parse_qsl(u.query, keep_blank_values=True))
            form = {}
            uzunluk = int(self.headers.get("Content-Length") or 0)
            if uzunluk:
                ham = self.rfile.read(min(uzunluk, 100_000)).decode("utf-8", "replace")
                form = dict(parse_qsl(ham, keep_blank_values=True))
            istek = Istek(self.command, u.path, sorgu, form, cerez_ayristir(self.headers.get("Cookie", "")),
                          dict(self.headers.items()), self.client_address[0])
            try:
                isle = canli.isle()
            except Exception as e:
                sayfa = ("<html><body><h1>500 Uygulama yüklenemedi</h1><pre>"
                         + html.escape(hata_ozeti(e)) + "</pre></body></html>\n")
                self.yanit(500, sayfa)
                return
            y = istek_calistir(isle, db_yolu, istek)
            self.send_response(y.kod)
            veri = y.govde.encode("utf-8")
            for k, v in y.basliklar:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(veri)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(veri)

        do_GET = do_POST = do_HEAD = _ele_al

    return Isleyici


def servis_calis(port: int, lab: Path, dur, ek_sunucular=()) -> None:
    sunucu = http_sunucu("127.0.0.1", port, uygulama_isleyici(lab))
    calistir([sunucu, *ek_sunucular], dur)


# ---------------------------------------------------------------- düzeltme kontrolü

class Deneme:
    """Oyuncunun `uygulama.py`'sini geçici bir veritabanı kopyasıyla yükleyip sahte istek gönderir."""

    def __init__(self, lab: Path):
        self.lab = Path(lab)
        self.hata = ""
        self.gecici = Path(tempfile.mkdtemp(prefix="hy_c05_"))
        self.db_yolu = self.gecici / "uygulama.db"
        self._isle = None
        yol = self.lab / "uygulama.py"
        if not yol.is_file():
            self.hata = "uygulama.py bulunamadı (lab'ı bozduysan `sifirla` ile yeniden kur)."
            return
        shutil.copy(self.lab / "uygulama.db", self.db_yolu)
        try:
            self._isle = kaynak_yukle(yol)["isle"]
        except Exception as e:
            self.hata = f"uygulama.py yüklenemedi: {hata_ozeti(e)}"

    def __enter__(self):
        return self

    def __exit__(self, *a):
        shutil.rmtree(self.gecici, ignore_errors=True)

    def istek(self, method: str, path: str, sorgu=None, form=None, cerez=None, ip="203.0.113.50",
              baslik=None) -> Yanit:
        sonuc: dict = {}

        def calis():
            sonuc["y"] = istek_calistir(self._isle, self.db_yolu,
                                        Istek(method, path, sorgu, form, cerez, baslik, ip))

        t = threading.Thread(target=calis, daemon=True)
        t.start()
        t.join(8)
        if "y" not in sonuc:
            return Yanit(0, hata="zaman aşımı (uygulama 8 saniyede cevap vermedi; sonsuz döngü?)")
        return sonuc["y"]

    def get(self, path: str, **kw) -> Yanit:
        return self.istek("GET", path, **kw)

    def post(self, path: str, form: dict, **kw) -> Yanit:
        return self.istek("POST", path, form=form, **kw)

    def giris(self, yol: str, form: dict, ip="203.0.113.50"):
        """Giriş isteği; (yanıt, oturum çerezleri sözlüğü) döndürür."""
        y = self.post(yol, form, ip=ip)
        cerezler = {}
        for sc in y.set_cerezler:
            ilk = sc.split(";", 1)[0]
            if "=" in ilk:
                k, v = ilk.split("=", 1)
                cerezler[k.strip()] = v.strip()
        return y, cerezler


def deneme_calistir(b, fonk):
    """`fonk(deneme) -> Sonuc` çağırır; uygulama.py yüklenemezse hatayı oyuncuya açıklar."""
    d = Deneme(Path(b.lab))
    try:
        if d.hata:
            return Sonuc(False, d.hata, yakin=True)
        return fonk(d)
    finally:
        d.__exit__()


def cokme_sonucu(y: Yanit, ne: str):
    """Uygulama istek sırasında çöktüyse oyuncuya açıklayan `Sonuc`, değilse None."""
    if y.hata:
        return Sonuc(False, f"{ne} isteğinde uygulama.py hata verdi: {y.hata}", yakin=True)
    return None


# ---------------------------------------------------------------- kaynak şablonu ve test yardımcıları

def kaynak_doldur(sablon: str, degerler: dict) -> str:
    """`@@AD@@` işaretlerini doldurur (Python kodundaki `{}` ile çakışmamak için)."""
    for k, v in degerler.items():
        sablon = sablon.replace(f"@@{k}@@", str(v))
    return sablon


def sh(komut: str, lab: Path, zaman: int = 60) -> str:
    return subprocess.run(["bash", "-c", komut], cwd=lab, capture_output=True, text=True,
                          timeout=zaman).stdout


def hazir_bekle(url: str, deneme: int = 30) -> bool:
    """Test çözücüsü için: servis cevap verene kadar bekler."""
    for _ in range(deneme):
        c = subprocess.run(["curl", "-s", "-o", "/dev/null", "-m", "2", url], capture_output=True)
        if c.returncode == 0:
            return True
        time.sleep(0.2)
    return False


# ---------------------------------------------------------------- Bölüm 2: iz süren vekil

def vekil_isleyici(log_yolu: Path):
    """Burp'un "HTTP geçmişi"nin minik taklidi: `curl -x` ile gelen istekleri kaydeder ve 127.x
    hedeflerine iletir. Başka hiçbir adrese iletmez."""
    log_yolu = Path(log_yolu)

    class Vekil(SessizIsleyici):
        server_version = "mini-vekil/1.0"
        protocol_version = "HTTP/1.0"

        def _ilet(self):
            hedef = urlsplit(self.path)
            if not hedef.scheme or not (hedef.hostname or "").startswith("127."):
                self.yanit(403, "<html><body><h1>403</h1><p>Bu vekil sadece laboratuvar (127.x) "
                                "adreslerine iletir.</p></body></html>\n")
                return
            uzunluk = int(self.headers.get("Content-Length") or 0)
            govde = self.rfile.read(min(uzunluk, 100_000)) if uzunluk else None
            yol = hedef.path or "/"
            if hedef.query:
                yol += "?" + hedef.query
            with contextlib.suppress(OSError):
                with open(log_yolu, "a", encoding="utf-8") as f:
                    f.write(f"{time.strftime('%H:%M:%S')} {self.command} {self.path}"
                            + (f"  GOVDE: {govde.decode('utf-8', 'replace')}" if govde else "") + "\n")
            try:
                bag = http.client.HTTPConnection(hedef.hostname, hedef.port or 80, timeout=5)
                basliklar = {k: v for k, v in self.headers.items()
                             if k.lower() not in ("proxy-connection", "connection", "host")}
                bag.request(self.command, yol, body=govde, headers=basliklar)
                y = bag.getresponse()
                veri = y.read()
                self.send_response(y.status)
                for k, v in y.getheaders():
                    if k.lower() not in ("content-length", "connection", "transfer-encoding", "server", "date"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(veri)))
                self.send_header("X-Vekil", "gecti")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(veri)
            except OSError as e:
                self.yanit(502, f"<html><body><h1>502</h1><p>{html.escape(str(e))}</p></body></html>\n")

        do_GET = do_POST = do_HEAD = _ilet

    return Vekil




# ---------------------------------------------------------------- Bölüm 7/8: giriş kodu parçaları

def giris_limit_kontrol() -> str:
    """uygulama.py'ye eklenen hız sınırı bloğu (aynı IP'den 5 başarısız denemeden sonra 429)."""
    return ('        simdi = time.time()\n'
            '        DENEMELER[istek.ip] = [t for t in DENEMELER.get(istek.ip, []) if simdi - t < 300]\n'
            '        if len(DENEMELER[istek.ip]) >= 5:\n'
            '            return 429, {"Retry-After": "300"}, sayfa("Çok fazla deneme", "<p>Çok fazla başarısız deneme. '
            'Lütfen 5 dakika sonra tekrar deneyin.</p>")\n')


def giris_hata_dali(tekil: bool, limit: bool) -> str:
    """Başarısız giriş dalı: `tekil` tek tip mesaj, `limit` her başarısızlığı sayar."""
    kayit = "            DENEMELER.setdefault(istek.ip, []).append(time.time())\n" if limit else ""
    if tekil:
        return ('        if k is None or k["parola"] != parola:\n' + kayit +
                '            return 401, {}, sayfa("Giriş", "<p>Kullanıcı adı veya parola hatalı.</p>" + FORM)\n')
    return ('        if k is None:\n' + kayit +
            '            return 401, {}, sayfa("Giriş", "<p>Kullanıcı bulunamadı.</p>" + FORM)\n'
            '        if k["parola"] != parola:\n' + kayit +
            '            return 401, {}, sayfa("Giriş", "<p>Parola hatalı.</p>" + FORM)\n')
