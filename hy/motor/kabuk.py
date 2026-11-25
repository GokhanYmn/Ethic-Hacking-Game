"""Lab dizini, arka plan servisleri ve görev kabuğu (gerçek bash)."""
from __future__ import annotations

import contextlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from hy.motor import arayuz as ui
from hy.motor.kayit import ev_dizini, lab_koku

ANA = Path(__file__).resolve().parents[2] / "hackeryolu.py"


def lab_dizini(sv) -> Path:
    return lab_koku() / sv.kimlik


def _tohum_isareti(sv) -> Path:
    # Lab'ın içinde değil yanında tutulur: oyuncunun "gizli dosya say" görevlerini bozmasın.
    return lab_koku() / f".{sv.kimlik}.tohum"


def _guvenli_sil(yol: Path) -> None:
    """Sadece lab kökü altındaki bir dizini siler; izni kısılmış alt dizinleri de açar."""
    kok = lab_koku().resolve()
    hedef = yol.resolve()
    if kok not in hedef.parents:
        raise RuntimeError(f"Lab kökü dışında silme reddedildi: {hedef}")

    def izin_ac(fonk, p, _hata):
        try:
            os.chmod(p, stat.S_IRWXU)
            ust = os.path.dirname(p)
            os.chmod(ust, stat.S_IRWXU)
        except OSError:
            pass
        fonk(p)

    # Önce tüm dizinlere sahibine tam yetki ver (chmod 000 görevleri silmeyi engellemesin).
    for kok_d, dizinler, _ in os.walk(hedef):
        for d in dizinler:
            with contextlib.suppress(OSError):
                os.chmod(os.path.join(kok_d, d), stat.S_IRWXU)
    if sys.version_info >= (3, 12):
        shutil.rmtree(hedef, onexc=izin_ac)
    else:
        shutil.rmtree(hedef, onerror=izin_ac)


def lab_kur(sv, senaryo: dict, zorla: bool = False) -> Path:
    """Senaryonun lab dosyalarını yazar. Tohum değişmişse ya da zorla=True ise yeniden kurar."""
    lab = lab_dizini(sv)
    isaret = _tohum_isareti(sv)
    tohum = str(senaryo["_tohum"])
    eski = isaret.read_text().strip() if isaret.exists() else None
    if lab.exists() and (zorla or eski != tohum):
        _guvenli_sil(lab)
    if not lab.exists():
        lab.mkdir(parents=True)
        if sv.yaz:
            sv.yaz(lab, senaryo)
        isaret.write_text(tohum)
    return lab


def _hazir_bekle(log_yolu: Path, surec: subprocess.Popen, sure: float = 6.0) -> bool:
    bitis = time.time() + sure
    while time.time() < bitis:
        if surec.poll() is not None:
            return False
        try:
            if "HAZIR" in log_yolu.read_text(errors="replace"):
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


@contextlib.contextmanager
def servisler(sv):
    """Seviyenin yerel servislerini ayrı bir süreç grubunda başlatır, çıkışta kapatır."""
    if not sv.servis:
        yield None
        return
    calisan = ev_dizini() / "calisan"
    calisan.mkdir(parents=True, exist_ok=True)
    log_yolu = calisan / f"{sv.kimlik}.log"
    with open(log_yolu, "w") as log:
        surec = subprocess.Popen(
            [sys.executable, str(ANA), "servis", sv.kimlik],
            stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        if not _hazir_bekle(log_yolu, surec):
            print(ui.hata("Görevin yerel servisleri başlatılamadı. Ayrıntı: " + str(log_yolu)))
            with contextlib.suppress(OSError):
                print(ui.r(log_yolu.read_text(errors="replace")[-800:], "gri"))
            print(ui.bilgi("Bir port başka bir program tarafından kullanılıyor olabilir. "
                           "Menüden 'Yeni vaka' seçmek farklı portlar üretir."))
        try:
            yield surec
        finally:
            if surec.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(surec.pid, signal.SIGTERM)
                try:
                    surec.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(surec.pid, signal.SIGKILL)
                    surec.wait()


RC_SABLONU = r"""# Hacker Yolu görev kabuğu (otomatik üretildi, elle düzenleme)
if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi
_hy()     { "$HY_PY" "$HY_ANA" "$@"; }
gorev()   { _hy gorev "$@"; }
ipucu()   { _hy ipucu "$@"; }
cevap()   { _hy cevap "$@"; }
pes()     { _hy pes "$@"; }
durum()   { _hy durum "$@"; }
yardim()  { _hy yardim "$@"; }
not()     { _hy not "$@"; }
sozluk()  { _hy sozluk "$@"; }
komut()   { _hy komut "$@"; }
sifirla() { _hy sifirla "$@"; cd "$LAB" 2>/dev/null || cd "$HOME"; }
lab()     { cd "$LAB"; }
cik()     { exit 0; }
PS1='\[\e[1;32m\]HY:'"$HY_SEVIYE"'\[\e[0m\] \[\e[1;34m\]\w\[\e[0m\] \$ '
cd "$LAB" && _hy gorev
"""


def gorev_kabugu(sv, lab: Path) -> int:
    """Oyuncuyu lab dizininde gerçek bir bash kabuğuna bırakır."""
    bash = shutil.which("bash")
    if not bash:
        print(ui.hata("bash bulunamadı. Kali'de varsayılan olarak kuruludur: sudo apt install bash"))
        return 1
    rc_dizini = ev_dizini() / "rc"
    rc_dizini.mkdir(parents=True, exist_ok=True)
    rc = rc_dizini / f"{sv.kimlik}.bashrc"
    rc.write_text(RC_SABLONU, encoding="utf-8")
    ortam = os.environ.copy()
    ortam.update({
        "HY_SEVIYE": sv.kimlik,
        "LAB": str(lab),
        "HY_PY": sys.executable,
        "HY_ANA": str(ANA),
    })
    print(ui.bilgi(f"Görev kabuğu açılıyor. Menüye dönmek için {ui.r('cik', 'camgobegi')} yaz."))
    with servisler(sv):
        return subprocess.call([bash, "--rcfile", str(rc), "-i"], cwd=str(lab), env=ortam)


def komut_calistir(komut: str, lab: Path, etkilesimli: bool = False, sinir: int = 40) -> None:
    """Eğitim adımında oyuncunun yazdığı komutu lab dizininde çalıştırıp çıktısını gösterir."""
    ortam = os.environ.copy()
    ortam["LAB"] = str(lab)
    if etkilesimli:
        subprocess.call(["bash", "-c", komut], cwd=str(lab), env=ortam)
        return
    try:
        p = subprocess.run(["bash", "-c", komut], cwd=str(lab), env=ortam, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, errors="replace", timeout=20)
    except subprocess.TimeoutExpired:
        print(ui.hata("Komut 20 saniyede bitmedi, durduruldu."))
        return
    cikti = (p.stdout + p.stderr).rstrip("\n")
    satirlar = cikti.split("\n") if cikti else []
    for s in satirlar[:sinir]:
        print("    " + s)
    if len(satirlar) > sinir:
        print(ui.r(f"    ... ({len(satirlar) - sinir} satır daha)", "gri"))
