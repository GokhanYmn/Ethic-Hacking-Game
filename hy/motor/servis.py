"""Görev sırasında arka planda çalışan küçük yerel servisler için yardımcılar.

Tüm servisler SADECE 127.0.0.1 (veya 127.0.0.0/8 içindeki bir adres) üzerinde dinler;
dış ağa açılmaz. Seviyenin `servis(senaryo, lab, dur)` fonksiyonu bu yardımcılarla
sunucuları kurar ve `calistir(...)` ile `dur` olayı set edilene kadar bloklar.
"""
from __future__ import annotations

import http.server
import socket
import socketserver
import threading
from typing import Callable


def _yerel_mi(host: str) -> bool:
    return host.startswith("127.")


class _TCPSunucu(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def tcp_banner(host: str, port: int, banner: str | Callable[[], str]) -> socketserver.BaseServer:
    """Bağlanana bir karşılama satırı (banner) gönderip bağlantıyı kapatan TCP servisi."""
    if not _yerel_mi(host):
        raise ValueError("Servisler sadece 127.x.x.x üzerinde dinleyebilir")

    class Isleyici(socketserver.BaseRequestHandler):
        def handle(self):
            metin = banner() if callable(banner) else banner
            try:
                self.request.sendall(metin.encode("utf-8"))
            except OSError:
                pass

    return _TCPSunucu((host, port), Isleyici)


def tcp_sohbet(host: str, port: int, cevapla: Callable[[str], str | None], karsilama: str = "") \
        -> socketserver.BaseServer:
    """Satır satır konuşan basit TCP servisi. `cevapla(satir)` None dönerse bağlantı kapanır."""
    if not _yerel_mi(host):
        raise ValueError("Servisler sadece 127.x.x.x üzerinde dinleyebilir")

    class Isleyici(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                if karsilama:
                    self.wfile.write(karsilama.encode("utf-8"))
                for ham in self.rfile:
                    yanit = cevapla(ham.decode("utf-8", "replace").rstrip("\r\n"))
                    if yanit is None:
                        break
                    self.wfile.write(yanit.encode("utf-8"))
            except OSError:
                pass

    return _TCPSunucu((host, port), Isleyici)


class _HTTPSunucu(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind, socket.getfqdn() ile ters DNS sorgusu yapar: 127.x adreslerinde
        # saniyelerce bekletir ve dış DNS'e gereksiz sorgu gider. Ad çözmeden bağlan.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port


class SessizIsleyici(http.server.BaseHTTPRequestHandler):
    """Konsola erişim logu basmayan temel HTTP işleyici. Seviyeler bundan türetir."""
    server_version = "Apache/2.4.41"
    sys_version = ""

    def log_message(self, *args):  # noqa: D401 - sessiz
        pass

    def yanit(self, kod: int, govde: str | bytes, tur: str = "text/html; charset=utf-8",
              basliklar: dict | None = None) -> None:
        veri = govde.encode("utf-8") if isinstance(govde, str) else govde
        self.send_response(kod)
        self.send_header("Content-Type", tur)
        self.send_header("Content-Length", str(len(veri)))
        for k, v in (basliklar or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(veri)


def http_sunucu(host: str, port: int, isleyici_sinifi) -> socketserver.BaseServer:
    if not _yerel_mi(host):
        raise ValueError("Servisler sadece 127.x.x.x üzerinde dinleyebilir")
    return _HTTPSunucu((host, port), isleyici_sinifi)


def calistir(sunucular: list, dur: threading.Event) -> None:
    """Sunucuları ayrı iş parçacıklarında başlatır, `dur` set edilince kapatır."""
    for s in sunucular:
        threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()
    print("HAZIR", flush=True)   # görev kabuğu bu satırı bekler
    try:
        dur.wait()
    finally:
        for s in sunucular:
            s.shutdown()
            s.server_close()


def port_bos_mu(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False
