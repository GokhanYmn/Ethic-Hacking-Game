"""Cilt 3 seviyelerinin ortak servis yardımcısı (motoru değiştirmeden).

`hy.motor.servis.http_sunucu`, Python'ın `HTTPServer.server_bind`'ını kullanır; o da bağlanılan
adres için `socket.getfqdn()` ile ters DNS sorgusu yapar. 127.0.0.1 dışındaki loopback
adreslerinde (127.a.b.c) bu sorgu ağdaki DNS sunucusuna gider ve sunucu başına bir-iki saniye
(DNS yavaşsa çok daha fazla) bekletir. Buradaki `http_sunucu` aynı işi ters DNS olmadan yapar.
"""
from __future__ import annotations

import http.server
import socketserver


class _HizliHTTPSunucu(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host       # getfqdn() yok: ters DNS sorgusu gönderilmez
        self.server_port = port


def http_sunucu(host: str, port: int, isleyici_sinifi) -> socketserver.BaseServer:
    """`hy.motor.servis.http_sunucu` ile aynı imza; sadece 127.x.x.x'te dinler."""
    if not str(host).startswith("127."):
        raise ValueError("Servisler sadece 127.x.x.x üzerinde dinleyebilir")
    return _HizliHTTPSunucu((host, port), isleyici_sinifi)
