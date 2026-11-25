#!/usr/bin/env python3
"""Hacker Yolu — giriş noktası. Kurulumdan sonra `hackeryolu` komutuyla çalışır."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.version_info < (3, 10):
    sys.exit("Hacker Yolu için Python 3.10 veya üstü gerekir.")

from hy.motor.oyun import main  # noqa: E402

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
