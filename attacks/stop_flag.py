"""Cờ dừng mềm dùng chung giữa dashboard và các module.

app_server ghi file monitoring/stop_flags/<key>.stop và đặt biến môi trường
NEXUS_MODULE_KEY cho tiến trình con. Module gọi stop_requested() mỗi vòng lặp
để thoát ra bằng finally (khôi phục ARP / IP forwarding) thay vì bị kill cứng.
"""

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STOP_DIR = os.path.join(BASE_DIR, "monitoring", "stop_flags")


def _key(name=None):
    return os.environ.get("NEXUS_MODULE_KEY") or name


def stop_requested(name=None):
    key = _key(name)
    if not key:
        return False
    return os.path.exists(os.path.join(STOP_DIR, f"{key}.stop"))


def clear(name=None):
    key = _key(name)
    if not key:
        return
    path = os.path.join(STOP_DIR, f"{key}.stop")
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
