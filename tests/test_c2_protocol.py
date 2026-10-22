"""Regression test cho C2 protocol v2 + legacy fallback.

Chạy: python tests/test_c2_protocol.py
Không mở port ra ngoài: chỉ bind 127.0.0.1 với cổng do OS cấp.
"""

import hashlib
import hmac
import json
import os
import socket
import sys
import threading

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "attacks"))

from c2_protocol import (  # noqa: E402
    decrypt,
    derive_key,
    encrypt,
    handshake_client,
    handshake_server_after_auth,
    recv_frame,
    result_frame,
    send_frame,
)
from c2_protocol import FrameStream  # noqa: E402

SECRET = b"NguoiDepTraiNhatTheGioi_2026"
KEY = derive_key(SECRET)
STATE = {}


def _server(sock):
    conn, _ = sock.accept()
    challenge = os.urandom(32)
    conn.sendall(challenge)
    conn.settimeout(5.0)
    response = conn.recv(1024).decode()
    assert response == hmac.new(SECRET, challenge, hashlib.sha256).hexdigest()

    conn.sendall(encrypt(KEY, b"AUTH_OK"))
    framing, meta = handshake_server_after_auth(conn, KEY, SECRET)
    STATE["framing"] = framing
    STATE["meta"] = meta

    message = json.loads(decrypt(KEY, recv_frame(conn)).decode())
    STATE["command"] = message
    send_frame(conn, result_frame(KEY, message["id"], 0, "ok\n", "", 0.01))
    conn.close()


def test_v2_roundtrip():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=_server, args=(server,), daemon=True).start()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(5.0)
    client.connect(("127.0.0.1", port))
    key, framing = handshake_client(client, SECRET)
    assert framing is True, "v2 handshake thất bại"

    send_frame(client, encrypt(key, json.dumps({"type": "exec", "id": "t1", "command": "whoami"}).encode()))
    result = json.loads(decrypt(key, recv_frame(client)).decode())
    client.close()
    server.close()

    assert STATE["framing"] is True
    assert STATE["meta"]["hostname"], "hello metadata rỗng"
    assert STATE["command"]["command"] == "whoami"
    assert result["stdout"] == "ok\n"
    assert result["exit_code"] == 0


def test_legacy_handshake():
    def legacy_server(sock):
        conn, _ = sock.accept()
        challenge = os.urandom(32)
        conn.sendall(challenge)
        conn.settimeout(5.0)
        conn.recv(1024)
        conn.sendall(encrypt(KEY, b"AUTH_OK"))
        framing, _ = handshake_server_after_auth(conn, KEY, SECRET, timeout=1.0)
        STATE["legacy_framing"] = framing
        command = decrypt(KEY, conn.recv(4096)).decode()
        STATE["legacy_command"] = command
        conn.sendall(encrypt(KEY, b"legacy\n"))
        conn.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    threading.Thread(target=legacy_server, args=(server,), daemon=True).start()

    agent = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    agent.settimeout(5.0)
    agent.connect(("127.0.0.1", port))
    challenge = agent.recv(32)
    agent.sendall(hmac.new(SECRET, challenge, hashlib.sha256).hexdigest().encode())
    assert decrypt(KEY, agent.recv(1024)) == b"AUTH_OK"
    agent.sendall(encrypt(KEY, b"whoami"))
    assert decrypt(KEY, agent.recv(4096)).decode() == "legacy\n"
    agent.close()
    server.close()

    assert STATE["legacy_framing"] is False
    assert STATE["legacy_command"] == "whoami"


def test_frame_stream_survives_timeout():
    """Frame đến lắt nhắt + timeout giữa frame không được làm mất byte."""
    import socket as socket_mod

    client, server = socket_mod.socketpair()
    client.settimeout(0.2)
    stream = FrameStream(server, max_size=1024)
    body = b"x" * 16
    frame = len(body).to_bytes(4, "big") + body

    client.sendall(frame[:2])
    try:
        stream.feed()
    except socket_mod.timeout:
        pass
    assert stream.pop_frame() is None

    client.sendall(frame[2:4])
    try:
        stream.feed()
    except socket_mod.timeout:
        pass
    assert stream.pop_frame() is None

    client.sendall(frame[4:10])
    try:
        stream.feed()
    except socket_mod.timeout:
        pass
    assert stream.pop_frame() is None

    client.sendall(frame[10:])
    stream.feed()
    assert stream.pop_frame() == body
    client.close()
    server.close()


if __name__ == "__main__":
    test_v2_roundtrip()
    test_legacy_handshake()
    test_frame_stream_survives_timeout()
    print("C2 PROTOCOL TESTS OK")