import os
import sys
import time
import socket
import threading
import urllib.request
import ctypes

# Force UTF-8 Mode
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# -----------------------------------------------------------------------------
# 1. DISPATCHER FOR SUBPROCESS WORKERS
# -----------------------------------------------------------------------------
if False:
    import scapy.all
    import rich
    import rich.prompt
    import rich.panel
    import rich.table
    import rich.progress
    import mac_vendor_lookup
    import psutil
    import cryptography
    import cryptography.hazmat.primitives.ciphers.aead

if len(sys.argv) > 1 and sys.argv[1] == "--run-script":
    script_path = sys.argv[2]
    script_args = sys.argv[3:]
    sys.argv = [script_path] + script_args
    import runpy
    runpy.run_path(script_path, run_name="__main__")
    sys.exit(0)

# -----------------------------------------------------------------------------
# 2. UAC ELEVATION (Yêu cầu quyền Administrator cho Network/Raw Sockets)
# -----------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def elevate():
    if sys.platform == "win32" and not is_admin():
        try:
            if getattr(sys, "frozen", False):
                exe = sys.executable
                params = " ".join([f'"{a}"' for a in sys.argv[1:]])
            else:
                exe = sys.executable
                params = f'"{os.path.abspath(__file__)}" ' + " ".join([f'"{a}"' for a in sys.argv[1:]])
            
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if int(ret) > 32:
                sys.exit(0)
        except Exception:
            pass

elevate()

# -----------------------------------------------------------------------------
# 3. DIRECTORY SETUP
# -----------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = getattr(sys, "_MEIPASS", APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = APP_DIR

os.chdir(APP_DIR)
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)

import app_server
import webview

def find_available_port(start_port=8080):
    for port in range(start_port, start_port + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) != 0:
                return port
            # Kiểm tra xem cổng này có phải là backend cũ đang chạy không
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/telemetry", timeout=0.5) as r:
                    if r.status == 200:
                        return port
            except Exception:
                pass
    return start_port

def wait_for_server(port, timeout=5.0):
    start = time.time()
    url = f"http://127.0.0.1:{port}/api/telemetry"
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.1)
    return False

def on_closed():
    app_server.stop_server()
    os._exit(0)

def main():
    target_port = find_available_port(8080)
    
    # Khởi động Backend HTTP Server trong background thread
    server_ready = False
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{target_port}/api/telemetry", timeout=0.5) as r:
            if r.status == 200:
                server_ready = True
    except Exception:
        server_ready = False

    if not server_ready:
        app_server.start_server_in_thread(target_port)
        wait_for_server(target_port, timeout=4.0)

    app_url = f"http://127.0.0.1:{target_port}"

    # Tạo cửa sổ Native Desktop App tích hợp WebView2
    window = webview.create_window(
        title="REDOPS // Security Operations & Control Center",
        url=app_url,
        width=1340,
        height=880,
        min_size=(1024, 680),
        background_color="#0a0e17",
        text_select=True,
    )
    window.events.closed += on_closed
    
    # Khởi động GUI Loop
    webview.start(debug=False)

if __name__ == "__main__":
    main()
