import os
import sys

# Force UTF-8 Mode globally before any other imports
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"

import time
import socket
import ipaddress
import platform
import psutil
import msvcrt
import threading
import subprocess
import signal
import webbrowser
import secrets
from datetime import datetime

# Khởi tạo Token bảo mật cho phiên làm việc
os.environ["API_AUTH_TOKEN"] = secrets.token_hex(16)

from rich.console import Console, Group
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.prompt import Prompt
from rich.align import Align
from rich import box

# Bắt buộc ép Windows CMD chạy ở chuẩn UTF-8
if os.name == 'nt':
    os.system('chcp 65001 > nul')

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    else:
        import codecs
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())
except Exception:
    pass

console = Console(force_terminal=True, color_system="truecolor", emoji=False)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from monitoring.reporter import report_event as report_dashboard_event
    from monitoring.reporter import report_module as report_dashboard_module
except ImportError:
    def report_dashboard_event(*args, **kwargs):
        return False

    def report_dashboard_module(*args, **kwargs):
        return False

# --- CACHED SYSTEM INFO ---
cached_nic_name = None
cached_local_ip = None
cached_is_admin = None
cached_default_subnet = None

last_sys_time = 0
cached_cpu = "0.0%"
cached_ram = "0.0%"

def get_cpu_ram():
    global last_sys_time, cached_cpu, cached_ram
    now = time.time()
    if now - last_sys_time > 1.0:
        # psutil.cpu_percent(interval=None) calculates since last call. 
        # Calling it every 1 second gives a stable 1-second average.
        cached_cpu = f"{psutil.cpu_percent(interval=None)}%"
        cached_ram = f"{psutil.virtual_memory().percent}%"
        last_sys_time = now
    return cached_cpu, cached_ram

def check_admin():
    global cached_is_admin
    if cached_is_admin is not None:
        return cached_is_admin
    try:
        import ctypes
        cached_is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        cached_is_admin = False
    return cached_is_admin

last_ip_try = 0
def get_local_ip():
    global cached_local_ip, last_ip_try
    if cached_local_ip is not None and cached_local_ip != "127.0.0.1":
        return cached_local_ip
    
    now = time.time()
    if now - last_ip_try < 5.0: # Thử lại sau mỗi 5s nếu mất mạng
        return cached_local_ip if cached_local_ip else "127.0.0.1"
    
    last_ip_try = now
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Truy vấn bảng định tuyến hệ điều hành bằng địa chỉ Private giả (Không cần Internet)
            s.connect(("10.255.255.255", 1))
            cached_local_ip = s.getsockname()[0]
    except:
        cached_local_ip = "127.0.0.1"
    return cached_local_ip

def get_default_subnet():
    global cached_default_subnet
    if cached_default_subnet:
        return cached_default_subnet
    import ipaddress
    local_ip = get_local_ip()
    if local_ip == "127.0.0.1": 
        cached_default_subnet = ""
        return cached_default_subnet
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    net = ipaddress.IPv4Network(f"{local_ip}/{addr.netmask}", strict=False)
                    # Nếu mạng quá to (như /16, /8), ép về /24 để tránh treo máy khi quét
                    if net.prefixlen < 20:
                        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                    cached_default_subnet = str(net)
                    return cached_default_subnet
    except:
        pass
    cached_default_subnet = ""
    return cached_default_subnet


def is_local_l2_target(target, allow_all=False):
    """Only allow usable IPv4 hosts on the active local subnet."""
    if not target:
        return False
    if target.strip().lower() in {"all", "*"}:
        return allow_all

    try:
        target_ip = ipaddress.ip_address(target.strip())
        local_ip = ipaddress.ip_address(get_local_ip())
    except ValueError:
        return False

    if target_ip.version != 4 or target_ip == local_ip:
        return False

    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family != socket.AF_INET or addr.address != str(local_ip) or not addr.netmask:
                continue
            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            return target_ip in network and target_ip not in {network.network_address, network.broadcast_address}
    return False


def is_local_l2_subnet(subnet):
    """Validate that a requested subnet is a bounded part of the active L2 network."""
    try:
        requested = ipaddress.ip_network(subnet, strict=False)
        local_ip = ipaddress.ip_address(get_local_ip())
    except ValueError:
        return False

    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family != socket.AF_INET or addr.address != str(local_ip) or not addr.netmask:
                continue
            local_network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            return requested.subnet_of(local_network) and requested.num_addresses <= 256
    return False

def get_default_gateway():
    try:
        from scapy.all import conf
        # Lấy Default Gateway từ bảng định tuyến OS (Destination 0.0.0.0)
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        local_ip = get_local_ip()
        if local_ip != "127.0.0.1":
            parts = local_ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        return "10.12.112.1"

def get_real_nic_name():
    global cached_nic_name
    if cached_nic_name is not None:
        return cached_nic_name
    try:
        cmd = "powershell -NoProfile -NonInteractive -Command \"(Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1).InterfaceDescription\""
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
        cached_nic_name = output if output else "Unknown Adapter"
    except:
        cached_nic_name = "Unknown Adapter"
    return cached_nic_name


# --- MODULE REGISTRY ---
class Module:
    def __init__(self, name, short_desc, desc, runner_func):
        self.name = name
        self.short_desc = short_desc
        self.desc = desc
        self.runner_func = runner_func

def get_target_choices(l2_only=False):
    """Đọc topology.json và trả về danh sách các mục tiêu đã quét được."""
    try:
        import json
        mon_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitoring")
        topo_path = os.path.join(mon_dir, "topology.json")
        if os.path.exists(topo_path):
            with open(topo_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Loại bỏ các node mang nhãn THIS PC hoặc GATEWAY
            nodes = [
                n for n in data.get("nodes", []) 
                if n.get("group") == "victim" and "THIS PC" not in n.get("hostname", "") and "GATEWAY" not in n.get("hostname", "")
            ]
            if l2_only:
                nodes = [
                    n for n in nodes
                    if n.get("is_l2_local", False) is True and n.get("mac") not in ("Routed-L3-Host", "00-0c-42-00-00-02")
                ]
            return nodes
    except Exception:
        pass
    return []

def select_target_ip(prompt_text, default_ip="", l2_only=False, allow_all=False):
    targets = get_target_choices(l2_only=l2_only)
    if targets:
        console.print("\n[bold cyan]📋 DANH SÁCH THIẾT BỊ VỪA QUÉT ĐƯỢC TRONG MẠNG LAN:[/bold cyan]")
        for idx, node in enumerate(targets, 1):
            ip = node.get("ip")
            mac = node.get("mac", "")
            name = node.get("hostname") or node.get("vendor", "Device")
            console.print(f"  [{idx}] [bold yellow]{ip}[/bold yellow] - {name} ({mac})")
        choice = Prompt.ask(f"[cyan]{prompt_text} (Nhập số [1-{len(targets)}] hoặc IP)[/cyan]")
        if choice.strip().isdigit():
            val = int(choice.strip())
            if 1 <= val <= len(targets):
                selected_ip = targets[val - 1].get("ip")
                console.print(f"[green][+] Đã chọn IP: [bold yellow]{selected_ip}[/bold yellow][/green]\n")
                return selected_ip
            elif val == 0:
                manual_ip = Prompt.ask("[cyan]Nhập IP thủ công[/cyan]").strip()
                return manual_ip
        elif choice.strip():
            return choice.strip()

    selected_ip = Prompt.ask(f"[cyan]{prompt_text}[/cyan]").strip() or default_ip
    return selected_ip

def run_mitm_sniffer():
    console.print("\n[bold cyan]💡 CHỌN CHẾ ĐỘ GIÁM SÁT LƯU LƯỢNG (MITM):[/bold cyan]")
    console.print("  • Gõ [bold yellow]ALL[/bold yellow] (hoặc bấm Enter): Giám sát lưu lượng [bold green]TOÀN BỘ MẠNG LAN[/bold green]")
    console.print("  • Hoặc chọn số [1, 2, 3...] bên dưới để giám sát 1 thiết bị cụ thể:\n")
    target = select_target_ip(
        "Nhập IP mục tiêu (Gõ ALL hoặc bấm Enter để GIÁM SÁT TOÀN MẠNG LAN)",
        default_ip="ALL",
        l2_only=True,
        allow_all=True,
    )
    if not target:
        return None, None
    gateway = Prompt.ask("[cyan]Nhập IP Gateway (Bỏ trống = Tự lấy IP Gateway Local)[/cyan]").strip()
    if not gateway:
        gateway = get_default_gateway() or "10.12.112.1"
    return [sys.executable, "attacks/mitm_sniffer.py", target, gateway], f"Mode: {target}"

def run_arp_vkill():
    console.print("\n[bold cyan]💡 CHỌN CHẾ ĐỘ KIỂM THỬ TỪ CHỐI DỊCH VỤ (ARP SPOOFING):[/bold cyan]")
    console.print("  • Gõ [bold yellow]ALL[/bold yellow] (hoặc bấm Enter): Cô lập [bold red]TOÀN BỘ MẠNG LAN[/bold red]")
    console.print("  • Hoặc chọn số [1, 2, 3...] bên dưới để cô lập 1 thiết bị cụ thể:\n")
    target = select_target_ip(
        "Nhập IP mục tiêu (Gõ ALL hoặc bấm Enter để CÔ LẬP TOÀN MẠNG LAN)",
        default_ip="ALL",
        l2_only=True,
        allow_all=True,
    )
    if not target:
        return None, None
    gateway = Prompt.ask("[cyan]Nhập IP Gateway (Bỏ trống = Tự lấy IP Gateway Local)[/cyan]").strip()
    if not gateway:
        gateway = get_default_gateway() or "10.12.112.1"
    return [sys.executable, "attacks/arp_vkill.py", target, gateway], f"Mode: {target}"

def run_dhcp_rogue():
    subnet = Prompt.ask("[cyan]Nhập Subnet mục tiêu (Bỏ trống để Tự Động Quét)[/cyan]")
    if not subnet: subnet = get_default_subnet()
    if subnet:
        return [sys.executable, "attacks/dhcp_rogue.py", subnet], "DHCP Starvation/Rogue Server"
    return None, None

def dashboard_backend_is_ready(timeout=1.0):
    import json
    import urllib.request

    try:
        with urllib.request.urlopen("http://localhost:8080/api/telemetry", timeout=timeout) as response:
            if response.status != 200:
                return False
            payload = json.load(response)
            return isinstance(payload, dict) and "system" in payload and "network" in payload
    except Exception:
        return False

def build_module_metrics(module_name, proc, duration):
    metrics = {
        "pid": proc.pid,
        "exit_code": proc.returncode,
        "duration_seconds": duration,
    }

    if module_name == "LAN Scanner & Device Finder":
        try:
            import json
            topology_path = os.path.join(BASE_DIR, "monitoring", "topology.json")
            with open(topology_path, "r", encoding="utf-8") as topology_stream:
                topology = json.load(topology_stream)
            metrics.update({
                "device_count": len(topology.get("nodes", [])),
                "link_count": len(topology.get("links", [])),
                "subnet": topology.get("subnet", "Unknown"),
            })
        except (OSError, ValueError):
            pass

    return metrics

def run_open_dashboard():
    dashboard_status = "[bold green][*] Dashboard Backend đã được chạy ngầm từ lúc bật Manager![/bold green]"
    # Kiểm tra xem cổng 8080 có đang mở không (có thể dashboard bị lỗi)
    try:
        if not dashboard_backend_is_ready():
            raise RuntimeError("Dashboard backend is unavailable")
        console.print(f"\n{dashboard_status}")
        console.print("[cyan]Đang mở trình duyệt web truy cập Dashboard SOC/NOC...[/cyan]")
        time.sleep(1)
        webbrowser.open("http://localhost:8080")
        return ["__dashboard_open__"], "localhost:8080"
    except:
        dashboard_status = "[bold red][!] Dashboard Backend dường như không hoạt động. Hãy kiểm tra lại cổng 8080.[/bold red]"
        console.print(f"\n{dashboard_status}")
        time.sleep(2)
        return None, None

def run_net_scan():
    # net_scan.py handles all prompts interactively — no CLI flags needed
    return [sys.executable, "attacks/net_scan.py"], "Interactive Subnet Discovery"
def run_share_hunter():
    return [sys.executable, "attacks/share_hunter.py"], "Local Subnet"

def run_l4_stress_tester():
    default_gw = get_default_gateway() or "127.0.0.1"
    console.print("\n[bold cyan]L4 SYN / UDP STRESS TESTER[/bold cyan]")
    console.print(f"  Gateway detected: [bold yellow]{default_gw}[/bold yellow]\n")

    targets = get_target_choices(l2_only=False)
    if targets:
        console.print("[bold cyan]Devices from last scan:[/bold cyan]")
        for idx, node in enumerate(targets, 1):
            ip   = node.get("ip")
            mac  = node.get("mac", "")
            name = node.get("hostname") or node.get("vendor", "Device")
            console.print(f"  [[bold yellow]{idx}[/bold yellow]] [cyan]{ip}[/cyan] — {name} ({mac})")
        console.print(f"\n[dim]Leave blank or Enter to test ALL {len(targets)} device(s)[/dim]")
        choice = Prompt.ask("[cyan]Select target (number / IP, or Enter for ALL)[/cyan]", default="").strip()
    else:
        console.print("[yellow][!] No topology data — run LAN Scanner first for device list.[/yellow]")
        choice = Prompt.ask(f"[cyan]Enter target IP (default: {default_gw})[/cyan]", default=default_gw).strip()

    # Resolve choice -> target IP or ALL
    if not choice:
        target = "ALL"
    elif choice.isdigit() and targets and 1 <= int(choice) <= len(targets):
        target = targets[int(choice) - 1].get("ip")
        console.print(f"[green][+] Target: [bold yellow]{target}[/bold yellow][/green]")
    else:
        target = choice

    if target != "ALL":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            console.print("[red][!] Invalid IPv4 address.[/red]")
            return None, None

    port = Prompt.ask("[cyan]Target port (default: 80)[/cyan]", default="80").strip()
    try:
        if not 1 <= int(port) <= 65535:
            raise ValueError
    except ValueError:
        console.print("[red][!] Port must be between 1 and 65535.[/red]")
        return None, None

    console.print("\n  [1] BOTH — Combined SYN + UDP flood [bold green](default)[/bold green]")
    console.print("  [2] UDP  — Bandwidth saturation via UDP")
    console.print("  [3] SYN  — TCP connection table exhaustion\n")
    mode_choice = Prompt.ask("[cyan]Select mode (1/2/3)[/cyan]", default="1").strip()
    mode = {"2": "UDP", "3": "SYN"}.get(mode_choice, "BOTH")

    duration = Prompt.ask("[cyan]Duration in seconds (default: 30)[/cyan]", default="30").strip()
    try:
        duration = max(5, int(duration))
    except ValueError:
        duration = 30

    threads = Prompt.ask("[cyan]Thread count (default: 500)[/cyan]", default="500").strip()
    try:
        threads = max(10, min(int(threads), 1000))
    except ValueError:
        threads = 500

    label = f"ALL devices" if target == "ALL" else target
    return [sys.executable, "attacks/l4_stress_tester.py", target, port, mode, str(duration), str(threads)], f"L4 [{mode}] -> {label}:{port}"

def run_cve_exploit():
    return [sys.executable, "attacks/router_cve_exploit.py"], "Router & CCTV Exploit"


def run_c2_listener():
    return [sys.executable, "attacks/c2_listener.py"], "Reverse Shell & Beacon Listener"

MODULE_REGISTRY = [
    Module(
        "LAN Scanner & Device Finder", 
        "Scan Subnet & Phân tích Thiết bị", 
        "[bold cyan]Master Recon & Device Intelligence[/bold cyan]\n\nRà quét toàn bộ mạng LAN để định danh thiết bị, tra cứu nhà sản xuất (OUI), phân giải tên miền (NetBIOS/mDNS) và trích xuất thông tin dịch vụ (Web Title/Banner).",
        run_net_scan
    ),
    Module(
        "MITM Sniffer", 
        "Giám sát & Phân tích Lưu lượng Mạng", 
        "[bold cyan]Layer 2/3 Interception[/bold cyan]\n\nCan thiệp và phân tích toàn bộ lưu lượng của một thiết bị cụ thể hoặc TOÀN BỘ MẠNG LAN.\n\n[bold green]Cơ chế:[/bold green]\nHỗ trợ bóc tách HTTP Host, nhận diện ứng dụng (TikTok, Facebook, Zalo...) và truy vấn DNS theo thời gian thực.",
        run_mitm_sniffer
    ),
    Module(
        "ARP Spoofing (DoS)", 
        "Kiểm thử Cô lập Mạng (DoS)", 
        "[bold red]Network Isolation & Denial of Service[/bold red]\n\nKiểm thử khả năng chịu lỗi bằng cách ngắt kết nối mạng của một mục tiêu duy nhất, hoặc cô lập toàn bộ các thiết bị trong mạng LAN cùng lúc.\n\n[bold green]Cơ chế:[/bold green]\nPhát sóng gói tin ARP giả mạo (ARP Spoofing / Blackhole) để thao túng bảng định tuyến của Router và Client.",
        run_arp_vkill
    ),
    Module(
        "L4 SYN / UDP Stress Tester", 
        "Kiểm thử Chịu tải & Băng thông L4", 
        "[bold red]Layer 4 Flood Engine[/bold red]\n\nThực hiện bài kiểm tra khả năng chịu tải (Stress Test) thông qua việc gửi lưu lượng lớn gói tin SYN / UDP vào Router hoặc IP/Cổng trong LAN.\n\n[bold green]Cơ chế:[/bold green]\nSử dụng đa luồng (Multi-threaded UDP & SYN socket flooding).",
        run_l4_stress_tester
    ),
    Module(
        "Public Share Hunter (PC/NAS)",
        "Kiểm tra Ổ Đĩa Mạng & Lỗ Hổng Mở",
        "[bold magenta]LAN File Share Auditor[/bold magenta]\n\nChuyên dụng tìm kiếm và kiểm tra các thiết bị (PC, Mac, NAS, Mobile) đang cấu hình chia sẻ ổ đĩa SMB công khai, hoặc máy chủ FTP thiếu bảo mật trong LAN.\n\n[bold green]Cơ chế:[/bold green]\nBỏ qua Router/Camera, tập trung rà quét Port 445/21 và kiểm tra quyền truy cập tệp tin.",
        run_share_hunter
    ),
    Module(
        "Router & CCTV Vuln Exploit",
        "Khai thác & Đánh giá Bảo mật Router/CCTV",
        "[bold red]Automated Vulnerability Exploitation[/bold red]\n\nCông cụ tự động rà quét và kiểm thử đánh giá lỗ hổng bảo mật trên các Router và Camera An Ninh (Dahua, Hikvision, VNPT, Viettel).\n\n[bold green]Cơ chế:[/bold green]\nTự động triển khai các kịch bản kiểm thử (CVE payload: Command Injection, Path Traversal) và kiểm tra xác thực mặc định.",
        run_cve_exploit
    ),

    Module(
        "Reverse Shell & Beacon Listener",
        "Lắng nghe & Chiếm quyền Điều khiển (Port 4444)",
        "[bold green]C2 Reverse Shell & Beacon Listener[/bold green]\n\nMáy chủ lắng nghe các kết nối đảo ngược (Reverse Shell) từ mã độc (KB5034441.exe / payload.exe) gửi về tại cổng 4444.\n\n[bold green]Cơ chế:[/bold green]\nSử dụng xác thực HMAC-SHA256 và mã hóa liên lạc bằng AES-GCM.",
        run_c2_listener
    ),
    Module(
        "Open Live Dashboard",
        "Mở bảng điều khiển SOC",
        "[bold cyan]Real-time Intelligence[/bold cyan]\n\nMở giao diện Dashboard SOC/NOC trên trình duyệt web. Máy chủ Backend (Port 8080) hoạt động ngầm để thu thập chỉ số mạng, CPU, RAM.",
        run_open_dashboard
    )
]

# --- GLOBAL STATE ---
selected_idx = 0
last_target = "None"
ping_ms = "Checking..."
is_running = True
logs = ["[18:00:00] [cyan]Hệ thống đã khởi động.[/cyan]", "[18:00:00] [green]Đang chờ lệnh từ bạn...[/green]"]

def log_event(msg, level="info"):
    timestamp = datetime.now().strftime("%H:%M:%S")
    color = "white"
    if level == "succ": color = "green"
    elif level == "err": color = "red"
    elif level == "warn": color = "yellow"
    elif level == "cyan": color = "cyan"
    
    logs.append(f"[{timestamp}] [{color}]{msg}[/{color}]")
    if len(logs) > 7:
        logs.pop(0)

def bg_ping():
    global ping_ms
    while is_running:
        try:
            gw = get_default_gateway()
            if not gw: gw = "127.0.0.1"
            if os.name == 'nt':
                output = subprocess.check_output(f"ping -n 1 -w 1000 {gw}", shell=True, text=True, stderr=subprocess.DEVNULL)
                for line in output.split('\n'):
                    if "time=" in line or "thời gian=" in line:
                        ms = line.split("time=")[-1].split("ms")[0].strip() if "time=" in line else line.split("thời gian=")[-1].split("ms")[0].strip()
                        ping_ms = f"{ms} ms (GW)"
                        break
                else:
                    ping_ms = "Timeout"
            else:
                output = subprocess.check_output(f"ping -c 1 -W 1 {gw}", shell=True, text=True, stderr=subprocess.DEVNULL)
                ping_ms = output.split("time=")[-1].split(" ")[0] + " ms (GW)"
        except:
            ping_ms = "Offline"
        time.sleep(2)


# --- UI GENERATORS ---
def generate_header():
    admin_status = "Administrator" if check_admin() else "User"
    return Panel(
        Group(
            Align.center("[bold cyan]NGUOI DEP TRAI NHAT THE GIOI[/bold cyan]"),
            Align.center("[white]Advanced Security Operations Framework[/white]"),
            Align.center(f"[cyan]v2.0 (Refactored) | {admin_status} | {platform.system()} | READY[/cyan]")
        ),
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )

def generate_menu():
    text = Text()
    for i, mod in enumerate(MODULE_REGISTRY):
        if i == selected_idx:
            text.append(f" ▶ {mod.name}\n", style="bold green")
            text.append(f"   {mod.short_desc}\n\n", style="bold green")
        else:
            text.append(f" ◆ {mod.name}\n", style="bold white")
            text.append(f"  {mod.short_desc}\n\n", style="dim white")  
    return Panel(text, title="[bold cyan]MODULES[/bold cyan]", border_style="cyan", box=box.ROUNDED)

def generate_description():
    desc = MODULE_REGISTRY[selected_idx].desc
    return Panel(Text.from_markup(desc), title="[bold cyan]DESCRIPTION[/bold cyan]", border_style="cyan", box=box.ROUNDED)

def generate_target():
    text = Text()
    text.append("Mục tiêu gần nhất:\n", style="dim white")
    text.append(f"{last_target}", style="bold yellow")
    return Panel(text, title="[bold cyan]TARGET[/bold cyan]", border_style="cyan", box=box.ROUNDED)

def generate_system_info():
    cpu, ram = get_cpu_ram()

    primary_nic = get_real_nic_name()
    if len(primary_nic) > 28:
        primary_nic = primary_nic[:25] + "..."
    
    text = Text()
    text.append(f"CPU   : ", style="cyan")
    text.append(f"{cpu}\n", style="white")
    text.append(f"RAM   : ", style="cyan")
    text.append(f"{ram}\n", style="white")
    text.append(f"PING  : ", style="cyan")
    text.append(f"{ping_ms}\n", style="white")
    text.append(f"NIC   : ", style="cyan")
    text.append(f"{primary_nic}\n", style="white")
    text.append(f"IPv4  : ", style="cyan")
    text.append(f"{get_local_ip()}\n", style="white")
    text.append(f"Time  : ", style="cyan")
    text.append(f"{datetime.now().strftime('%H:%M:%S')}\n", style="white")
    
    return Panel(text, title="[bold cyan]SYSTEM[/bold cyan]", border_style="cyan", box=box.ROUNDED)

def generate_logs():
    text = Text.from_markup("\n".join(logs))
    return Panel(text, title="[bold cyan]LIVE LOGS[/bold cyan]", border_style="cyan", box=box.ROUNDED)

def generate_footer():
    return Align.center("[bold white]↑↓[/bold white] Chuyển đổi   [bold white][ENTER][/bold white] Chạy Module   [bold white][Q][/bold white] Dừng Module   [bold white][ESC][/bold white] Thoát")

def make_layout():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=5),
        Layout(name="body"),
        Layout(name="footer", size=1)
    )
    
    layout["body"].split_row(
        Layout(name="menu", ratio=1),
        Layout(name="center", ratio=1),
        Layout(name="right", ratio=1)
    )
    
    layout["center"].split_column(
        Layout(name="desc", ratio=2),
        Layout(name="target", size=5)
    )
    
    layout["right"].split_column(
        Layout(name="sys", size=8),
        Layout(name="log")
    )
    
    layout["header"].update(generate_header())
    layout["menu"].update(generate_menu())
    layout["desc"].update(generate_description())
    layout["target"].update(generate_target())
    layout["sys"].update(generate_system_info())
    layout["log"].update(generate_logs())
    layout["footer"].update(generate_footer())
    
    return layout

def clear_screen():
    console.clear()

# --- CONTROLLER ---
def get_key():
    if msvcrt.kbhit():
        char = msvcrt.getch()
        if char in (b'\x00', b'\xe0'):
            char = msvcrt.getch()
            if char == b'H': return 'UP'
            if char == b'P': return 'DOWN'
        elif char == b'\r': return 'ENTER'
        elif char == b'\x1b': return 'ESC'
    return None

def execute_tool(idx):
    global last_target
    mod = MODULE_REGISTRY[idx]
    cleanup_sensitive = mod.name.strip() in {
        "ARP Spoofing (DoS)",
        "ARP Kill",
        "ARP Kill (Subnet)",
        "MITM Sniffer",
    }
    
    while True:
        clear_screen()
        module_title = mod.name.upper()
        header = Panel(f"[bold cyan]KHỞI CHẠY MODULE: {module_title}[/bold cyan]\n[dim]Attack Operations Center | attack.py | Status : ONLINE[/dim]", border_style="cyan", expand=False)
        console.print(header)
        console.print()
        
        cmd_parts, target_info = mod.runner_func()
        proc = None
        operation_started_at = None
        stop_requested = False
        
        if cmd_parts:
            if target_info: last_target = target_info
            
            if cmd_parts != ["__dashboard_open__"]:
                operation_started_at = time.time()
                report_dashboard_module(
                    mod.name,
                    "STARTING",
                    target=target_info,
                    message=f"Preparing {mod.name}.",
                    started_at=operation_started_at,
                )
                try:
                    # Dùng spinner="line" mượt hơn và nhỏ gọn hơn dots12
                    with console.status(f"[bold cyan]Authorizing Core...[/bold cyan]", spinner="line") as status:
                        time.sleep(0.4)
                        status.update(f"[bold cyan]Allocating memory buffers for {mod.name}...[/bold cyan]")
                        time.sleep(0.5)
                        status.update(f"[bold green]Launching Module: {mod.name}...[/bold green]")
                        time.sleep(0.3)
                    
                    console.print(f"\n[bold cyan][*] Module is running. Press [white]Q[/white] to stop.[/bold cyan]\n")
                    
                    proc = subprocess.Popen(
                        cmd_parts,
                        cwd=BASE_DIR,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                    report_dashboard_module(
                        mod.name,
                        "RUNNING",
                        target=target_info,
                        message=f"{mod.name} is running.",
                        metrics={"pid": proc.pid},
                        started_at=operation_started_at,
                    )
                    
                    while proc.poll() is None:
                        if msvcrt.kbhit():
                            key = msvcrt.getch().lower()
                            if key == b'q':
                                stop_requested = True
                                report_dashboard_module(
                                    mod.name,
                                    "STOPPING",
                                    target=target_info,
                                    message=f"Stopping {mod.name} and waiting for cleanup.",
                                    metrics={"pid": proc.pid},
                                    started_at=operation_started_at,
                                )
                                console.print("\n[bold yellow][!] Đang chờ module dọn dẹp và dừng an toàn (Tối đa 30s)...[/bold yellow]")
                                proc.send_signal(signal.CTRL_BREAK_EVENT)
                                try:
                                    proc.wait(timeout=30)
                                except subprocess.TimeoutExpired:
                                    if cleanup_sensitive:
                                        console.print("\n[bold yellow][!] Module đang cleanup trạng thái mạng; manager sẽ không force-kill.[/bold yellow]")
                                        continue
                                    force = Prompt.ask("\n[bold red][!] Module vẫn đang chạy (có thể đang khôi phục ARP). Bạn có muốn ép tắt ngay lập tức? (Y/n)[/bold red]", default="Y")
                                    if force.lower() == 'y':
                                        proc.kill()
                                        proc.wait()
                                        break
                                    else:
                                        console.print("[bold green]Tiếp tục chờ module hoàn tất...[/bold green]")
                                        continue
                                break
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    stop_requested = True
                    report_dashboard_module(
                        mod.name,
                        "STOPPING",
                        target=target_info,
                        message=f"Keyboard interrupt received. Waiting for {mod.name} cleanup.",
                        metrics={"pid": proc.pid if proc else None},
                        started_at=operation_started_at,
                    )
                    console.print("\n[bold red][!] Đã nhận lệnh Ctrl+C, đang chờ module dọn dẹp và dừng an toàn (Tối đa 30s)...[/bold red]")
                    if proc and proc.poll() is None:
                        proc.send_signal(signal.CTRL_BREAK_EVENT)
                        while proc.poll() is None:
                            try:
                                proc.wait(timeout=30)
                            except subprocess.TimeoutExpired:
                                if cleanup_sensitive:
                                    console.print("\n[bold yellow][!] Module đang cleanup trạng thái mạng; manager sẽ không force-kill.[/bold yellow]")
                                    continue
                                force = Prompt.ask("\n[bold red][!] Module vẫn đang chạy (có thể đang khôi phục ARP). Bạn có muốn ép tắt ngay lập tức? (Y/n)[/bold red]", default="Y")
                                if force.lower() == 'y':
                                    proc.kill()
                                    proc.wait()
                                    break
                                else:
                                    console.print("[bold green]Tiếp tục chờ module hoàn tất...[/bold green]")
                                    continue
                finally:
                    if proc and proc.poll() is None:
                        # Nếu rơi vào finally mà chưa tắt, thử đợi thêm 2s
                        try:
                            proc.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            pass # Không tự ý kill() ở đây nữa để bảo toàn trạng thái mạng nếu bạn chọn 'n'

                if proc and proc.returncode is not None:
                    duration = round(time.time() - operation_started_at, 1) if operation_started_at else 0
                    if stop_requested:
                        report_status = "STOPPED"
                        report_message = f"{mod.name} stopped after cleanup."
                    elif proc.returncode == 0:
                        report_status = "COMPLETED"
                        report_message = f"{mod.name} completed successfully."
                    else:
                        report_status = "FAILED"
                        report_message = f"{mod.name} exited with code {proc.returncode}."
                    report_dashboard_module(
                        mod.name,
                        report_status,
                        target=target_info,
                        message=report_message,
                        metrics=build_module_metrics(mod.name, proc, duration),
                        started_at=operation_started_at,
                    )
                
                Prompt.ask("\n[bold yellow]Nhấn ENTER để tiếp tục...[/bold yellow]")
            else:
                Prompt.ask("\n[bold yellow]Nhấn ENTER để tiếp tục...[/bold yellow]")
            
            console.print("\n[bold yellow]--------------------------------------------------------------[/bold yellow]")
            if proc and proc.returncode == 0:
                console.print("[bold green][+] Module đã thực thi xong và phục hồi hệ thống an toàn (Exit Code 0).[/bold green]")
            elif proc and proc.returncode == 1:
                console.print("[bold red][!] Module kết thúc với lỗi hoặc bị gián đoạn (Exit Code 1).[/bold red]")
            elif proc and proc.returncode is not None:
                console.print(f"[bold yellow][*] Module đã dừng (Exit Code: {proc.returncode}).[/bold yellow]")
            else:
                console.print("[bold cyan][*] Quá trình thực thi hoàn tất.[/bold cyan]")
            
            action = Prompt.ask("[bold green][B] Quay lại Menu | [R] Chạy lại Module này[/bold green]", choices=["B", "b", "R", "r"], default="B")
            if action.lower() == 'b':
                if stop_requested:
                    return f"Đã dừng: {mod.name}", "cyan"
                elif proc and proc.returncode != 0:
                    return f"Lỗi thực thi: {mod.name}", "err"
                return f"Đã chạy: {mod.name}", "succ"
            # Nếu chọn 'r', vòng lặp while True sẽ lặp lại!
        else:
            return "Đã hủy chạy module.", "warn"

def main():
    global selected_idx, is_running
    log_event("Đang khởi động lõi Framework...", "cyan")
    
    t_ping = threading.Thread(target=bg_ping, daemon=True)
    t_ping.start()
    
    # Start Dashboard Server ONCE in the background
    dashboard_proc = None
    try:
        if dashboard_backend_is_ready():
            log_event("Dashboard Backend đang hoạt động sẵn trên Port 8080", "succ")
        else:
            dashboard_path = os.path.join(BASE_DIR, "app_server.py")
            dashboard_proc = subprocess.Popen(
                [sys.executable, dashboard_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            time.sleep(1)
            if dashboard_proc.poll() is not None or not dashboard_backend_is_ready():
                log_event("Dashboard Backend không thể bật (Cổng 8080 có thể bị chiếm)", "err")
            else:
                log_event("Dashboard Backend đã được bật (Port 8080)", "succ")
    except Exception as e:
        log_event(f"Không thể bật Dashboard Backend: {e}", "err")

    if dashboard_backend_is_ready():
        report_dashboard_module(
            "NEXUS Core",
            "IDLE",
            target="None",
            message="Waiting for an operation.",
        )

    try:
        while is_running:
            action_selected = False
            with Live(make_layout(), refresh_per_second=10, screen=True) as live:
                while not action_selected and is_running:
                    key = get_key()
                    if key == 'UP':
                        selected_idx = max(0, selected_idx - 1)
                    elif key == 'DOWN':
                        selected_idx = min(len(MODULE_REGISTRY) - 1, selected_idx + 1)
                    elif key == 'ENTER':
                        action_selected = True
                    elif key == 'ESC':
                        is_running = False
                    
                    if not action_selected:
                        live.update(make_layout())
                        time.sleep(0.02) # Giảm độ trễ bàn phím xuống 20ms để hết lag
            
            if not is_running:
                break
                
            res_msg, res_level = execute_tool(selected_idx)
            log_event(res_msg, res_level)
            time.sleep(1)
    finally:
        is_running = False
        if dashboard_backend_is_ready():
            report_dashboard_module(
                "NEXUS Core",
                "STOPPED",
                target="None",
                message="Manager shutdown requested.",
            )
        if dashboard_proc and dashboard_proc.poll() is None:
            try:
                dashboard_proc.send_signal(signal.CTRL_BREAK_EVENT)
                dashboard_proc.wait(timeout=3)
            except:
                dashboard_proc.kill()
                
        clear_screen()
        console.print("[bold cyan][*] System Shutdown. Tạm biệt Bạn![/bold cyan]")

if __name__ == "__main__":
    main()
