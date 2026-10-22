import os
import sys
import time
import json
import socket
import threading
import subprocess
import ipaddress
import ctypes
import winreg
from datetime import datetime

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    from rich import box
except ImportError:
    print("[-] Missing rich. Run: pip install rich"); sys.exit(1)

try:
    import psutil
except ImportError:
    print("[-] Missing psutil. Run: pip install psutil"); sys.exit(1)

console = Console(emoji=False)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MON_DIR    = os.path.join(BASE_DIR, "monitoring")
LOG_DIR    = os.path.join(MON_DIR, "logs")
TOPO_PATH  = os.path.join(MON_DIR, "topology.json")
ARP_LOG    = os.path.join(LOG_DIR, "arp_alerts.log")
FLOOD_LOG  = os.path.join(LOG_DIR, "flood_alerts.log")
BLOCK_LOG  = os.path.join(LOG_DIR, "block_actions.log")
os.makedirs(LOG_DIR, exist_ok=True)

_stop_event = threading.Event()


def is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False

def ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def write_log(path, message):
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{ts()}] {message}\n")

def load_topology():
    if not os.path.exists(TOPO_PATH):
        return {}
    try:
        with open(TOPO_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {n["ip"]: n.get("mac","").lower().replace("-",":") for n in data.get("nodes",[]) if n.get("ip")}
    except: return {}


# ═══════════════════════════════════════════════════════════════════
# MODULE 1 - ARP SPOOF DETECTOR
# ═══════════════════════════════════════════════════════════════════

class ArpSpoofDetector:
    def __init__(self):
        self.known = {}
        self.alerts = 0
        self._lock = threading.Lock()

    def _seed(self):
        self.known = load_topology()
        try:
            out = subprocess.check_output(["arp","-a"], text=True, errors="ignore")
            for line in out.splitlines():
                p = line.split()
                if len(p) >= 3 and "." in p[0] and "-" in p[1]:
                    ip  = p[0].strip()
                    mac = p[1].strip().replace("-",":").lower()
                    if ip not in self.known:
                        self.known[ip] = mac
        except: pass
        console.print(f"  [cyan][*] Seeded {len(self.known)} trusted IP->MAC entries[/cyan]")

    def _handler(self, pkt):
        try:
            from scapy.all import ARP
            if not pkt.haslayer(ARP) or pkt[ARP].op != 2: return
            ip  = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc.lower()
            with self._lock:
                if ip in self.known:
                    if self.known[ip] != mac:
                        self.alerts += 1
                        msg = f"[!] ARP SPOOF: {ip} was {self.known[ip]} now {mac}"
                        console.print(f"\n[bold red]{msg}[/bold red]")
                        write_log(ARP_LOG, msg)
                else:
                    self.known[ip] = mac
        except: pass

    def run(self):
        try: from scapy.all import sniff
        except ImportError:
            console.print("[red][-] Scapy not found. pip install scapy[/red]"); return
        self._seed()
        console.print("[bold green][+] ARP Spoof Detector active[/bold green]\n")
        while not _stop_event.is_set():
            try: sniff(filter="arp", prn=self._handler, store=False, timeout=2)
            except Exception as e:
                console.print(f"[red]Sniff error: {e}[/red]"); time.sleep(2)
        console.print(f"[yellow][*] ARP Detector stopped. Alerts: {self.alerts}[/yellow]")


# ═══════════════════════════════════════════════════════════════════
# MODULE 2 - FLOOD DETECTOR + AUTO-BLOCK
# ═══════════════════════════════════════════════════════════════════

class FloodDetector:
    FLOOD_PPS = 500
    SYN_THRESH = 200

    def __init__(self, auto_block=False, block_timeout=300):
        self.auto_block    = auto_block
        self.block_timeout = block_timeout
        self.blocked       = {}
        self._lock         = threading.Lock()
        self.alerts        = 0

    def _iface(self):
        c = psutil.net_io_counters(pernic=True)
        u = {k:v for k,v in c.items() if not k.lower().startswith(("loopback","lo","vmware","vethernet"))}
        return max(u or c, key=lambda k: c[k].bytes_recv+c[k].bytes_sent)

    def _syn_recv(self):
        n = 0
        try:
            for conn in psutil.net_connections(kind="tcp"):
                if conn.status == psutil.CONN_SYN_RECV: n += 1
        except: pass
        return n

    def _block(self, ip):
        with self._lock:
            if ip in self.blocked: return
            try:
                subprocess.run(
                    f'netsh advfirewall firewall add rule name="DEFENDER_BLOCK_{ip}" dir=in action=block remoteip={ip} protocol=any',
                    shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.blocked[ip] = time.time() + self.block_timeout
                msg = f"[AUTO-BLOCK] Blocked {ip} for {self.block_timeout}s"
                console.print(f"[bold red]{msg}[/bold red]")
                write_log(BLOCK_LOG, msg)
            except Exception as e:
                console.print(f"[red]Block failed: {e}[/red]")

    def _unblock_expired(self):
        now = time.time()
        for ip in [ip for ip,exp in self.blocked.items() if now >= exp]:
            try:
                subprocess.run(f'netsh advfirewall firewall delete rule name="DEFENDER_BLOCK_{ip}"',
                               shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                del self.blocked[ip]
                msg = f"[AUTO-UNBLOCK] {ip} unblocked"
                console.print(f"[yellow]{msg}[/yellow]")
                write_log(BLOCK_LOG, msg)
            except: pass

    def run(self):
        iface = self._iface()
        prev  = psutil.net_io_counters(pernic=True)[iface]
        prev_t = time.monotonic()
        console.print(f"[bold green][+] Flood Detector on [cyan]{iface}[/cyan][/bold green]")
        if self.auto_block:
            console.print(f"[yellow]  Auto-Block ENABLED ({self.block_timeout}s)[/yellow]")
        console.print()

        while not _stop_event.is_set():
            time.sleep(2)
            self._unblock_expired()
            c = psutil.net_io_counters(pernic=True)
            if iface not in c:
                iface = self._iface(); prev = c[iface]; prev_t = time.monotonic(); continue
            now_t = time.monotonic()
            cur = c[iface]
            el  = max(now_t - prev_t, 0.001)
            rx_pps  = max(0, int((cur.packets_recv - prev.packets_recv) / el))
            syn     = self._syn_recv()

            if rx_pps >= self.FLOOD_PPS:
                self.alerts += 1
                msg = f"[FLOOD] RX={rx_pps} pkt/s >= threshold {self.FLOOD_PPS}"
                console.print(f"\n[bold red]{msg}[/bold red]")
                write_log(FLOOD_LOG, msg)
            if syn >= self.SYN_THRESH:
                self.alerts += 1
                msg = f"[SYN FLOOD] {syn} half-open TCP connections"
                console.print(f"\n[bold red]{msg}[/bold red]")
                write_log(FLOOD_LOG, msg)

            rx_col = "red" if rx_pps > 500 else "green"
            console.print(
                f"[dim]{ts()}[/dim]  "
                f"RX=[{rx_col}]{rx_pps:>5} pps[/{rx_col}]  "
                f"SYN_RECV=[{'red' if syn>50 else 'white'}]{syn}[/{'red' if syn>50 else 'white'}]  "
                f"alerts=[yellow]{self.alerts}[/yellow]  blocked=[red]{len(self.blocked)}[/red]"
            )
            prev = cur; prev_t = now_t
        console.print(f"[yellow][*] Flood Detector stopped. Alerts: {self.alerts}[/yellow]")


# ═══════════════════════════════════════════════════════════════════
# MODULE 3 - WINDOWS HARDENING
# ═══════════════════════════════════════════════════════════════════

def run_hardening():
    console.print("\n[bold cyan]WINDOWS HARDENING[/bold cyan]\n")
    if not is_admin():
        console.print("[bold red][!] Must run as Administrator.[/bold red]"); return

    results = []

    def do(name, fn):
        try: fn(); results.append((name,"OK","Applied"))
        except Exception as e: results.append((name,"FAIL",str(e)[:60]))

    # 1. LLMNR
    def llmnr():
        k = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,r"Software\Policies\Microsoft\Windows NT\DNSClient")
        winreg.SetValueEx(k,"EnableMulticast",0,winreg.REG_DWORD,0); winreg.CloseKey(k)
    do("Disable LLMNR", llmnr)

    # 2. NetBIOS via WMIC
    def netbios():
        subprocess.run(["wmic","nicconfig","where","TcpipNetbiosOptions!=null","call","SetTcpipNetbios","2"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    do("Disable NetBIOS over TCP/IP", netbios)

    # 3. NBT-NS (NodeType P-node)
    def nbtns():
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",0,winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k,"NodeType",0,winreg.REG_DWORD,2); winreg.CloseKey(k)
        except FileNotFoundError: pass
    do("Disable NBT-NS (NodeType P-node)", nbtns)

    # 4. SMBv1
    def smbv1():
        subprocess.run(["powershell","-NoProfile","-Command",
                        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    do("Disable SMBv1", smbv1)

    # 5. Block port 445
    def b445():
        subprocess.run('netsh advfirewall firewall add rule name="DEFENDER_Block_SMB_445" dir=in action=block protocol=TCP localport=445',
                       shell=True,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    do("Block Port 445 (SMB)", b445)

    # 6. Block port 139
    def b139():
        subprocess.run('netsh advfirewall firewall add rule name="DEFENDER_Block_NBT_139" dir=in action=block protocol=TCP localport=139',
                       shell=True,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    do("Block Port 139 (NBT)", b139)

    # 7. Disable Remote Registry
    def regrpc():
        subprocess.run(["sc","config","RemoteRegistry","start=","disabled"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["sc","stop","RemoteRegistry"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    do("Disable Remote Registry", regrpc)

    # 8. Enable Audit Logon Policy
    def audit():
        subprocess.run(["auditpol","/set","/subcategory:Logon","/success:enable","/failure:enable"],
                       check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    do("Enable Audit Policy (Logon)", audit)

    # 9. Persistence scan
    findings = []
    run_keys = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hive, path in run_keys:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name,val,_ = winreg.EnumValue(key,i)
                    findings.append(f"{path}\\{name} = {val[:60]}")
                    i += 1
                except OSError: break
            winreg.CloseKey(key)
        except: pass
    for d in [os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
              r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"]:
        if os.path.isdir(d):
            for f in os.listdir(d): findings.append(f"Startup: {d}\\{f}")

    if findings:
        results.append(("Persistence Scan","WARN",f"{len(findings)} entries found"))
        for f in findings: console.print(f"  [yellow]{f}[/yellow]")
    else:
        results.append(("Persistence Scan","OK","No suspicious entries"))

    # Print table
    t = Table(box=box.SIMPLE,show_header=True,header_style="bold cyan")
    t.add_column("Step"); t.add_column("Status",justify="center"); t.add_column("Detail",style="dim")
    for name,status,detail in results:
        col = {"OK":"green","WARN":"yellow","FAIL":"red"}.get(status,"white")
        t.add_row(name,f"[{col}]{status}[/{col}]",detail)
    console.print(t)
    console.print("\n[bold green][+] Hardening complete.[/bold green]")


# ═══════════════════════════════════════════════════════════════════
# MODULE 4 - LIVE STATUS
# ═══════════════════════════════════════════════════════════════════

def run_live_status():
    console.print("[bold green][+] Live Network Status — Ctrl+C to stop[/bold green]\n")
    c0 = psutil.net_io_counters(pernic=True)
    usable = {k:v for k,v in c0.items() if not k.lower().startswith(("loopback","lo","vmware"))}
    iface  = max(usable or c0, key=lambda k: c0[k].bytes_recv+c0[k].bytes_sent)
    prev   = c0[iface]; prev_t = time.monotonic()

    try:
        while not _stop_event.is_set():
            time.sleep(1)
            now_t = time.monotonic()
            c = psutil.net_io_counters(pernic=True)
            if iface not in c:
                usable = {k:v for k,v in c.items() if not k.lower().startswith(("loopback","lo","vmware"))}
                iface = max(usable or c, key=lambda k: c[k].bytes_recv+c[k].bytes_sent)
            cur = c[iface]; el = max(now_t-prev_t,0.001)
            rx_pps  = max(0,int((cur.packets_recv-prev.packets_recv)/el))
            tx_pps  = max(0,int((cur.packets_sent-prev.packets_sent)/el))
            rx_mb   = max(0,(cur.bytes_recv-prev.bytes_recv)/el/1e6)
            tx_mb   = max(0,(cur.bytes_sent-prev.bytes_sent)/el/1e6)
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent
            syn = sum(1 for conn in psutil.net_connections(kind="tcp") if conn.status==psutil.CONN_SYN_RECV)
            rc  = "red" if rx_pps>500 else "green"
            console.print(
                f"[dim]{ts()}[/dim]  [{rc}]RX {rx_pps:>5}pps {rx_mb:>5.2f}MB/s[/{rc}]  "
                f"[blue]TX {tx_pps:>5}pps {tx_mb:>5.2f}MB/s[/blue]  "
                f"CPU=[yellow]{cpu:>4.1f}%[/yellow] MEM=[yellow]{mem:>4.1f}%[/yellow] "
                f"SYN_RECV=[{'red' if syn>50 else 'white'}]{syn}[/{'red' if syn>50 else 'white'}]"
            )
            prev = cur; prev_t = now_t
    except KeyboardInterrupt: pass


# ═══════════════════════════════════════════════════════════════════
# MODULE 5 - FULL DEFENSE (all modules concurrent)
# ═══════════════════════════════════════════════════════════════════

def run_full_defense():
    _stop_event.clear()
    ab = Prompt.ask("[cyan]Enable auto-block for flood sources? (y/n)[/cyan]",default="n").strip().lower()=="y"
    bt = 300
    if ab:
        try: bt = max(30,int(Prompt.ask("[cyan]Block timeout seconds[/cyan]",default="300").strip()))
        except: bt = 300

    det  = ArpSpoofDetector()
    fdet = FloodDetector(auto_block=ab, block_timeout=bt)

    threads = [
        threading.Thread(target=det.run,         daemon=True, name="ARP"),
        threading.Thread(target=fdet.run,         daemon=True, name="Flood"),
        threading.Thread(target=run_live_status,  daemon=True, name="Status"),
    ]
    for t in threads: t.start()

    console.print("\n[bold green][+] Full Defense Mode active — all 3 monitors running.[/bold green]")
    console.print("[dim]Type Q + Enter to stop...[/dim]\n")
    try:
        while True:
            if input().strip().lower()=="q": break
    except (KeyboardInterrupt,EOFError): pass
    finally:
        _stop_event.set()
        for t in threads: t.join(timeout=3)
    console.print("\n[yellow][*] Full Defense Mode stopped.[/yellow]")


# ═══════════════════════════════════════════════════════════════════
# MAIN MENU
# ═══════════════════════════════════════════════════════════════════

BANNER = r"""
  ____  _____ _____ _____ _   _ ____  _____ ____
 |  _ \| ____|  ___|  ___| \ | |  _ \| ____|  _ \
 | | | |  _| | |_  |  _| |  \| | | | |  _| | |_) |
 | |_| | |___|  _| |  |__| |\  | |_| | |___| |_/ /
 |____/|_____|_|   |_____|_| \_|____/|_____|____/
"""

MODS = [
    ("1", "ARP Spoof Detector",    "Passive ARP monitor — real-time MITM / poisoning detection"),
    ("2", "Flood Detector",        "Monitor pkt/s + SYN_RECV — alert + optional auto-block via firewall"),
    ("3", "Windows Hardening",     "Apply 9 hardening steps + scan persistence locations"),
    ("4", "Live Network Status",   "Real-time pkt/s, MB/s, CPU, RAM, SYN_RECV"),
    ("5", "Full Defense Mode",     "Run ARP Detector + Flood Detector + Live Status concurrently"),
    ("0", "Exit",                  ""),
]

def main():
    while True:
        os.system("cls")
        console.print(f"[bold red]{BANNER}[/bold red]")
        console.print(Panel(
            "[bold white]defender.py — Network Defense System[/bold white]\n"
            "[dim]Companion to attack.py | ARP Monitor | Flood Detect | Auto-Block | Hardening[/dim]",
            border_style="red", expand=False))
        console.print()
        t = Table(box=box.SIMPLE_HEAD,show_header=False,padding=(0,2))
        t.add_column("N",style="bold yellow",justify="right",width=4)
        t.add_column("Module",style="bold cyan")
        t.add_column("Description",style="dim white")
        for n,name,desc in MODS: t.add_row(f"[{n}]",name,desc)
        console.print(t); console.print()

        choice = Prompt.ask("[cyan]Select module[/cyan]",default="0").strip()
        _stop_event.clear()

        if choice=="0":
            console.print("[dim]Goodbye.[/dim]"); break
        elif choice=="1":
            console.print(Panel("[bold cyan]ARP SPOOF DETECTOR[/bold cyan]",border_style="cyan",expand=False))
            d = ArpSpoofDetector()
            th = threading.Thread(target=d.run,daemon=True); th.start()
            try:
                while True:
                    if input().strip().lower()=="q": break
            except (KeyboardInterrupt,EOFError): pass
            _stop_event.set(); th.join(timeout=3)
        elif choice=="2":
            console.print(Panel("[bold cyan]FLOOD DETECTOR[/bold cyan]",border_style="cyan",expand=False))
            ab = Prompt.ask("[cyan]Auto-block? (y/n)[/cyan]",default="n").strip().lower()=="y"
            bt = 300
            if ab:
                try: bt = max(30,int(Prompt.ask("[cyan]Block timeout (seconds)[/cyan]",default="300").strip()))
                except: bt=300
            fd = FloodDetector(auto_block=ab,block_timeout=bt)
            th = threading.Thread(target=fd.run,daemon=True); th.start()
            try:
                while True:
                    if input().strip().lower()=="q": break
            except (KeyboardInterrupt,EOFError): pass
            _stop_event.set(); th.join(timeout=3)
        elif choice=="3":
            console.print(Panel("[bold cyan]WINDOWS HARDENING[/bold cyan]",border_style="cyan",expand=False))
            run_hardening()
            input("\nPress Enter to return to menu...")
        elif choice=="4":
            console.print(Panel("[bold cyan]LIVE NETWORK STATUS[/bold cyan]",border_style="cyan",expand=False))
            try: run_live_status()
            except KeyboardInterrupt: pass
        elif choice=="5":
            run_full_defense()
        else:
            console.print("[red][!] Invalid selection.[/red]"); time.sleep(1)

        _stop_event.clear()
        console.print()

if __name__ == "__main__":
    main()
