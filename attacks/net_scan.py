import sys, time, argparse, os, io, socket, subprocess, threading, urllib.request, ipaddress, re, json, struct, select
from concurrent.futures import ThreadPoolExecutor, as_completed

if sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True, write_through=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True, write_through=True)

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    print("[-] Scapy library missing. Please run: pip install scapy")
    sys.exit(1)

try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    try:
        mac_lookup.load_vendors()
    except Exception:
        pass
    import threading
    mac_lock = threading.Lock()
except ImportError:
    print("[-] mac-vendor-lookup library missing. Please run: pip install mac-vendor-lookup")
    sys.exit(1)

NMAP_TOP_1000 = sorted(list(set([
    1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,
    99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,
    280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,
    524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,
    711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,
    990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,
    1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,
    1080,1090,1099,1100,1110,1111,1119,1121,1122,1123,1141,1234,1433,1434,1443,1521,1556,1723,1812,1900,1935,
    2000,2001,2002,2003,2049,2100,2222,2323,2375,2376,3000,3001,3128,3268,3269,3306,3389,3478,4000,4001,4243,
    4444,4500,4848,4899,5000,5001,5004,5050,5060,5061,5080,5222,5432,5555,5900,5901,5938,6379,6443,6666,7000,
    7001,7070,7443,7474,7777,7878,8000,8001,8008,8009,8010,8080,8081,8082,8083,8084,8085,8086,8088,8089,8090,
    8180,8181,8443,8500,8545,8888,8899,9000,9001,9002,9090,9091,9092,9200,9300,9418,9999,10000,10001,10080,
    11211,27017,27018,28017,37777,34567,554,8554,8899,6000,49152,49153,49154,49155,49156,49157,50000,65535,
    5985,5986,47001,135,137,138,139,389,636,593,88,464,
])))

QUICK_PORTS = [21,22,23,25,53,80,110,143,443,445,554,3389,3306,5000,8080,8443,8554,37777,34567,5900,27017,6379]

def get_arp_cache_full():
    entries = {}
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and "." in parts[0] and "-" in parts[1]:
                ip, mac = parts[0].strip(), parts[1].strip()
                if ip not in ("127.0.0.1", "255.255.255.255") and not ip.startswith("224.") and not ip.startswith("239."):
                    entries[ip] = mac
    except Exception:
        pass
    return entries

def _ps_json(command, timeout=6):
    """Chay PowerShell va parse JSON; luon tra ve list."""
    if sys.platform != "win32":
        return []
    try:
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", command],
            text=True, errors="ignore", timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).strip()
        if not out:
            return []
        data = json.loads(out)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []

def _ipv6_bare(ip):
    return str(ip).split("%", 1)[0]

def _ipv6_scope_id(ip):
    if "%" in str(ip):
        try:
            return int(str(ip).split("%", 1)[1])
        except Exception:
            return 0
    return 0

def _ipv6_sockaddr(ip, port):
    return (_ipv6_bare(ip), int(port), 0, _ipv6_scope_id(ip))

def _ipv6_with_scope(ip, ifindex=None):
    ip = str(ip)
    if "%" in ip or not ifindex:
        return ip
    try:
        if ipaddress.ip_address(ip).is_link_local:
            return f"{ip}%{ifindex}"
    except Exception:
        pass
    return ip

def get_ipv6_config():
    """Tra ve cac dia chi IPv6 usable tren interface dang connected."""
    cmd = ("Get-NetIPInterface -AddressFamily IPv6 -ConnectionState Connected -ErrorAction SilentlyContinue | "
           "Select-Object InterfaceIndex,InterfaceAlias | ConvertTo-Json -Compress")
    ifaces = {}
    for item in _ps_json(cmd):
        try:
            ifaces[int(item.get("InterfaceIndex", -1))] = item.get("InterfaceAlias", "")
        except Exception:
            pass
    cmd = ("Get-NetIPAddress -AddressFamily IPv6 -AddressState Preferred -ErrorAction SilentlyContinue | "
           "Select-Object IPAddress,PrefixLength,InterfaceIndex,InterfaceAlias,PrefixOrigin | ConvertTo-Json -Compress")
    configs, seen = [], set()
    for item in _ps_json(cmd):
        raw = str(item.get("IPAddress", "")).strip()
        if not raw or raw in seen:
            continue
        try:
            addr = ipaddress.ip_address(_ipv6_bare(raw))
        except Exception:
            continue
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            continue
        try:
            ifidx = int(item.get("InterfaceIndex", 0) or 0)
        except Exception:
            ifidx = 0
        if ifaces and ifidx not in ifaces:
            continue
        seen.add(raw)
        configs.append({
            "ip": raw,
            "ifindex": ifidx,
            "iface": item.get("InterfaceAlias", "") or ifaces.get(ifidx, ""),
            "prefix": int(item.get("PrefixLength", 64) or 64),
            "kind": "link-local" if addr.is_link_local else ("ula" if addr.is_private else "global"),
        })
    return configs

def get_ipv6_neighbors():
    """Doc NDP cache (Get-NetNeighbor), bo multicast/loopback."""
    cmd = ("Get-NetNeighbor -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
           "Where-Object { $_.LinkLayerAddress -and $_.IPAddress -notlike 'ff*' -and $_.IPAddress -ne '::1' } | "
           "Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State | ConvertTo-Json -Compress")
    result = []
    for item in _ps_json(cmd):
        raw = str(item.get("IPAddress", "")).strip()
        mac = str(item.get("LinkLayerAddress", "")).strip().replace(":", "-").upper()
        if not raw or not mac or mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF"):
            continue
        try:
            addr = ipaddress.ip_address(_ipv6_bare(raw))
        except Exception:
            continue
        if addr.is_multicast or addr.is_loopback or addr.is_unspecified:
            continue
        try:
            ifidx = int(item.get("InterfaceIndex", 0) or 0)
        except Exception:
            ifidx = 0
        result.append({"ip": raw, "mac": mac, "ifindex": ifidx, "state": item.get("State")})
    return result

def ping_ipv6(ip, ifindex=None, timeout_ms=800):
    target = _ipv6_with_scope(ip, ifindex)
    try:
        res = subprocess.run(
            ["ping", "-6", "-n", "1", "-w", str(timeout_ms), target],
            capture_output=True, text=True, errors="ignore",
            timeout=max(2, int(timeout_ms / 1000) + 2),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return res.returncode == 0
    except Exception:
        return False

def probe_ipv6_neighbors(configs, timeout_ms=800):
    """Ping multicast + tung neighbor de lam moi NDP cache, tra ve neighbor con song."""
    ifindices = sorted({c["ifindex"] for c in configs if c.get("ifindex")})
    for idx in ifindices:
        try:
            subprocess.run(
                ["ping", "-6", "-n", "1", "-w", "500", f"ff02::1%{idx}"],
                capture_output=True, timeout=2,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass
    neighbors = get_ipv6_neighbors()
    if not neighbors:
        return []
    def check(nb):
        return nb, ping_ipv6(nb["ip"], nb.get("ifindex"), timeout_ms)
    alive = []
    with ThreadPoolExecutor(max_workers=32) as ex:
        for nb, ok in ex.map(check, neighbors):
            if ok:
                alive.append(nb)
    fresh = {nb["ip"]: nb for nb in get_ipv6_neighbors()}
    for nb in alive:
        if nb["ip"] in fresh:
            nb["state"] = fresh[nb["ip"]].get("state")
    return alive

def _tcp_connect(ip, port, timeout):
    if ":" in str(ip):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(_ipv6_sockaddr(ip, port))
        return s
    return socket.create_connection((ip, port), timeout=timeout)

def _nbstat_names(ip, timeout=0.5):
    """Gui NBSTAT va tra ve toan bo bang ten: [(name, suffix, is_group), ...]."""
    transaction_id = os.urandom(2)
    netbios_name = b"*" + b"\x00" * 15
    encoded_name = b"".join(bytes((ord("A")+(byte>>4), ord("A")+(byte&0x0F))) for byte in netbios_name)
    packet = transaction_id + b"\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20" + encoded_name + b"\x00" + b"\x00\x21\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    entries = []
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(4096)
        if len(data) < 12 or data[:2] != transaction_id:
            return entries
        def skip_dns_name(payload, start):
            if start >= len(payload): return len(payload)
            if payload[start] & 0xC0 == 0xC0: return start + 2
            while start < len(payload) and payload[start] != 0:
                start += payload[start] + 1
            return start + 1
        offset = 12
        question_count = int.from_bytes(data[4:6], "big")
        answer_count = int.from_bytes(data[6:8], "big")
        for _ in range(question_count):
            offset = skip_dns_name(data, offset) + 4
        if answer_count < 1: return entries
        offset = skip_dns_name(data, offset)
        if offset + 10 > len(data): return entries
        data_length = int.from_bytes(data[offset+8:offset+10], "big")
        offset += 10
        if data_length < 1 or offset >= len(data): return entries
        name_count = data[offset]
        offset += 1
        for _ in range(name_count):
            if offset + 18 > len(data): break
            name = data[offset:offset+15].decode("ascii", errors="ignore").strip("\x00 ").strip()
            suffix = data[offset+15]
            flags = int.from_bytes(data[offset+16:offset+18], "big")
            is_group = bool(flags & 0x8000)
            if name: entries.append((name, suffix, is_group))
            offset += 18
    except (OSError, socket.timeout):
        return entries
    finally:
        sock.close()
    return entries

def get_netbios_info(ip, timeout=0.5):
    """Doc bang ten NetBIOS: ten may, workgroup/domain va user (suffix 0x03)."""
    entries = _nbstat_names(ip, timeout)
    info = {"name": "", "user": "", "workgroup": "", "domain": ""}
    for name, suffix, is_group in entries:
        low = name.lower()
        if suffix == 0x00 and not is_group and not info["name"]:
            info["name"] = name
        elif suffix == 0x00 and is_group and not info["workgroup"]:
            info["workgroup"] = name
        elif suffix == 0x1c and is_group and not info["domain"]:
            info["domain"] = name
        elif suffix == 0x03 and not is_group and not info["user"]:
            # Messenger service: tren Windows cu entry nay thuong la ten user dang dang nhap
            if len(name) > 1 and not low.endswith("$") and low != "__msbrowse__":
                info["user"] = name
    return info

def get_windows_hostname(ip, timeout=0.5):
    return get_netbios_info(ip, timeout).get("name", "")

def query_mdns_hostname(ip, timeout=0.6):
    try:
        parts = ip.split(".")
        reverse = ".".join(reversed(parts)) + ".in-addr.arpa"
        txid = os.urandom(2)
        header = txid + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in reverse.split("."):
            enc = label.encode("ascii")
            qname += bytes([len(enc)]) + enc
        qname += b"\x00"
        packet = header + qname + b"\x00\x0c\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(4096)
        sock.close()
        if len(data) < 12: return ""
        qdcount = int.from_bytes(data[4:6], "big")
        ancount = int.from_bytes(data[6:8], "big")
        offset = 12
        def read_name(buf, pos):
            labels = []
            jumped = False
            orig_pos = pos
            for _ in range(100):
                if pos >= len(buf): break
                length = buf[pos]
                if length == 0: pos += 1; break
                elif (length & 0xC0) == 0xC0:
                    if pos+1 >= len(buf): break
                    ptr = ((length & 0x3F) << 8) | buf[pos+1]
                    if not jumped: orig_pos = pos + 2
                    pos = ptr; jumped = True
                else:
                    pos += 1
                    labels.append(buf[pos:pos+length].decode("ascii", errors="ignore"))
                    pos += length
            return ".".join(labels), (orig_pos if jumped else pos)
        for _ in range(qdcount):
            _, offset = read_name(data, offset)
            offset += 4
        for _ in range(ancount):
            _, offset = read_name(data, offset)
            if offset + 10 > len(data): break
            rtype = int.from_bytes(data[offset:offset+2], "big")
            offset += 8
            rdlength = int.from_bytes(data[offset:offset+2], "big")
            offset += 2
            if rtype == 12:
                ptr_name, _ = read_name(data, offset)
                hostname = ptr_name.split(".")[0]
                if hostname: return hostname
            offset += rdlength
    except Exception:
        pass
    return ""

_mdns_info = {}
_mdns_by_ip = {}
_mdns_passives = {}
_ssdp_info = {}
_mdns_lock = threading.Lock()

def _read_dns_name(buf, pos):
    labels = []
    jumped = False
    orig_pos = pos
    for _ in range(64):
        if pos >= len(buf): break
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped: orig_pos = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(buf): break
            ptr = ((length & 0x3F) << 8) | buf[pos+1]
            if not jumped:
                orig_pos = pos + 2
                jumped = True
            pos = ptr
            continue
        pos += 1
        if pos + length > len(buf): break
        labels.append(buf[pos:pos+length].decode("utf-8", "ignore"))
        pos += length
    return ".".join(labels), (orig_pos if jumped else pos)

def _handle_mdns_packet(data, src_ip):
    """Parse A/PTR/SRV/TXT cua mot goi mDNS va luu theo IP nguon."""
    if len(data) < 12: return
    try:
        qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", data[4:12])
    except struct.error:
        return
    pos = 12
    for _ in range(qdcount):
        try:
            _, pos = _read_dns_name(data, pos)
        except Exception:
            return
        pos += 4
        if pos > len(data): return
    got = {"srv": set(), "ptr": set(), "a": set(), "aaaa": set(), "services": set()}
    model = ""
    for _ in range(ancount + nscount + arcount):
        if pos >= len(data): break
        try:
            name, pos = _read_dns_name(data, pos)
        except Exception:
            break
        if pos + 10 > len(data): break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos+10])
        pos += 10
        if pos + rdlen > len(data): break
        rd_start, rd_end = pos, pos + rdlen
        try:
            if rtype == 12:
                target, _ = _read_dns_name(data, rd_start)
                parts = target.split(".")
                if len(parts) >= 3:
                    if parts[0].startswith("_"):
                        # PTR cua _services._dns-sd._udp: ban than ten la mot service type
                        if parts[1].startswith("_"):
                            got["services"].add(f"{parts[0]}.{parts[1]}")
                    elif parts[1].startswith("_"):
                        got["services"].add(".".join(parts[1:3]))
                        inst = parts[0].strip()
                        if inst and not inst.startswith("_"):
                            got["ptr"].add(inst[:48])
            elif rtype == 33 and rdlen >= 6:
                target, _ = _read_dns_name(data, rd_start + 6)
                short = target.split(".")[0].strip()
                if short:
                    got["srv"].add(short[:48])
                    with _mdns_lock:
                        _mdns_by_ip[src_ip] = short[:48]
            elif rtype == 1 and rdlen == 4:
                a_ip = ".".join(str(b) for b in data[rd_start:rd_end])
                short = name.split(".")[0].strip()
                if short:
                    got["a"].add(short[:48])
                    with _mdns_lock:
                        if a_ip not in _mdns_by_ip:
                            _mdns_by_ip[a_ip] = short[:48]
            elif rtype == 28 and rdlen == 16:
                try:
                    aaaa_ip = socket.inet_ntop(socket.AF_INET6, data[rd_start:rd_end])
                except Exception:
                    aaaa_ip = ""
                short = name.split(".")[0].strip()
                if short:
                    got["aaaa"].add(short[:48])
                    if aaaa_ip:
                        with _mdns_lock:
                            if aaaa_ip not in _mdns_by_ip:
                                _mdns_by_ip[aaaa_ip] = short[:48]
            elif rtype == 16:
                txt = data[rd_start:rd_end].decode("utf-8", "ignore")
                m = re.search(r"model=([^\x00]+)", txt)
                if m: model = m.group(1).strip()[:40]
        except Exception:
            pass
        pos = rd_end
    with _mdns_lock:
        if not (got["srv"] or got["ptr"] or got["a"] or got["aaaa"] or got["services"] or model):
            return
        info = _mdns_info.setdefault(src_ip, {"srv": set(), "ptr": set(), "a": set(), "aaaa": set(), "services": set(), "model": ""})
        for key in ("srv", "ptr", "a", "aaaa", "services"):
            info[key].update(got[key])
        if model and not info["model"]:
            info["model"] = model
        if got["ptr"] or got["srv"] or got["a"]:
            _mdns_passives[src_ip] = (sorted(got["srv"]) or sorted(got["a"]) or sorted(got["ptr"]))[0]

def mdns_discover(timeout=2.0):
    """Gui query multicast cho cac service pho bien va thu cau tra loi."""
    queries = [
        "_services._dns-sd._udp.local", "_airplay._tcp.local", "_googlecast._tcp.local",
        "_ipp._tcp.local", "_http._tcp.local", "_smb._tcp.local", "_ssh._tcp.local",
        "_device-info._tcp.local", "_raop._tcp.local",
    ]
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try: sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        except Exception: pass
        try:
            # Bind 5353 de nhan ca response multicast; nhieu stack (iOS) khong tra loi unicast
            sock.bind(("", 5353))
            mreq = struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
            try: sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception: pass
        except OSError:
            sock.bind(("", 0))
        sock.settimeout(0.3)
        for q in queries:
            qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in q.split(".")) + b"\x00"
            # class 0x8001 = QU bit: xin tra loi unicast ve cong nguon
            pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x80\x01"
            try: sock.sendto(pkt, ("224.0.0.251", 5353))
            except Exception: pass
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(9000)
                _handle_mdns_packet(data, src_ip)
            except socket.timeout:
                continue
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock: sock.close()

def start_passive_mdns_listener(duration=10.0):
    def _listen():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", 5353))
            mreq = struct.pack("4sL", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)
            try: sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception: pass
            sock.settimeout(0.5)
            deadline = time.time() + duration
            while time.time() < deadline:
                try:
                    data, (src_ip, _) = sock.recvfrom(9000)
                    _handle_mdns_packet(data, src_ip)
                except socket.timeout:
                    continue
                except Exception:
                    continue
            sock.close()
        except Exception:
            pass
    t = threading.Thread(target=_listen, daemon=True)
    t.start()
    return t

def ssdp_discover(timeout=2.5):
    """M-SEARCH + doc LOCATION XML -> friendlyName/modelName cua TV, loa, printer..."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n').encode()
    seen_locations = set()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", 0))
        sock.settimeout(0.4)
        for _ in range(2):
            sock.sendto(msg, ("239.255.255.250", 1900))
            time.sleep(0.15)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except Exception:
                continue
            text = data.decode("utf-8", "ignore")
            headers = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    headers[key.strip().lower()] = val.strip()
            with _mdns_lock:
                entry = _ssdp_info.setdefault(src_ip, {"friendly": "", "model": "", "server": "", "location": ""})
            if headers.get("server") and not entry["server"]:
                entry["server"] = headers["server"][:60]
            loc = entry["location"] or headers.get("location", "")
            if not loc: continue
            entry["location"] = loc
            loc_key = loc.lower()
            if loc_key in seen_locations: continue
            seen_locations.add(loc_key)
            if len(seen_locations) > 40: continue
            if not loc_key.startswith("http://"): continue
            try:
                req = urllib.request.Request(loc, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=0.9) as resp:
                    xml = resp.read(20000).decode("utf-8", "ignore")
                fm = re.search(r"<friendlyName[^>]*>(.*?)</friendlyName>", xml, re.I | re.S)
                mm = re.search(r"<modelName[^>]*>(.*?)</modelName>", xml, re.I | re.S)
                mn = re.search(r"<manufacturer[^>]*>(.*?)</manufacturer>", xml, re.I | re.S)
                if fm and not entry["friendly"]:
                    entry["friendly"] = re.sub(r"\s+", " ", fm.group(1)).strip()[:48]
                if not entry["model"]:
                    if mm: entry["model"] = re.sub(r"\s+", " ", mm.group(1)).strip()[:40]
                    elif mn: entry["model"] = re.sub(r"\s+", " ", mn.group(1)).strip()[:40]
            except Exception:
                continue
    except Exception:
        pass
    finally:
        if sock: sock.close()

def get_tls_hostname(ip, port, timeout=1.2):
    """Doc CN/SAN tu certificate TLS (NAS, router, printer HTTPS)."""
    try:
        import ssl
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except Exception:
        return ""
    der = None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with _tcp_connect(ip, port, timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
    except Exception:
        return ""
    if not der: return ""
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return ""
    candidates = []
    try:
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            candidates.append(str(attr.value))
    except Exception: pass
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        candidates.extend(str(v) for v in san.get_values_for_type(x509.DNSName))
    except Exception: pass
    for name in candidates:
        n = str(name).strip().strip("*.").strip().lower()
        if not n or n in ("localhost", "localhost.localdomain"): continue
        if re.fullmatch(r"[0-9.]+", n): continue
        if len(n) < 3: continue
        return n[:60]
    return ""

def _ber_len(n):
    if n < 0x80: return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _ber_tlv(tag, payload):
    return bytes([tag]) + _ber_len(len(payload)) + payload

def _ber_int(n):
    if n == 0: return b"\x00"
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b

def _ber_oid(oid):
    parts = [int(p) for p in oid.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 128:
            out += bytes([p])
        else:
            chunks = []
            while p:
                chunks.append(p & 0x7F)
                p >>= 7
            chunks.reverse()
            out += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return out

def _ber_read_tlv(data, pos):
    if pos + 2 > len(data): return None, pos
    tag = data[pos]; pos += 1
    length = data[pos]; pos += 1
    if length & 0x80:
        n = length & 0x7F
        if pos + n > len(data): return None, pos
        length = int.from_bytes(data[pos:pos+n], "big"); pos += n
    if pos + length > len(data): return None, pos
    return (tag, data[pos:pos+length]), pos + length

def snmp_get(ip, oids, community="public", timeout=0.7):
    """SNMPv2c GET nhieu OID cung luc. Tra ve list value hoac None."""
    varbinds = b""
    for oid in oids:
        varbinds += _ber_tlv(0x30, _ber_tlv(0x06, _ber_oid(oid)) + _ber_tlv(0x05, b""))
    pdu = _ber_tlv(0xA0,
        _ber_tlv(0x02, b"\x2a") +
        _ber_tlv(0x02, b"\x00") +
        _ber_tlv(0x02, b"\x00") +
        _ber_tlv(0x30, varbinds))
    packet = _ber_tlv(0x30, _ber_tlv(0x02, b"\x01") + _ber_tlv(0x04, community.encode()) + pdu)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, 161))
        data, _ = sock.recvfrom(4096)
    except Exception:
        return None
    finally:
        sock.close()
    msg, _ = _ber_read_tlv(data, 0)
    if not msg or msg[0] != 0x30: return None
    body = msg[1]; pos = 0
    _, pos = _ber_read_tlv(body, pos)  # version
    _, pos = _ber_read_tlv(body, pos)  # community
    pdu_tlv, pos = _ber_read_tlv(body, pos)
    if not pdu_tlv or pdu_tlv[0] not in (0xA1, 0xA2): return None
    p = pdu_tlv[1]; q = 0
    for _ in range(3):
        _, q = _ber_read_tlv(p, q)
    vbl, q = _ber_read_tlv(p, q)
    if not vbl: return None
    values = []; rp = 0
    for _ in range(len(oids)):
        vb, next_rp = _ber_read_tlv(vbl[1], rp)
        if not vb: break
        rp = next_rp
        vp = 0
        _, vp = _ber_read_tlv(vb[1], vp)
        val_tlv, vp = _ber_read_tlv(vb[1], vp)
        if not val_tlv: break
        tag, raw = val_tlv
        if tag == 0x04: val = raw.decode("utf-8", "ignore")
        elif tag == 0x02: val = str(int.from_bytes(raw, "big"))
        elif tag == 0x06: val = raw.hex()
        else: val = raw.decode("utf-8", "ignore")
        values.append(val.strip())
    return values

def get_snmp_identity(ip, timeout=0.7):
    values = snmp_get(
        ip,
        ["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.4.0"],
        timeout=timeout,
    ) or []
    def at(i): return values[i].strip() if i < len(values) else ""
    return {"name": at(0)[:60], "descr": at(1)[:80], "contact": at(2)[:60]}

def get_hostname(ip, timeout=0.4, tls_port=None, do_snmp=False):
    """Gop nhieu nguon: NetBIOS > mDNS > SSDP > SNMP > TLS > DNS/ping."""
    names = []
    identity = ""
    nb = get_netbios_info(ip, timeout=0.5)
    windows_host = nb.get("name", "")
    if windows_host:
        names.append((0, windows_host, "NetBIOS"))

    mdns_host = query_mdns_hostname(ip, timeout=0.6)
    with _mdns_lock:
        info = _mdns_info.get(ip, {})
        srv_names = sorted(info.get("srv", set()))
        ptr_names = sorted(info.get("ptr", set()))
        a_names = sorted(info.get("a", set()))
        by_ip = _mdns_by_ip.get(ip, "")
    mdns_pick = srv_names or a_names or ([by_ip] if by_ip else []) or ptr_names
    if mdns_pick:
        names.append((1, mdns_pick[0], "mDNS"))
    elif mdns_host:
        names.append((1, mdns_host, "mDNS"))

    with _mdns_lock:
        ssdp = dict(_ssdp_info.get(ip, {}))
    if ssdp.get("friendly"):
        names.append((2, ssdp["friendly"], "SSDP"))

    snmp_info = {"name": "", "descr": "", "contact": ""}
    if do_snmp:
        snmp_info = get_snmp_identity(ip)
        if snmp_info.get("name"):
            names.append((3, snmp_info["name"], "SNMP"))

    if tls_port:
        tls_name = get_tls_hostname(ip, tls_port)
        if tls_name:
            names.append((4, tls_name, "TLS"))

    if not names:
        try:
            dns_host = None
            def run_query():
                nonlocal dns_host
                try: dns_host = socket.gethostbyaddr(ip)[0]
                except: pass
            t = threading.Thread(target=run_query, daemon=True)
            t.start(); t.join(timeout)
            if dns_host: names.append((5, dns_host.split(".")[0], "DNS"))
        except Exception: pass

    ping_ttl = None
    try:
        out = subprocess.check_output(["ping","-a","-n","1","-w","400",ip], text=True, errors="ignore", timeout=1.2, creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        match = re.search(r"Pinging\s+([^\s]+)\s+\[", out)
        if match and not names: names.append((5, match.group(1), "DNS"))
        ttl_match = re.search(r"TTL[=:]\s*(\d+)", out, re.IGNORECASE)
        if ttl_match: ping_ttl = int(ttl_match.group(1))
    except Exception: pass

    names = [n for n in names if n[1]]
    if names:
        names.sort(key=lambda item: item[0])
        _, host, source = names[0]
    else:
        host, source = "", ""

    h = host.lower()
    if "iphone" in h: identity = "Apple iPhone"
    elif "ipad" in h: identity = "Apple iPad"
    elif any(n in h for n in ("macbook","imac","mac-mini","macmini","apple")): identity = "Apple Mac"
    elif "samsung" in h or "galaxy" in h: identity = "Samsung"
    elif "oppo" in h: identity = "OPPO"
    elif "oneplus" in h: identity = "OnePlus"
    elif "realme" in h: identity = "realme"
    elif "android" in h: identity = "Android"
    elif windows_host and ping_ttl is not None and ping_ttl >= 96: identity = "Windows/NetBIOS"
    elif windows_host: identity = "Windows/NetBIOS"

    if host and identity: result = f"{host} [{identity}]"
    elif host: result = host
    elif identity: result = f"[{identity}] Hostname unavailable"
    else: result = ""

    if host and source not in ("NetBIOS", "DNS") and "[" not in result:
        result = f"{result} [{source}]"
    user = nb.get("user", "")
    if user and user.lower() != host.lower():
        result = f"{result} [user: {user[:24]}]" if result else f"[user: {user[:24]}]"
    contact = snmp_info.get("contact", "")
    if contact and contact.lower() not in (host.lower(), user.lower()) and len(contact) > 1:
        if contact.lower() not in result.lower():
            result = f"{result} [contact: {contact[:24]}]" if result else f"[contact: {contact[:24]}]"
    return result

def get_hostname_ipv6(ip, timeout=0.5, tls_port=None):
    """Hostname cho IPv6: reverse DNS + mDNS cache + TLS; khong dung NetBIOS/SNMP IPv4."""
    names = []
    bare = _ipv6_bare(ip)
    dns_host = ""
    def run_query():
        nonlocal dns_host
        try:
            dns_host = socket.gethostbyaddr(bare)[0]
        except Exception:
            pass
    t = threading.Thread(target=run_query, daemon=True)
    t.start()
    t.join(timeout)
    if dns_host:
        names.append((5, dns_host.split(".")[0], "DNS"))
    with _mdns_lock:
        mdns_name = _mdns_by_ip.get(ip) or _mdns_by_ip.get(bare)
    if mdns_name:
        names.insert(0, (1, mdns_name, "mDNS"))
    if tls_port:
        tls_name = get_tls_hostname(ip, tls_port)
        if tls_name:
            names.append((4, tls_name, "TLS"))
    names = [n for n in names if n[1]]
    if not names:
        return ""
    names.sort(key=lambda item: item[0])
    _, host, source = names[0]
    h = host.lower()
    identity = ""
    if "iphone" in h: identity = "Apple iPhone"
    elif "ipad" in h: identity = "Apple iPad"
    elif any(n in h for n in ("macbook", "imac", "mac-mini", "macmini", "apple")): identity = "Apple Mac"
    elif "samsung" in h or "galaxy" in h: identity = "Samsung"
    elif "oppo" in h: identity = "OPPO"
    elif "android" in h: identity = "Android"
    result = f"{host} [{identity}]" if identity else host
    if source != "DNS" and "[" not in result:
        result = f"{result} [{source}]"
    return result

def get_mac_vendor(mac):
    if mac in ("ff-ff-ff-ff-ff-ff","ff:ff:ff:ff:ff:ff"): return "Broadcast"
    try:
        with mac_lock: return mac_lookup.lookup(mac)[:25]
    except Exception:
        if len(mac) >= 2 and mac.replace("-",":")[1].lower() in ["2","6","a","e"]: return "Virtual MAC (Random)"
        return "Unknown"

def add_vendor_identity(host, vendor):
    if "[" in host: return host
    v = vendor.lower()
    labels = [("apple","Apple Device"),("samsung","Samsung Mobile/TV"),("oppo","OPPO Mobile"),("oneplus","OnePlus Mobile"),
               ("realme","realme Mobile"),("xiaomi","Xiaomi Device"),("huawei","Huawei Device"),("honor","Honor Device"),
               ("hangzhou huacheng","Imou/Dahua Camera"),("dahua","Dahua IP Camera"),("hikvision","Hikvision Camera"),
               ("ezviz","EZVIZ Camera"),("imilab","Imilab Camera"),("reolink","Reolink Camera"),("espressif","ESP32/ESP8266 IoT"),
               ("tuya","Tuya Smart Home"),("sonoff","Sonoff Switch"),("raspberry","Raspberry Pi"),
               ("tp-link","TP-Link Device"),("tplink","TP-Link Device")]
    for kw, lbl in labels:
        if kw in v:
            return f"{host} [{lbl}]" if host else f"[{lbl}] Hostname unavailable"
    return host

def scan_ports(ip, port_list=None, port_threads=300, timeout=0.18):
    if port_list is None: port_list = NMAP_TOP_1000
    open_ports = []
    lock = threading.Lock()
    device_hint = ""
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    with lock: open_ports.append(port)
        except Exception: pass
    with ThreadPoolExecutor(max_workers=port_threads) as ex:
        list(ex.map(check_port, port_list))
    open_ports.sort()
    http_ports = [p for p in open_ports if p in (80,8080,443,8443,8000,5000,8888,8181,8888)]
    if http_ports:
        for hport in http_ports[:2]:
            try:
                import ssl
                protocol = "https" if hport in (443,8443) else "http"
                url = f"{protocol}://{ip}:{hport}/"
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=1.2, context=ctx if protocol=="https" else None) as resp:
                    server_h = resp.headers.get("Server","")
                    body = resp.read(3000).decode("utf-8", errors="ignore")
                    title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE|re.DOTALL)
                    if title_m: device_hint = title_m.group(1).strip()[:35]
                    elif server_h: device_hint = server_h.strip()[:35]
                    if device_hint: break
            except Exception: pass
    return ",".join(str(p) for p in open_ports) if open_ports else "None", device_hint

def scan_ports_v6(ip, port_list=None, port_threads=300, timeout=0.18):
    if port_list is None: port_list = NMAP_TOP_1000
    open_ports = []
    lock = threading.Lock()
    device_hint = ""
    def check_port(port):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex(_ipv6_sockaddr(ip, port)) == 0:
                    with lock: open_ports.append(port)
        except Exception: pass
    with ThreadPoolExecutor(max_workers=port_threads) as ex:
        list(ex.map(check_port, port_list))
    open_ports.sort()
    http_ports = [p for p in open_ports if p in (80,8080,443,8443,8000,5000,8888,8181)]
    if http_ports:
        try:
            if ipaddress.ip_address(_ipv6_bare(ip)).is_link_local:
                http_ports = []
        except Exception:
            http_ports = []
    for hport in http_ports[:2]:
        try:
            import ssl
            protocol = "https" if hport in (443,8443) else "http"
            url = f"{protocol}://[{_ipv6_bare(ip)}]:{hport}/"
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=1.2, context=ctx if protocol=="https" else None) as resp:
                server_h = resp.headers.get("Server","")
                body = resp.read(3000).decode("utf-8", errors="ignore")
                title_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE|re.DOTALL)
                if title_m: device_hint = title_m.group(1).strip()[:35]
                elif server_h: device_hint = server_h.strip()[:35]
                if device_hint: break
        except Exception: pass
    return ",".join(str(p) for p in open_ports) if open_ports else "None", device_hint

def detect_network_config():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255",1))
        local_ip = sock.getsockname()[0]
    except Exception:
        try:
            from scapy.all import conf, get_if_addr
            local_ip = get_if_addr(conf.iface)
            if local_ip in ("127.0.0.1","0.0.0.0",None): raise Exception("Invalid fallback IP")
        except Exception: raise Exception("Could not detect local IP")
    finally: sock.close()
    prefix_length = 24
    gateway = ""
    if sys.platform == "win32":
        try:
            prefix_cmd = f"(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{local_ip}' -ErrorAction Stop).PrefixLength"
            prefix_length = int(subprocess.check_output(["powershell","-NoProfile","-Command",prefix_cmd], text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW).strip())
        except: pass
        try:
            gateway_cmd = (f"$i=(Get-NetIPAddress -AddressFamily IPv4 -IPAddress '{local_ip}' -ErrorAction Stop).InterfaceIndex; "
                "(Get-NetRoute -InterfaceIndex $i -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop)")
            gateway = subprocess.check_output(["powershell","-NoProfile","-Command",gateway_cmd], text=True, timeout=3, creationflags=subprocess.CREATE_NO_WINDOW).strip()
        except: pass
    network = ipaddress.ip_network(f"{local_ip}/{prefix_length}", strict=False)
    return local_ip, network, gateway

def send_multicast_probe():
    # Active discovery: gui query va thu cau tra loi (mDNS + SSDP), khong chi gui suong
    try:
        mdns_discover(timeout=2.0)
    except Exception:
        pass
    try:
        ssdp_discover(timeout=2.5)
    except Exception:
        pass

def auto_discover_router_subnets(local_ip):
    from rich.console import Console
    from rich.table import Table
    from rich import box
    console = Console()
    console.print("\n[bold cyan][*] DANG KICH HOAT AUTO ROUTER SUBNET DISCOVERY...[/bold cyan]")
    console.print("[yellow] Do quet cac IP Gateway (.1) tren dai de tim tat ca cac VLAN dang mo...[/yellow]")
    ip_parts = local_ip.split(".")
    base_prefix = f"{ip_parts[0]}.{ip_parts[1]}"
    candidate_gateways = [f"{base_prefix}.{c}.1" for c in range(0, 255)]
    live_subnets = []
    def check_gw(gw_ip):
        try:
            res = subprocess.run(f"ping -n 1 -w 150 {gw_ip}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if res.returncode == 0 and b"TTL=" in res.stdout.upper():
                parts = gw_ip.split(".")
                seg = int(parts[2]) // 16 * 16
                return (gw_ip, f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", f"{parts[0]}.{parts[1]}.{seg}.0/20")
        except: pass
        return None
    with ThreadPoolExecutor(max_workers=100) as executor:
        for f in as_completed([executor.submit(check_gw, gw) for gw in candidate_gateways]):
            res = f.result()
            if res and res not in live_subnets: live_subnets.append(res)
    if live_subnets:
        table = Table(title="[bold green]PHat HIEN CAC DAI VLAN / SUBNET DANG HOAT DONG TREN ROUTER[/bold green]", box=box.ROUNDED)
        table.add_column("IP Gateway Router (.1)", style="cyan", no_wrap=True)
        table.add_column("Dai Mang Goi Y (/24)", style="bold yellow")
        table.add_column("Dai Mang Goi Y (/20)", style="magenta")
        for gw, s24, s20 in sorted(live_subnets, key=lambda x: x[0]):
            table.add_row(gw, s24, s20)
        console.print(table)
        console.print("[dim white]Goi y: Anh go mot trong cac Dai Mang o tren vao o nhap Subnet de quet nha![/dim white]\n")
    else:
        console.print("[yellow][!] Khong tim thay dai VLAN phu nao phan hoi Ping .1 bo sung.[/yellow]\n")

def get_ipv6_gateways():
    cmd = ("Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
           "Sort-Object RouteMetric | Select-Object NextHop,InterfaceIndex | ConvertTo-Json -Compress")
    result = []
    for item in _ps_json(cmd):
        nh = str(item.get("NextHop", "")).strip()
        if nh and nh not in ("::", "::1"):
            result.append({"ip": nh, "ifindex": int(item.get("InterfaceIndex", 0) or 0)})
    return result

def _topology_path():
    mon_dir = os.path.dirname(os.path.abspath(__file__))
    if os.path.basename(mon_dir) != "monitoring":
        mon_dir = os.path.join(os.path.dirname(mon_dir), "monitoring")
    return os.path.join(mon_dir, "topology.json")

def run_ipv6_scan(subnet6, port_mode, port_list):
    """Quet IPv6 dua tren NDP cache + ping tung neighbor + port scan AF_INET6."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    console = Console(emoji=False)
    console.print(Panel.fit(
        "[bold cyan]LAN SCANNER (IPv6 / NDP)[/bold cyan]\n"
        "[white]Quet neighbor IPv6, phan giai ten va quet cong qua AF_INET6.[/white]",
        border_style="cyan",
    ))

    configs = get_ipv6_config()
    if not configs:
        console.print("[red][-] Khong tim thay dia chi IPv6 usable tren may.[/red]")
        return False
    ifindices = {c["ifindex"] for c in configs if c.get("ifindex")}
    local_ips = [c["ip"] for c in configs]
    local_primary = sorted(
        configs,
        key=lambda c: 2 if c["kind"] == "link-local" else (1 if c["kind"] == "ula" else 0),
    )[0]["ip"]

    console.print(f"[*] IPv6 local: [bold yellow]{local_primary}[/bold yellow]")
    if subnet6:
        console.print(f"[*] Dai muc tieu: [bold yellow]{subnet6}[/bold yellow]")
    else:
        console.print("[*] Dai muc tieu: [bold yellow]AUTO6 (NDP cache toan bo interface)[/bold yellow]")
    console.print("[dim cyan][*] Dang ping multicast + tung neighbor de lam moi NDP cache...[/dim cyan]")

    alive = probe_ipv6_neighbors(configs)
    alive_ips = {nb["ip"] for nb in alive}
    neighbors = [nb for nb in get_ipv6_neighbors() if not ifindices or nb["ifindex"] in ifindices]
    # NDP cache la bang chung L2; nhieu thiet bi (iPhone) chan ICMPv6 nen van giu.
    for nb in neighbors:
        nb["alive"] = nb["ip"] in alive_ips
    if not neighbors:
        neighbors = alive

    gateway_entries = get_ipv6_gateways()
    gateway_ips = {str(g["ip"]).split("%", 1)[0] for g in gateway_entries}
    if subnet6:
        def in_subnet(nb):
            try:
                return ipaddress.ip_address(_ipv6_bare(nb["ip"])) in subnet6
            except Exception:
                return False
        scoped = [nb for nb in neighbors if in_subnet(nb) or _ipv6_bare(nb["ip"]) in gateway_ips]
        if scoped:
            neighbors = scoped

    if not neighbors:
        console.print("[yellow][!] Khong co neighbor IPv6 nao trong NDP cache.[/yellow]")
        return False

    def norm_mac(mac):
        return str(mac or "").replace(":", "-").upper()

    topo_path = _topology_path()
    try:
        with open(topo_path, "r", encoding="utf-8") as f:
            topology = json.load(f)
    except Exception:
        topology = {"nodes": [], "links": [], "subnet": ""}
    old_nodes = []
    removed_ids = set()
    def is_v6_node(n):
        return n.get("family") == "ipv6" or ":" in str(n.get("ip", ""))
    if subnet6 is None:
        old_nodes = [n for n in topology.get("nodes", []) if not is_v6_node(n)]
        removed_ids = {n.get("id") for n in topology.get("nodes", []) if is_v6_node(n)}
    else:
        def in_scan_node(n):
            try:
                return ipaddress.ip_address(_ipv6_bare(n.get("ip", ""))) in subnet6
            except Exception:
                return False
        old_nodes = [n for n in topology.get("nodes", []) if not (is_v6_node(n) and in_scan_node(n))]
        removed_ids = {n.get("id") for n in topology.get("nodes", []) if is_v6_node(n) and in_scan_node(n)}
    mac_meta = {}
    for n in old_nodes:
        m = norm_mac(n.get("mac"))
        if m and m not in ("UNKNOWN", "LOCAL PC", "LOCAL SYSTEM"):
            mac_meta[m] = n

    gateway_macs = {norm_mac(n.get("mac")) for n in old_nodes if n.get("group") == "gateway" and n.get("mac")}
    gateway_macs.discard("")
    for nb in neighbors:
        if _ipv6_bare(nb["ip"]) in gateway_ips:
            gateway_macs.add(norm_mac(nb["mac"]))

    groups = {}
    for nb in neighbors:
        groups.setdefault(norm_mac(nb["mac"]), []).append(nb)

    def rank(nb):
        try:
            addr = ipaddress.ip_address(_ipv6_bare(nb["ip"]))
            if addr.is_link_local: return 2
            if addr.is_private: return 1
            return 0
        except Exception:
            return 3

    results = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        futures = {}
        for mac, group in groups.items():
            primary = sorted(group, key=rank)[0]
            old = mac_meta.get(mac, {})
            futures[ex.submit(
                _ipv6_identify_device, primary, group, old, mac, port_mode, port_list
            )] = (mac, group, primary, old)
        for fut in as_completed(futures):
            mac, group, primary, old = futures[fut]
            try:
                results.append(fut.result())
            except Exception:
                results.append({
                    "mac": mac, "group": group, "primary": primary, "old": old,
                    "vendor": "Unknown", "hostname": "", "ports": "Error",
                    "hint": "", "type": "pc",
                })

    table = Table(
        title="[bold green]THIET BI IPv6 TRONG LAN[/bold green]",
        box=box.MINIMAL_DOUBLE_HEAD, show_lines=True,
    )
    table.add_column("Dia chi IPv6", style="cyan", no_wrap=True)
    table.add_column("MAC", style="magenta", no_wrap=True)
    table.add_column("Nha San Xuat", style="bold yellow")
    table.add_column("Cong Mo", style="green")
    table.add_column("Ten May / Goi Y", style="white", overflow="fold")

    gateway_existing = next((n for n in old_nodes if n.get("group") == "gateway"), None)
    local_existing = next((n for n in old_nodes if n.get("group") == "attacker"), None)
    gateway_node_id = gateway_existing.get("id") if gateway_existing else None
    local_node_id = local_existing.get("id") if local_existing else None
    new_nodes = []

    for item in results:
        mac, group, primary = item["mac"], item["group"], item["primary"]
        ip = primary["ip"]
        bare = _ipv6_bare(ip)
        is_gateway = mac in gateway_macs or bare in gateway_ips
        old = item["old"]
        vendor = item["vendor"]
        host = item["hostname"]
        ports = item["ports"]
        dev_type = item["type"]
        display_name = host or vendor or f"IPv6-{bare.split(':')[-1]}"
        if item.get("hint") and item["hint"] not in display_name:
            display_name = f"{display_name} ({item['hint']})"
        label = f"{display_name}\n{ip}"

        old_is_v6 = bool(old) and (old.get("family") == "ipv6" or ":" in str(old.get("ip", "")))
        if old and not is_gateway:
            old.setdefault("ipv6_addresses", [])
            for nb in group:
                if nb["ip"] not in old["ipv6_addresses"]:
                    old["ipv6_addresses"].append(nb["ip"])
            old["family_v6"] = True
            old["ipv6_primary"] = ip
            if not old.get("hostname") and host:
                old["hostname"] = host
            if (not old.get("vendor") or old.get("vendor") == "Unknown") and vendor:
                old["vendor"] = vendor
            if old_is_v6:
                old["ports"] = ports
                old["label"] = label
            table.add_row(ip, mac, str(vendor)[:25], str(ports)[:40], display_name[:80])
            continue

        if is_gateway:
            if gateway_existing:
                gateway_existing.setdefault("ipv6_addresses", [])
                for nb in group:
                    if nb["ip"] not in gateway_existing["ipv6_addresses"]:
                        gateway_existing["ipv6_addresses"].append(nb["ip"])
                gateway_existing["family_v6"] = True
                gateway_existing["ipv6_primary"] = ip
                gateway_node_id = gateway_existing.get("id")
                table.add_row(ip, mac, str(vendor)[:25], str(ports)[:40], f"{display_name[:72]} [GATEWAY]")
                continue
            node = {
                "id": ip, "ip": ip, "label": f"Gateway\n{ip}", "group": "gateway",
                "mac": mac, "vendor": vendor or "Router/Gateway",
                "hostname": host or "Router/Gateway", "ports": ports, "type": "router",
                "family": "ipv6", "ipv6_addresses": [nb["ip"] for nb in group],
                "ipv6_primary": ip,
                "ifindex": primary.get("ifindex"), "is_l2_local": True,
            }
            gateway_node_id = ip
            new_nodes.append(node)
        else:
            node = {
                "id": ip, "ip": ip, "label": label, "group": "victim",
                "mac": mac, "vendor": vendor, "hostname": host or display_name,
                "ports": ports, "type": dev_type, "family": "ipv6",
                "ipv6_addresses": [nb["ip"] for nb in group],
                "ipv6_primary": ip,
                "ifindex": primary.get("ifindex"), "is_l2_local": True,
            }
            new_nodes.append(node)

        table.add_row(ip, mac, str(vendor)[:25], str(ports)[:40], display_name[:80])

    if local_existing:
        local_existing.setdefault("ipv6_addresses", [])
        for ip in local_ips:
            if ip not in local_existing["ipv6_addresses"]:
                local_existing["ipv6_addresses"].append(ip)
        local_existing["family_v6"] = True
        local_existing["ipv6_primary"] = local_primary
        local_node_id = local_existing.get("id")
    else:
        node = {
            "id": local_primary, "ip": local_primary,
            "label": f"Attacker\n{local_primary}", "group": "attacker",
            "mac": "Local PC", "vendor": "Local System",
            "hostname": "Attacker Machine (IPv6)", "type": "attacker",
            "family": "ipv6", "ipv6_addresses": local_ips,
            "ipv6_primary": local_primary,
            "is_l2_local": True,
        }
        new_nodes.append(node)
        local_node_id = local_primary

    links = [
        l for l in topology.get("links", [])
        if l.get("source") not in removed_ids and l.get("target") not in removed_ids
    ]
    existing_links = {(l.get("source"), l.get("target")) for l in links}
    def add_link(src, dst, color):
        if src and dst and (src, dst) not in existing_links:
            links.append({"source": src, "target": dst, "color": color})
            existing_links.add((src, dst))
    for node in new_nodes:
        if node.get("group") == "victim":
            add_link(node["id"], gateway_node_id, "rgba(56, 189, 248, 0.4)")
            add_link(local_node_id, node["id"], "rgba(168, 85, 247, 0.3)")

    topology["nodes"] = old_nodes + new_nodes
    topology["links"] = links
    topology["subnet_v6"] = str(subnet6) if subnet6 else "auto"
    topology["ipv6_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(topo_path, "w", encoding="utf-8") as f:
            json.dump(topology, f, ensure_ascii=False, indent=2)
        console.print(f"[dim green][*] Topology IPv6 da merge: {topo_path}[/dim green]")
    except Exception as e:
        console.print(f"[red][-] Khong ghi duoc topology: {e}[/red]")

    console.print(table)
    console.print(f"[bold green][*] Hoan tat quet IPv6: {len(new_nodes)} node moi.[/bold green]")
    return True

def _ipv6_identify_device(primary, group, old, mac, port_mode, port_list):
    ip = primary["ip"]
    old_vendor = str(old.get("vendor") or "").strip()
    old_host = str(old.get("hostname") or "").strip()
    ports, hint = ("N/A", "")
    if port_mode != "skip":
        ports, hint = scan_ports_v6(ip, port_list=port_list)
    open_list = [p.strip() for p in str(ports).split(",") if p.strip().isdigit()]
    tls_port = next((int(p) for p in open_list if int(p) in (443, 8443, 9443, 5001)), None)
    host = old_host if old_host and old_host not in (ip, "Router/Gateway") else ""
    if not host:
        host = get_hostname_ipv6(ip, tls_port=tls_port)
    vendor = old_vendor or get_mac_vendor(mac)
    if old_vendor in ("", "Unknown") and vendor == "Unknown":
        try:
            vendor = get_mac_vendor(mac)
        except Exception:
            pass
    dev_type = old.get("type") or "pc"
    if ports and str(ports).strip().lower() not in ("none", "null", "", "n/a"):
        if dev_type not in ("router", "mobile"):
            dev_type = "server"
    return {
        "mac": mac, "group": group, "primary": primary, "old": old,
        "vendor": vendor, "hostname": host, "ports": ports,
        "hint": hint, "type": dev_type,
    }

def main():
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.prompt import Prompt
    from rich import box
    console = Console(emoji=False)
    console.print(Panel.fit("[bold cyan]LAN SCANNER (RECONNAISSANCE)[/bold cyan]\n[white]Quet mang, phan tich thiet bi va nhan dien diem mu.[/white]", border_style="cyan"))
    console.print("[*] Detecting local subnet...")
    local_ip = "127.0.0.1"
    detected_network = None
    gateway_ip = ""
    try:
        local_ip, detected_network, gateway_ip = detect_network_config()
    except Exception as e:
        console.print(f"[red][-] Khong detect duoc mang: {e}[/red]")
        sys.exit(1)
    raw_arg = sys.argv[1].strip() if len(sys.argv) > 1 else ""
    ipv6_hint = raw_arg.upper() in ("AUTO6", "IPV6", "V6") or ":" in raw_arg
    if not ipv6_hint:
        auto_discover_router_subnets(local_ip)
    is_interactive = sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty()
    
    user_input = ""
    mode_input = "2" # Mặc định Quick Scan khi chạy ngầm từ Web App

    if len(sys.argv) > 1 and sys.argv[1].strip() and sys.argv[1].strip().upper() != "AUTO":
        user_input = sys.argv[1].strip()
    elif is_interactive:
        try:
            user_input = Prompt.ask("[bold cyan]Nhap Dai Mang muon quet (hoac bam Enter de quet dai mac dinh)[/bold cyan]", default="").strip()
        except (EOFError, OSError):
            user_input = ""
            
    ipv6_request = False
    if user_input:
        if user_input.upper() in ("AUTO6", "IPV6", "V6") or ":" in user_input:
            ipv6_request = True
        else:
            if user_input.startswith("17.") and local_ip.startswith("172."): user_input = "172." + user_input[3:]
            try: scan_network = ipaddress.ip_network(user_input, strict=False)
            except ValueError:
                console.print(f"[red][-] Subnet khong hop le: {user_input}[/red]")
                sys.exit(1)
    else:
        scan_network = detected_network
        if detected_network.prefixlen < 24: scan_network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    target_subnet = str(scan_network) if not ipv6_request else user_input
    
    if len(sys.argv) > 2 and sys.argv[2].strip():
        mode_input = sys.argv[2].strip()
    elif is_interactive:
        console.print("\n[bold yellow]CHE DO QUET CONG (PORT SCAN):[/bold yellow]")
        console.print("  [cyan][1][/cyan] Full Scan -- Top-1000 ports (Nmap-level) [bold green]<-- Mac dinh[/bold green]")
        console.print("  [cyan][2][/cyan] Quick Scan -- Top-20 ports co ban (Nhanh hon)")
        console.print("  [cyan][3][/cyan] Skip -- Bo qua quet cong (Chi ARP/hostname)")
        try:
            mode_input = Prompt.ask("[bold cyan]Chon che do[/bold cyan]", choices=["1","2","3",""], default="1").strip()
        except (EOFError, OSError):
            mode_input = "2"
            
    if mode_input == "2": port_mode = "quick"; port_list = QUICK_PORTS
    elif mode_input == "3": port_mode = "skip"; port_list = []
    else: port_mode = "full"; port_list = NMAP_TOP_1000
    if ipv6_request:
        subnet6 = None
        if user_input.upper() not in ("AUTO6", "IPV6", "V6"):
            try:
                subnet6 = ipaddress.ip_network(user_input, strict=False)
            except ValueError:
                console.print(f"[red][-] Subnet IPv6 khong hop le: {user_input}[/red]")
                return
        run_ipv6_scan(subnet6, port_mode, port_list)
        return
    console.print(Panel.fit("[bold cyan]LAN SCANNER (LAYER 2 DISCOVERY)[/bold cyan]\n[white]Quet & Anh Xa Toan Bo Thiet Bi Trong Mang LAN[/white]", border_style="cyan"))
    console.print(f"[*] Dang quet dai mang muc tieu: [bold yellow]{target_subnet}[/bold yellow] ({scan_network.num_addresses} IPs)...")
    console.print("[dim cyan][*] Kich hoat Passive mDNS Listener...[/dim cyan]")
    start_passive_mdns_listener(duration=15.0)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
        task1 = progress.add_task("[cyan][1/2] Dang quet song ARP toan dai...", total=100)
        try:
            gateway_mac = get_arp_cache_full().get(gateway_ip) if gateway_ip else None
            active_l3_hosts = {}
            def force_arp(target_ip):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: s.sendto(b"", (target_ip, 1))
                    if gateway_mac:
                        try:
                            from scapy.all import Ether, IP, ICMP, sendp
                            pkt = Ether(dst=gateway_mac)/IP(dst=target_ip)/ICMP(type=8, code=0)
                            sendp(pkt, verbose=False)
                        except: pass
                except: pass
            def ping_l3_host(target_ip):
                try:
                    res = subprocess.run(f"ping -n 1 -w 300 {target_ip}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    if res.returncode == 0 and b"TTL=" in res.stdout.upper():
                        active_l3_hosts[target_ip] = gateway_mac if gateway_mac else "Routed L3 Host"
                except: pass
            total_hosts = scan_network.num_addresses
            step_progress = 50.0 / max(1, total_hosts)
            def force_arp_p(ip): force_arp(ip); progress.advance(task1, step_progress)
            def ping_l3_p(ip): ping_l3_host(ip); progress.advance(task1, step_progress)
            with ThreadPoolExecutor(max_workers=200) as ex: list(ex.map(force_arp_p, (str(ip) for ip in scan_network.hosts())))
            with ThreadPoolExecutor(max_workers=200) as ex: list(ex.map(ping_l3_p, (str(ip) for ip in scan_network.hosts())))
            if gateway_ip and ipaddress.ip_address(gateway_ip) not in scan_network: force_arp(gateway_ip)
            arp_retry = 1 if scan_network.num_addresses <= 256 else 0
            try:
                correct_iface = conf.route.route(gateway_ip)[0]
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet), iface=correct_iface, timeout=1.0, retry=arp_retry, verbose=False)
            except Exception:
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_subnet), timeout=1.0, retry=arp_retry, verbose=False)
        except KeyboardInterrupt: ans = []
        progress.update(task1, completed=100)
        arp_after = {ip: mac for ip, mac in get_arp_cache_full().items() if ipaddress.ip_address(ip) in scan_network or ip == gateway_ip}
        for _, reply in ans: arp_after[reply.psrc] = reply.hwsrc.replace(":", "-")
        to_remove = []
        for ip, mac in arp_after.items():
            if mac in ("ff-ff-ff-ff-ff-ff","ff:ff:ff:ff:ff:ff"): to_remove.append(ip); continue
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_multicast or str(addr).endswith(".255") or str(addr).endswith(".0"): to_remove.append(ip)
            except: pass
        for ip in to_remove: arp_after.pop(ip, None)
        for ip, mac_val in active_l3_hosts.items():
            if ip not in arp_after: arp_after[ip] = "Routed-L3-Host"
        send_multicast_probe()
        task2_label = f"[green][2/2] Phan giai ten may & nha san xuat{' + quet cong' if port_mode != 'skip' else ''}..."
        task2 = progress.add_task(task2_label, total=max(len(arp_after), 1))
        results = {}
        def resolve_device(ip, mac):
            vendor = get_mac_vendor(mac)
            if port_mode != "skip":
                ports, hint = scan_ports(ip, port_list=port_list)
            else:
                ports, hint = "N/A", ""
            open_list = [p.strip() for p in str(ports).split(",") if p.strip().isdigit()]
            tls_port = next((int(p) for p in open_list if int(p) in (443, 8443, 9443, 5001)), None)
            do_snmp = "161" in open_list
            hostname = get_hostname(ip, tls_port=tls_port, do_snmp=do_snmp)
            if not hostname:
                with _mdns_lock:
                    passive_name = _mdns_passives.get(ip, "")
                if passive_name: hostname = f"{passive_name} [mDNS passive]"
            return vendor, hostname, ports, hint
        with ThreadPoolExecutor(max_workers=25) as executor:
            future_to_ip = {executor.submit(resolve_device, ip, mac): ip for ip, mac in arp_after.items()}
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try: results[ip] = future.result()
                except: results[ip] = ("Unknown", "", "Error", "")
                progress.advance(task2)
    table = Table(title="[bold green]DANH SACH THIET BI HOAT DONG TRONG LAN[/bold green]", box=box.MINIMAL_DOUBLE_HEAD, show_lines=True)
    table.add_column("Dia chi IP", style="cyan", no_wrap=True)
    table.add_column("Dia chi MAC", style="magenta", no_wrap=True)
    table.add_column("Nha San Xuat", style="bold yellow")
    table.add_column("Cong Mo", style="green")
    table.add_column("Ten May / Goi Y Thiet Bi", style="white", overflow="fold")
    def sort_key(ip):
        if ip == gateway_ip: return (0, 0)
        if ip == local_ip: return (1, 0)
        try: return (2, int(ip.split(".")[-1]))
        except: return (2, 999)
    for ip in sorted(arp_after.keys(), key=sort_key):
        mac = arp_after[ip]
        vendor, host, ports, hint = results.get(ip, ("Unknown","","?",""))
        if mac == "Routed-L3-Host": vendor = "L3/VPN/Docker/Isolated"
        if vendor == "Virtual MAC (Random)":
            h = host.lower()
            if "iphone" in h or "ipad" in h or "apple" in h: vendor = "Apple (hostname)"
            elif "samsung" in h or "galaxy" in h: vendor = "Samsung (hostname)"
            elif "android" in h: vendor = "Android (hostname)"
        vendor_str = str(vendor).strip()[:25]
        gw_mark = ""
        if ip == gateway_ip: gw_mark = " [bold green](GATEWAY)[/bold green]"
        elif ip == local_ip: gw_mark = " [bold cyan](THIS PC)[/bold cyan]"
        host = add_vendor_identity(host, vendor_str)
        if ports and any(p in str(ports) for p in ["554","37777","34567","8554"]):
            if not host or host == "?": host = "[IP Camera / CCTV (RTSP)]"
        display_hint = f"{host} ({hint})" if hint and hint not in host else host
        if not display_hint or display_hint.strip() == "?": display_hint = "?"
        table.add_row(f"{ip}{gw_mark}", mac, vendor_str, str(ports)[:40] if ports else "None", display_hint)
    console.print(table)
    topology = {"nodes": [], "links": [], "subnet": target_subnet}
    if gateway_ip:
        topology["nodes"].append({"id":gateway_ip,"ip":gateway_ip,"label":f"Gateway\n{gateway_ip}","group":"gateway","mac":arp_after.get(gateway_ip,"Unknown"),"vendor":results.get(gateway_ip,("Router","","None",""))[0],"hostname":results.get(gateway_ip,("Router","","None",""))[1] or "Router/Gateway","type":"router","ports":results.get(gateway_ip,("Router","","None",""))[2]})
    topology["nodes"].append({"id":local_ip,"ip":local_ip,"label":f"Attacker\n{local_ip}","group":"attacker","mac":arp_after.get(local_ip,"Local PC"),"vendor":"Local System","hostname":"Attacker Machine","type":"attacker"})
    for ip, mac in arp_after.items():
        if ip in (gateway_ip, local_ip): continue
        vendor, host, ports, hint = results.get(ip, ("Unknown","","None",""))
        display_name = host if host and host not in ("?","") else (vendor if vendor not in ("Unknown","Virtual MAC (Random)") else f"Host-{ip.split('.')[-1]}")
        dev_type = "mobile" if any(k in str(vendor) for k in ["Apple","Samsung","OPPO","iPhone","Android","Xiaomi"]) else "pc"
        if ports and str(ports).strip().lower() not in ("none","null","","n/a"): dev_type = "server"
        topology["nodes"].append({"id":ip,"ip":ip,"label":f"{display_name}\n{ip}","group":"victim","mac":mac,"vendor":vendor,"hostname":host or display_name,"ports":ports,"type":dev_type,"is_l2_local":bool(mac and mac not in ("Routed-L3-Host","00-0c-42-00-00-02"))})
        if gateway_ip: topology["links"].append({"source":ip,"target":gateway_ip,"color":"rgba(56, 189, 248, 0.4)"})
        topology["links"].append({"source":local_ip,"target":ip,"color":"rgba(168, 85, 247, 0.3)"})
    try:
        mon_dir = os.path.dirname(os.path.abspath(__file__))
        if os.path.basename(mon_dir) != "monitoring": mon_dir = os.path.join(os.path.dirname(mon_dir), "monitoring")
        topo_path = os.path.join(mon_dir, "topology.json")
        with open(topo_path, "w", encoding="utf-8") as f: json.dump(topology, f, ensure_ascii=False, indent=2)
        console.print(f"[dim green][*] Topology da luu: {topo_path}[/dim green]")
    except Exception as e: print(f"[-] Error saving topology: {e}")
    console.print("\n[bold green][*] Hoan tat qua trinh quet mang![/bold green]")

if __name__ == "__main__":
    main()
