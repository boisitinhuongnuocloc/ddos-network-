import sys, io, subprocess, winreg, ctypes

if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace', line_buffering=True, write_through=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace', line_buffering=True, write_through=True)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def disable_llmnr():
    print("[*] Dang vo hieu hoa LLMNR trong Registry...")
    try:
        key_path = r"Software\Policies\Microsoft\Windows NT\DNSClient"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.SetValueEx(key, "EnableMulticast", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        print("[+] Thanh cong: LLMNR da bi tat!")
    except Exception as e:
        print(f"[-] Loi tat LLMNR: {e}")

def block_smb():
    print("[*] Dang thiet lap Tuong lua chan Port 445 (Chong SMB/WannaCry)...")
    cmd = 'netsh advfirewall firewall add rule name="Block SMB 445" dir=in action=block protocol=TCP localport=445'
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[+] Thanh cong: Port 445 da bi dong chat!")
    except Exception as e:
        print(f"[-] Loi thiet lap Tuong lua: {e}")

def main():
    print("==================================================")
    print("  WINDOWS DEFEND - KICH HOAT LA CHAN THEP")
    print("==================================================")
    
    if not is_admin():
        print("[!] LOI: Ban phai chay CMD bang quyen Administrator de thiet lap he thong!")
        sys.exit(1)
        
    disable_llmnr()
    block_smb()
    print("\n[+] He thong cua ban da duoc boc giap! Khong con so bi tan cong nguoc nua.")

if __name__ == "__main__":
    main()
