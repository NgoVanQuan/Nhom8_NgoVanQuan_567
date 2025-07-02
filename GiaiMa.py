import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import os
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import base64
import json
import datetime

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ứng dụng Mã hóa/Giải mã")
        self.root.geometry("800x600")
        
        # Tạo notebook (tabs)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tạo các tab
        self.create_key_tab()
        self.create_sender_tab()
        self.create_receiver_tab()
        
    def create_key_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Tạo Khóa")
        
        frame = ttk.LabelFrame(tab, text="Quản lý Khóa RSA")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="Thư mục khóa:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.key_dir = tk.StringVar(value="rsa_keys")
        ttk.Entry(frame, textvariable=self.key_dir, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Duyệt...", command=self.browse_key_dir).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Label(frame, text="Trạng thái:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.key_status = tk.StringVar()
        ttk.Label(frame, textvariable=self.key_status).grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Button(frame, text="Tạo Khóa", command=self.generate_keys).grid(row=2, column=0, columnspan=3, pady=10)
        
        ttk.Separator(frame, orient='horizontal').grid(row=3, column=0, columnspan=3, sticky='ew', pady=10)
        
        # Hiển thị thông tin khóa
        key_info_frame = ttk.Frame(frame)
        key_info_frame.grid(row=4, column=0, columnspan=3, sticky='nsew')
        
        ttk.Label(key_info_frame, text="Khóa Sender Public:").pack(anchor='w')
        self.sender_pub_info = scrolledtext.ScrolledText(key_info_frame, height=4, width=70)
        self.sender_pub_info.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_info_frame, text="Khóa Receiver Private:").pack(anchor='w')
        self.receiver_priv_info = scrolledtext.ScrolledText(key_info_frame, height=4, width=70)
        self.receiver_priv_info.pack(fill='x', padx=5, pady=5)
        
    def create_sender_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Người gửi")
        
        frame = ttk.LabelFrame(tab, text="Mã hóa Tệp")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Chọn tệp đầu vào
        ttk.Label(frame, text="Tệp cần mã hóa:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.input_file = tk.StringVar()
        ttk.Entry(frame, textvariable=self.input_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn...", command=self.browse_input_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Chọn tệp đầu ra
        ttk.Label(frame, text="Tệp kết quả (JSON):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.output_file = tk.StringVar(value="encrypted.json")
        ttk.Entry(frame, textvariable=self.output_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn...", command=self.browse_output_file).grid(row=1, column=2, padx=5, pady=5)
        
        # Hiển thị nội dung
        ttk.Label(frame, text="Nội dung gốc:").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.original_content = scrolledtext.ScrolledText(frame, height=8, width=40)
        self.original_content.grid(row=3, column=0, padx=5, pady=5, sticky='nsew')
        
        ttk.Label(frame, text="Kết quả mã hóa:").grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky='nw')
        self.encrypted_content = scrolledtext.ScrolledText(frame, height=8, width=40)
        self.encrypted_content.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky='nsew')
        
        # Nút mã hóa
        ttk.Button(frame, text="Mã hóa", command=self.encrypt_file).grid(row=4, column=0, columnspan=3, pady=10)
        
    def create_receiver_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Người nhận")
        
        frame = ttk.LabelFrame(tab, text="Giải mã Tệp")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Chọn tệp đầu vào
        ttk.Label(frame, text="Tệp mã hóa (JSON):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.encrypted_file = tk.StringVar(value="encrypted.json")
        ttk.Entry(frame, textvariable=self.encrypted_file, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn...", command=self.browse_encrypted_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Chọn tệp đầu ra
        ttk.Label(frame, text="Tệp kết quả:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.decrypted_file = tk.StringVar(value="email_decrypted.txt")
        ttk.Entry(frame, textvariable=self.decrypted_file, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(frame, text="Chọn...", command=self.browse_decrypted_file).grid(row=1, column=2, padx=5, pady=5)
        
        # Hiển thị nội dung
        ttk.Label(frame, text="Dữ liệu mã hóa:").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.cipher_content = scrolledtext.ScrolledText(frame, height=8, width=40)
        self.cipher_content.grid(row=3, column=0, padx=5, pady=5, sticky='nsew')
        
        ttk.Label(frame, text="Nội dung giải mã:").grid(row=2, column=1, columnspan=2, padx=5, pady=5, sticky='nw')
        self.decrypted_content = scrolledtext.ScrolledText(frame, height=8, width=40)
        self.decrypted_content.grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky='nsew')
        
        # Kết quả xác thực
        ttk.Label(frame, text="Kết quả xác thực:").grid(row=4, column=0, padx=5, pady=5, sticky='w')
        self.auth_result = tk.StringVar()
        ttk.Label(frame, textvariable=self.auth_result).grid(row=4, column=1, padx=5, pady=5, sticky='w')
        
        # Nút giải mã
        ttk.Button(frame, text="Giải mã", command=self.decrypt_file).grid(row=5, column=0, columnspan=3, pady=10)
    
    def browse_key_dir(self):
        directory = filedialog.askdirectory()
        if directory:
            self.key_dir.set(directory)
    
    def browse_input_file(self):
        file = filedialog.askopenfilename()
        if file:
            self.input_file.set(file)
            self.load_file_content(file, self.original_content)
    
    def browse_output_file(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file:
            self.output_file.set(file)
    
    def browse_encrypted_file(self):
        file = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file:
            self.encrypted_file.set(file)
            self.load_file_content(file, self.cipher_content)
    
    def browse_decrypted_file(self):
        file = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file:
            self.decrypted_file.set(file)
    
    def load_file_content(self, file_path, text_widget):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, content)
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể đọc tệp: {str(e)}")
    
    def generate_keys(self):
        try:
            key_dir = self.key_dir.get()
            os.makedirs(key_dir, exist_ok=True)
            
            # Tạo khóa cho sender
            sender_key = RSA.generate(2048)
            with open(f"{key_dir}/sender_private.pem", "wb") as f:
                f.write(sender_key.export_key())
            with open(f"{key_dir}/sender_public.pem", "wb") as f:
                f.write(sender_key.publickey().export_key())
            
            # Tạo khóa cho receiver
            receiver_key = RSA.generate(2048)
            with open(f"{key_dir}/receiver_private.pem", "wb") as f:
                f.write(receiver_key.export_key())
            with open(f"{key_dir}/receiver_public.pem", "wb") as f:
                f.write(receiver_key.publickey().export_key())
            
            # Hiển thị thông tin khóa
            self.sender_pub_info.delete(1.0, tk.END)
            self.sender_pub_info.insert(tk.END, sender_key.publickey().export_key().decode())
            
            self.receiver_priv_info.delete(1.0, tk.END)
            self.receiver_priv_info.insert(tk.END, receiver_key.export_key().decode())
            
            self.key_status.set("✅ Đã tạo khóa thành công!")
        except Exception as e:
            self.key_status.set(f"❌ Lỗi: {str(e)}")
    
    def encrypt_file(self):
        try:
            # Đọc nội dung tệp
            with open(self.input_file.get(), "rb") as f:
                plaintext = f.read()
            
            # Tạo session key và iv
            session_key = get_random_bytes(32)
            iv = get_random_bytes(16)
            
            # Mã hóa AES
            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            pad = lambda s: s + b"\0" * (AES.block_size - len(s) % AES.block_size)
            ciphertext = cipher.encrypt(pad(plaintext))
            
            # Thời gian hết hạn
            exp_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            # Tạo chữ ký
            hash_val = SHA512.new(iv + ciphertext + exp_time.encode())
            with open(f"{self.key_dir.get()}/sender_private.pem", "rb") as f:
                sender_priv = RSA.import_key(f.read())
            signature = pkcs1_15.new(sender_priv).sign(hash_val)
            
            # Mã hóa session key
            with open(f"{self.key_dir.get()}/receiver_public.pem", "rb") as f:
                receiver_pub = RSA.import_key(f.read())
            cipher_rsa = PKCS1_v1_5.new(receiver_pub)
            enc_session_key = cipher_rsa.encrypt(session_key)
            
            # Tạo payload
            payload = {
                "iv": base64.b64encode(iv).decode(),
                "cipher": base64.b64encode(ciphertext).decode(),
                "hash": hash_val.hexdigest(),
                "sig": base64.b64encode(signature).decode(),
                "exp": exp_time,
                "session_key": base64.b64encode(enc_session_key).decode()
            }
            
            # Lưu kết quả
            output_path = self.output_file.get()
            with open(output_path, "w") as f:
                json.dump(payload, f, indent=4)
            
            # Hiển thị kết quả
            self.encrypted_content.delete(1.0, tk.END)
            self.encrypted_content.insert(tk.END, json.dumps(payload, indent=4))
            
            messagebox.showinfo("Thành công", f"✅ Đã tạo {output_path} với hạn dùng đến {exp_time}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"❌ Lỗi khi mã hóa: {str(e)}")
    
    def decrypt_file(self):
        try:
            # Đọc dữ liệu mã hóa
            with open(self.encrypted_file.get(), "r") as f:
                data = json.load(f)
            
            # Kiểm tra thời hạn
            exp = datetime.datetime.strptime(data["exp"], "%Y-%m-%dT%H:%M:%SZ")
            now = datetime.datetime.utcnow()
            if now > exp:
                self.auth_result.set("❌ Quá hạn! Không giải mã.")
                return
            
            # Giải mã session key
            with open(f"{self.key_dir.get()}/receiver_private.pem", "rb") as f:
                receiver_priv = RSA.import_key(f.read())
            enc_key = base64.b64decode(data["session_key"])
            cipher_rsa = PKCS1_v1_5.new(receiver_priv)
            session_key = cipher_rsa.decrypt(enc_key, None)
            
            # Xác thực chữ ký
            iv = base64.b64decode(data["iv"])
            ciphertext = base64.b64decode(data["cipher"])
            sig = base64.b64decode(data["sig"])
            hash_val = SHA512.new(iv + ciphertext + data["exp"].encode())
            
            try:
                with open(f"{self.key_dir.get()}/sender_public.pem", "rb") as f:
                    sender_pub = RSA.import_key(f.read())
                pkcs1_15.new(sender_pub).verify(hash_val, sig)
                self.auth_result.set("✅ Chữ ký hợp lệ.")
            except (ValueError, TypeError):
                self.auth_result.set("❌ Chữ ký không hợp lệ.")
                return
            
            # Giải mã nội dung
            cipher = AES.new(session_key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).rstrip(b"\0")
            
            # Lưu kết quả
            output_path = self.decrypted_file.get()
            with open(output_path, "wb") as f:
                f.write(plaintext)
            
            # Hiển thị nội dung
            self.decrypted_content.delete(1.0, tk.END)
            self.decrypted_content.insert(tk.END, plaintext.decode())
            
            messagebox.showinfo("Thành công", f"✅ Đã giải mã và lưu vào {output_path}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"❌ Lỗi khi giải mã: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
