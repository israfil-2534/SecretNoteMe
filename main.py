from tkinter import *
from tkinter import messagebox
import tkinter as tk
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
#------------------------

def encrypt_text(password, plaintext):
    salt = os.urandom(16)  # Rastgele salt oluştur
    key = PBKDF2(password, salt, dkLen=32)  # Kullanıcı şifresinden AES anahtarı oluştur

    cipher = AES.new(key, AES.MODE_GCM)  # AES-GCM Modu (Daha güvenli)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())  # Metni şifrele

    # Salt, nonce, tag ve şifreli veriyi birleştirip base64 olarak döndür
    encrypted_data = base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()
    return encrypted_data


def decrypt_text(password, encrypted_data):
    try:
        data = base64.b64decode(encrypted_data)  # Base64 çöz
        salt, nonce, tag, ciphertext = data[:16], data[16:32], data[32:48], data[48:]

        key = PBKDF2(password, salt, dkLen=32)  # Aynı şifre ile AES anahtarını üret
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # Şifreyi çöz
        return plaintext.decode()
    except Exception:
        return None  # Hatalı şifre girildiğinde None döndür


# Şifreli Dosya Kaydetme
def save_encrypted_file():
    file_name = entry_filename.get()
    password = entry_password.get().strip()
    text_content = text_area.get("1.0", tk.END).strip()

    if not file_name or not password or not text_content:
        messagebox.showwarning("Uyarı", "Lütfen tüm alanları doldurun!")
        return

    encrypted_content = encrypt_text(password, text_content)

    with open(f"{file_name}.txt", "w") as file:
        file.write(encrypted_content)
        clear_Element()
    messagebox.showinfo("Başarılı", f"Şifreli dosya {file_name}.txt olarak kaydedildi.")


# Şifreli Dosya Açma
def open_encrypted_file():
    file_name = entry_filename.get().strip()
    password = entry_password.get().strip()

    if not file_name or not password:
        messagebox.showwarning("Uyarı", "Dosya adı ve şifreyi girin!")
        return

    try:
        with open(f"{file_name}.txt", "r") as file:
            encrypted_content = file.read()

        decrypted_content = decrypt_text(password, encrypted_content)

        if decrypted_content is None:
            messagebox.showerror("Hata", "Hatalı şifre! Dosya çözülemedi.")
        else:
            text_area.delete("1.0", tk.END)
            text_area.insert(tk.END, decrypted_content)

            messagebox.showinfo("Başarılı", "Dosya başarıyla çözüldü!")

    except FileNotFoundError:
        messagebox.showerror("Hata", "Dosya bulunamadı!")



#------------------------------
window=Tk()
window.title("Secreet Notes")
window.config(padx=30, pady=30)
#window.minsize(width=400, height=600)
def image_converter(use_image):
    image_path= use_image
    image_o=Image.open(image_path)
    new_w=60
    new_h=60
    im_rsz=image_o.resize((new_w, new_h))
    photo=ImageTk.PhotoImage(im_rsz)
    return photo
#----------------





#------------------
image=image_converter("download.png")
label=Label(window,image=image)
label.pack()

#Label
title_name=Label(text="Enter Your Title")
title_name.pack()

entry_filename=Entry(window,bg="light green",
                     justify="center",
                     width=20,
                     validate="key",
                     font=("Arial Black",10, "bold"),
                    )
entry_filename.pack()

label_title=Label(text="Enter Your Secret")
label_title.pack()

text_area=Text(window,bg="light green",
                     width=20,
                     height=10,
                     font=("Arial Black",10, "bold"),
                    )
text_area.pack()

label_master=Label(text="Enter Master Key")
label_master.pack()

entry_password=Entry(window,bg="red",
                     justify="center",
                     width=20,
                     validate="key",
                     font=("Arial Black",10, "bold"),
                    )
entry_password.pack()


save_encrypt=Button(text="Save & Encrypt",command=save_encrypted_file)
save_encrypt.pack()

decrypt=Button(text="Decrypt", command=open_encrypted_file)
decrypt.pack()

def clear_Element():
    entry_filename.delete(0, tk.END)
    entry_password.delete(0, tk.END)
    text_area.delete("1.0", tk.END)

window.mainloop()