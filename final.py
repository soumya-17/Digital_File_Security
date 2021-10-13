import os
from pathlib import Path
import tkinter.filedialog
from tkinter import *
from tkinter import ttk, messagebox
import tkinter.messagebox
import mysql.connector
from Crypto import Random
from Crypto.Cipher import AES
import hashlib

# connecting to the database
connectiondb = mysql.connector.connect(
    host="127.0.0.1",
    user="root",
    password="trisha@09",
    database="login",
    auth_plugin='mysql_native_password'
)
cursordb = connectiondb.cursor()

def login():
    global root2
    root2 = Toplevel(root)
    root2.title("Account Login")
    root2.geometry("500x500")
    root2.config(bg="cyan3")
    global password_verification
    global secans_verification
    Label(root2, text='Please Enter your Account Details', bd=5, font=('arial', 12, 'bold'), relief="groove",
          fg="black", bg="gray60", width=300).pack()
    password_verification = StringVar()
    secans_verification = StringVar()
    Label(root2, text="", bg="cyan3").pack()
    Label(root2, text="Password :", fg="black", bg="gray60", font=('arial', 12, 'bold')).pack()
    Label(root2, text="", bg="cyan3").pack()
    Entry(root2, textvariable=password_verification, show="*").pack()
    Label(root2, text="", bg="cyan3").pack()
    Label(root2, text="Name your Virtual friend", fg="black", bg="gray60", font=('arial', 12, 'bold')).pack()
    Label(root2, text="", bg="cyan3").pack()
    Entry(root2, textvariable=secans_verification, show="*").pack()
    Label(root2, text="", bg="cyan3").pack()
    Button(root2, text='Forgot password', height="1", width="20", bd=8, font=('arial', 12, 'bold'), relief="groove",fg="white",bg="gray50", command=forget_password).pack()
    Label(root2, text="", bg="cyan3").pack()
    Button(root2, text="Login", bg="gray60", fg='black', relief="groove", font=('arial', 12, 'bold'),
           command=login_verification).pack()


def forgetpass_verification():
    if cmb_box.get() == "select" or ans_wer.get() == "" or new_password.get() == "":
        messagebox.showerror("Error ", " All the fields are required ")
    else:

        sql = "select * from record where  question= %s and sans=%s "
        cursordb.execute(sql, [(cmb_box.get()), (ans_wer.get())])
        results = cursordb.fetchall()
        if results==False:
            messagebox.showerror("Error", "Please select the corrected security question / enter answer")
            
        else:
            sql = "update record set password= %s where sans= %s"
            cursordb.execute(sql, [(new_password.get()),(ans_wer.get())])
            connectiondb.commit()
            connectiondb.close()
            messagebox.showinfo("success", "your password has been reset , Please login with new password")


def forget_password():
                for_pass = Toplevel(root2)
                for_pass.title("Forget Password ")
                for_pass.geometry("500x500")
                for_pass.config(bg="cyan3")
                for_pass.grab_set()
                global new_password
                global ans_wer
                new_password = StringVar()
                ans_wer = StringVar()
                global cmb_box

                Label(for_pass, text='Forget password', bd=10, font=('times new roman',14, 'bold'), relief="groove",fg="white", bg="gray50", width=100).pack()
                Label(for_pass, text="",bg="cyan3").pack()
                Label(for_pass, text='SECURITY QUESTION', bd=10, font=('times new roman', 14, 'bold'), relief="groove",
                      fg="white", bg="gray50", width=100).pack()

                n= StringVar()
                cmb_box = ttk.Combobox(for_pass, font=("times new roman", 13), width=27, textvariable= n)
                cmb_box['values'] = (
                "select", " your first pet name", " name your virtual friend ", "your favourite anime character")
                cmb_box.current(0)
                cmb_box.pack()
                Label(for_pass, text="",bg="cyan3").pack()
                Label(for_pass, text='Answer', bd=10, font=('arial',14, 'bold'), fg="white",bg="gray50", width=100).pack()
                Label(for_pass, text="",bg="cyan3").pack()
                Entry(for_pass, textvariable=ans_wer, show= "*").pack()
                Label(for_pass, text="", bg="cyan3").pack()
                Label(for_pass, text='New password', bd=10, font=('arial',14, 'bold'), fg="white",bg="gray50", width=100).pack()
                Label(for_pass, text="",bg="cyan3").pack()
                Entry(for_pass, textvariable=new_password).pack()
                Label(for_pass, text="", bg="cyan3").pack()
                Button(for_pass, text='Reset password', height="1", width="20", bd=8, font=('comic sans ms', 12, 'bold'), relief="groove", fg="white", bg="gray60",command =forgetpass_verification ).pack()

def logged_destroy():
    logged_next.destroy()
    root2.destroy()


def failed_destroy():
    failed_message.destroy()


class Encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, message, key, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def hash_file(self, file_name):
        print("reached")
        h = hashlib.sha1()
        with open(file_name, 'rb') as fo:
            chunk = 0
            while chunk != b'':
                chunk = fo.read(1024)
                h.update(chunk)
            return h.hexdigest()

    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            plaintext = fo.read()
        enc = self.encrypt(plaintext, self.key)
        with open(file_name + ".enc", 'wb') as fo:
            fo.write(enc)
        os.remove(file_name)
        print("stop")

    def decrypt(self, ciphertext, key):
        iv = ciphertext[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")

    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fo:
            ciphertext = fo.read()
        dec = self.decrypt(ciphertext, self.key)
        with open(file_name[:-4], 'wb') as fo:
            fo.write(dec)
        os.remove(file_name)


key = b'[EX\xc8\xd5\xbfI{\xa2$\x05(\xd5\x18\xbf\xc0\x85)\x10nc\x94\x02)j\xdf\xcb\xc4\x94\x9d(\x9e'
enc = Encryptor(key)


def encryption():
    global com1
    s = tkinter.filedialog.askopenfilename()  # API to select file from system
    print(s)  # path of file selected
    p = Path(s)
    file, ext = os.path.splitext(s)
    y = (p.stem)  # storing root value at y
    print(y)
    print(ext)
    k = (y + ext)
    print(enc.hash_file(k))
    com1 =enc.hash_file(k)
    enc.encrypt_file(k)


def decryption():
    global com2
    s = tkinter.filedialog.askopenfilename()  # API to select file from system
    print(s)  # path of file selected
    p = Path(s)
    file, ext = os.path.splitext(s)
    y = (p.stem)  # storing root value at y
    print(y)
    print(ext)
    k = (y + ext)
    enc.decrypt_file(k)
    file1,ext1 =os.path.splitext(k)
    print(enc.hash_file(file1))
    com2 =enc.hash_file(file1)
    if (com1==com2):
            global failed_message
            failed_message = Toplevel(root2)
            failed_message.title("Invalid Message")
            failed_message.geometry("500x100")
            Label(failed_message, text="Integrity of the file is preserved", fg="red", font="bold").pack()
            Label(failed_message, text="").pack()
            Button(failed_message, text="Ok", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'),
                     command=failed_destroy).pack()



def decrypt():
    global logged_next
    logged_next = Toplevel(root2)
    logged_next.title("Option")
    logged_next.geometry("450x300")
    logged_next.config(bg="cyan3")
    Label(logged_next, text="", bg="cyan3").pack()
    Label(logged_next, text="select a file to decrypt", fg="black", font=('comic sans ms', 12, 'bold'),
          bg="cyan3").pack()
    Button(logged_next, text="SELECT", bg="indianRed1", fg='black', relief="groove", font=('comic sans ms', 11, 'bold'),
           command=decryption).pack()


def encrypt():
    global logged_next
    logged_next = Toplevel(root2)
    logged_next.title("Option")
    logged_next.geometry("450x300")
    logged_next.config(bg="cyan3")
    Label(logged_next, text="", bg="cyan3").pack()
    Label(logged_next, text="select a file to encrypt", fg="black", font=('comic sans ms', 12, 'bold'),
          bg="cyan3").pack()
    Button(logged_next, text="SELECT", bg="indianRed1", fg='black', relief="groove", font=('comic sans ms', 11, 'bold'),
           command=encryption).pack()




def logged():
    global logged_next
    logged_next = Toplevel(root2)
    logged_next.title("Option")
    logged_next.geometry("450x300")
    logged_next.config(bg="cyan3")
    Label(logged_next, text="",bg="cyan3").pack()
    Button(logged_next, text="ENCRYPT  FILE", bg="indianRed1", fg='black', relief="groove",
           font=('comic sans ms', 11, 'bold'), command=encrypt).pack()
    Label(logged_next, text="",bg="cyan3").pack()
    Button(logged_next, text="DECRYPT  FILE", bg="indianRed1", fg='black', relief="groove",
           font=('comic sans ms', 11, 'bold'), command=decrypt).pack()
    Label(logged_next, text="",bg="cyan3").pack()
    Button(logged_next, text="Logout", bg="gray50", fg='black', relief="groove", font=('arial', 12, 'bold'),
           command=logged_destroy).pack()
def failed():
    global failed_message
    failed_message = Toplevel(root2)
    failed_message.title("Invalid Message")
    failed_message.geometry("500x100")
    Label(failed_message, text="Invalid security answer or Password", fg="red", font="bold").pack()
    Label(failed_message, text="").pack()
    Button(failed_message, text="Ok", bg="blue", fg='white', relief="groove", font=('arial', 12, 'bold'),
           command=failed_destroy).pack()


def login_verification():
    pass_verification = password_verification.get()
    sans_verification = secans_verification.get()
    sql = "select * from record where  password = %s and sans= %s"
    cursordb.execute(sql, [(pass_verification), (sans_verification)])
    results = cursordb.fetchall()
    if results:
        for i in results:
            logged()
            break
    else:
        failed()


def Exit():
    wayOut = tkinter.messagebox.askyesno("Login System", "Do you want to exit the system")
    if wayOut > 0:
        root.destroy()
        return


def main_display():
    global root
    root = Tk()
    root.config(bg="cyan3")
    root.title("Login System")
    root.geometry("500x500")
    Label(root, text='Welcome to Log In System', bd=20, font=('arial', 20, 'bold'), relief="groove", fg="white",
          bg="gray50", width=300).pack()
    Label(root, text="", bg="cyan3").pack()
    Button(root, text='Log In', height="1", width="20", bd=8, font=('arial', 12, 'bold'), relief="groove", fg="white",
           bg="gray50", command=login).pack()
    Label(root, text="", bg="cyan3").pack()
    Button(root, text='Exit', height="1", width="20", bd=8, font=('arial', 12, 'bold'), relief="groove", fg="white",
           bg="gray50", command=Exit).pack()


main_display()
root.mainloop()
