import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import json, os, base64, secrets, tempfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

DB_FILE = "passwords.json"
BACKUP_FILE = os.path.join(tempfile.gettempdir(), "passwords.json")

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                db = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Error while loading the database: {e}")
            db = {"salt": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(), "entries": {}}
    else:
        db = {"salt": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode(), "entries": {}}
        save_db(db, update_backup=False)
    return db

def save_db(db, update_backup=True):
    try:
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f)
    except Exception as e:
        messagebox.showerror("Error", f"Error while saving the database: {e}")
    if update_backup:
        try:
            with open(BACKUP_FILE, "w", encoding="utf-8") as f:
                json.dump(db, f)
        except Exception as e:
            messagebox.showerror("Error", f"Error while saving the Backup: {e}")
        try:
            with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                backup_content = json.load(f)
            print("Backup file was updated. Content:", backup_content)
        except Exception as e:
            print("Error while reading Backup:", e)

def derive_key(master_password, salt):
    salt_bytes = base64.urlsafe_b64decode(salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=10000000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

class PasswordManager:
    def __init__(self, key, db):
        self.cipher = Fernet(key)
        self.db = db

    def add_entry(self, name, password):
        encrypted = self.cipher.encrypt(password.encode()).decode()
        self.db["entries"][name] = encrypted
        save_db(self.db, update_backup=True)

    def get_all_entries(self):
        return self.db["entries"]

    def get_decrypted(self, name):
        encrypted = self.db["entries"][name]
        return self.cipher.decrypt(encrypted.encode()).decode()

    def delete_entry(self, name):
        if name in self.db["entries"]:
            del self.db["entries"][name]
            save_db(self.db, update_backup=True)

    def edit_entry(self, name, new_password):
        encrypted = self.cipher.encrypt(new_password.encode()).decode()
        self.db["entries"][name] = encrypted
        save_db(self.db, update_backup=True)

class LoginWindow(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding="20")
        master.title("Login - Password Manager")
        self.master = master
        self.create_widgets()
        self.grid(sticky=(tk.N, tk.W, tk.E, tk.S))
        self.entry_master.focus()

    def create_widgets(self):
        ttk.Label(self, text="Please enter your master password:", font=("Arial", 12)).grid(row=0, column=0, pady=(0,10))
        self.entry_master = ttk.Entry(self, show="*", width=30)
        self.entry_master.grid(row=1, column=0, pady=(0,10))
        self.entry_master.bind("<Return>", lambda event: self.login())
        ttk.Button(self, text="Anmelden", command=self.login).grid(row=2, column=0, pady=(10,0))

    def login(self):
        master_pw = self.entry_master.get()
        if not master_pw:
            messagebox.showerror("Error", "Please enter Master Password")
            return
        db = load_db()
        key = derive_key(master_pw, db["salt"])
        pm = PasswordManager(key, db)
        try:
            if pm.db["entries"]:
                test_name = next(iter(pm.db["entries"]))
                _ = pm.get_decrypted(test_name)
        except Exception as e:
            messagebox.showerror("Error", "Wrong Password!")
            return
        self.master.destroy()
        root_main = tk.Tk()
        MainWindow(root_main, pm)
        root_main.mainloop()

class MainWindow:
    def __init__(self, master, pm: PasswordManager):
        self.master = master
        self.pm = pm
        self.master.title("Passwort Manager")
        self.master.geometry("500x400")
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.create_widgets()
        self.master.protocol("WM_DELETE_WINDOW", self.secure_close)

    def create_widgets(self):
        frame = ttk.Frame(self.master, padding="10")
        frame.pack(fill="both", expand=True)
        
        menubar = tk.Menu(self.master)
        self.master.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.secure_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Change Master Password", command=self.change_master_password)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0,10))
        ttk.Button(btn_frame, text="Add Password", command=self.add_password).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Show Password", command=self.show_passwords).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Recovery", command=self.recover_from_backup).pack(side="left", padx=5)

        self.tree = ttk.Treeview(frame, columns=("Name"), show="headings", selectmode="browse")
        self.tree.heading("Name", text="Name")
        self.tree.column("Name", width=200, anchor="center")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self.on_tree_select)
        self.refresh_tree()

    def refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for name in self.pm.get_all_entries().keys():
            self.tree.insert("", tk.END, values=(name,))

    def add_password(self):
        dialog = AddPasswordDialog(self.master)
        self.master.wait_window(dialog.top)
        if dialog.result:
            name, password = dialog.result
            self.pm.add_entry(name, password)
            messagebox.showinfo("Success", f"Password '{name}' added")
            self.refresh_tree()

    def on_tree_select(self, event):
        selected = self.tree.focus()
        if not selected:
            return
        name = self.tree.item(selected)["values"][0]
        OptionsWindow(self.master, name, self.pm, self.refresh_tree)

    def show_passwords(self):
        win = tk.Toplevel(self.master)
        win.title("All passwords")
        win.geometry("400x300")
        listbox = tk.Listbox(win, font=("Arial", 10))
        listbox.pack(fill="both", expand=True, padx=10, pady=10)
        for name, _ in self.pm.get_all_entries().items():
            try:
                decrypted = self.pm.get_decrypted(name)
                listbox.insert(tk.END, f"{name}: {decrypted}")
            except Exception as e:
                listbox.insert(tk.END, f"{name}: <Fehler>")
        ttk.Button(win, text="Close", command=lambda: self.secure_close_window(win, listbox)).pack(pady=(0,10))
        win.protocol("WM_DELETE_WINDOW", lambda: self.secure_close_window(win, listbox))

    def secure_close_window(self, window, widget):
        widget.delete(0, tk.END)
        window.destroy()

    def change_master_password(self):
        dialog = ChangeMasterPasswordDialog(self.master)
        self.master.wait_window(dialog.top)
        if dialog.result:
            new_master = dialog.result
            new_salt = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode()
            new_key = derive_key(new_master, new_salt)
            new_cipher = Fernet(new_key)
            for name in list(self.pm.db["entries"].keys()):
                try:
                    decrypted = self.pm.get_decrypted(name)
                    encrypted_new = new_cipher.encrypt(decrypted.encode()).decode()
                    self.pm.db["entries"][name] = encrypted_new
                except Exception as e:
                    messagebox.showerror("Error", f"Error while re-encrypting '{name}': {e}")
                    return
            self.pm.db["salt"] = new_salt
            self.pm.cipher = new_cipher
            save_db(self.pm.db, update_backup=False)
            messagebox.showinfo("Success", "Master password has been successfully changed!")

    def recover_from_backup(self):
        if not os.path.exists(BACKUP_FILE):
            messagebox.showinfo("Recovery", "No backup found in the temp directory.")
            return
        if not messagebox.askyesno("Recovery", "Backup found. Do you want to recover the data?"):
            return
        try:
            with open(BACKUP_FILE, "r", encoding="utf-8") as f:
                recovered_db = json.load(f)
            with open(DB_FILE, "w", encoding="utf-8") as f:
                json.dump(recovered_db, f)
            self.pm.db = recovered_db
            self.refresh_tree()
            messagebox.showinfo("Recovery", "Database successfully restored from backup.")
        except Exception as e:
            messagebox.showerror("Recovery", f"Error while recovery: {e}")

    def secure_close(self):
        self.master.clipboard_clear()
        self.pm.cipher = None  
        self.master.destroy()

class AddPasswordDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Add a new password")
        self.top.grab_set()
        self.result = None
        
        ttk.Label(self.top, text="Password name:").pack(padx=10, pady=(10,0))
        self.entry_name = ttk.Entry(self.top, width=30)
        self.entry_name.pack(padx=10, pady=(0,10))
        
        ttk.Label(self.top, text="Password:").pack(padx=10, pady=(0,0))
        self.entry_password = ttk.Entry(self.top, show="*", width=30)
        self.entry_password.pack(padx=10, pady=(0,10))
        
        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Enter manually", command=self.manual).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="From file", command=self.from_file).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side="left", padx=5)

    def manual(self):
        name = self.entry_name.get().strip()
        password = self.entry_password.get().strip()
        if not name or not password:
            messagebox.showerror("Error", "Name and password must not be empty")
            return
        self.result = (name, password)
        self.top.destroy()

    def from_file(self):
        name = self.entry_name.get().strip()
        if not name:
            messagebox.showerror("Error", "Please enter your name first")
            return
        filename = filedialog.askopenfilename(title="Choose file")
        if not filename:
            return
        try:
            with open(filename, "r", encoding="utf-8") as f:
                password = f.read().strip()
            if not password:
                messagebox.showerror("Error", "The file is empty")
                return
            self.result = (name, password)
            self.top.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Error while reading file: {e}")

class ChangeMasterPasswordDialog:
    def __init__(self, parent):
        self.top = tk.Toplevel(parent)
        self.top.title("Change Master‑Password")
        self.top.grab_set()
        self.result = None
        
        ttk.Label(self.top, text="New Master‑Password:").pack(padx=10, pady=(10,0))
        self.entry_new = ttk.Entry(self.top, show="*", width=30)
        self.entry_new.pack(padx=10, pady=(0,10))
        
        ttk.Label(self.top, text="Repeat the new Master Password:").pack(padx=10, pady=(0,0))
        self.entry_confirm = ttk.Entry(self.top, show="*", width=30)
        self.entry_confirm.pack(padx=10, pady=(0,10))
        
        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Apply", command=self.on_ok).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.top.destroy).pack(side="left", padx=5)
    
    def on_ok(self):
        new_pw = self.entry_new.get().strip()
        confirm_pw = self.entry_confirm.get().strip()
        if not new_pw or not confirm_pw:
            messagebox.showerror("Error", "Both fields must be filled in")
            return
        if new_pw != confirm_pw:
            messagebox.showerror("Error", "The inputs do not match")
            return
        self.result = new_pw
        self.top.destroy()

class OptionsWindow:
    def __init__(self, parent, name, pm: PasswordManager, refresh_callback):
        self.pm = pm
        self.name = name
        self.refresh_callback = refresh_callback
        self.top = tk.Toplevel(parent)
        self.top.title(f"Options for password '{name}'")
        self.top.geometry("350x200")
        self.create_widgets()

    def create_widgets(self):
        try:
            decrypted = self.pm.get_decrypted(self.name)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption error: {e}")
            self.top.destroy()
            return

        ttk.Label(self.top, text="Password:", font=("Arial", 10, "bold")).pack(pady=(10,0))
        self.entry_pw = ttk.Entry(self.top, font=("Arial", 10), width=40)
        self.entry_pw.pack(pady=(0,10))
        self.entry_pw.insert(0, decrypted)
        self.entry_pw.config(state="readonly")

        btn_frame = ttk.Frame(self.top)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Delete", command=self.delete_entry).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Edit", command=self.edit_entry).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Download", command=self.download_entry).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Copy", command=self.copy_to_clipboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Close", command=self.secure_close).pack(side="left", padx=5)

        self.top.protocol("WM_DELETE_WINDOW", self.secure_close)

    def delete_entry(self):
        if messagebox.askyesno("Delete", f"Should '{self.name}' really be deleted?"):
            self.pm.delete_entry(self.name)
            messagebox.showinfo("Erfolg", f"'{self.name}' wurde gelöscht")
            self.secure_close()
            self.refresh_callback()

    def edit_entry(self):
        new_pw = simpledialog.askstring("Edit", "Input new password:", show="*")
        if new_pw:
            self.pm.edit_entry(self.name, new_pw)
            messagebox.showinfo("Success", f"'{self.name}' was updated")
            self.secure_close()
            self.refresh_callback()

    def download_entry(self):
        decrypted = self.pm.get_decrypted(self.name)
        save_path = filedialog.asksaveasfilename(initialfile=self.name, title="Download Password", defaultextension="")
        if save_path:
            try:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(decrypted)
                messagebox.showinfo("Success", f"'{self.name}' was downloaded")
            except Exception as e:
                messagebox.showerror("Error", f"Error while saving: {e}")

    def copy_to_clipboard(self):
        decrypted = self.pm.get_decrypted(self.name)
        self.top.clipboard_clear()
        self.top.clipboard_append(decrypted)
        messagebox.showinfo("Info", "Password copied to clipboard")
        self.top.after(20000, self.top.clipboard_clear)

    def secure_close(self):
        if hasattr(self, 'entry_pw'):
            self.entry_pw.config(state="normal")
            self.entry_pw.delete(0, tk.END)
        self.top.destroy()

def main():
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
