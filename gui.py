import tkinter as tk
from tkinter import messagebox
import socket
import re
import hashlib
import multiprocessing
import threading
import time
from protocol import client_protocol
import sys

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Client GUI")
        self.server_ip = "192.168.0.238"
        self.server_port = 5555
        self.client_socket = socket.socket()
        self.connected = False
        self.username = ""
        self.found = False
        self.start_time = 0
        self.logged_in = False

        self.root.withdraw() # hide root
        self.connect_to_server()
        if not self.connected:
            self.root.destroy()
            return
        self.root.deiconify() # show root after connection
        self.setup_gui()
        self.label.config(text="Please register or login.")

    def setup_gui(self):
        self.frame = tk.Frame(self.root)
        self.frame.pack(padx=20, pady=20)

        tk.Label(self.frame, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self.frame)
        self.username_entry.grid(row=0, column=1, columnspan=2)

        tk.Label(self.frame, text="Password:").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.frame, show="*")
        self.password_entry.grid(row=1, column=1, columnspan=2)

        tk.Label(self.frame, text="Phone Number:").grid(row=2, column=0)
        self.phone_entry = tk.Entry(self.frame)
        self.phone_entry.grid(row=2, column=1, columnspan=2)

        self.register_button = tk.Button(self.frame, text="Register", command=self.register)
        self.register_button.grid(row=3, column=0, sticky="nsew", padx=(0, 5))

        self.login_button = tk.Button(self.frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=1, sticky="nsew", padx=5)

        self.logout_button = tk.Button(self.frame, text="Logout", command=self.logout)
        self.logout_button.grid(row=3, column=2, sticky="nsew", padx=(5, 0))
        
        self.label = tk.Label(self.frame, text="Welcome to the Client GUI")
        self.label.grid(row=4, column=0, columnspan=3)

        # Center the window on the screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

        # Set focus back to the username entry after displaying messages
        self.root.focus_force()
        self.username_entry.focus_set()

    def connect_to_server(self):
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            self.connected = True
            messagebox.showinfo("Connection", "Connected to server successfully.")
        except socket.error as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")

    def validate_username(self, username):
        return (4 <= len(username) <= 16 and
                re.fullmatch(r"[a-zA-Z0-9]+", username) is not None)

    def validate_password(self, password):
        return (6 <= len(password) <= 16 and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                re.fullmatch(r"[a-zA-Z0-9]+", password) is not None)

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        phone_number = self.phone_entry.get()

        if not self.validate_username(username):
            messagebox.showerror("Invalid Username", "Username must be 4-16 characters, letters, or numbers.")
            self.username_entry.focus_set()
            return

        if not self.validate_password(password):
            messagebox.showerror("Invalid Password", "Password must be 6-16 characters, include 1 uppercase and 1 digit.")
            self.password_entry.focus_set()
            return

        if len(phone_number) != 10 or not phone_number.isdigit():
            messagebox.showerror("Invalid Phone Number", "Phone number must be 10 digits.")
            self.phone_entry.focus_set()
            return

        try:
            response = client_protocol.register(self.client_socket, username, password, phone_number)
            if response:
                messagebox.showinfo("Success", "Registration Successful")
                self.label.config(text="You have registered, Please click login.")
            else:
                messagebox.showerror("Failed", "Registration on server failed")
                self.label.config(text="Please retry registration.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

        self.username_entry.focus_set()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        # Validate username/password first
        if not self.validate_username(username) or not self.validate_password(password):
            messagebox.showerror("Invalid Input", "Invalid username or password format.")
            self.username_entry.focus_set()
            return

        try:
            response = client_protocol.login(self.client_socket, username, password)
            if response:
                messagebox.showinfo("Success", "Login Successful")
                self.connected = True
                self.username = username

                # Hide all widgets except the logout button and label
                for widget in self.frame.winfo_children():
                    if widget not in [self.logout_button, self.label]:
                        widget.grid_remove()

                # Remove any old geometry management on label/logout_button
                self.logout_button.grid_remove()
                self.label.grid_remove()

                # (Optional) Place the label higher up
                self.label.config(text="Searching for the number...")
                self.label.place(relx=0.5, rely=0.25, anchor=tk.CENTER)

                # Center the logout button
                self.logout_button.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

                self.logged_in = True
                self.start_hash_search()
            else:
                messagebox.showerror("Failed", "Login Failed")
        except Exception as e:
            messagebox.showerror("Error", str(e))

        self.username_entry.focus_set()

    def logout(self):
        if not self.logged_in:
            messagebox.showwarning("Warning", "Not logged in.")
            self.username_entry.focus_set()
            return

        try:
            client_protocol.logout(self.client_socket)
            self.logged_in = False
            messagebox.showinfo("Success", "Logout Successful")

            # Remove place geometry for logout button and label
            self.logout_button.place_forget()
            self.label.place_forget()

            # Restore all widgets with grid
            for widget in self.frame.winfo_children():
                widget.grid()

            self.label.config(text="Welcome to the Client GUI")
        except Exception as e:
            messagebox.showerror("Error", str(e))

        self.username_entry.focus_set()

    def start_hash_search(self):
        threading.Thread(target=self.hash_search_loop, daemon=True).start()

    def hash_search_loop(self):
        while self.connected and self.logged_in and not self.found:
            print(self.connected, self.logged_in, self.found)
            ans = client_protocol.get_range(self.client_socket, self.username)
            while isinstance(ans, bool) and not ans:
                ans = client_protocol.get_range(self.client_socket, self.username)
            if isinstance(ans, int):
                self.found = True
                messagebox.showinfo("Found", f"Hash match found: {ans}")
                break
            start, end, target_hash = ans
            result = find_md5_match(start, end, target_hash)
            if result is not None:
                client_protocol.send_found(self.client_socket, result)


def calc_hash(args):
    start, end, target_hash = args
    for number in range(start, end + 1):
        if hashlib.md5(str(number).encode()).hexdigest() == target_hash:
            return number
    return None


def find_md5_match(start, end, target_hash, num_processes=None):
    if num_processes is None:
        num_processes = multiprocessing.cpu_count()

    range_size = end - start + 1
    chunk_size = range_size // num_processes
    chunks = [(start + i * chunk_size, min(start + (i + 1) * chunk_size - 1, end), target_hash) for i in range(num_processes)]

    with multiprocessing.Pool(processes=num_processes) as pool:
        results = pool.map(calc_hash, chunks)
        for result in results:
            if result is not None:
                return result
    return None

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientGUI(root)
    if app.connected:
        root.mainloop()
    app.client_socket.close()
