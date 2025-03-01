import base64
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyperclip
from typing import Optional

class ModernEncryptionApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure Message Encryption and Decryption")
        self.window.geometry("800x700")
        self.window.configure(bg="#f3f4f6")
        
        # Configure styles
        self.setup_styles()
        
        # Create main container
        self.main_frame = ttk.Frame(self.window, style="Main.TFrame")
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Add components
        self.create_header()
        self.create_input_area()
        self.create_password_field()
        self.create_action_buttons()
        self.create_utility_buttons()
        self.create_result_area()
        
        # Initialize encryption service
        self.stored_password_hash = self.hash_password("MyS@ecretMessage123")  # Default password
        
    def setup_styles(self):
        """Configure custom styles for widgets"""
        style = ttk.Style()
        style.configure("Main.TFrame", background="#ffffff")
        
        # Button styles with explicitly set text color and background color
        style.configure("Encrypt.TButton",
                    padding=10,
                    background="#ef4444",
                    foreground="black",  # Text color for visibility
                    font=("Helvetica", 12))
        style.map("Encrypt.TButton", 
                background=[("active", "#dc2626")],  # Color when hovered
                foreground=[("active", "black")])     # Text color when hovered

        style.configure("Decrypt.TButton",
                    padding=10,
                    background="#22c55e",
                    foreground="black",  # Text color for visibility
                    font=("Helvetica", 12))
        style.map("Decrypt.TButton", 
                background=[("active", "#16a34a")],  # Color when hovered
                foreground=[("active", "black")])     # Text color when hovered

        style.configure("Utility.TButton",
                    padding=10,
                    background="#3b82f6",
                    foreground="black",  # Text color for visibility
                    font=("Helvetica", 12))
        style.map("Utility.TButton", 
                background=[("active", "#2563eb")],  # Color when hovered
                foreground=[("active", "black")])     # Text color when hovered
        
        # Label and Entry styles
        style.configure("Header.TLabel",
                    font=("Helvetica", 24, "bold"),
                    background="#ffffff")
        style.configure("Label.TLabel",
                    font=("Helvetica", 12),
                    background="#ffffff")

        
    def create_header(self):
        """Create the header section"""
        header = ttk.Label(
            self.main_frame,
            text="Secure Message Encryption and Decryption",
            style="Header.TLabel"
        )
        header.pack(pady=(0, 20))
        
    def create_input_area(self):
        """Create the text input area"""
        ttk.Label(
            self.main_frame,
            text="Enter text for encryption and decryption",
            style="Label.TLabel"
        ).pack(anchor="w", pady=(0, 5))
        
        self.text_input = tk.Text(
            self.main_frame,
            height=10,
            width=50,
            font=("Helvetica", 12),
            wrap=tk.WORD,
            bd=1,
            relief="solid"
        )
        self.text_input.pack(fill=tk.X, pady=(0, 20))
        
    def create_password_field(self):
        """Create the password input field"""
        ttk.Label(
            self.main_frame,
            text="Password",
            style="Label.TLabel"
        ).pack(anchor="w", pady=(0, 5))
        
        self.password_input = ttk.Entry(
            self.main_frame,
            show="•",
            font=("Helvetica", 12)
        )
        self.password_input.pack(fill=tk.X, pady=(0, 20))
        
    def create_action_buttons(self):
        """Create the main action buttons (Encrypt/Decrypt)"""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        encrypt_btn = ttk.Button(
            button_frame,
            text="Encrypt",
            style="Encrypt.TButton",
            command=self.handle_encryption
        )
        encrypt_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        decrypt_btn = ttk.Button(
            button_frame,
            text="Decrypt",
            style="Decrypt.TButton",
            command=self.handle_decryption
        )
        decrypt_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
    def create_utility_buttons(self):
        """Create utility buttons (Open/Save/Copy)"""
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))
        
        open_btn = ttk.Button(
            button_frame,
            text="Open File",
            style="Utility.TButton",
            command=self.handle_file_open
        )
        open_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        save_btn = ttk.Button(
            button_frame,
            text="Save",
            style="Utility.TButton",
            command=self.handle_save
        )
        save_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
        copy_btn = ttk.Button(
            button_frame,
            text="Copy",
            style="Utility.TButton",
            command=self.handle_copy
        )
        copy_btn.pack(side=tk.LEFT, expand=True, padx=5)
        
    def create_result_area(self):
        """Create the result display area"""
        self.result_frame = ttk.Frame(self.main_frame)
        self.result_frame.pack(fill=tk.X, pady=(0, 20))
        self.result_frame.pack_forget()
        
        ttk.Label(
            self.result_frame,
            text="Result",
            style="Label.TLabel"
        ).pack(anchor="w", pady=(0, 5))
        
        self.result_text = tk.Text(
            self.result_frame,
            height=4,
            width=50,
            font=("Helvetica", 12),
            wrap=tk.WORD,
            bd=1,
            relief="solid",
            bg="#f3f4f6"
        )
        self.result_text.pack(fill=tk.X)
        
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def encrypt(self, message: str, password: str) -> Optional[str]:
        """Encrypt the message"""
        if self.hash_password(password) != self.stored_password_hash:
            return None
        try:
            message_bytes = message.encode('utf-8')
            base64_bytes = base64.b64encode(message_bytes)
            return base64_bytes.decode('utf-8')
        except Exception:
            return None
            
    def decrypt(self, encrypted_message: str, password: str) -> Optional[str]:
        """Decrypt the message"""
        if self.hash_password(password) != self.stored_password_hash:
            return None
        try:
            base64_bytes = encrypted_message.encode('utf-8')
            message_bytes = base64.b64decode(base64_bytes)
            return message_bytes.decode('utf-8')
        except Exception:
            return None
    
    def handle_encryption(self):
        """Handle encryption button click"""
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        
        result = self.encrypt(message, password)
        if result:
            self.show_result(result)
            messagebox.showinfo("Success", "Text encrypted successfully!")
        else:
            messagebox.showerror("Error", "Encryption failed: Invalid password or error occurred")
    
    def handle_decryption(self):
        """Handle decryption button click"""
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        
        result = self.decrypt(message, password)
        if result:
            self.show_result(result)
            messagebox.showinfo("Success", "Text decrypted successfully!")
        else:
            messagebox.showerror("Error", "Decryption failed: Invalid password or error occurred")
    
    def handle_file_open(self):
        """Handle file open button click"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    content = file.read()
                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert("1.0", content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
    
    def handle_save(self):
        """Handle save button click"""
        message = self.text_input.get("1.0", tk.END).strip()
        password = self.password_input.get()
        
        encrypted = self.encrypt(message, password)
        if encrypted:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if file_path:
                try:
                    with open(file_path, 'w') as file:
                        file.write(encrypted)
                    messagebox.showinfo("Success", "File saved successfully!")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save file: {str(e)}")
        else:
            messagebox.showerror("Error", "Encryption failed: Invalid password or error occurred")
    
    def handle_copy(self):
        """Handle copy button click"""
        result = self.result_text.get("1.0", tk.END).strip()
        if result:
            pyperclip.copy(result)
            messagebox.showinfo("Success", "Text copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No result to copy!")
    
    def show_result(self, result: str):
        """Show the result in the result area"""
        self.result_frame.pack(fill=tk.X, pady=(0, 20))
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert("1.0", result)
    
    def run(self):
        """Start the application"""
        self.window.mainloop()

if __name__ == "__main__":
    app = ModernEncryptionApp()
    app.run()