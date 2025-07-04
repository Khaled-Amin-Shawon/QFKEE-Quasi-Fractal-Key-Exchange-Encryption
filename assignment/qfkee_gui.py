import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib

# QFKEE core logic (simplified, as in README)
def logistic_map(x, r, n):
    seq = []
    for _ in range(n):
        x = r * x * (1 - x)
        seq.append(x)
    return seq

def float_to_bin(f):
    return format(int(f * 255), '08b')

def generate_quasi_prime(seq):
    bin_str = ''.join([float_to_bin(x) for x in seq[:8]])
    return int(bin_str, 2) | 1

def key_generation(seed=0.54321, r=3.99, n=16):
    fs = logistic_map(seed, r, n)
    fs_bin = ''.join([float_to_bin(x) for x in fs])
    quasi_prime = generate_quasi_prime(fs)
    combined = fs_bin + str(quasi_prime)
    key = hashlib.sha512(combined.encode()).hexdigest()
    return key, seed, r

def xor_blocks(plain_bin, mask_bin):
    return ''.join(['1' if a != b else '0' for a, b in zip(plain_bin, mask_bin)])

def encrypt(plaintext, seed=0.54321, r=3.99):
    fs = logistic_map(seed, r, len(plaintext))
    mask_blocks = [float_to_bin(x) for x in fs]
    plain_blocks = [format(ord(c), '08b') for c in plaintext]
    cipher_blocks = [xor_blocks(p, m) for p, m in zip(plain_blocks, mask_blocks)]
    permuted = cipher_blocks[::-1]
    ciphertext = ''.join(permuted)
    return ciphertext, mask_blocks

def decrypt(ciphertext, mask_blocks):
    n = len(mask_blocks)
    cipher_blocks = [ciphertext[i*8:(i+1)*8] for i in range(n)][::-1]
    plain_blocks = [xor_blocks(c, m) for c, m in zip(cipher_blocks, mask_blocks)]
    plaintext = ''.join([chr(int(b, 2)) for b in plain_blocks])
    return plaintext

# Button hover effect
class HoverButton(tk.Button):
    def __init__(self, master, **kw):
        tk.Button.__init__(self, master=master, **kw)
        self.defaultBackground = self["background"]
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
    def on_enter(self, e):
        self["background"] = self["activebackground"]
    def on_leave(self, e):
        self["background"] = self.defaultBackground

# GUI Application
def main():
    root = tk.Tk()
    root.title("QFKEE Cryptography")
    root.geometry("750x700")
    root.minsize(750, 700)
    root.maxsize(750, 700)
    root.resizable(False, False)
    root.configure(bg="#f7fafd")

    # Add a canvas+scrollbar for full window scrolling
    canvas = tk.Canvas(root, bg="#f7fafd", highlightthickness=0)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    v_scroll = tk.Scrollbar(root, orient=tk.VERTICAL, command=canvas.yview)
    v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    canvas.configure(yscrollcommand=v_scroll.set)
    canvas.xview_moveto(0)
    canvas.yview_moveto(0)

    main_frame = tk.Frame(canvas, bg="#f7fafd")
    canvas.create_window((0, 0), window=main_frame, anchor="nw")

    def on_configure(event):
        canvas.configure(scrollregion=canvas.bbox('all'))
    main_frame.bind('<Configure>', on_configure)

    # Fonts and Colors
    font_main = ("Segoe UI", 12)
    font_header = ("Segoe UI", 22, "bold")
    font_label = ("Segoe UI", 13, "bold")
    font_entry = ("Consolas", 11)
    font_button = ("Segoe UI", 11, "bold")
    section_bg = "#ffffff"
    border_color = "#e0e7ef"
    accent = "#2563eb"
    accent_hover = "#1d4ed8"
    button_fg = "#ffffff"
    field_bg = "#f4f7fa"
    field_border = 0
    radius = 12

    # State
    key = tk.StringVar()
    seed = tk.DoubleVar(value=0.54321)
    r = tk.DoubleVar(value=3.99)
    mask_blocks = []
    ciphertext = tk.StringVar()
    decrypted = tk.StringVar()

    # Key Generation
    def generate_key():
        k, s, rr = key_generation(seed.get(), r.get())
        key.set(k)
        messagebox.showinfo("Key Generated", f"Key:\n{k}\nSeed: {s}\nr: {rr}")

    # Encryption
    def do_encrypt():
        pt = plaintext_entry.get("1.0", tk.END).strip()
        if not pt:
            messagebox.showwarning("Input Needed", "Please enter plaintext.")
            return
        ct, mb = encrypt(pt, seed.get(), r.get())
        ciphertext.set(ct)
        nonlocal mask_blocks
        mask_blocks = mb
        ciphertext_entry.config(state='normal')
        ciphertext_entry.delete("1.0", tk.END)
        ciphertext_entry.insert(tk.END, ct)
        ciphertext_entry.config(state='disabled')
        # Show ASCII representation
        try:
            chars = []
            for i in range(0, len(ct), 8):
                byte = ct[i:i+8]
                if len(byte) == 8:
                    val = int(byte, 2)
                    if 32 <= val <= 126:
                        chars.append(chr(val))
                    else:
                        chars.append('.')
            ct_ascii = ''.join(chars)
        except Exception:
            ct_ascii = ''
        ciphertext_text_entry.config(state='normal')
        ciphertext_text_entry.delete("1.0", tk.END)
        ciphertext_text_entry.insert(tk.END, ct_ascii)
        ciphertext_text_entry.config(state='disabled')

    # Decryption
    def do_decrypt():
        ct = ciphertext_entry.get("1.0", tk.END).strip()
        if not ct or not mask_blocks:
            messagebox.showwarning("Input Needed", "Please encrypt first or provide ciphertext and mask blocks.")
            return
        try:
            pt = decrypt(ct, mask_blocks)
            decrypted.set(pt)
            decrypted_entry.config(state='normal')
            decrypted_entry.delete("1.0", tk.END)
            decrypted_entry.insert(tk.END, pt)
            decrypted_entry.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    # Section: Header
    header = tk.Label(main_frame, text="QFKEE Cryptography", font=font_header, bg="#f7fafd", fg=accent, pady=18)
    header.pack(fill=tk.X, pady=(0, 10))

    # Section: Key
    key_frame = tk.Frame(main_frame, bg=section_bg, highlightbackground=border_color, highlightthickness=2, bd=0)
    key_frame.pack(fill=tk.X, padx=30, pady=12)
    tk.Label(key_frame, text="Key (SHA-512):", font=font_label, bg=section_bg).pack(anchor='w', padx=12, pady=(10, 2))
    tk.Entry(key_frame, textvariable=key, width=80, font=font_entry, state='readonly', bg=field_bg, bd=field_border, relief=tk.FLAT).pack(padx=12, pady=(0, 10))
    HoverButton(key_frame, text="Generate Key", font=font_button, bg=accent, fg=button_fg, activebackground=accent_hover, activeforeground=button_fg, command=generate_key, bd=0, relief=tk.FLAT, height=1, padx=18, pady=4, cursor="hand2").pack(padx=12, pady=(0, 12), anchor='e')

    # Section: Plaintext
    pt_frame = tk.Frame(main_frame, bg=section_bg, highlightbackground=border_color, highlightthickness=2, bd=0)
    pt_frame.pack(fill=tk.X, padx=30, pady=12)
    tk.Label(pt_frame, text="Plaintext:", font=font_label, bg=section_bg).pack(anchor='w', padx=12, pady=(10, 2))
    pt_scroll = tk.Scrollbar(pt_frame)
    pt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    plaintext_entry = tk.Text(pt_frame, width=60, height=3, font=font_entry, bg=field_bg, bd=field_border, yscrollcommand=pt_scroll.set, relief=tk.FLAT, wrap=tk.WORD)
    plaintext_entry.pack(padx=12, pady=(0, 10))
    pt_scroll.config(command=plaintext_entry.yview)
    HoverButton(pt_frame, text="Encrypt", font=font_button, bg=accent, fg=button_fg, activebackground=accent_hover, activeforeground=button_fg, command=do_encrypt, bd=0, relief=tk.FLAT, height=1, padx=18, pady=4, cursor="hand2").pack(padx=12, pady=(0, 12), anchor='e')

    # Section: Ciphertext (binary)
    ct_frame = tk.Frame(main_frame, bg=section_bg, highlightbackground=border_color, highlightthickness=2, bd=0)
    ct_frame.pack(fill=tk.X, padx=30, pady=12)
    tk.Label(ct_frame, text="Ciphertext (binary):", font=font_label, bg=section_bg).pack(anchor='w', padx=12, pady=(10, 2))
    ct_scroll = tk.Scrollbar(ct_frame)
    ct_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    ciphertext_entry = tk.Text(ct_frame, width=60, height=3, font=font_entry, bg=field_bg, bd=field_border, yscrollcommand=ct_scroll.set, state='disabled', relief=tk.FLAT, wrap=tk.WORD)
    ciphertext_entry.pack(padx=12, pady=(0, 10))
    ct_scroll.config(command=ciphertext_entry.yview)

    # Section: Ciphertext (text)
    ctt_frame = tk.Frame(main_frame, bg=section_bg, highlightbackground=border_color, highlightthickness=2, bd=0)
    ctt_frame.pack(fill=tk.X, padx=30, pady=12)
    tk.Label(ctt_frame, text="Ciphertext (text):", font=font_label, bg=section_bg).pack(anchor='w', padx=12, pady=(10, 2))
    ctt_scroll = tk.Scrollbar(ctt_frame)
    ctt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    ciphertext_text_entry = tk.Text(ctt_frame, width=60, height=2, font=font_entry, bg=field_bg, bd=field_border, yscrollcommand=ctt_scroll.set, state='disabled', relief=tk.FLAT, wrap=tk.WORD)
    ciphertext_text_entry.pack(padx=12, pady=(0, 10))
    ctt_scroll.config(command=ciphertext_text_entry.yview)
    HoverButton(ctt_frame, text="Decrypt", font=font_button, bg="#22c55e", fg=button_fg, activebackground="#16a34a", activeforeground=button_fg, command=do_decrypt, bd=0, relief=tk.FLAT, height=1, padx=18, pady=4, cursor="hand2").pack(padx=12, pady=(0, 12), anchor='e')

    # Section: Decrypted Text
    dt_frame = tk.Frame(main_frame, bg=section_bg, highlightbackground=border_color, highlightthickness=2, bd=0)
    dt_frame.pack(fill=tk.X, padx=30, pady=12)
    tk.Label(dt_frame, text="Decrypted Text:", font=font_label, bg=section_bg).pack(anchor='w', padx=12, pady=(10, 2))
    dt_scroll = tk.Scrollbar(dt_frame)
    dt_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    dt_hscroll = tk.Scrollbar(dt_frame, orient=tk.HORIZONTAL)
    dt_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
    decrypted_entry = tk.Text(dt_frame, width=60, height=6, font=font_entry, bg=field_bg, bd=field_border, yscrollcommand=dt_scroll.set, xscrollcommand=dt_hscroll.set, state='disabled', relief=tk.FLAT, wrap=tk.NONE)
    decrypted_entry.pack(padx=12, pady=(0, 10), fill=tk.BOTH, expand=True)
    dt_scroll.config(command=decrypted_entry.yview)
    dt_hscroll.config(command=decrypted_entry.xview)

    # Footer
    footer = tk.Label(main_frame, text="© 2024 QFKEE Cryptography | Developed by Khaled Amin Shawon", font=("Segoe UI", 10), bg="#f7fafd", fg="#94a3b8", pady=8)
    footer.pack(side=tk.BOTTOM, fill=tk.X)

    root.mainloop()

if __name__ == "__main__":
    main() 