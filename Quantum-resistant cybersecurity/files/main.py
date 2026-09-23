"""
CipherShield -- Post-Quantum Cryptography Lab
===============================================
An educational desktop app for exploring classical vs. post-quantum
cryptography: real RSA / ECC / Kyber (ML-KEM-768) hybrid encryption, real
RSA-PSS / ECDSA / Dilithium (ML-DSA-65) signatures, a labeled "quantum
threat" explainer, and a live benchmark with an embedded chart.

This is a teaching tool, not a security product and not an antivirus --
it doesn't scan for malware. It demonstrates how classical public-key
algorithms fall to Shor's algorithm on a (hypothetical, large-scale)
quantum computer, and why NIST's post-quantum standards (Kyber/ML-KEM,
Dilithium/ML-DSA) are believed to resist that attack.

Run:
    pip install -r requirements.txt
    python3 main.py
"""

from __future__ import annotations

import json
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from crypto_backends import (
    RSAEngine, ECCEngine, KyberEngine,
    RSASignEngine, ECDSAEngine, DilithiumEngine,
    PQCRYPTO_AVAILABLE, EncryptedPayload, b64,
)

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
BG = "#101820"
PANEL_BG = "#17222E"
FG = "white"
ACCENT = "#00FFCC"
ACCENT_DIM = "#0B8F73"
DANGER = "#FF5C5C"
WARN = "#FFB454"
MONO = ("Consolas", 10)
SANS = ("Segoe UI", 10)
SANS_BOLD = ("Segoe UI", 10, "bold")

ENC_INFO = {
    "RSA-2048": dict(engine=RSAEngine, quantum_safe=False,
                      blurb="Classical hybrid encryption (RSA-OAEP wraps an AES-256 key). "
                            "Broken in polynomial time by Shor's algorithm on a large "
                            "enough quantum computer."),
    "ECC P-256": dict(engine=ECCEngine, quantum_safe=False,
                       blurb="Classical ECIES hybrid encryption (ephemeral ECDH + AES-256-GCM). "
                             "Also falls to a quantum computer via the discrete-log variant "
                             "of Shor's algorithm."),
    "Kyber (ML-KEM-768)": dict(engine=KyberEngine, quantum_safe=True,
                                blurb="NIST-standardized post-quantum key encapsulation, "
                                      "hybridized with AES-256-GCM. Based on the Module-LWE "
                                      "lattice problem -- no known efficient quantum attack."),
}

SIGN_INFO = {
    "RSA-PSS-2048": dict(engine=RSASignEngine, quantum_safe=False,
                          blurb="Classical RSA signature scheme. Broken by Shor's algorithm "
                                "on a large enough quantum computer."),
    "ECDSA P-256": dict(engine=ECDSAEngine, quantum_safe=False,
                         blurb="Classical elliptic-curve signature scheme. Also broken by "
                               "Shor's algorithm (discrete-log variant)."),
    "Dilithium (ML-DSA-65)": dict(engine=DilithiumEngine, quantum_safe=True,
                                   blurb="NIST-standardized post-quantum signature scheme. "
                                         "Based on lattice problems (Module-LWE/Module-SIS) "
                                         "with no known efficient quantum attack."),
}

ATTACK_INFO = {
    "RSA-2048": dict(vulnerable=True,
                      detail="Shor's algorithm factors the RSA modulus in polynomial time on "
                             "a fault-tolerant quantum computer, which recovers the private key."),
    "ECC P-256": dict(vulnerable=True,
                       detail="A quantum variant of Shor's algorithm solves the elliptic-curve "
                              "discrete-log problem, which recovers the private key."),
    "Kyber (ML-KEM-768)": dict(vulnerable=False,
                                detail="Security rests on the Module-LWE lattice problem, for "
                                       "which no efficient quantum algorithm is currently known."),
    "Dilithium (ML-DSA-65)": dict(vulnerable=False,
                                   detail="Security rests on Module-LWE / Module-SIS lattice "
                                          "problems, for which no efficient quantum algorithm "
                                          "is currently known."),
}


class ToolTip:
    """Minimal hover tooltip for a widget."""

    def __init__(self, widget, text: str):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tip, text=self.text, justify="left", bg="#2A3B4C", fg="white",
                          relief="solid", borderwidth=1, font=("Segoe UI", 9),
                          padx=8, pady=5, wraplength=320)
        label.pack()

    def _hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class LogPanel(ttk.Frame):
    """Persistent, color-tagged activity log shown at the bottom of the window."""

    def __init__(self, parent):
        super().__init__(parent)
        header = tk.Frame(self, bg=PANEL_BG)
        header.pack(fill="x")
        tk.Label(header, text="Activity Log", font=SANS_BOLD, bg=PANEL_BG, fg=FG).pack(
            side="left", padx=8, pady=4)
        tk.Button(header, text="Copy", command=self.copy, bg="#243447", fg=FG,
                   relief="flat", padx=8).pack(side="right", padx=4, pady=4)
        tk.Button(header, text="Save…", command=self.save, bg="#243447", fg=FG,
                   relief="flat", padx=8).pack(side="right", padx=4, pady=4)
        tk.Button(header, text="Clear", command=self.clear, bg="#243447", fg=FG,
                   relief="flat", padx=8).pack(side="right", padx=4, pady=4)

        body = tk.Frame(self)
        body.pack(fill="both", expand=True)
        self.text = tk.Text(body, height=10, bg="#0B1116", fg=ACCENT, font=MONO,
                             wrap="word", state="disabled", relief="flat")
        scroll = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        self.text.tag_config("info", foreground=ACCENT)
        self.text.tag_config("success", foreground="#5CFF9D")
        self.text.tag_config("warn", foreground=WARN)
        self.text.tag_config("error", foreground=DANGER)
        self.text.tag_config("dim", foreground="#7A8A99")

    def log(self, message: str, level: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.text.configure(state="normal")
        self.text.insert("end", f"[{ts}] ", "dim")
        self.text.insert("end", message + "\n", level)
        self.text.see("end")
        self.text.configure(state="disabled")

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.text.get("1.0", "end"))

    def save(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text file", "*.txt")],
                                             initialfile="ciphershield_log.txt")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.text.get("1.0", "end"))


def add_placeholder(text_widget: tk.Text, placeholder: str):
    """Show dimmed placeholder text that clears itself on first focus/edit."""
    text_widget.insert("1.0", placeholder)
    text_widget.configure(fg="#5A6B7A")
    state = {"active": True}
    text_widget._placeholder_state = state  # looked up by callers before reading .get()

    def clear(_event=None):
        if state["active"]:
            text_widget.delete("1.0", "end")
            text_widget.configure(fg="white")
            state["active"] = False

    text_widget.bind("<FocusIn>", clear)
    text_widget.bind("<Key>", clear)


def styled_button(parent, text, command, bg=ACCENT, fg="black", width=18):
    return tk.Button(parent, text=text, command=command, bg=bg, fg=fg, width=width,
                      font=("Segoe UI", 10, "bold"), relief="flat", activebackground=bg,
                      cursor="hand2", padx=4, pady=6)


class CipherShieldApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("CipherShield -- Post-Quantum Cryptography Lab")
        root.geometry("1080x780")
        root.minsize(920, 680)
        root.configure(bg=BG)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#1B2836", foreground=FG,
                         padding=(16, 8), font=SANS_BOLD)
        style.map("TNotebook.Tab", background=[("selected", PANEL_BG)],
                  foreground=[("selected", ACCENT)])
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL_BG)
        style.configure("TLabel", background=BG, foreground=FG, font=SANS)
        style.configure("Panel.TLabel", background=PANEL_BG, foreground=FG, font=SANS)
        style.configure("TCombobox", padding=4)
        style.configure("Horizontal.TProgressbar", background=ACCENT, troughcolor="#1B2836")
        style.configure("Treeview", background="#0B1116", fieldbackground="#0B1116",
                         foreground=FG, rowheight=24, font=SANS)
        style.configure("Treeview.Heading", background="#1B2836", foreground=ACCENT, font=SANS_BOLD)
        style.map("Treeview", background=[("selected", ACCENT_DIM)])

        # Per-algorithm engine instances persist for the life of the app so
        # Decrypt/Verify keep working against whatever was last encrypted/signed.
        self.enc_engines = {name: info["engine"]() for name, info in ENC_INFO.items()}
        self.sign_engines = {name: info["engine"]() for name, info in SIGN_INFO.items()}
        self.last_payload: dict[str, EncryptedPayload] = {}
        self.last_signature: dict[str, tuple[bytes, bytes]] = {}  # name -> (message, signature)
        self.benchmark_results: list[dict] = []

        self._build_menu()
        self._build_header()

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(8, 4))

        self.enc_tab = ttk.Frame(self.notebook, style="TFrame")
        self.sign_tab = ttk.Frame(self.notebook, style="TFrame")
        self.attack_tab = ttk.Frame(self.notebook, style="TFrame")
        self.bench_tab = ttk.Frame(self.notebook, style="TFrame")
        self.about_tab = ttk.Frame(self.notebook, style="TFrame")

        self.notebook.add(self.enc_tab, text="Encrypt / Decrypt")
        self.notebook.add(self.sign_tab, text="Sign / Verify")
        self.notebook.add(self.attack_tab, text="Quantum Threat Simulator")
        self.notebook.add(self.bench_tab, text="Benchmark & Compare")
        self.notebook.add(self.about_tab, text="About")

        self._build_encrypt_tab()
        self._build_sign_tab()
        self._build_attack_tab()
        self._build_benchmark_tab()
        self._build_about_tab()

        self.log_panel = LogPanel(root)
        self.log_panel.pack(fill="both", expand=False, padx=12, pady=(0, 8))

        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(root, textvariable=self.status_var, bg=BG, fg="#8FE3C7",
                           font=("Segoe UI", 9), anchor="w")
        status.pack(fill="x", padx=14, pady=(0, 6))

        if not PQCRYPTO_AVAILABLE:
            self.log_panel.log(
                "Optional package 'pqcrypto' not found -- Kyber and Dilithium are disabled. "
                "Install with:  pip install pqcrypto", "warn")

        self.log_panel.log("CipherShield ready.", "success")

    # ------------------------------------------------------------------
    # Chrome: menu + header
    # ------------------------------------------------------------------
    def _build_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export benchmark results (JSON)…", command=self.export_benchmark)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="pqcrypto status", command=self.show_pqcrypto_status)
        help_menu.add_command(label="About CipherShield", command=lambda: self.notebook.select(self.about_tab))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _build_header(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(header, text="CipherShield", font=("Segoe UI", 24, "bold"),
                 bg=BG, fg=ACCENT).pack(side="left")
        tk.Label(header, text="  Post-Quantum Cryptography Lab", font=("Segoe UI", 12),
                 bg=BG, fg="white").pack(side="left", padx=(4, 0), pady=(8, 0))
        badge_bg = ACCENT_DIM if PQCRYPTO_AVAILABLE else "#5A4A1A"
        badge_fg = "white"
        badge_text = "Kyber + Dilithium enabled" if PQCRYPTO_AVAILABLE else "Kyber + Dilithium unavailable"
        tk.Label(header, text=badge_text, bg=badge_bg, fg=badge_fg, font=("Segoe UI", 9, "bold"),
                 padx=10, pady=3).pack(side="right", pady=(6, 0))

    # ------------------------------------------------------------------
    # Tab: Encrypt / Decrypt
    # ------------------------------------------------------------------
    def _build_encrypt_tab(self):
        tab = self.enc_tab
        left = tk.Frame(tab, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=10)
        right = tk.Frame(tab, bg=PANEL_BG, width=300)
        right.pack(side="right", fill="y", padx=(0, 4), pady=10)
        right.pack_propagate(False)

        tk.Label(left, text="Message to encrypt", font=SANS_BOLD, bg=BG, fg=FG).pack(anchor="w")
        self.enc_message = tk.Text(left, height=8, font=SANS, bg="#0B1116", fg="white",
                                    insertbackground="white", wrap="word")
        self.enc_message.pack(fill="x", pady=(4, 10))
        add_placeholder(self.enc_message, "Type a secret message here…")

        row = tk.Frame(left, bg=BG)
        row.pack(fill="x", pady=(0, 10))
        tk.Label(row, text="Algorithm:", bg=BG, fg=FG, font=SANS).pack(side="left")
        self.enc_algo = ttk.Combobox(row, values=list(ENC_INFO.keys()), state="readonly", width=24)
        self.enc_algo.current(0)
        self.enc_algo.pack(side="left", padx=8)
        self.enc_algo.bind("<<ComboboxSelected>>", lambda e: self._refresh_enc_info())

        btns = tk.Frame(left, bg=BG)
        btns.pack(fill="x", pady=(0, 10))
        styled_button(btns, "Generate Keypair", self.on_generate_enc_keypair, bg="#3A4B5C", fg="white").pack(side="left", padx=(0, 8))
        styled_button(btns, "Encrypt", self.on_encrypt).pack(side="left", padx=(0, 8))
        styled_button(btns, "Decrypt", self.on_decrypt, bg="#3A4B5C", fg="white").pack(side="left")

        tk.Label(left, text="Result", font=SANS_BOLD, bg=BG, fg=FG).pack(anchor="w")
        result_frame = tk.Frame(left, bg="#0B1116")
        result_frame.pack(fill="both", expand=True, pady=(4, 0))
        self.enc_result = tk.Text(result_frame, height=10, font=MONO, bg="#0B1116", fg=ACCENT,
                                   wrap="word", state="disabled")
        rscroll = ttk.Scrollbar(result_frame, orient="vertical", command=self.enc_result.yview)
        self.enc_result.configure(yscrollcommand=rscroll.set)
        self.enc_result.pack(side="left", fill="both", expand=True)
        rscroll.pack(side="right", fill="y")
        copy_row = tk.Frame(left, bg=BG)
        copy_row.pack(fill="x", pady=(4, 0))
        styled_button(copy_row, "Copy ciphertext", self.copy_enc_result, bg="#243447", fg="white", width=16).pack(side="left")

        # Info panel
        tk.Label(right, text="Algorithm info", font=SANS_BOLD, bg=PANEL_BG, fg=ACCENT).pack(
            anchor="w", padx=12, pady=(12, 4))
        self.enc_badge = tk.Label(right, text="", font=("Segoe UI", 9, "bold"), padx=8, pady=3)
        self.enc_badge.pack(anchor="w", padx=12, pady=(0, 8))
        self.enc_blurb = tk.Label(right, text="", bg=PANEL_BG, fg="white", font=SANS,
                                   wraplength=260, justify="left")
        self.enc_blurb.pack(anchor="w", padx=12)
        tk.Label(right, text="How it actually works:", font=SANS_BOLD, bg=PANEL_BG, fg=FG).pack(
            anchor="w", padx=12, pady=(16, 4))
        self.enc_how = tk.Label(right, text="", bg=PANEL_BG, fg="#B9C6D2", font=("Segoe UI", 9),
                                 wraplength=260, justify="left")
        self.enc_how.pack(anchor="w", padx=12)

        self._refresh_enc_info()

    def _refresh_enc_info(self):
        name = self.enc_algo.get()
        info = ENC_INFO[name]
        if info["quantum_safe"]:
            self.enc_badge.configure(text="Post-quantum (NIST standard)", bg=ACCENT_DIM, fg="white")
        else:
            self.enc_badge.configure(text="Classical -- quantum-vulnerable", bg="#5A2A2A", fg="white")
        self.enc_blurb.configure(text=info["blurb"])
        self.enc_how.configure(
            text="A random AES-256 key does the actual bulk encryption (AES-256-GCM). "
                 "The public-key algorithm only wraps/derives that AES key -- this is "
                 "exactly how RSA and ECC are used in the real world, since none of them "
                 "can efficiently encrypt an arbitrary-length message directly.")

    def on_generate_enc_keypair(self):
        name = self.enc_algo.get()
        engine = self.enc_engines[name]
        try:
            t = engine.generate_keypair()
        except RuntimeError as e:
            messagebox.showerror("Missing dependency", str(e))
            self.log_panel.log(str(e), "error")
            return
        sizes = engine.key_sizes()
        self.log_panel.log(
            f"[{name}] generated new keypair in {t*1000:.2f} ms "
            f"(public {sizes['public_key_bytes']} B / private {sizes['private_key_bytes']} B)",
            "success")
        self.status_var.set(f"New {name} keypair generated.")

    def on_encrypt(self):
        name = self.enc_algo.get()
        engine = self.enc_engines[name]
        is_placeholder = getattr(self.enc_message, "_placeholder_state", {"active": False})["active"]
        message = "" if is_placeholder else self.enc_message.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("Empty message", "Type a message to encrypt first.")
            return
        if getattr(engine, "public_key", None) is None:
            self.on_generate_enc_keypair()
        try:
            t0 = time.perf_counter()
            payload = engine.encrypt(message.encode("utf-8"))
            elapsed = time.perf_counter() - t0
        except RuntimeError as e:
            messagebox.showerror("Missing dependency", str(e))
            self.log_panel.log(str(e), "error")
            return
        except Exception as e:
            messagebox.showerror("Encryption failed", str(e))
            self.log_panel.log(f"Encryption failed: {e}", "error")
            return
        self.last_payload[name] = payload
        self._show_enc_result(name, payload, elapsed)
        self.log_panel.log(f"[{name}] encrypted {len(message)} chars in {elapsed*1000:.2f} ms "
                            f"({len(payload.ciphertext)} B ciphertext).", "success")
        self.status_var.set(f"Encrypted with {name}.")

    def _show_enc_result(self, name, payload: EncryptedPayload, elapsed):
        self.enc_result.configure(state="normal")
        self.enc_result.delete("1.0", "end")
        self.enc_result.insert("end", f"Algorithm:        {name}\n")
        self.enc_result.insert("end", f"Encrypt time:     {elapsed*1000:.2f} ms\n")
        self.enc_result.insert("end", f"Wrapped key/CT:   {len(payload.wrapped_key)} bytes\n")
        self.enc_result.insert("end", f"Ciphertext:       {len(payload.ciphertext)} bytes\n\n")
        self.enc_result.insert("end", "Ciphertext (base64):\n")
        self.enc_result.insert("end", b64(payload.ciphertext) + "\n")
        self.enc_result.configure(state="disabled")

    def copy_enc_result(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.enc_result.get("1.0", "end"))
        self.status_var.set("Result copied to clipboard.")

    def on_decrypt(self):
        name = self.enc_algo.get()
        engine = self.enc_engines[name]
        payload = self.last_payload.get(name)
        if payload is None:
            messagebox.showinfo("Nothing to decrypt", f"Encrypt something with {name} first.")
            return
        try:
            t0 = time.perf_counter()
            plaintext = engine.decrypt(payload)
            elapsed = time.perf_counter() - t0
        except Exception as e:
            messagebox.showerror("Decryption failed", str(e))
            self.log_panel.log(f"[{name}] decryption failed: {e}", "error")
            return
        self.enc_result.configure(state="normal")
        self.enc_result.insert("end", f"\nDecrypted in {elapsed*1000:.2f} ms:\n{plaintext.decode('utf-8')}\n")
        self.enc_result.configure(state="disabled")
        self.log_panel.log(f"[{name}] decrypted successfully in {elapsed*1000:.2f} ms.", "success")
        self.status_var.set(f"Decrypted with {name}.")

    # ------------------------------------------------------------------
    # Tab: Sign / Verify
    # ------------------------------------------------------------------
    def _build_sign_tab(self):
        tab = self.sign_tab
        left = tk.Frame(tab, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(4, 8), pady=10)
        right = tk.Frame(tab, bg=PANEL_BG, width=300)
        right.pack(side="right", fill="y", padx=(0, 4), pady=10)
        right.pack_propagate(False)

        tk.Label(left, text="Message to sign", font=SANS_BOLD, bg=BG, fg=FG).pack(anchor="w")
        self.sign_message = tk.Text(left, height=5, font=SANS, bg="#0B1116", fg="white",
                                     insertbackground="white", wrap="word")
        self.sign_message.pack(fill="x", pady=(4, 10))
        add_placeholder(self.sign_message, "Type the message you want to sign…")

        row = tk.Frame(left, bg=BG)
        row.pack(fill="x", pady=(0, 10))
        tk.Label(row, text="Algorithm:", bg=BG, fg=FG, font=SANS).pack(side="left")
        self.sign_algo = ttk.Combobox(row, values=list(SIGN_INFO.keys()), state="readonly", width=24)
        self.sign_algo.current(0)
        self.sign_algo.pack(side="left", padx=8)
        self.sign_algo.bind("<<ComboboxSelected>>", lambda e: self._refresh_sign_info())

        btns = tk.Frame(left, bg=BG)
        btns.pack(fill="x", pady=(0, 10))
        styled_button(btns, "Generate Keypair", self.on_generate_sign_keypair, bg="#3A4B5C", fg="white").pack(side="left", padx=(0, 8))
        styled_button(btns, "Sign", self.on_sign).pack(side="left", padx=(0, 8))

        tk.Label(left, text="Signature", font=SANS_BOLD, bg=BG, fg=FG).pack(anchor="w", pady=(6, 0))
        sig_frame = tk.Frame(left, bg="#0B1116")
        sig_frame.pack(fill="both", expand=False, pady=(4, 10))
        self.sign_result = tk.Text(sig_frame, height=5, font=MONO, bg="#0B1116", fg=ACCENT,
                                    wrap="word", state="disabled")
        self.sign_result.pack(fill="both", expand=True)

        tk.Label(left, text="Message to verify against (edit this to test a tampered message)",
                 font=SANS_BOLD, bg=BG, fg=FG).pack(anchor="w")
        self.verify_message = tk.Text(left, height=3, font=SANS, bg="#0B1116", fg="white",
                                       insertbackground="white", wrap="word")
        self.verify_message.pack(fill="x", pady=(4, 8))

        vrow = tk.Frame(left, bg=BG)
        vrow.pack(fill="x")
        styled_button(vrow, "Verify", self.on_verify, bg="#3A4B5C", fg="white").pack(side="left")
        self.verify_badge = tk.Label(vrow, text="", font=("Segoe UI", 10, "bold"), padx=10, pady=4)
        self.verify_badge.pack(side="left", padx=12)

        tk.Label(right, text="Algorithm info", font=SANS_BOLD, bg=PANEL_BG, fg=ACCENT).pack(
            anchor="w", padx=12, pady=(12, 4))
        self.sign_badge = tk.Label(right, text="", font=("Segoe UI", 9, "bold"), padx=8, pady=3)
        self.sign_badge.pack(anchor="w", padx=12, pady=(0, 8))
        self.sign_blurb = tk.Label(right, text="", bg=PANEL_BG, fg="white", font=SANS,
                                    wraplength=260, justify="left")
        self.sign_blurb.pack(anchor="w", padx=12)
        tk.Label(right, text="Note:", font=SANS_BOLD, bg=PANEL_BG, fg=FG).pack(
            anchor="w", padx=12, pady=(16, 4))
        tk.Label(right, text="Signing proves authenticity/integrity -- it does not hide the "
                              "message. That's what the Encrypt tab is for.",
                 bg=PANEL_BG, fg="#B9C6D2", font=("Segoe UI", 9), wraplength=260,
                 justify="left").pack(anchor="w", padx=12)

        self._refresh_sign_info()

    def _refresh_sign_info(self):
        name = self.sign_algo.get()
        info = SIGN_INFO[name]
        if info["quantum_safe"]:
            self.sign_badge.configure(text="Post-quantum (NIST standard)", bg=ACCENT_DIM, fg="white")
        else:
            self.sign_badge.configure(text="Classical -- quantum-vulnerable", bg="#5A2A2A", fg="white")
        self.sign_blurb.configure(text=info["blurb"])

    def on_generate_sign_keypair(self):
        name = self.sign_algo.get()
        engine = self.sign_engines[name]
        try:
            t = engine.generate_keypair()
        except RuntimeError as e:
            messagebox.showerror("Missing dependency", str(e))
            self.log_panel.log(str(e), "error")
            return
        self.log_panel.log(f"[{name}] generated new keypair in {t*1000:.2f} ms.", "success")
        self.status_var.set(f"New {name} keypair generated.")

    def on_sign(self):
        name = self.sign_algo.get()
        engine = self.sign_engines[name]
        is_placeholder = getattr(self.sign_message, "_placeholder_state", {"active": False})["active"]
        message = "" if is_placeholder else self.sign_message.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("Empty message", "Type a message to sign first.")
            return
        if getattr(engine, "public_key", None) is None:
            self.on_generate_sign_keypair()
        try:
            msg_bytes = message.encode("utf-8")
            t0 = time.perf_counter()
            sig = engine.sign(msg_bytes)
            elapsed = time.perf_counter() - t0
        except RuntimeError as e:
            messagebox.showerror("Missing dependency", str(e))
            self.log_panel.log(str(e), "error")
            return
        self.last_signature[name] = (msg_bytes, sig)
        self.sign_result.configure(state="normal")
        self.sign_result.delete("1.0", "end")
        self.sign_result.insert("end", f"{len(sig)} bytes, signed in {elapsed*1000:.2f} ms\n\n{b64(sig)}")
        self.sign_result.configure(state="disabled")
        self.verify_message.delete("1.0", "end")
        self.verify_message.insert("1.0", message)
        self.verify_badge.configure(text="")
        self.log_panel.log(f"[{name}] signed {len(message)} chars -> {len(sig)} byte signature "
                            f"in {elapsed*1000:.2f} ms.", "success")
        self.status_var.set(f"Signed with {name}.")

    def on_verify(self):
        name = self.sign_algo.get()
        engine = self.sign_engines[name]
        stored = self.last_signature.get(name)
        if stored is None:
            messagebox.showinfo("Nothing to verify", f"Sign something with {name} first.")
            return
        _, sig = stored
        candidate = self.verify_message.get("1.0", "end").strip().encode("utf-8")
        try:
            ok = engine.verify(candidate, sig)
        except RuntimeError as e:
            messagebox.showerror("Missing dependency", str(e))
            return
        if ok:
            self.verify_badge.configure(text="VALID SIGNATURE", bg=ACCENT_DIM, fg="white")
            self.log_panel.log(f"[{name}] signature verified OK.", "success")
        else:
            self.verify_badge.configure(text="INVALID SIGNATURE", bg="#5A2A2A", fg="white")
            self.log_panel.log(f"[{name}] signature verification FAILED "
                                f"(message doesn't match what was signed).", "warn")
        self.status_var.set("Verification complete.")

    # ------------------------------------------------------------------
    # Tab: Quantum Threat Simulator
    # ------------------------------------------------------------------
    def _build_attack_tab(self):
        tab = self.attack_tab
        banner = tk.Frame(tab, bg="#3A2A0A")
        banner.pack(fill="x", padx=4, pady=(10, 10))
        tk.Label(banner,
                 text="⚠ Educational simulation only. No real attack runs here -- a "
                      "cryptographically relevant fault-tolerant quantum computer doesn't "
                      "exist yet. This shows the established theoretical result from the "
                      "cryptography literature, not a live computation.",
                 bg="#3A2A0A", fg=WARN, font=("Segoe UI", 9, "bold"), wraplength=900,
                 justify="left", padx=12, pady=10).pack(fill="x")

        row = tk.Frame(tab, bg=BG)
        row.pack(fill="x", padx=8, pady=(0, 10))
        tk.Label(row, text="Target algorithm:", bg=BG, fg=FG, font=SANS).pack(side="left")
        self.attack_algo = ttk.Combobox(row, values=list(ATTACK_INFO.keys()), state="readonly", width=24)
        self.attack_algo.current(0)
        self.attack_algo.pack(side="left", padx=8)
        self.attack_btn = styled_button(row, "Run Simulation", self.on_run_attack, bg=DANGER, fg="white")
        self.attack_btn.pack(side="left", padx=8)

        self.attack_progress = ttk.Progressbar(tab, mode="indeterminate")
        self.attack_progress.pack(fill="x", padx=8, pady=(0, 12))

        result_frame = tk.Frame(tab, bg="#0B1116")
        result_frame.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        self.attack_result = tk.Text(result_frame, font=MONO, bg="#0B1116", fg=ACCENT,
                                      wrap="word", state="disabled")
        self.attack_result.pack(fill="both", expand=True, padx=8, pady=8)
        self.attack_result.tag_config("vuln", foreground=DANGER)
        self.attack_result.tag_config("safe", foreground="#5CFF9D")

    def on_run_attack(self):
        name = self.attack_algo.get()
        info = ATTACK_INFO[name]
        self.attack_btn.configure(state="disabled")
        self.attack_progress.start(12)

        def worker():
            time.sleep(1.1)  # purely cosmetic pacing for the simulation
            self.root.after(0, lambda: self._finish_attack(name, info))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_attack(self, name, info):
        self.attack_progress.stop()
        self.attack_btn.configure(state="normal")
        self.attack_result.configure(state="normal")
        self.attack_result.delete("1.0", "end")
        self.attack_result.insert("end", f"Target: {name}\n\n")
        if info["vulnerable"]:
            self.attack_result.insert("end", "Result: VULNERABLE TO QUANTUM ATTACK\n\n", "vuln")
        else:
            self.attack_result.insert("end", "Result: RESISTANT TO KNOWN QUANTUM ATTACKS\n\n", "safe")
        self.attack_result.insert("end", info["detail"] + "\n")
        self.attack_result.configure(state="disabled")
        level = "warn" if info["vulnerable"] else "success"
        self.log_panel.log(f"[Quantum Threat Simulator] {name}: "
                            f"{'vulnerable' if info['vulnerable'] else 'resistant'} (simulated).", level)
        self.status_var.set("Simulation complete.")

    # ------------------------------------------------------------------
    # Tab: Benchmark & Compare
    # ------------------------------------------------------------------
    def _build_benchmark_tab(self):
        tab = self.bench_tab
        top = tk.Frame(tab, bg=BG)
        top.pack(fill="x", padx=8, pady=(10, 6))
        tk.Label(top, text="Iterations per algorithm:", bg=BG, fg=FG, font=SANS).pack(side="left")
        self.bench_iters = tk.Spinbox(top, from_=1, to=50, width=5)
        self.bench_iters.delete(0, "end")
        self.bench_iters.insert(0, "5")
        self.bench_iters.pack(side="left", padx=8)
        self.bench_btn = styled_button(top, "Run Benchmark", self.on_run_benchmark)
        self.bench_btn.pack(side="left", padx=8)
        styled_button(top, "Export JSON", self.export_benchmark, bg="#3A4B5C", fg="white").pack(side="left", padx=8)
        self.bench_progress = ttk.Progressbar(top, mode="indeterminate", length=160)
        self.bench_progress.pack(side="left", padx=12)

        body = tk.Frame(tab, bg=BG)
        body.pack(fill="both", expand=True, padx=8, pady=(0, 10))

        cols = ("algorithm", "category", "quantum_safe", "keygen_ms", "op_ms", "size_bytes")
        self.bench_tree = ttk.Treeview(body, columns=cols, show="headings", height=7)
        headings = {"algorithm": "Algorithm", "category": "Category", "quantum_safe": "Quantum-safe",
                    "keygen_ms": "Keygen (ms)", "op_ms": "Operation (ms)", "size_bytes": "Size (bytes)"}
        widths = {"algorithm": 190, "category": 90, "quantum_safe": 100,
                  "keygen_ms": 100, "op_ms": 100, "size_bytes": 100}
        for c in cols:
            self.bench_tree.heading(c, text=headings[c])
            self.bench_tree.column(c, width=widths[c], anchor="center")
        self.bench_tree.pack(fill="x", pady=(0, 10))

        self.bench_figure = Figure(figsize=(9, 3.6), dpi=100, facecolor=BG)
        self.bench_canvas = FigureCanvasTkAgg(self.bench_figure, master=body)
        self.bench_canvas.get_tk_widget().pack(fill="both", expand=True)
        self._draw_empty_chart()

    def _draw_empty_chart(self):
        self.bench_figure.clear()
        ax = self.bench_figure.add_subplot(111, facecolor=BG)
        ax.set_title("Run a benchmark to see real measured results", color="white")
        ax.tick_params(colors="white")
        for spine in ax.spines.values():
            spine.set_color("#3A4B5C")
        self.bench_canvas.draw()

    def on_run_benchmark(self):
        try:
            iterations = max(1, int(self.bench_iters.get()))
        except ValueError:
            iterations = 5
        self.bench_btn.configure(state="disabled")
        self.bench_progress.start(12)
        self.log_panel.log(f"Running benchmark ({iterations} iteration(s) per algorithm)…", "info")

        def worker():
            results = self._run_benchmark_suite(iterations)
            self.root.after(0, lambda: self._finish_benchmark(results))

        threading.Thread(target=worker, daemon=True).start()

    def _run_benchmark_suite(self, iterations: int) -> list[dict]:
        results = []

        for name, info in ENC_INFO.items():
            Engine = info["engine"]
            eng = Engine()
            try:
                keygen_times, op_times, size = [], [], 0
                for _ in range(iterations):
                    keygen_times.append(eng.generate_keypair())
                    payload = eng.encrypt(b"Benchmark payload for CipherShield timing.")
                    t0 = time.perf_counter()
                    eng.decrypt(payload)
                    op_times.append(time.perf_counter() - t0)
                    size = len(payload.wrapped_key) + len(payload.ciphertext)
                results.append(dict(
                    name=name, category="Encryption", quantum_safe=info["quantum_safe"],
                    keygen_ms=sum(keygen_times) / len(keygen_times) * 1000,
                    op_ms=sum(op_times) / len(op_times) * 1000,
                    size_bytes=size,
                ))
            except RuntimeError:
                continue  # optional dependency missing; skip silently, logged elsewhere

        for name, info in SIGN_INFO.items():
            Engine = info["engine"]
            eng = Engine()
            try:
                keygen_times, op_times, size = [], [], 0
                msg = b"Benchmark payload for CipherShield timing."
                for _ in range(iterations):
                    keygen_times.append(eng.generate_keypair())
                    t0 = time.perf_counter()
                    sig = eng.sign(msg)
                    eng.verify(msg, sig)
                    op_times.append(time.perf_counter() - t0)
                    size = len(sig)
                results.append(dict(
                    name=name, category="Signature", quantum_safe=info["quantum_safe"],
                    keygen_ms=sum(keygen_times) / len(keygen_times) * 1000,
                    op_ms=sum(op_times) / len(op_times) * 1000,
                    size_bytes=size,
                ))
            except RuntimeError:
                continue

        return results

    def _finish_benchmark(self, results: list[dict]):
        self.bench_progress.stop()
        self.bench_btn.configure(state="normal")
        self.benchmark_results = results

        for row in self.bench_tree.get_children():
            self.bench_tree.delete(row)
        for r in results:
            self.bench_tree.insert("", "end", values=(
                r["name"], r["category"], "Yes" if r["quantum_safe"] else "No",
                f"{r['keygen_ms']:.3f}", f"{r['op_ms']:.3f}", r["size_bytes"]))

        self._draw_benchmark_chart(results)
        skipped = [n for n in list(ENC_INFO) + list(SIGN_INFO) if n not in [r["name"] for r in results]]
        if skipped:
            self.log_panel.log(f"Skipped (missing pqcrypto): {', '.join(skipped)}", "warn")
        self.log_panel.log("Benchmark complete.", "success")
        self.status_var.set("Benchmark complete.")

    def _draw_benchmark_chart(self, results: list[dict]):
        self.bench_figure.clear()
        names = [r["name"] for r in results]
        total_ms = [r["keygen_ms"] + r["op_ms"] for r in results]
        sizes = [r["size_bytes"] for r in results]
        colors = [ACCENT if r["quantum_safe"] else "#FF8A65" for r in results]

        ax1 = self.bench_figure.add_subplot(121, facecolor=BG)
        ax1.bar(range(len(names)), total_ms, color=colors)
        ax1.set_xticks(range(len(names)))
        ax1.set_xticklabels(names, rotation=30, ha="right", color="white", fontsize=8)
        ax1.set_title("Avg. keygen + operation time (ms)", color="white", fontsize=10)
        ax1.tick_params(colors="white")
        for spine in ax1.spines.values():
            spine.set_color("#3A4B5C")

        ax2 = self.bench_figure.add_subplot(122, facecolor=BG)
        ax2.bar(range(len(names)), sizes, color=colors)
        ax2.set_xticks(range(len(names)))
        ax2.set_xticklabels(names, rotation=30, ha="right", color="white", fontsize=8)
        ax2.set_title("Ciphertext / signature size (bytes)", color="white", fontsize=10)
        ax2.tick_params(colors="white")
        for spine in ax2.spines.values():
            spine.set_color("#3A4B5C")

        self.bench_figure.tight_layout()
        self.bench_canvas.draw()

    def export_benchmark(self):
        if not self.benchmark_results:
            messagebox.showinfo("No data", "Run a benchmark first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("JSON", "*.json")],
                                             initialfile="benchmark_results.json")
        if not path:
            return
        payload = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "results": self.benchmark_results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        self.log_panel.log(f"Benchmark results exported to {path}", "success")
        self.status_var.set("Benchmark exported. Run graph.py on this file for a standalone chart.")

    # ------------------------------------------------------------------
    # Tab: About
    # ------------------------------------------------------------------
    def _build_about_tab(self):
        tab = self.about_tab
        frame = tk.Frame(tab, bg=PANEL_BG)
        frame.pack(fill="both", expand=True, padx=8, pady=10)
        text = tk.Text(frame, bg=PANEL_BG, fg="white", font=SANS, wrap="word",
                        relief="flat", padx=16, pady=16)
        text.pack(fill="both", expand=True)
        content = (
            "CipherShield is an educational cryptography lab, not an antivirus and not a "
            "certified security product. It doesn't scan files or detect malware -- it lets "
            "you experiment with classical vs. post-quantum public-key cryptography.\n\n"
            "What's real in this app:\n"
            "  - RSA-2048 and ECC P-256 encryption are genuine hybrid schemes (RSA-OAEP / "
            "ECIES wrapping a random AES-256 key, then AES-256-GCM for the message).\n"
            "  - Kyber is NIST's standardized ML-KEM-768 key-encapsulation mechanism, used "
            "the same hybrid way.\n"
            "  - RSA-PSS, ECDSA, and Dilithium (NIST's ML-DSA-65) are genuine signature "
            "schemes -- sign, tamper with the message, and verification will actually fail.\n"
            "  - The benchmark measures real wall-clock timing and real byte sizes on your "
            "machine.\n\n"
            "What's a labeled simulation:\n"
            "  - The Quantum Threat Simulator does not run a real quantum attack (no such "
            "computer exists yet for these key sizes). It shows the established theoretical "
            "result: RSA and ECC are broken by Shor's algorithm; Kyber and Dilithium rely on "
            "lattice problems with no known efficient quantum algorithm. This is clearly "
            "labeled in the app.\n\n"
            "Dependencies:\n"
            "  - cryptography (RSA/ECC/AES) -- required.\n"
            "  - pqcrypto (Kyber/Dilithium) -- optional; install with `pip install pqcrypto`. "
            "Without it, Kyber and Dilithium options are disabled but the rest of the app "
            "works normally.\n"
            "  - matplotlib -- for the embedded benchmark chart.\n"
        )
        text.insert("1.0", content)
        text.configure(state="disabled")

    def show_pqcrypto_status(self):
        if PQCRYPTO_AVAILABLE:
            messagebox.showinfo("pqcrypto status", "pqcrypto is installed. Kyber and Dilithium are available.")
        else:
            messagebox.showwarning(
                "pqcrypto status",
                "pqcrypto is NOT installed. Kyber and Dilithium are disabled.\n\n"
                "Install it with:\n\n    pip install pqcrypto\n\nthen restart the app.")


def main():
    root = tk.Tk()
    CipherShieldApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
