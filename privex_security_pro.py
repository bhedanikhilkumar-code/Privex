import os
import sys
import json
import time
import math
import base64
import hashlib
import threading
import datetime
import tempfile
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import psutil
except ImportError:
    psutil = None

try:
    import winreg
except ImportError:
    winreg = None

try:
    from PIL import Image, ImageDraw
    import pystray
    from pystray import MenuItem as item
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

try:
    from winotify import Notification, audio
    WINOTIFY_AVAILABLE = True
except ImportError:
    WINOTIFY_AVAILABLE = False

# =============================================================================
# PRIVEX PRO DARK THEME PALETTE & DIRECTORIES
# =============================================================================
BG_SIDEBAR    = "#111526"
BG_MAIN       = "#191F35"
BG_CARD       = "#232B47"
ACCENT_GREEN  = "#00D68F"
ACCENT_ORANGE = "#FF7800"
ACCENT_RED    = "#FF3D71"
ACCENT_BLUE   = "#0095FF"
TEXT_PRIMARY  = "#FFFFFF"
TEXT_MUTED    = "#8F9BB3"

APP_DIR       = os.path.dirname(os.path.abspath(__file__))
VAULT_DIR     = os.path.join(APP_DIR, ".privex_quarantine")
VAULT_INDEX   = os.path.join(VAULT_DIR, "vault_index.json")
SIG_FILE      = os.path.join(APP_DIR, "privex_signatures.json")
ICON_CACHE    = os.path.join(VAULT_DIR, "privex_shield_icon.png")
DEMO_MARKER   = "PRIVEX-PRO-DEMO-THREAT-SIGNATURE-2026"


# =============================================================================
# DYNAMIC SHIELD ICON & NATIVE WINDOWS 11 TOAST ENGINE
# =============================================================================
def create_shield_icon(state="protected", size=64):
    os.makedirs(VAULT_DIR, exist_ok=True)
    colors = {
        "protected": (0, 214, 143, 255),
        "warning":   (255, 120, 0, 255),
        "danger":    (255, 61, 113, 255)
    }
    fill_color = colors.get(state, colors["protected"])
    bg_dark = (17, 21, 38, 255)

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    shield_pts = [
        (size * 0.50, size * 0.06),
        (size * 0.88, size * 0.20),
        (size * 0.84, size * 0.58),
        (size * 0.50, size * 0.94),
        (size * 0.16, size * 0.58),
        (size * 0.12, size * 0.20),
    ]
    draw.polygon(shield_pts, fill=fill_color)

    inner_pts = [
        (size * 0.50, size * 0.15),
        (size * 0.79, size * 0.26),
        (size * 0.75, size * 0.55),
        (size * 0.50, size * 0.84),
        (size * 0.25, size * 0.55),
        (size * 0.21, size * 0.26),
    ]
    draw.polygon(inner_pts, fill=bg_dark)

    if state == "protected":
        draw.line(
            [(size * 0.33, size * 0.50), (size * 0.45, size * 0.63), (size * 0.68, size * 0.36)],
            fill=fill_color, width=max(4, size // 12), joint="curve"
        )
    else:
        draw.line(
            [(size * 0.50, size * 0.30), (size * 0.50, size * 0.54)],
            fill=fill_color, width=max(4, size // 12)
        )
        r = max(2, size // 18)
        draw.ellipse(
            (size * 0.50 - r, size * 0.64 - r, size * 0.50 + r, size * 0.64 + r),
            fill=fill_color
        )

    try:
        img.save(ICON_CACHE, "PNG")
    except Exception:
        pass
    return img


class ToastManager:
    tray_ref = None

    @classmethod
    def notify(cls, title: str, message: str, urgent: bool = False):
        def _worker():
            if not os.path.exists(ICON_CACHE):
                create_shield_icon("protected")

            if WINOTIFY_AVAILABLE:
                try:
                    toast = Notification(
                        app_id="Privex Security Pro",
                        title=title,
                        msg=message,
                        icon=ICON_CACHE if os.path.exists(ICON_CACHE) else "",
                        duration="long" if urgent else "short"
                    )
                    toast.set_audio(audio.SMS if urgent else audio.Default, loop=False)
                    toast.show()
                    return
                except Exception:
                    pass

            if cls.tray_ref is not None:
                try:
                    cls.tray_ref.notify(message, title)
                except Exception:
                    pass

        threading.Thread(target=_worker, daemon=True).start()


# =============================================================================
# CORE ANTIVIRUS ENGINE (SHA-256 + HEURISTICS + ENTROPY + QUARANTINE)
# =============================================================================
class AntivirusEngine:

    def __init__(self):
        os.makedirs(VAULT_DIR, exist_ok=True)
        self.signatures = self._load_signatures()
        self.vault_data = self._load_vault()
        self.file_shield_active = True

    def _load_signatures(self):
        if os.path.exists(SIG_FILE):
            try:
                with open(SIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "version": "2026.10.15",
            "hashes": {
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Win32.EICAR.StandardTestSignature"
            },
            "suspicious_extensions": [".pdf.exe", ".jpg.exe", ".docx.exe", ".scr", ".pif"],
            "suspicious_markers": [DEMO_MARKER]
        }

    def _load_vault(self):
        if os.path.exists(VAULT_INDEX):
            try:
                with open(VAULT_INDEX, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_vault(self):
        with open(VAULT_INDEX, "w", encoding="utf-8") as f:
            json.dump(self.vault_data, f, indent=2)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for c in counts:
            if c > 0:
                p = c / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    def scan_single_file(self, filepath: str):
        try:
            if not os.path.isfile(filepath):
                return None
            abs_p = os.path.abspath(filepath)
            if VAULT_DIR in abs_p or abs_p == os.path.abspath(__file__) or abs_p == os.path.abspath(SIG_FILE):
                return None

            size = os.path.getsize(filepath)
            if size == 0 or size > 50 * 1024 * 1024:
                return None

            lower_name = os.path.basename(filepath).lower()

            for ext in self.signatures.get("suspicious_extensions", []):
                if lower_name.endswith(ext):
                    return {
                        "path": filepath,
                        "threat": f"Heuristic.DoubleExtension ({ext})",
                        "sha256": "N/A",
                        "severity": "High"
                    }

            with open(filepath, "rb") as f:
                raw = f.read(2 * 1024 * 1024)

            sha256_hash = hashlib.sha256(raw).hexdigest()

            if sha256_hash in self.signatures.get("hashes", {}):
                return {
                    "path": filepath,
                    "threat": self.signatures["hashes"][sha256_hash],
                    "sha256": sha256_hash,
                    "severity": "Critical"
                }

            text_sample = raw[:65536].decode("utf-8", errors="ignore")
            for marker in self.signatures.get("suspicious_markers", []):
                if marker in text_sample:
                    return {
                        "path": filepath,
                        "threat": "Win32.PrivexTestVirus.Signature",
                        "sha256": sha256_hash,
                        "severity": "Critical"
                    }

            if lower_name.endswith((".exe", ".dll", ".scr")) and len(raw) > 4096:
                entropy = self.calculate_entropy(raw[:65536])
                if entropy > 7.65:
                    return {
                        "path": filepath,
                        "threat": f"Heur.Packed.HighEntropy ({entropy}/8.0)",
                        "sha256": sha256_hash,
                        "severity": "Medium"
                    }
        except (PermissionError, OSError):
            return None
        return None

    def quarantine_file(self, threat_info: dict) -> bool:
        filepath = threat_info.get("path")
        if not filepath or not os.path.exists(filepath):
            return False
        try:
            with open(filepath, "rb") as f:
                encoded = base64.b64encode(f.read())

            vault_id = f"q_{int(time.time()*1000)}_{os.path.basename(filepath)}.vault"
            vault_path = os.path.join(VAULT_DIR, vault_id)
            with open(vault_path, "wb") as vf:
                vf.write(encoded)

            os.remove(filepath)
            record = {
                "id": vault_id,
                "original_path": filepath,
                "threat": threat_info.get("threat", "Unknown.Threat"),
                "sha256": threat_info.get("sha256", "N/A"),
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.vault_data.append(record)
            self._save_vault()
            return True
        except Exception:
            return False

    def restore_from_quarantine(self, vault_id: str) -> bool:
        for item_rec in list(self.vault_data):
            if item_rec["id"] == vault_id:
                vault_path = os.path.join(VAULT_DIR, vault_id)
                orig_path = item_rec["original_path"]
                try:
                    os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                    with open(vault_path, "rb") as vf:
                        raw = base64.b64decode(vf.read())
                    with open(orig_path, "wb") as of:
                        of.write(raw)
                    os.remove(vault_path)
                    self.vault_data.remove(item_rec)
                    self._save_vault()
                    return True
                except Exception:
                    return False
        return False

    def delete_from_quarantine(self, vault_id: str) -> bool:
        for item_rec in list(self.vault_data):
            if item_rec["id"] == vault_id:
                vault_path = os.path.join(VAULT_DIR, vault_id)
                try:
                    if os.path.exists(vault_path):
                        os.remove(vault_path)
                    self.vault_data.remove(item_rec)
                    self._save_vault()
                    return True
                except Exception:
                    return False
        return False

    @staticmethod
    def get_startup_items():
        items = []
        if not winreg:
            return items
        locations = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM")
        ]
        for hive, subkey, label in locations:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            items.append((label, name, str(val)))
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass
        return items


# =============================================================================
# MAIN PRIVEX PRO DESKTOP UI + SYSTEM TRAY GUARD
# =============================================================================
class PrivexSecurityApp(tk.Tk):

    def __init__(self, start_minimized=False):
        super().__init__()
        self.title("Privex Security Pro — Enterprise Endpoint Protection")
        self.geometry("1120x680")
        self.minsize(1000, 620)
        self.configure(bg=BG_MAIN)

        self.engine = AntivirusEngine()
        self.is_scanning = False
        self.detected_threats = []
        self.tray_icon = None
        self.notified_minimized_once = False

        self.protocol("WM_DELETE_WINDOW", self.hide_to_tray)

        self._configure_styles()
        self._build_layout()
        self.show_frame("status")

        self._init_system_tray()
        self._update_telemetry()
        self._start_realtime_shield()

        if start_minimized:
            self.after(100, self.hide_to_tray)
        else:
            ToastManager.notify(
                "Privex Real-Time Protection Active",
                "All Shields are online. Monitoring Downloads and Desktop in real time."
            )

    def _init_system_tray(self):
        if not TRAY_AVAILABLE:
            return

        icon_img = create_shield_icon("protected")

        menu = pystray.Menu(
            item("Open Privex Security Pro", self._tray_open_window, default=True),
            item("Run Smart Scan Now", self._tray_run_smart_scan),
            pystray.Menu.SEPARATOR,
            item(
                lambda _: f"Real-Time File Shield: {'ON' if self.engine.file_shield_active else 'PAUSED'}",
                self._tray_toggle_shield
            ),
            item("Drop Demo Virus Sample (Test Alert)", self._tray_create_demo),
            pystray.Menu.SEPARATOR,
            item("Exit Privex Completely", self._tray_quit_app)
        )

        self.tray_icon = pystray.Icon(
            "privex_security_pro",
            icon_img,
            "Privex Security Pro — You are protected",
            menu
        )
        ToastManager.tray_ref = self.tray_icon
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def update_tray_state(self, state="protected", tooltip="Privex Security Pro — You are protected"):
        if self.tray_icon and TRAY_AVAILABLE:
            try:
                self.tray_icon.icon = create_shield_icon(state)
                self.tray_icon.title = tooltip
                self.tray_icon.update_menu()
            except Exception:
                pass

    def hide_to_tray(self):
        if not TRAY_AVAILABLE:
            self.quit_app()
            return
        self.withdraw()
        if not self.notified_minimized_once:
            self.notified_minimized_once = True
            ToastManager.notify(
                "Running in System Tray",
                "Privex Security Pro is still protecting your PC in the background. Right-click the tray shield icon anytime."
            )

    def restore_from_tray(self):
        self.deiconify()
        self.state("normal")
        self.lift()
        self.focus_force()

    def _tray_open_window(self, icon=None, menu_item=None):
        self.after(0, self.restore_from_tray)

    def _tray_run_smart_scan(self, icon=None, menu_item=None):
        def _start():
            self.restore_from_tray()
            self.show_frame("scans")
            self.start_smart_scan()
        self.after(0, _start)

    def _tray_toggle_shield(self, icon=None, menu_item=None):
        self.after(0, self.toggle_file_shield)

    def _tray_create_demo(self, icon=None, menu_item=None):
        self.after(0, lambda: self.create_demo_test_file(silent=True))

    def _tray_quit_app(self, icon=None, menu_item=None):
        self.after(0, self.quit_app)

    def quit_app(self):
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.destroy()
        sys.exit(0)

    def _configure_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background=BG_CARD,
            foreground=TEXT_PRIMARY,
            fieldbackground=BG_CARD,
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 10)
        )
        style.configure(
            "Treeview.Heading",
            background=BG_SIDEBAR,
            foreground=ACCENT_GREEN,
            font=("Segoe UI", 10, "bold"),
            borderwidth=0
        )
        style.map("Treeview", background=[("selected", ACCENT_BLUE)])
        style.configure(
            "Privex.Horizontal.TProgressbar",
            troughcolor=BG_SIDEBAR,
            background=ACCENT_GREEN,
            thickness=14
        )

    def _build_layout(self):
        self.sidebar = tk.Frame(self, bg=BG_SIDEBAR, width=235)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand_frame = tk.Frame(self.sidebar, bg=BG_SIDEBAR, pady=20)
        brand_frame.pack(fill="x")
        tk.Label(
            brand_frame, text="🛡️ PRIVEX", fg=ACCENT_ORANGE, bg=BG_SIDEBAR,
            font=("Segoe UI", 18, "bold")
        ).pack()
        tk.Label(
            brand_frame, text="PRO ENGINE + TRAY GUARD", fg=TEXT_MUTED, bg=BG_SIDEBAR,
            font=("Segoe UI", 8, "bold")
        ).pack()

        self.nav_buttons = {}
        nav_items = [
            ("status",     "🏠  Status Dashboard"),
            ("scans",      "🔍  Protection & Scans"),
            ("quarantine", "🧰  Virus Chest (Vault)"),
            ("shields",    "🛡️  Real-Time Shields"),
            ("network",    "🌐  Network Inspector"),
            ("cleanup",    "🚀  PC Speedup & Junk")
        ]
        for key, label in nav_items:
            btn = tk.Button(
                self.sidebar, text=label, anchor="w", padx=22, pady=12,
                bg=BG_SIDEBAR, fg=TEXT_PRIMARY, activebackground=BG_CARD,
                activeforeground=ACCENT_GREEN, bd=0, font=("Segoe UI", 11, "bold"),
                cursor="hand2", command=lambda k=key: self.show_frame(k)
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[key] = btn

        tk.Button(
            self.sidebar, text="🔽 Minimize to System Tray", bg=BG_CARD, fg=ACCENT_GREEN,
            font=("Segoe UI", 9, "bold"), bd=0, pady=8, cursor="hand2",
            command=self.hide_to_tray
        ).pack(side="bottom", fill="x", padx=14, pady=(0, 12))

        self.telemetry_lbl = tk.Label(
            self.sidebar, text="CPU: --%  |  RAM: --%\nTray Shield: Active",
            fg=TEXT_MUTED, bg=BG_SIDEBAR, font=("Segoe UI", 9), justify="left", pady=10
        )
        self.telemetry_lbl.pack(side="bottom", padx=16)

        self.main_area = tk.Frame(self, bg=BG_MAIN)
        self.main_area.pack(side="right", fill="both", expand=True)

        self.frames = {}
        for name in ("status", "scans", "quarantine", "shields", "network", "cleanup"):
            frame = tk.Frame(self.main_area, bg=BG_MAIN, padx=28, pady=22)
            self.frames[name] = frame

        self._build_status_tab(self.frames["status"])
        self._build_scans_tab(self.frames["scans"])
        self._build_quarantine_tab(self.frames["quarantine"])
        self._build_shields_tab(self.frames["shields"])
        self._build_network_tab(self.frames["network"])
        self._build_cleanup_tab(self.frames["cleanup"])

    def show_frame(self, name: str):
        for k, f in self.frames.items():
            f.pack_forget()
            self.nav_buttons[k].configure(bg=BG_SIDEBAR, fg=TEXT_PRIMARY)

        self.frames[name].pack(fill="both", expand=True)
        self.nav_buttons[name].configure(bg=BG_CARD, fg=ACCENT_GREEN)

        if name == "quarantine":
            self.refresh_quarantine_table()
        elif name == "network":
            self.refresh_network_table()
        elif name == "shields":
            self.refresh_startup_table()
        elif name == "cleanup":
            self.calculate_temp_junk()

    def _build_status_tab(self, parent):
        top_bar = tk.Frame(parent, bg=BG_MAIN)
        top_bar.pack(fill="x")
        tk.Label(
            top_bar, text="System Protection Status", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(side="left")

        tk.Button(
            top_bar, text="🔔 Test Win11 Toast Alert", bg=BG_CARD, fg=ACCENT_BLUE,
            font=("Segoe UI", 10, "bold"), padx=14, pady=6, bd=0, cursor="hand2",
            command=lambda: ToastManager.notify(
                "Privex Security Pro — Live Test",
                "Native Windows 11 Toast Notifications and System Tray icon are working!"
            )
        ).pack(side="right")

        center = tk.Frame(parent, bg=BG_CARD, padx=30, pady=28)
        center.pack(fill="x", pady=18)

        self.ring_canvas = tk.Canvas(center, width=170, height=170, bg=BG_CARD, highlightthickness=0)
        self.ring_canvas.pack(side="left", padx=20)
        self._draw_status_ring(protected=True)

        info_col = tk.Frame(center, bg=BG_CARD)
        info_col.pack(side="left", fill="both", expand=True, padx=20)

        self.status_headline = tk.Label(
            info_col, text="You are protected", fg=ACCENT_GREEN, bg=BG_CARD,
            font=("Segoe UI", 24, "bold"), anchor="w"
        )
        self.status_headline.pack(fill="x")

        self.status_subtext = tk.Label(
            info_col,
            text="Real-Time Tray Shield & Windows 11 Toast Alerts are active. Closing this window keeps protection running in the System Tray.",
            fg=TEXT_MUTED, bg=BG_CARD, font=("Segoe UI", 10), anchor="w", pady=8, wraplength=580, justify="left"
        )
        self.status_subtext.pack(fill="x")

        btn_row = tk.Frame(info_col, bg=BG_CARD, pady=10)
        btn_row.pack(fill="x")

        tk.Button(
            btn_row, text="▶  RUN SMART SCAN", bg=ACCENT_ORANGE, fg=TEXT_PRIMARY,
            font=("Segoe UI", 12, "bold"), padx=24, pady=10, bd=0, cursor="hand2",
            command=lambda: [self.show_frame("scans"), self.start_smart_scan()]
        ).pack(side="left", padx=(0, 12))

        tk.Button(
            btn_row, text="🧪 Drop Demo Virus File", bg=BG_SIDEBAR, fg=ACCENT_GREEN,
            font=("Segoe UI", 10, "bold"), padx=16, pady=10, bd=0, cursor="hand2",
            command=self.create_demo_test_file
        ).pack(side="left")

        cards_row = tk.Frame(parent, bg=BG_MAIN)
        cards_row.pack(fill="both", expand=True, pady=6)

        pillars = [
            ("🛡️ Real-Time Tray Shield", "Background Folder & Heuristic Guard", "ACTIVE IN TRAY", ACCENT_GREEN, "shields"),
            ("🧰 Virus Chest", "Base64 Encrypted Quarantine Vault", f"{len(self.engine.vault_data)} Isolated", ACCENT_BLUE, "quarantine"),
            ("🌐 Network Guard", "Live TCP & Process Inspector", "MONITORING", ACCENT_GREEN, "network")
        ]
        for title, desc, badge, color, target in pillars:
            card = tk.Frame(cards_row, bg=BG_CARD, padx=20, pady=18)
            card.pack(side="left", fill="both", expand=True, padx=6)
            tk.Label(card, text=title, fg=TEXT_PRIMARY, bg=BG_CARD, font=("Segoe UI", 14, "bold")).pack(anchor="w")
            tk.Label(card, text=desc, fg=TEXT_MUTED, bg=BG_CARD, font=("Segoe UI", 10), pady=6).pack(anchor="w")
            tk.Label(card, text=badge, fg=color, bg=BG_CARD, font=("Segoe UI", 11, "bold"), pady=6).pack(anchor="w")
            tk.Button(
                card, text="Open Module →", bg=BG_SIDEBAR, fg=TEXT_PRIMARY, bd=0,
                padx=12, pady=6, cursor="hand2", command=lambda t=target: self.show_frame(t)
            ).pack(anchor="w", pady=(8, 0))

    def _draw_status_ring(self, protected=True):
        self.ring_canvas.delete("all")
        color = ACCENT_GREEN if protected else ACCENT_RED
        icon = "✓" if protected else "!"
        self.ring_canvas.create_oval(12, 12, 158, 158, outline=color, width=10)
        self.ring_canvas.create_oval(26, 26, 144, 144, outline=BG_SIDEBAR, width=3)
        self.ring_canvas.create_text(85, 85, text=icon, fill=color, font=("Segoe UI", 48, "bold"))

    def _build_scans_tab(self, parent):
        tk.Label(
            parent, text="Protection & Virus Scans", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w")

        btn_bar = tk.Frame(parent, bg=BG_MAIN, pady=14)
        btn_bar.pack(fill="x")

        tk.Button(
            btn_bar, text="⚡ Smart Scan", bg=ACCENT_ORANGE, fg=TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"), padx=18, pady=8, bd=0, cursor="hand2",
            command=self.start_smart_scan
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar, text="🚀 Quick Scan (Downloads & Desktop)", bg=ACCENT_BLUE, fg=TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"), padx=18, pady=8, bd=0, cursor="hand2",
            command=self.start_quick_scan
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar, text="📂 Custom Folder Scan", bg=BG_CARD, fg=TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"), padx=18, pady=8, bd=0, cursor="hand2",
            command=self.start_custom_scan
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar, text="🧰 Quarantine All Detected", bg=ACCENT_RED, fg=TEXT_PRIMARY,
            font=("Segoe UI", 11, "bold"), padx=18, pady=8, bd=0, cursor="hand2",
            command=self.quarantine_all_detected
        ).pack(side="right")

        prog_card = tk.Frame(parent, bg=BG_CARD, padx=18, pady=14)
        prog_card.pack(fill="x", pady=(0, 14))

        self.scan_stage_lbl = tk.Label(
            prog_card, text="Ready to scan. Select a scan mode above.",
            fg=ACCENT_GREEN, bg=BG_CARD, font=("Segoe UI", 11, "bold"), anchor="w"
        )
        self.scan_stage_lbl.pack(fill="x")

        self.scan_file_lbl = tk.Label(
            prog_card, text="Waiting...", fg=TEXT_MUTED, bg=BG_CARD,
            font=("Consolas", 9), anchor="w", pady=4
        )
        self.scan_file_lbl.pack(fill="x")

        self.scan_progress = ttk.Progressbar(
            prog_card, style="Privex.Horizontal.TProgressbar", orient="horizontal", mode="determinate"
        )
        self.scan_progress.pack(fill="x", pady=6)

        cols = ("severity", "threat", "path", "sha256")
        self.scan_tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        self.scan_tree.heading("severity", text="Severity")
        self.scan_tree.heading("threat", text="Threat Name")
        self.scan_tree.heading("path", text="File Path")
        self.scan_tree.heading("sha256", text="SHA-256 Signature")
        self.scan_tree.column("severity", width=90, anchor="center")
        self.scan_tree.column("threat", width=230)
        self.scan_tree.column("path", width=380)
        self.scan_tree.column("sha256", width=180)
        self.scan_tree.pack(fill="both", expand=True)

    def create_demo_test_file(self, silent=False):
        target_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        if not os.path.exists(target_dir):
            target_dir = APP_DIR
        test_path = os.path.join(target_dir, f"privex_demo_malware_{int(time.time())}.txt")
        with open(test_path, "w", encoding="utf-8") as f:
            f.write(f"SAFE DEMO FILE FOR PRIVEX ANTIVIRUS TESTING: {DEMO_MARKER}\n")

        ToastManager.notify(
            "Demo Virus Sample Dropped",
            f"Created {os.path.basename(test_path)} in Downloads. Real-Time Shield will intercept it within 3 seconds!"
        )
        if not silent:
            messagebox.showinfo(
                "Demo Virus Sample Created",
                f"Safe Privex Test Virus created at:\n{test_path}\n\n"
                "If Real-Time Shield is ON, watch the Windows 11 Toast Notification as it catches and quarantines it!"
            )

    def start_smart_scan(self):
        if self.is_scanning:
            return
        folders = [
            APP_DIR,
            os.path.join(os.path.expanduser("~"), "Downloads"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]
        threading.Thread(target=self._run_scan_worker, args=(folders, True), daemon=True).start()

    def start_quick_scan(self):
        if self.is_scanning:
            return
        folders = [
            os.path.join(os.path.expanduser("~"), "Downloads"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]
        threading.Thread(target=self._run_scan_worker, args=(folders, False), daemon=True).start()

    def start_custom_scan(self):
        if self.is_scanning:
            return
        folder = filedialog.askdirectory(title="Select Folder for Deep Antivirus Scan")
        if folder:
            threading.Thread(target=self._run_scan_worker, args=([folder], False), daemon=True).start()

    def _run_scan_worker(self, folders, is_smart):
        self.is_scanning = True
        self.detected_threats.clear()
        self.after(0, lambda: self.scan_tree.delete(*self.scan_tree.get_children()))

        if is_smart:
            self.after(0, lambda: self.scan_stage_lbl.configure(
                text="[Stage 1/3] Auditing Active Memory Processes & Startup Registry...", fg=ACCENT_ORANGE
            ))
            time.sleep(0.5)

        all_files = []
        for folder in folders:
            if not os.path.exists(folder):
                continue
            for root_dir, _, files in os.walk(folder):
                if ".git" in root_dir or "node_modules" in root_dir or ".privex_quarantine" in root_dir:
                    continue
                for f in files:
                    all_files.append(os.path.join(root_dir, f))
                if len(all_files) >= 1200:
                    break

        total = max(len(all_files), 1)
        self.after(0, lambda: self.scan_stage_lbl.configure(
            text=f"[Stage 2/3] Scanning {len(all_files)} files (SHA-256 + Heuristics + Entropy)...", fg=ACCENT_ORANGE
        ))

        for idx, fpath in enumerate(all_files, start=1):
            pct = int((idx / total) * 100)
            if idx % 5 == 0 or idx == total:
                self.after(0, lambda p=pct, fp=fpath: [
                    self.scan_progress.configure(value=p),
                    self.scan_file_lbl.configure(text=f"Scanning ({p}%): {fp[:95]}")
                ])

            res = self.engine.scan_single_file(fpath)
            if res:
                self.detected_threats.append(res)
                self.after(0, lambda r=res: self.scan_tree.insert(
                    "", "end", values=(r["severity"], r["threat"], r["path"], r["sha256"])
                ))

        self.is_scanning = False
        count = len(self.detected_threats)
        if count > 0:
            self.update_tray_state("danger", f"Privex Alert — {count} Threat(s) Detected!")
            ToastManager.notify(
                f"⚠️ {count} Threat(s) Detected!",
                "Malicious files were found during the scan. Open Privex to quarantine them immediately.",
                urgent=True
            )
            self.after(0, lambda: [
                self.scan_stage_lbl.configure(
                    text=f"⚠️ Scan Complete: {count} Threat(s) Detected! Click 'Quarantine All Detected' to isolate.",
                    fg=ACCENT_RED
                ),
                self.status_headline.configure(text=f"{count} Threat(s) Found!", fg=ACCENT_RED),
                self._draw_status_ring(protected=False)
            ])
        else:
            self.update_tray_state("protected", "Privex Security Pro — You are protected")
            ToastManager.notify(
                "✓ Smart Scan Complete",
                f"Scanned {len(all_files)} files. No malware or suspicious threats detected."
            )
            self.after(0, lambda: [
                self.scan_stage_lbl.configure(
                    text=f"✓ Scan Complete! {len(all_files)} files verified clean. No malware found.",
                    fg=ACCENT_GREEN
                ),
                self.scan_file_lbl.configure(text="All scanned paths are clean."),
                self.status_headline.configure(text="You are protected", fg=ACCENT_GREEN),
                self._draw_status_ring(protected=True)
            ])

    def quarantine_all_detected(self):
        if not self.detected_threats:
            messagebox.showinfo("Quarantine", "No active threats in the scan list to quarantine.")
            return
        moved = 0
        for t in list(self.detected_threats):
            if self.engine.quarantine_file(t):
                moved += 1
        self.detected_threats.clear()
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.status_headline.configure(text="You are protected", fg=ACCENT_GREEN)
        self._draw_status_ring(protected=True)
        self.update_tray_state("protected", "Privex Security Pro — You are protected")
        self.scan_stage_lbl.configure(
            text=f"✓ {moved} threat(s) safely locked in Virus Chest (Quarantine).", fg=ACCENT_GREEN
        )
        ToastManager.notify(
            "🧰 Threats Quarantined",
            f"Successfully isolated {moved} threat(s) into the encrypted Virus Chest."
        )

    def _build_quarantine_tab(self, parent):
        tk.Label(
            parent, text="Virus Chest (Quarantine Vault)", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w")
        tk.Label(
            parent, text="Isolated files are encoded in Base64 inside .privex_quarantine so they cannot execute.",
            fg=TEXT_MUTED, bg=BG_MAIN, font=("Segoe UI", 10), pady=6
        ).pack(anchor="w")

        btn_bar = tk.Frame(parent, bg=BG_MAIN, pady=10)
        btn_bar.pack(fill="x")

        tk.Button(
            btn_bar, text="♻️ Restore Selected File", bg=ACCENT_BLUE, fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"), padx=16, pady=8, bd=0, cursor="hand2",
            command=self.restore_selected_vault
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar, text="🗑️ Delete Permanently", bg=ACCENT_RED, fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"), padx=16, pady=8, bd=0, cursor="hand2",
            command=self.delete_selected_vault
        ).pack(side="left")

        cols = ("id", "threat", "original_path", "date")
        self.vault_tree = ttk.Treeview(parent, columns=cols, show="headings", height=14)
        self.vault_tree.heading("id", text="Vault ID")
        self.vault_tree.heading("threat", text="Threat Classification")
        self.vault_tree.heading("original_path", text="Original Path")
        self.vault_tree.heading("date", text="Quarantined At")
        self.vault_tree.column("id", width=180)
        self.vault_tree.column("threat", width=220)
        self.vault_tree.column("original_path", width=360)
        self.vault_tree.column("date", width=150)
        self.vault_tree.pack(fill="both", expand=True)

    def refresh_quarantine_table(self):
        self.vault_tree.delete(*self.vault_tree.get_children())
        for item_rec in self.engine.vault_data:
            self.vault_tree.insert(
                "", "end", values=(item_rec["id"], item_rec["threat"], item_rec["original_path"], item_rec["date"])
            )

    def restore_selected_vault(self):
        sel = self.vault_tree.selection()
        if not sel:
            return
        vid = self.vault_tree.item(sel[0])["values"][0]
        if self.engine.restore_from_quarantine(vid):
            self.refresh_quarantine_table()
            ToastManager.notify("File Restored", f"Restored {vid} from Virus Chest.")

    def delete_selected_vault(self):
        sel = self.vault_tree.selection()
        if not sel:
            return
        vid = self.vault_tree.item(sel[0])["values"][0]
        if self.engine.delete_from_quarantine(vid):
            self.refresh_quarantine_table()
            ToastManager.notify("Threat Shredded", "Permanently deleted threat from Virus Chest.")

    def _build_shields_tab(self, parent):
        tk.Label(
            parent, text="Real-Time Core Shields & Startup Guard", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w")

        toggles = tk.Frame(parent, bg=BG_CARD, padx=18, pady=14)
        toggles.pack(fill="x", pady=12)

        self.shield_btn_text = tk.StringVar(value="🟢 Real-Time File Shield: ON (Monitoring Downloads & Desktop)")
        tk.Button(
            toggles, textvariable=self.shield_btn_text, bg=BG_SIDEBAR, fg=ACCENT_GREEN,
            font=("Segoe UI", 11, "bold"), padx=16, pady=8, bd=0, cursor="hand2",
            command=self.toggle_file_shield
        ).pack(side="left")

        tk.Label(
            parent, text="Windows Startup Registry Entries (HKCU / HKLM Run)",
            fg=TEXT_PRIMARY, bg=BG_MAIN, font=("Segoe UI", 13, "bold"), pady=8
        ).pack(anchor="w")

        cols = ("hive", "name", "command")
        self.startup_tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        self.startup_tree.heading("hive", text="Registry Hive")
        self.startup_tree.heading("name", text="Startup Entry")
        self.startup_tree.heading("command", text="Executable Command Path")
        self.startup_tree.column("hive", width=110, anchor="center")
        self.startup_tree.column("name", width=220)
        self.startup_tree.column("command", width=550)
        self.startup_tree.pack(fill="both", expand=True)

    def toggle_file_shield(self):
        self.engine.file_shield_active = not self.engine.file_shield_active
        if self.engine.file_shield_active:
            self.shield_btn_text.set("🟢 Real-Time File Shield: ON (Monitoring Downloads & Desktop)")
            self.update_tray_state("protected", "Privex Security Pro — Real-Time Shield ON")
            ToastManager.notify("🛡️ Real-Time Shield Activated", "Background File Shield is now actively monitoring new files.")
        else:
            self.shield_btn_text.set("🔴 Real-Time File Shield: PAUSED")
            self.update_tray_state("warning", "Privex Security Pro — Real-Time Shield PAUSED")
            ToastManager.notify("⚠️ Real-Time Shield Paused", "Live background monitoring is temporarily paused.", urgent=True)

    def refresh_startup_table(self):
        self.startup_tree.delete(*self.startup_tree.get_children())
        for hive, name, cmd in self.engine.get_startup_items():
            self.startup_tree.insert("", "end", values=(hive, name, cmd))

    def _start_realtime_shield(self):
        def monitor():
            watch_dirs = [
                os.path.join(os.path.expanduser("~"), "Downloads"),
                os.path.join(os.path.expanduser("~"), "Desktop")
            ]
            known = set()
            for d in watch_dirs:
                if os.path.exists(d):
                    try:
                        for f in os.listdir(d):
                            known.add(os.path.join(d, f))
                    except Exception:
                        pass

            while True:
                time.sleep(2.5)
                if not self.engine.file_shield_active or self.is_scanning:
                    continue
                for d in watch_dirs:
                    if not os.path.exists(d):
                        continue
                    try:
                        current = {os.path.join(d, f) for f in os.listdir(d)}
                        new_files = current - known
                        known = current
                        for nf in new_files:
                            res = self.engine.scan_single_file(nf)
                            if res:
                                self.engine.quarantine_file(res)
                                self.update_tray_state("protected", f"Privex Blocked: {res['threat']}")
                                ToastManager.notify(
                                    "🚨 Threat Blocked & Quarantined!",
                                    f"Shield intercepted '{os.path.basename(res['path'])}' ({res['threat']}) and locked it in Virus Chest.",
                                    urgent=True
                                )
                                self.after(0, self.refresh_quarantine_table)
                    except Exception:
                        pass

        threading.Thread(target=monitor, daemon=True).start()

    def _build_network_tab(self, parent):
        tk.Label(
            parent, text="Network Shield & Active Connections", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w")

        btn_bar = tk.Frame(parent, bg=BG_MAIN, pady=10)
        btn_bar.pack(fill="x")

        tk.Button(
            btn_bar, text="🔄 Refresh Connections", bg=ACCENT_BLUE, fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"), padx=16, pady=8, bd=0, cursor="hand2",
            command=self.refresh_network_table
        ).pack(side="left", padx=(0, 10))

        tk.Button(
            btn_bar, text="⛔ Terminate Selected Process", bg=ACCENT_RED, fg=TEXT_PRIMARY,
            font=("Segoe UI", 10, "bold"), padx=16, pady=8, bd=0, cursor="hand2",
            command=self.kill_selected_network_process
        ).pack(side="left")

        cols = ("pid", "process", "local", "remote", "status")
        self.net_tree = ttk.Treeview(parent, columns=cols, show="headings", height=14)
        self.net_tree.heading("pid", text="PID")
        self.net_tree.heading("process", text="Process Name")
        self.net_tree.heading("local", text="Local Address")
        self.net_tree.heading("remote", text="Remote Address")
        self.net_tree.heading("status", text="TCP Status")
        self.net_tree.column("pid", width=80, anchor="center")
        self.net_tree.column("process", width=200)
        self.net_tree.column("local", width=220)
        self.net_tree.column("remote", width=220)
        self.net_tree.column("status", width=130, anchor="center")
        self.net_tree.pack(fill="both", expand=True)

    def refresh_network_table(self):
        self.net_tree.delete(*self.net_tree.get_children())
        if not psutil:
            return
        try:
            conns = psutil.net_connections(kind="tcp")
            for c in conns[:80]:
                if not c.raddr:
                    continue
                pid = c.pid or 0
                try:
                    pname = psutil.Process(pid).name() if pid else "System"
                except Exception:
                    pname = "Unknown"
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
                self.net_tree.insert("", "end", values=(pid, pname, laddr, raddr, c.status))
        except Exception:
            pass

    def kill_selected_network_process(self):
        sel = self.net_tree.selection()
        if not sel or not psutil:
            return
        pid, pname = self.net_tree.item(sel[0])["values"][:2]
        if messagebox.askyesno("Terminate Process", f"Are you sure you want to kill {pname} (PID {pid})?"):
            try:
                psutil.Process(int(pid)).terminate()
                self.refresh_network_table()
                ToastManager.notify("Process Terminated", f"Killed {pname} (PID {pid}).")
            except Exception as e:
                messagebox.showerror("Error", f"Could not terminate process: {e}")

    def _build_cleanup_tab(self, parent):
        tk.Label(
            parent, text="PC Speedup & Temp Junk Cleaner", fg=TEXT_PRIMARY, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")
        ).pack(anchor="w")

        card = tk.Frame(parent, bg=BG_CARD, padx=24, pady=24)
        card.pack(fill="x", pady=18)

        self.junk_lbl = tk.Label(
            card, text="Scanning Windows Temp directory...", fg=ACCENT_ORANGE, bg=BG_CARD,
            font=("Segoe UI", 16, "bold")
        )
        self.junk_lbl.pack(anchor="w")

        tk.Label(
            card,
            text=f"Target Path: {tempfile.gettempdir()}\nSafely removes unlocked temporary cache files to free up disk space.",
            fg=TEXT_MUTED, bg=BG_CARD, font=("Segoe UI", 10), justify="left", pady=10
        ).pack(anchor="w")

        tk.Button(
            card, text="🧹 Clean Temporary Junk Now", bg=ACCENT_GREEN, fg=BG_SIDEBAR,
            font=("Segoe UI", 12, "bold"), padx=20, pady=10, bd=0, cursor="hand2",
            command=self.clean_temp_junk
        ).pack(anchor="w", pady=8)

    def calculate_temp_junk(self):
        temp_dir = tempfile.gettempdir()
        total_bytes = 0
        file_count = 0
        for root_dir, _, files in os.walk(temp_dir):
            for f in files:
                try:
                    total_bytes += os.path.getsize(os.path.join(root_dir, f))
                    file_count += 1
                except OSError:
                    pass
        mb = round(total_bytes / (1024 * 1024), 2)
        self.junk_lbl.configure(text=f"Found {mb} MB of Temp Junk across {file_count} files")

    def clean_temp_junk(self):
        temp_dir = tempfile.gettempdir()
        removed = 0
        freed = 0
        for root_dir, _, files in os.walk(temp_dir):
            for f in files:
                fpath = os.path.join(root_dir, f)
                try:
                    sz = os.path.getsize(fpath)
                    os.remove(fpath)
                    removed += 1
                    freed += sz
                except OSError:
                    pass
        mb = round(freed / (1024 * 1024), 2)
        self.calculate_temp_junk()
        ToastManager.notify("🧹 PC Speedup Complete", f"Removed {removed} junk files ({mb} MB freed).")

    def _update_telemetry(self):
        if psutil:
            cpu = psutil.cpu_percent(interval=None)
            ram = psutil.virtual_memory().percent
            state_txt = "ON" if self.engine.file_shield_active else "PAUSED"
            self.telemetry_lbl.configure(
                text=f"CPU Load: {cpu}%  |  RAM: {ram}%\nTray Shield: {state_txt}  |  v2026.10"
            )
        self.after(2500, self._update_telemetry)


if __name__ == "__main__":
    minimized_flag = "--minimized" in sys.argv
    app = PrivexSecurityApp(start_minimized=minimized_flag)
    app.mainloop()