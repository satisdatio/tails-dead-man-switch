#!/usr/bin/env python3
"""
TailsOS Dead Man Switch
A minimal, auditable, and secure dead man switch for TailsOS.
Features: Tor-aware, Air-gap support, Tamper-evident logging, Modern UI.
#                                                                                                    
#                                                                                                  
#                                                                                                   
#                                                                                                   
#                                             :*%%%%%=.                                             
#                                         .+@@@@@@@@@@@@%:                                          
#                                       .*@@@@@@@@@@@@@@@@%:                                        
#                                      .%@@@@@@@@@@@@@@@@@@@=                                       
#                                      %@@@@@@@@@@@@@@@@@@@@@:                                      
#                                     -@@@@@@@@@@@@@@@@@@@@@@@                                      
#                                     %@@@@@@@@@@@@@@@@@@@@@@@                                      
#                                     %@@@@@@@@@@@@@@@@@@@@@@@                                      
#                  ..-===-:.          .@@@@@@@@@@@@@@@@@@@@@@@           .::::...                   
#               .*@@@@@@@@@@@%=.       #@@@@@@@@@@@@@@@@@@@@@.       .*@@@@@@@@@@%=.                
#             .%@@@@@@@@@@@@@@@@+.      #@@@@@@@@@@@@@@@@@@@:      .@@@@@@@@@@@@@@@@#.              
#            -@@@@@@@@@@@@@@@@@@@%.     .%@@@@@@@@@@@@@@@@@=      +@@@@@@@@@@@@@@@@@@@:             
#           :@@@@@@@@@@@@@@@@@@@@@@:     .@@@@@@@@@@@@@@@@+      %@@@@@@@@@@@@@@@@@@@@@.            
#          .@@@@@@@@@@@@@@@@@@@@@@@@=     .@@@@@@@@@@@@@@+     .@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@@#.    :@@@@@@@@@@@@*.    :@@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@@.    :@@@@@@@@@@%.   .+@@@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@@@:    -@@@@@@@@@.   .#@@@@@@@@@@@@@@@@@@@@@@@@@@@.           
#           :@@@@@@@@@@@@@@@@@@@@@@@@@@@@=    *@@@@@@@.   .@@@@@@@@@@@@@@@@@@@@@@@@@@@@-            
#            -@@@@@@@@@@@@@@@@@@@@@@@@@@@@#   :@@@@@@@.  -@@@@@@@@@@@@@@@@@@@@@@@@@@@@*             
#             .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@:              
#               .#@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:    .%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%:                
#                  .:==+#@@@@@@@@@@@@@@@@@@@@          %@@@@@@@@@@@@@@@@@@@@@#==.                   
#                                      .%@@@            @@@@*.                                      
#                                       .@@%     ..     *@@.                                        
#                                      .%@@@    =++=    @@@@-                                       
#                 .-=@@@@@@@@@@@@@@@@@@@@@@@@.-++++++-.%@@@@@@@@@@@@@@@@@@@@@@%=:.                  
#               -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*++++*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@%=                
#             :@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%@@@@@@@@@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@:              
#            *@@@@@@@@@@@@@@@@@@@@@@@@@@@@=   =@@@@@@@.  :@@@@@@@@@@@@@@@@@@@@@@@@@@@@*             
#           -@@@@@@@@@@@@@@@@@@@@@@@@@@@@.    %@@@@@@@.    %@@@@@@@@@@@@@@@@@@@@@@@@@@@-            
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@@%.   .%@@@@@@@@@.    *@@@@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@@@*.    +@@@@@@@@@@@.    -@@@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@@=     =@@@@@@@@@@@@*.    .@@@@@@@@@@@@@@@@@@@@@@@@@.           
#          .@@@@@@@@@@@@@@@@@@@@@@@@:     -@@@@@@@@@@@@@@=     .%@@@@@@@@@@@@@@@@@@@@@@@.           
#            @@@@@@@@@@@@@@@@@@@@@%      :@@@@@@@@@@@@@@@@=      #@@@@@@@@@@@@@@@@@@@@@.            
#            .%@@@@@@@@@@@@@@@@@@*      .@@@@@@@@@@@@@@@@@@:      +@@@@@@@@@@@@@@@@@@@:             
#             .=@@@@@@@@@@@@@@@@:      .@@@@@@@@@@@@@@@@@@@@.      .@@@@@@@@@@@@@@@@#.              
#                :#@@@@@@@@@@*.        %@@@@@@@@@@@@@@@@@@@@%        .*@@@@@@@@@@%=.                
#                    ..::..           +@@@@@@@@@@@@@@@@@@@@@@+           .::::..                    
#                                     %@@@@@@@@@@@@@@@@@@@@@@@                                      
#                                     %@@@@@@@@@@@@@@@@@@@@@@@                                      
#                                     %@@@@@@@@@@@@@@@@@@@@@@@                                      
#                                     .@@@@@@@@@@@@@@@@@@@@@@.                                      
#                                      -@@@@@@@@@@@@@@@@@@@@:                                       
#                                       .%@@@@@@@@@@@@@@@@%.                                        
#                                         :%@@@@@@@@@@@@#:                                          
#                                             =%@@@@%+.                                             
"""

import os
import sys
import json
import time
import hmac
import hashlib
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# GTK3 is native to Tails. No pip install required.
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GLib, Pango

# --- CONFIGURATION & CONSTANTS ---
APP_DIR = Path.home() / "Persistent" / "DeadManSwitch"
CONFIG_FILE = APP_DIR / "config.json"
AUDIT_LOG = APP_DIR / "audit.log"
PAYLOAD_DIR = APP_DIR / "payloads"
STATE_FILE = APP_DIR / ".state"

# Apple-style Palette
COLORS = {
    "bg": "#F5F5F7",
    "card": "#FFFFFF",
    "text": "#1D1D1F",
    "subtext": "#86868B",
    "accent": "#0071E3",
    "danger": "#FF3B30",
    "success": "#34C759",
    "border": "#D2D2D7"
}

# --- SECURITY UTILITIES ---

def ensure_dirs():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)

def audit_log(action: str, details: str):
    """Tamper-evident logging with chained hashes."""
    timestamp = datetime.utcnow().isoformat() + "Z"
    prev_hash = "0" * 64
    if AUDIT_LOG.exists():
        with open(AUDIT_LOG, 'r') as f:
            lines = f.readlines()
            if lines:
                prev_hash = lines[-1].strip().split("|")[-1]
    
    content = f"{timestamp}|{action}|{details}|{prev_hash}"
    current_hash = hashlib.sha256(content.encode()).hexdigest()
    log_line = f"{content}|{current_hash}\n"
    
    with open(AUDIT_LOG, 'a') as f:
        f.write(log_line)

def load_config():
    if not CONFIG_FILE.exists():
        return {"deadline": None, "actions": [], "armed": False, "mode": "tor"}
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        return {"deadline": None, "actions": [], "armed": False, "mode": "tor"}

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    audit_log("CONFIG_SAVE", "Configuration updated")

# --- ACTION EXECUTOR ---

class ActionExecutor:
    @staticmethod
    def execute(action: dict):
        atype = action.get("type")
        audit_log("ACTION_TRIGGER", f"Executing {atype}")
        
        try:
            if atype == "delete_file":
                target = Path(action["path"])
                if target.exists():
                    # Secure delete simulation (Tails has shred available)
                    subprocess.run(["shred", "-u", str(target)], check=True)
                    return True, "Securely deleted"
                return False, "File not found"
            
            elif atype == "run_command":
                # Warning: Commands run as amnesia user
                result = subprocess.run(action["command"], shell=True, capture_output=True, text=True)
                return result.returncode == 0, result.stdout
            
            elif atype == "write_email_draft":
                # Creates an encrypted draft for manual export in air-gap mode
                filename = f"email_{int(time.time())}.txt.gpg"
                draft_path = PAYLOAD_DIR / filename
                content = f"To: {action['to']}\nSubject: {action['subject']}\n\n{action['body']}"
                
                # Use GPG available in Tails
                proc = subprocess.run(
                    ["gpg", "--symmetric", "--armor", "--output", str(draft_path)],
                    input=content, text=True, capture_output=True
                )
                return proc.returncode == 0, f"Draft created: {draft_path}"
            
            return False, "Unknown action type"
        except Exception as e:
            audit_log("ACTION_ERROR", str(e))
            return False, str(e)

# --- UI COMPONENTS ---

class ModernButton(Gtk.Button):
    def __init__(self, label, color="accent", action=None):
        super().__init__(label=label)
        self.set_valign(Gtk.Align.CENTER)
        self.set_halign(Gtk.Align.CENTER)
        
        css = f"""
        button {{
            background-color: {COLORS[color]};
            color: white;
            border-radius: 12px;
            padding: 12px 24px;
            font-size: 14px;
            font-weight: 500;
            border: none;
        }}
        button:hover {{
            opacity: 0.9;
        }}
        """
        self.apply_css(css)
        if action:
            self.connect("clicked", action)

    def apply_css(self, css_data):
        provider = Gtk.CssProvider()
        provider.load_from_data(css_data.encode())
        self.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)

class ModernCard(Gtk.Frame):
    def __init__(self):
        super().__init__()
        self.set_shadow_type(Gtk.ShadowType.NONE)
        css = f"""
        frame {{
            background-color: {COLORS['card']};
            border-radius: 16px;
            padding: 20px;
        }}
        """
        provider = Gtk.CssProvider()
        provider.load_from_data(css.encode())
        self.get_style_context().add_provider(provider, Gtk.STYLE_PROVIDER_PRIORITY_USER)

# --- MAIN APPLICATION ---

class DeadManSwitchApp(Gtk.Window):
    def __init__(self):
        super().__init__(title="Dead Man Switch")
        ensure_dirs()
        self.config = load_config()
        self.timer_active = False
        
        self.set_default_size(420, 600)
        self.set_resizable(False)
        self.connect("destroy", Gtk.main_quit)
        
        # Global CSS
        screen = Gdk.Screen.get_default()
        provider = Gtk.CssProvider()
        provider.load_from_data(f"""
        window {{
            background-color: {COLORS['bg']};
        }}
        label {{
            color: {COLORS['text']};
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial;
        }}
        .title {{
            font-size: 28px;
            font-weight: 700;
            color: {COLORS['text']};
        }}
        .subtitle {{
            font-size: 13px;
            color: {COLORS['subtext']};
        }}
        .timer {{
            font-size: 48px;
            font-weight: 200;
            font-feature-settings: "tnum";
            color: {COLORS['text']};
        }}
        """.encode())
        Gtk.StyleContext.add_provider_for_screen(screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        
        self.build_ui()
        self.update_state()
        
        # Start background checker
        GLib.timeout_add_seconds(5, self.check_deadline)

    def build_ui(self):
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24)
        main_box.set_margin_top(40)
        main_box.set_margin_bottom(40)
        main_box.set_margin_start(30)
        main_box.set_margin_end(30)
        
        # Header
        title = Gtk.Label(label="Dead Man Switch")
        title.get_style_context().add_class("title")
        title.set_halign(Gtk.Align.START)
        
        subtitle = Gtk.Label(label="TailsOS Persistent Storage • Auditable")
        subtitle.get_style_context().add_class("subtitle")
        subtitle.set_halign(Gtk.Align.START)
        
        main_box.pack_start(title, False, False, 0)
        main_box.pack_start(subtitle, False, False, 0)
        
        # Status Card
        self.status_card = ModernCard()
        card_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        
        self.status_label = Gtk.Label(label="DISARMED")
        self.status_label.set_halign(Gtk.Align.CENTER)
        self.status_label.set_valign(Gtk.Align.CENTER)
        
        self.timer_label = Gtk.Label(label="00:00:00")
        self.timer_label.get_style_context().add_class("timer")
        self.timer_label.set_halign(Gtk.Align.CENTER)
        
        card_box.pack_start(self.status_label, False, False, 0)
        card_box.pack_start(self.timer_label, False, False, 0)
        self.status_card.add(card_box)
        main_box.pack_start(self.status_card, False, False, 0)
        
        # Controls
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        btn_box.set_halign(Gtk.Align.CENTER)
        
        self.btn_heartbeat = ModernButton("Send Heartbeat", "success", self.on_heartbeat)
        self.btn_arm = ModernButton("Arm Switch", "accent", self.on_arm)
        self.btn_config = ModernButton("Configure", "subtext", self.on_config)
        
        btn_box.pack_start(self.btn_heartbeat, False, False, 0)
        btn_box.pack_start(self.btn_arm, False, False, 0)
        
        main_box.pack_start(btn_box, False, False, 0)
        main_box.pack_start(self.btn_config, False, False, 0)
        
        self.add(main_box)

    def update_state(self):
        armed = self.config.get("armed", False)
        deadline = self.config.get("deadline")
        
        if armed and deadline:
            self.status_label.set_text("ARMED")
            self.status_label.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0, 0.45, 0.89, 1))
            self.btn_arm.set_sensitive(False)
            self.btn_heartbeat.set_sensitive(True)
        else:
            self.status_label.set_text("DISARMED")
            self.status_label.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.5, 0.5, 0.5, 1))
            self.btn_arm.set_sensitive(True)
            self.btn_heartbeat.set_sensitive(False)
        
        self.update_timer_display()

    def update_timer_display(self):
        deadline = self.config.get("deadline")
        if deadline and self.config.get("armed"):
            remaining = datetime.fromisoformat(deadline) - datetime.utcnow()
            if remaining.total_seconds() > 0:
                h, rem = divmod(int(remaining.total_seconds()), 3600)
                m, s = divmod(rem, 60)
                self.timer_label.set_text(f"{h:02}:{m:02}:{s:02}")
                return True
            else:
                self.timer_label.set_text("00:00:00")
                return False
        else:
            self.timer_label.set_text("--:--:--")
            return False

    def check_deadline(self):
        if not self.config.get("armed"):
            return True
        
        deadline = self.config.get("deadline")
        if deadline:
            if datetime.utcnow() >= datetime.fromisoformat(deadline):
                self.trigger_switch()
                return False
        
        self.update_timer_display()
        return True

    def on_heartbeat(self, widget):
        hours = 24  # Default heartbeat extension
        new_deadline = datetime.utcnow() + timedelta(hours=hours)
        self.config["deadline"] = new_deadline.isoformat()
        save_config(self.config)
        audit_log("HEARTBEAT", f"Extended to {new_deadline.isoformat()}")
        self.update_state()
        
        # Visual feedback
        self.timer_label.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0.2, 0.78, 0.35, 1))
        GLib.timeout_add(500, lambda: self.timer_label.override_color(Gtk.StateFlags.NORMAL, Gdk.RGBA(0,0,0,1)) or False)

    def on_arm(self, widget):
        if not self.config.get("actions"):
            dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.WARNING,
                Gtk.ButtonsType.OK, "No Actions Configured")
            dialog.format_secondary_text("Please configure actions before arming.")
            dialog.run()
            dialog.destroy()
            return
        
        self.config["armed"] = True
        self.on_heartbeat(None)  # Set initial deadline
        audit_log("ARM", "Switch armed")
        self.update_state()

    def trigger_switch(self):
        audit_log("TRIGGER", "Deadline passed. Executing actions.")
        self.config["armed"] = False
        save_config(self.config)
        
        for action in self.config.get("actions", []):
            ActionExecutor.execute(action)
        
        dialog = Gtk.MessageDialog(self, 0, Gtk.MessageType.ERROR,
            Gtk.ButtonsType.OK, "DEAD MAN SWITCH TRIGGERED")
        dialog.format_secondary_text("All configured actions have been executed. Check audit.log.")
        dialog.run()
        dialog.destroy()
        self.update_state()

    def on_config(self, widget):
        # Simple config dialog for demo
        dialog = Gtk.Dialog("Configuration", self, 0,
            (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
             Gtk.STOCK_SAVE, Gtk.ResponseType.OK))
        
        box = dialog.get_content_area()
        box.set_margin(20)
        
        label = Gtk.Label(label="Edit config.json manually for advanced actions.\n\nQuick Add: Delete File")
        box.add(label)
        
        entry = Gtk.Entry()
        entry.set_placeholder_text("/path/to/sensitive/file")
        box.add(entry)
        
        dialog.show_all()
        response = dialog.run()
        
        if response == Gtk.ResponseType.OK:
            path = entry.get_text()
            if path:
                self.config["actions"].append({"type": "delete_file", "path": path})
                save_config(self.config)
                audit_log("CONFIG_ADD", f"Added delete action for {path}")
        
        dialog.destroy()

def main():
    # Verify running in Tails/Persistent
    if not str(Path.home()).endswith("amnesia"):
        print("Warning: Not running as amnesia user.")
    
    if not (Path.home() / "Persistent").exists():
        print("Error: Persistent storage not found. DMS requires persistence.")
        sys.exit(1)
        
    win = DeadManSwitchApp()
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    main()