import hashlib
import json
import uuid
import webbrowser
import os
import re
from datetime import datetime, timezone
from dataclasses import dataclass
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_der
import jcs
import requests
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog
from typing import Optional, Dict, Any
import sys

os.chdir(sys._MEIPASS)

PROFILE_FILE = "profiles.json"

def load_profiles():
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"profiles": [], "active": None}

def save_profiles(profiles_data):
    with open(PROFILE_FILE, "w", encoding="utf-8") as f:
        json.dump(profiles_data, f, indent=4)

# -----------------------------
# Fingerprint Functions
# -----------------------------
def hash_document(document_content: bytes) -> str:
    return hashlib.sha256(document_content).hexdigest()

@dataclass
class FingerprintValue:
    orgId: str
    tenantId: str
    eventId: str
    documentId: str
    documentRef: str
    timestamp: str
    version: int

def create_fingerprint_value(orgId, tenantId, documentId, documentRef):
    return FingerprintValue(
        orgId=orgId,
        tenantId=tenantId,
        eventId=str(uuid.uuid4()),
        documentId=documentId,
        documentRef=documentRef,
        timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        version=1
    )

@dataclass
class SignatureProof:
    id: str
    signature: str
    algorithm: str

@dataclass
class SignedFingerprint:
    content: FingerprintValue
    proofs: list[SignatureProof]

def sign_fingerprint(fingerprint_value, private_key):
    canonical_json = jcs.canonicalize(fingerprint_value.__dict__)
    sha256 = hashlib.sha256(canonical_json).hexdigest().encode("utf-8")
    sha512 = hashlib.sha512(sha256).digest()[:32]
    signature = private_key.sign_digest(sha512, sigencode=sigencode_der)
    vk = private_key.verifying_key.pubkey.point
    pub_hex = f"04{vk.x():064x}{vk.y():064x}"
    return SignedFingerprint(
        content=fingerprint_value,
        proofs=[SignatureProof(
            id=pub_hex,
            signature=signature.hex(),
            algorithm="SECP256K1_RFC8785_V1"
        )]
    )

def submit_fingerprint(signed_fingerprint, user_metadata, profile):
    # Grab required profile info
    api_key = profile.get("api_key")
    org_id = profile.get("org_id")
    tenant_id = profile.get("tenant_id")
    meta_name = user_metadata or signed_fingerprint.content.documentId

    # Ensure nothing is missing
    if not api_key:
        raise ValueError("Active profile is missing API key.")
    if not org_id:
        raise ValueError("Active profile is missing Org ID.")
    if not tenant_id:
        raise ValueError("Active profile is missing Tenant ID.")

    # Assign profile values to fingerprint
    signed_fingerprint.content.orgId = org_id
    signed_fingerprint.content.tenantId = tenant_id

    payload = {
        "attestation": {
            "content": signed_fingerprint.content.__dict__,
            "proofs": [p.__dict__ for p in signed_fingerprint.proofs]
        },
        "metadata": {
            "tags": {
                "type": "file",
                "name": meta_name
            }
        }
    }

    r = requests.post(
        "https://de-api.constellationnetwork.io/v1/fingerprints",
        headers={
            "Content-Type": "application/json",
            "X-API-KEY": api_key
        },
        json=[payload]
    )
    r.raise_for_status()
    return r.json()

def log_fingerprint(file_path, document_id, link):
    with open("fingerprint_log.txt", "a", encoding="utf-8") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} | "
            f"File: {file_path} | "
            f"Document ID: {document_id} | "
            f"Link: {link}\n"
        )

# -----------------------------
# GUI
# -----------------------------
class FingerprintApp:
    def __init__(self, master):
        self.master = master
        master.title("The Proofmaker 1.1")
        master.geometry("800x680")
        icon = tk.PhotoImage(file="fingerprint.png")
        master.iconphoto(True, icon)

        # Load profiles
        self.profiles_data = load_profiles()
        self.private_key = SigningKey.generate(curve=SECP256k1)

        # -----------------
        # Profile manager functions
        # -----------------
        def get_active_profile():
            active_name = self.profiles_data.get("active")
            for p in self.profiles_data.get("profiles", []):
                if p["profile_name"] == active_name:
                    return p
            return {}

        self.get_active_profile = get_active_profile
        self.active_profile = self.get_active_profile()

        # ---- Add profile using a single-page form ----
        def add_profile():
            form_win = tk.Toplevel(self.master)
            form_win.title("Add / Edit Profile")
            form_win.geometry("400x220")
            form_win.grab_set()  # Modal behavior

            # Labels & entries
            tk.Label(form_win, text="Profile Name:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
            name_entry = tk.Entry(form_win)
            name_entry.grid(row=0, column=1, padx=5, pady=5)

            tk.Label(form_win, text="API Key:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
            api_entry = tk.Entry(form_win)
            api_entry.grid(row=1, column=1, padx=5, pady=5)

            tk.Label(form_win, text="Org ID:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
            org_entry = tk.Entry(form_win)
            org_entry.grid(row=2, column=1, padx=5, pady=5)

            tk.Label(form_win, text="Tenant ID:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
            tenant_entry = tk.Entry(form_win)
            tenant_entry.grid(row=3, column=1, padx=5, pady=5)

            # Enable right-click menus for the profile pop-up entries
            self.enable_entry_context_menus(form_win)

            def save_profile():
                name = name_entry.get().strip()
                api = api_entry.get().strip()
                org = org_entry.get().strip()
                tenant = tenant_entry.get().strip()

                if not name:
                    messagebox.showerror("Error", "Profile Name is required.")
                    return

                # Update or add
                for idx, p in enumerate(self.profiles_data["profiles"]):
                    if p["profile_name"] == name:
                        self.profiles_data["profiles"][idx] = {
                            "profile_name": name,
                            "api_key": api,
                            "org_id": org,
                            "tenant_id": tenant
                        }
                        break
                else:
                    self.profiles_data["profiles"].append({
                        "profile_name": name,
                        "api_key": api,
                        "org_id": org,
                        "tenant_id": tenant
                    })

                self.profiles_data["active"] = name
                save_profiles(self.profiles_data)
                self.active_profile = self.get_active_profile()
                messagebox.showinfo("Profile Saved", f"Profile '{name}' saved and set active.")
                form_win.destroy()

            tk.Button(form_win, text="Save Profile", command=save_profile).grid(row=4, column=0, columnspan=2, pady=10)

        # ---- Select profile ----
        def select_profile():
            if not self.profiles_data["profiles"]:
                messagebox.showwarning("No Profiles", "No profiles to select.")
                return
            options = [p["profile_name"] for p in self.profiles_data["profiles"]]
            selected = simpledialog.askstring("Select Profile",
                                              f"Available profiles:\n{options}\nEnter profile name:")
            if selected and selected in options:
                self.profiles_data["active"] = selected
                save_profiles(self.profiles_data)
                self.active_profile = self.get_active_profile()
                messagebox.showinfo("Profile Selected", f"Profile '{selected}' is now active.")

        # ---- Delete profile ----
        def delete_profile():
            if not self.profiles_data["profiles"]:
                messagebox.showwarning("No Profiles", "No profiles to delete.")
                return
            options = [p["profile_name"] for p in self.profiles_data["profiles"]]
            selected = simpledialog.askstring("Delete Profile",
                                              f"Available profiles:\n{options}\nEnter profile name to delete:")
            if selected and selected in options:
                self.profiles_data["profiles"] = [p for p in self.profiles_data["profiles"]
                                                  if p["profile_name"] != selected]
                if self.profiles_data.get("active") == selected:
                    self.profiles_data["active"] = None
                    self.active_profile = {}
                save_profiles(self.profiles_data)
                messagebox.showinfo("Profile Deleted", f"Profile '{selected}' deleted.")

        # ---- Attach functions to self ----
        self.add_profile = add_profile
        self.select_profile = select_profile
        self.delete_profile = delete_profile

        # ---- Menu ----
        menubar = tk.Menu(master)
        profile_menu = tk.Menu(menubar, tearoff=0)
        profile_menu.add_command(label="Add / Edit Profile", command=self.add_profile)
        profile_menu.add_command(label="Select Profile", command=self.select_profile)
        profile_menu.add_command(label="Delete Profile", command=self.delete_profile)
        menubar.add_cascade(label="Profile", menu=profile_menu)
        master.config(menu=menubar)

        # -----------------
        # Form
        # -----------------
        form = tk.Frame(master)
        form.pack(fill="x", padx=10, pady=5)
        form.columnconfigure(1, weight=1)

        tk.Label(form, text="File:").grid(row=0, column=0, sticky="w")
        self.file_entry = tk.Entry(form)
        self.file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        tk.Button(form, text="Browse", command=self.browse_file).grid(row=0, column=2)

        tk.Label(form, text="Document ID (the visible part)").grid(row=1, column=0, sticky="w")
        self.doc_id_entry = tk.Entry(form)
        self.doc_id_entry.grid(row=1, column=1, sticky="ew", padx=5)

        tk.Label(form, text="Metadata (optional - up to 32 characters):").grid(row=2, column=0, sticky="w")
        self.meta_var = tk.StringVar(master=self.master)
        self.meta_entry = tk.Entry(form, textvariable=self.meta_var)
        self.meta_entry.grid(row=2, column=1, sticky="ew", padx=5)
        self.meta_count_label = tk.Label(form, text="0 / 32")
        self.meta_count_label.grid(row=2, column=2, sticky="w", padx=5)
        self.meta_var.trace_add("write", self.update_meta_count)

        # -----------------
        # Buttons
        # -----------------
        tk.Button(master, text="Generate Fingerprint", command=self.generate_single).pack(pady=5)
        tk.Button(master, text="Batch Autoprint (up to 10 files - leave Doc. ID blank)", command=self.batch_fingerprint).pack(pady=5)

        self.output = scrolledtext.ScrolledText(master, height=25, wrap=tk.WORD)
        self.output.pack(fill="both", expand=True, padx=10, pady=5)

        self.enable_entry_context_menus()

    # -----------------
    # Automatically add right-click menu to all Entry widgets
    # -----------------
    def enable_entry_context_menus(self, parent=None):
        if parent is None:
            parent = self.master
        for widget in parent.winfo_children():
            if isinstance(widget, tk.Entry):
                menu = tk.Menu(widget, tearoff=0)
                menu.add_command(label="Cut", command=lambda w=widget: w.event_generate("<<Cut>>"))
                menu.add_command(label="Copy", command=lambda w=widget: w.event_generate("<<Copy>>"))
                menu.add_command(label="Paste", command=lambda w=widget: w.event_generate("<<Paste>>"))

                def show_menu(event, m=menu):
                    m.tk_popup(event.x_root, event.y_root)

                widget.bind("<Button-3>", show_menu)
                widget.bind("<Control-Button-1>", show_menu)

            if widget.winfo_children():
                self.enable_entry_context_menus(widget)

    # -----------------
    # Metadata counter
    # -----------------
    def update_meta_count(self, *args):
        count = len(self.meta_var.get())
        self.meta_count_label.config(
            text=f"{count} / 32",
            fg="red" if count > 32 else "black"
        )

    # -----------------
    # File Browsing
    # -----------------
    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, path)

    # -----------------
    # Single / Batch
    # -----------------
    def generate_single(self):
        self.process_files([self.file_entry.get()])

    def batch_fingerprint(self):
        files = filedialog.askopenfilenames()
        if not files:
            return
        if len(files) > 10:
            messagebox.showerror("Error", "Maximum 10 files per batch.")
            return
        self.process_files(files)

    # -----------------
    # Core processing
    # -----------------
    def process_files(self, files):
        try:
            user_metadata = self.meta_entry.get().strip()
            if len(user_metadata) > 32:
                messagebox.showerror("Error", "Metadata cannot exceed 32 characters.")
                return

            files = [f for f in files if f and f.strip()]
            if not files:
                messagebox.showerror("Error", "No file selected.")
                return

            # Ensure active profile is complete
            if not self.active_profile.get("org_id") or not self.active_profile.get("tenant_id") or not self.active_profile.get("api_key"):
                messagebox.showerror(
                    "Profile Error",
                    "Active profile missing Org ID, Tenant ID, or API key.\n"
                    "Please add/edit your profile first."
                )
                return

            processed = 0
            for path in files:
                if not os.path.exists(path):
                    raise FileNotFoundError(f"File not found: {path}")

                doc_id = self.doc_id_entry.get().strip() or os.path.splitext(os.path.basename(path))[0]
                with open(path, "rb") as f:
                    content = f.read()

                h = hash_document(content)

                fp = create_fingerprint_value(
                    orgId=self.active_profile.get("org_id"),
                    tenantId=self.active_profile.get("tenant_id"),
                    documentId=doc_id,
                    documentRef=h
                )

                signed_fp = sign_fingerprint(fp, self.private_key)
                result = submit_fingerprint(signed_fp, user_metadata, self.active_profile)

                if result and "hash" in result[0]:
                    link = f"https://digitalevidence.constellationnetwork.io/fingerprint/{result[0]['hash']}"
                    self.output.insert(tk.END, f"{doc_id} → {link}\n")
                    start_index = f"{self.output.index(tk.END)}-2l linestart"
                    end_index = f"{self.output.index(tk.END)}-1c"
                    tag_name = f"link_{uuid.uuid4().hex}"
                    self.output.tag_add(tag_name, start_index, end_index)
                    self.output.tag_config(tag_name, foreground="blue", underline=True)
                    self.output.tag_bind(tag_name, "<Enter>", lambda e: self.output.config(cursor="hand2"))
                    self.output.tag_bind(tag_name, "<Leave>", lambda e: self.output.config(cursor=""))
                    self.output.tag_bind(tag_name, "<Button-1>", lambda e, url=link: webbrowser.open(url))

                    log_fingerprint(path, doc_id, link)

                    output_folder = "fingerprint_proofs"
                    os.makedirs(output_folder, exist_ok=True)
                    safe_doc_id = re.sub(r"[^\w\d_-]", "_", doc_id)
                    json_filename = os.path.join(output_folder, f"{safe_doc_id}.fingerprint.json")
                    proof_data = {
                        "file_name": os.path.basename(path),
                        "file_path": path,
                        "file_hash": h,
                        "document_id": doc_id,
                        "metadata": user_metadata,
                        "fingerprint_tx_hash": result[0]["hash"],
                        "explorer_link": link,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "algorithm": "SHA-256",
                        "network": "Constellation",
                        "signing_key": signed_fp.proofs[0].id
                    }
                    with open(json_filename, "w", encoding="utf-8") as jf:
                        json.dump(proof_data, jf, indent=4)

                    self.output.insert(tk.END, f"JSON sidecar saved: {json_filename}\n")
                    processed += 1

            if processed == 0:
                messagebox.showerror("Error", "No files were fingerprinted.")
                return

            self.output.insert(tk.END, "\n")
            messagebox.showinfo(
                "Success",
                f"Fingerprinting completed for {processed} file{'s' if processed>1 else ''}."
            )

        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    FingerprintApp(root)
    root.mainloop()
