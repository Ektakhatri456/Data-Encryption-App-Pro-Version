
"""
Secure Data Vault — Pro
- Single-file Streamlit app (production mode)
- Full encryption, per-user isolation, admin license UI, export, activity log
- License keys are generated dynamically via Gumroad webhook and emailed to buyers
- No hardcoded test license keys
"""

import os
import base64
import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

import streamlit as st
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import bcrypt

import threading
from flask import Flask, request, jsonify
import smtplib
from email.message import EmailMessage

st.set_page_config(page_title="Secure Data Vault — Pro", layout="wide")

st.markdown("""
    <style>
    /* 🌈 Background */
    body {
        background: linear-gradient(120deg, #fdfbfb 0%, #ebedee 100%);
        font-family: "Segoe UI", sans-serif;
        color: #333;
    }

    /* 🎨 Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #2c5364, #203a43, #0f2027);
        color: white;
    }
    [data-testid="stSidebar"] * {
        color: white !important;
    }

    /* 🖱️ Buttons */
    div.stButton > button {
        background: linear-gradient(90deg, #667eea, #764ba2);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.6em 1.2em;
        font-weight: bold;
        box-shadow: 0px 4px 8px rgba(0,0,0,0.2);
        transition: 0.3s;
    }
    div.stButton > button:hover {
        background: linear-gradient(90deg, #764ba2, #667eea);
        transform: translateY(-2px);
    }

    /* 📌 Headers */
    h1, h2, h3 {
        color: #764ba2;
        font-family: "Poppins", sans-serif;
        font-weight: 700;
    }

    /* 📝 Input fields */
    input, textarea {
        border-radius: 8px !important;
        border: 1px solid #ccc !important;
        padding: 0.5em !important;
    }

    /* 📦 Tabs */
    .stTabs [role="tablist"] button {
        background: #f0f0f0;
        border-radius: 10px;
        margin-right: 8px;
        padding: 6px 12px;
        font-weight: 600;
    }
    .stTabs [role="tablist"] button[data-baseweb="tab"]:hover {
        background: #e2e2e2;
    }
    .stTabs [role="tablist"] button[aria-selected="true"] {
        background: linear-gradient(90deg, #667eea, #764ba2);
        color: white !important;
    }
    </style>
""", unsafe_allow_html=True)


# -------- CONFIG --------
DB_PATH = "pro_vault.db"  # renamed for production
PBKDF2_ITERATIONS = 200_000
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 5

# Optionally set ADMIN_KEY in environment for admin UI
ADMIN_KEY = os.getenv("ADMIN_KEY", "admin-prod-key")  # change in real deployment

ADMIN_KEY = "alpha-6711"  # keep or change as needed


# -------- DB / Helper --------
@st.cache_resource
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = get_db().cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        salt BLOB NOT NULL,
        pw_hash BLOB NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        lockout_until TEXT DEFAULT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS data (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        data_key TEXT NOT NULL,
        encrypted_text TEXT,
        encrypted_file TEXT,
        filename TEXT,
        created_at TEXT,
        UNIQUE(user_id, data_key),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY,
        license_key TEXT UNIQUE NOT NULL,
        active INTEGER DEFAULT 1,
        assigned_to INTEGER,
        assigned_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")
    get_db().commit()

init_db()

# -------- Crypto helpers --------
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def check_password(password: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), pw_hash)

def gen_license_key() -> str:
    return secrets.token_urlsafe(18)

# -------- DB functions --------
def register_user(username: str, password: str, email: Optional[str] = None):
    conn = get_db()
    c = conn.cursor()
    salt = os.urandom(16)
    pw_hash = hash_password(password)
    try:
        c.execute("INSERT INTO users (username, email, salt, pw_hash) VALUES (?, ?, ?, ?)",
                  (username, email, salt, pw_hash))
        conn.commit()
        return True, "Registered."
    except sqlite3.IntegrityError:
        return False, "Username or email already exists."

def get_user(username: str):
    c = get_db().cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    return c.fetchone()

def get_user_by_id(uid: int):
    c = get_db().cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return c.fetchone()

def record_failed(user_id: int):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    attempts = (row["failed_attempts"] or 0) + 1
    lockout_until = None
    if attempts >= LOCKOUT_THRESHOLD:
        lockout_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
        attempts = 0
    c.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id = ?", (attempts, lockout_until, user_id))
    conn.commit()

def reset_failed(user_id: int):
    conn = get_db(); c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?", (user_id,))
    conn.commit()

def check_lockout(user_row):
    if not user_row:
        return False
    lock = user_row["lockout_until"]
    if lock:
        try:
            until = datetime.fromisoformat(lock)
            if datetime.utcnow() < until:
                mins = ((until - datetime.utcnow()).seconds // 60) + 1
                return f"Account locked. Try after {mins} min"
        except Exception:
            return False
    return False

def add_license(key: str = None):
    conn = get_db(); c = conn.cursor()
    if not key:
        key = gen_license_key()
    try:
        c.execute("INSERT INTO licenses (license_key, active) VALUES (?, 1)", (key,))
        conn.commit()
        return True, key
    except sqlite3.IntegrityError:
        return False, "exists"

def valid_license(key: str):
    c = get_db().cursor()
    c.execute("SELECT * FROM licenses WHERE license_key = ? AND active = 1", (key,))
    return c.fetchone()

def assign_license(key: str, user_id: int):
    conn = get_db(); c = conn.cursor()
    c.execute("UPDATE licenses SET assigned_to = ?, assigned_at = ? WHERE license_key = ?", (user_id, datetime.utcnow().isoformat(), key))
    conn.commit()

def invalidate_license(key: str):
    conn = get_db(); c = conn.cursor()
    c.execute("UPDATE licenses SET active = 0 WHERE license_key = ?", (key,))
    conn.commit()

def log_activity(user_id: Optional[int], action: str, details: str = ""):
    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO activity (user_id, action, details) VALUES (?, ?, ?)", (user_id, action, details))
    conn.commit()

# -------- Data storage --------
def save_entry(user_id: int, data_key: str, plaintext: Optional[str], fernet: Fernet, file_bytes: Optional[bytes] = None, filename: Optional[str] = None):
    conn = get_db(); c = conn.cursor()
    enc_t = None; enc_f = None
    if plaintext:
        enc_t = fernet.encrypt(plaintext.encode()).decode()
    if file_bytes:
        enc_f = fernet.encrypt(file_bytes).decode()
    now = datetime.utcnow().isoformat()
    c.execute("INSERT OR REPLACE INTO data (user_id, data_key, encrypted_text, encrypted_file, filename, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (user_id, data_key, enc_t, enc_f, filename, now))
    conn.commit()
    log_activity(user_id, "save", data_key)
    return True

def fetch_entry(user_id: int, data_key: str):
    c = get_db().cursor()
    c.execute("SELECT * FROM data WHERE user_id = ? AND data_key = ?", (user_id, data_key))
    return c.fetchone()

def list_keys(user_id: int):
    c = get_db().cursor()
    c.execute("SELECT data_key, created_at FROM data WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    return c.fetchall()

def search_keys(user_id: int, q: str):
    c = get_db().cursor()
    pattern = f"%{q}%"
    c.execute("SELECT data_key, created_at FROM data WHERE user_id = ? AND data_key LIKE ? ORDER BY created_at DESC", (user_id, pattern))
    return c.fetchall()

def export_all_encrypted(user_id: int):
    c = get_db().cursor()
    c.execute("SELECT data_key, encrypted_text, encrypted_file, filename, created_at FROM data WHERE user_id = ?", (user_id,))
    rows = c.fetchall()
    arr = []
    for r in rows:
        arr.append({"data_key": r["data_key"], "encrypted_text": r["encrypted_text"], "encrypted_file": r["encrypted_file"], "filename": r["filename"], "created_at": r["created_at"]})
    return json.dumps(arr)

# -------- UI & Flow --------
st.title("🔐 Secure Data Vault — Pro")

# Session defaults
if "license_ok" not in st.session_state:
    st.session_state["license_ok"] = False
if "verified_license" not in st.session_state:
    st.session_state["verified_license"] = None
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "username" not in st.session_state:
    st.session_state["username"] = None
if "key_b64" not in st.session_state:
    st.session_state["key_b64"] = None
if "is_admin" not in st.session_state:
    st.session_state["is_admin"] = False

st.sidebar.markdown("**Pro features:** File encryption  • Export  • Admin license keys")

# --- License gating ---
if not st.session_state["license_ok"]:
    st.subheader("Enter your License Key")
    lic = st.text_input("License key", type="password", key="lic_in")
    if st.button("Verify License"):
        if not lic or not lic.strip():
            st.error("Enter a license key.")
        else:
            row = valid_license(lic.strip())
            if not row:
                st.error("Invalid or inactive license key.")
            else:
                # If assigned to another user, invalidate to prevent sharing
                assigned_to = row["assigned_to"]
                if assigned_to and assigned_to != None:
                    # key already assigned to another user -> invalidate and deny
                    invalidate_license(lic.strip())
                    st.error("This license has been invalidated due to sharing/previous assignment.")
                else:
                    st.session_state["license_ok"] = True
                    st.session_state["verified_license"] = lic.strip()
                    st.success("License valid. Proceed to Register or Login.")
                    st.rerun()
    st.info("Enter the license key you received after purchase.")
    st.stop()

# --- Auth: Login and Register (separate columns)
col1, col2 = st.columns(2)
with col1:
    st.header("Login")
    login_u = st.text_input("Username", key="login_u")
    login_pw = st.text_input("Password", type="password", key="login_pw")
    if st.button("Login"):
        if not login_u or not login_pw:
            st.error("Fill both fields.")
        else:
            user_row = get_user(login_u.strip())
            if not user_row:
                st.error("User not found.")
            else:
                lockmsg = check_lockout(user_row)
                if lockmsg:
                    st.error(lockmsg)
                elif not check_password(login_pw, user_row["pw_hash"]):
                    record_failed(user_row["id"])
                    st.error("Invalid credentials.")
                else:
                    # success: reset counters, derive key and store key string (not Fernet obj)
                    reset_failed(user_row["id"])
                    key = derive_key(login_pw, user_row["salt"])
                    key_b64 = key.decode()
                    st.session_state["user_id"] = user_row["id"]
                    st.session_state["username"] = user_row["username"]
                    st.session_state["key_b64"] = key_b64  # safe-ish for production (not storing password)
                    # assign license to this user (if verified_license present)
                    if st.session_state.get("verified_license"):
                        # double-check license is still active
                        row = valid_license(st.session_state["verified_license"])
                        if row:
                            assign_license(st.session_state["verified_license"], user_row["id"])
                        else:
                            st.warning("The license you used appears inactive now.")
                    log_activity(user_row["id"], "login", "success")
                    st.success(f"Logged in as {user_row['username']}.")
                    st.rerun()

with col2:
    st.header("Register")
    reg_u = st.text_input("Choose username", key="reg_u")
    reg_email = st.text_input("Email (optional)", key="reg_email")
    reg_pw = st.text_input("Choose password", type="password", key="reg_pw")
    reg_pw2 = st.text_input("Confirm password", type="password", key="reg_pw2")
    if st.button("Register"):
        if not reg_u or not reg_pw or reg_pw != reg_pw2:
            st.error("Fill fields correctly and ensure passwords match.")
        else:
            ok, msg = register_user(reg_u.strip(), reg_pw, (reg_email.strip() or None))
            if ok:
                st.success("Registered. Now login with your credentials.")
            else:
                st.error(msg)

# If not logged in, stop
if not st.session_state["user_id"]:
    st.info("Login or register to use your vault.")
    st.stop()

# --- Main app (user is logged in) ---
user_id = st.session_state["user_id"]
username = st.session_state["username"]
st.sidebar.markdown(f"**User:** {username}")

def get_fernet_from_session():
    if not st.session_state.get("key_b64"):
        st.error("Encryption key not available in session (login required).")
        return None
    return Fernet(st.session_state["key_b64"].encode())

menu = st.sidebar.radio("Menu", ["Home", "Encrypt", "Decrypt", "My Vault", "Export", "Account", "Admin"])

if menu == "Home":
    st.header(f"Welcome, {username} 👋")
    st.write("Your encryption key is derived from your password locally. We do not store raw passwords in DB.")
    st.write("Use the sidebar to encrypt/decrypt, export or manage account.")

elif menu == "Encrypt":
    st.header("🔐 Encrypt / Save Secret")
    key = st.text_input("Unique key for this secret (e.g., 'bank_pin')", key="enc_key")
    text = st.text_area("Secret text (leave blank if uploading file)", key="enc_text")
    uploaded = st.file_uploader("Upload file to encrypt (optional)", key="enc_file")
    if st.button("Encrypt & Save"):
        if not key:
            st.error("Provide a data key.")
        elif not text and not uploaded:
            st.error("Provide text or upload a file.")
        else:
            file_bytes = uploaded.read() if uploaded else None
            filename = uploaded.name if uploaded else None
            fernet = get_fernet_from_session()
            if not fernet:
                st.error("Encryption failed due to missing encryption key.")
            else:
                ok = save_entry(user_id, key.strip(), text.strip() if text else None, fernet, file_bytes, filename)
                if ok:
                    st.success("Saved encrypted entry.")
                else:
                    st.error("Save failed.")

elif menu == "Decrypt":
    st.header("🔓 Decrypt / Retrieve")
    q = st.text_input("Enter data key to decrypt", key="dec_q")
    if st.button("Decrypt"):
        if not q:
            st.error("Provide key.")
        else:
            row = fetch_entry(user_id, q.strip())
            if not row:
                st.warning("No entry found.")
            else:
                fernet = get_fernet_from_session()
                if not fernet:
                    st.error("Missing encryption key for decryption.")
                else:
                    try:
                        if row["encrypted_text"]:
                            plain = fernet.decrypt(row["encrypted_text"].encode()).decode()
                            st.subheader("Decrypted text")
                            st.code(plain)
                            st.download_button("Download decrypted text (.txt)", data=plain, file_name=f"{q.strip()}_decrypted.txt", mime="text/plain")
                        if row["encrypted_file"]:
                            b = fernet.decrypt(row["encrypted_file"].encode())
                            fname = row["filename"] or f"{q.strip()}_decrypted"
                            st.subheader("Decrypted file")
                            st.download_button("Download file", data=b, file_name=fname, mime="application/octet-stream")
                        log_activity(user_id, "decrypt", q.strip())
                    except Exception:
                        st.error("Decryption failed. Did you change your password or is the key incorrect?")

elif menu == "My Vault":
    st.header("🔎 Your Entries")
    search = st.text_input("Search keys (partial)", key="search_k")
    if st.button("Search"):
        rows = search_keys(user_id, search.strip() if search else "")
        if rows:
            for r in rows:
                st.write(f"- **{r['data_key']}** (saved: {r['created_at']})")
        else:
            st.info("No matches.")
    if st.button("List all"):
        rows = list_keys(user_id)
        if rows:
            for r in rows:
                st.write(f"- **{r['data_key']}** (saved: {r['created_at']})")
        else:
            st.info("No entries yet.")

elif menu == "Export":
    st.header("Export / Backup")
    if st.button("Download encrypted backup (JSON)"):
        blob = export_all_encrypted(user_id)
        st.download_button("Download backup", data=blob, file_name="vault_backup.json", mime="application/json")

elif menu == "Account":
    st.header("Account & Security")
    st.write("Username:", username)
    if st.button("Show my keys"):
        rows = list_keys(user_id)
        st.write([r["data_key"] for r in rows] or "No entries")
    if st.button("Delete all my entries (PERMANENT)"):
        c = get_db().cursor()
        c.execute("DELETE FROM data WHERE user_id = ?", (user_id,))
        get_db().commit()
        log_activity(user_id, "delete_all", "user deleted all entries")
        st.success("Deleted all entries.")
        st.rerun()

elif menu == "Admin":
    st.header("Admin — License Management (protected)")
    admin_input = st.text_input("Enter ADMIN_KEY to authenticate", type="password", key="adm_k")
    if st.button("Authenticate Admin"):
        if ADMIN_KEY and admin_input == ADMIN_KEY:
            st.session_state["is_admin"] = True
            st.success("Admin authenticated.")
            st.rerun()
        else:
            st.error("Invalid admin key.")

    if st.session_state.get("is_admin"):
        st.subheader("Generate license keys")
        n = st.number_input("How many keys?", min_value=1, max_value=100, value=3, step=1)
        if st.button("Generate"):
            ks = []
            for _ in range(int(n)):
                ok, k = add_license()
                if ok:
                    ks.append(k)
            st.success(f"Generated {len(ks)} keys.")
            st.write(ks)
        st.markdown("---")
        st.subheader("List recent keys")
        c = get_db().cursor()
        c.execute("SELECT license_key, active, assigned_to, assigned_at, created_at FROM licenses ORDER BY created_at DESC LIMIT 200")
        rows = c.fetchall()
        if rows:
            for r in rows:
                st.write(dict(r))
        else:
            st.info("No keys yet.")
        st.markdown("---")
        st.subheader("Activity log (recent)")
        c.execute("SELECT a.id, a.user_id, u.username as user, a.action, a.details, a.created_at FROM activity a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.created_at DESC LIMIT 200")
        acts = c.fetchall()
        if acts:
            for a in acts:
                st.write(f"{a['created_at']} — user:{a['user']} — {a['action']} — {a['details']}")
        else:
            st.info("No activity yet.")

# Logout control
st.sidebar.markdown("---")
if st.sidebar.button("Logout"):
    # Clear session-level sensitive data
    st.session_state["user_id"] = None
    st.session_state["username"] = None
    st.session_state["key_b64"] = None
    st.session_state["license_ok"] = False
    st.session_state["verified_license"] = None
    st.session_state["is_admin"] = False
    st.success("Logged out.")
    st.rerun()


# Flask app for webhook
webhook_app = Flask(__name__)

# Email config (set your SMTP server details here)

   SMTP_PASSWORD = st.secrets["SMTP_PASSWORD"]
   ADMIN_KEY = st.secrets["ADMIN_KEY"]
   SMTP_USERNAME = st.secrets["SMTP_USERNAME"]
   EMAIL_FROM = st.secrets["EMAIL_FROM"]
   SMTP_SERVER = "smtp.gmail.com"
   SMTP_PORT = 587
   
EMAIL_SUBJECT = "Your Secure Data Vault License Key"

def send_license_email(to_email: str, license_key: str):
    msg = EmailMessage()
    msg["Subject"] = EMAIL_SUBJECT
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Thank you for your purchase!\n\nYour license key is:\n\n{license_key}\n\nKeep it safe.")

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"License email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")

@webhook_app.route("/gumroad-webhook", methods=["POST"])
def gumroad_webhook():
    data = request.form or request.json
    # Gumroad sends a POST with form data; adjust if JSON

    # Basic validation (you should verify Gumroad signature for security)
    if not data:
        return jsonify({"error": "No data received"}), 400

    # Extract buyer email from Gumroad webhook payload
    buyer_email = data.get("email")
    if not buyer_email:
        return jsonify({"error": "No buyer email found"}), 400

    # Generate license key and add to DB
    ok, license_key = add_license()
    if not ok:
        return jsonify({"error": "Failed to generate license key"}), 500

    # Optionally assign license to a dummy user or leave unassigned
    # assign_license(license_key, user_id)  # if you want to assign immediately

    # Send license key to buyer email
    send_license_email(buyer_email, license_key)

    return jsonify({"message": "License generated and emailed", "license_key": license_key}), 200

def run_flask():
    webhook_app.run(host="0.0.0.0", port=5001)

# Run Flask webhook server in a separate thread alongside Streamlit

threading.Thread(target=run_flask, daemon=True).start()

