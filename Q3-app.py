import os
import streamlit as st
import json
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac, sha256

# Constants
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_here"  # Use a secure random salt in production!
LOCKOUT_DURATION = 60  # seconds

# Session state initialization
if 'authenticate_user' not in st.session_state:
    st.session_state.authenticate_user = False
if 'failed_login' not in st.session_state:
    st.session_state.failed_login = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# Utility functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def hash_password_pbkdf2(password: str) -> str:
    key = pbkdf2_hmac(
        'sha256',
        password.encode(),
        SALT,
        100000
    )
    return key.hex()

def generate_key(password: str) -> bytes:
    key = sha256(password.encode()).digest()
    return urlsafe_b64encode(key)

def encrypt_data(data: str, password: str) -> str:
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:
    try:
        cipher = Fernet(generate_key(password))
        return cipher.decrypt(encrypted_data.encode()).decode()
    except Exception:
        st.error("Decryption failed. Please check your password.")
        return None

# App UI
st.title("🔒 Secure User Data System")
menu = ["🏠 Home", "🔑 Login", "📝 Register", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("Select an option", menu)

# Home Page
if choice == "🏠 Home":
    st.subheader("Welcome to the Secure Multi User Data System")
    st.write("This app lets you encrypt and store data securely, tied to each user.")
    st.write("Please login or register to continue.")

# Login Page
elif choice == "🔑 Login":
    st.subheader("🔑 Login")

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("🔓 Login"):
        # Lockout check
        if st.session_state.failed_login >= 3:
            time_since_lockout = time.time() - st.session_state.lockout_time
            if time_since_lockout < LOCKOUT_DURATION:
                remaining = int(LOCKOUT_DURATION - time_since_lockout)
                st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
                st.stop()
            else:
                st.session_state.failed_login = 0  # Reset after lockout

        if username and password:
            data = load_data()
            hashed_input = hash_password_pbkdf2(password)

            if username in data:
                stored_password = data[username].get("password")
                if hashed_input == stored_password:
                    st.success("✅ Login successful!")
                    st.session_state.authenticate_user = username
                    st.session_state.failed_login = 0
                else:
                    st.session_state.failed_login += 1
                    st.session_state.lockout_time = time.time()
                    st.error("❌ Incorrect password.")
            else:
                st.session_state.failed_login += 1
                st.session_state.lockout_time = time.time()
                st.error("❌ Username does not exist.")
        else:
            st.warning("⚠️ Please enter both username and password.")

# Register Page
elif choice == "📝 Register":
    st.subheader("📝 Register")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    if st.button("✅ Register"):
        if username and password:
            data = load_data()
            if username in data:
                st.error("❌ Username already exists.")
            else:
                hashed_password = hash_password_pbkdf2(password)
                data[username] = {
                    "password": hashed_password,
                    "data": []
                }
                save_data(data)
                st.success("🎉 User registered successfully! You can now login.")
        else:
            st.error("⚠️ Please enter both username and password.")

# Store Data Page
elif choice == "📥 Store Data":
    st.subheader("📥 Store Data")
    if st.session_state.authenticate_user:
        user = st.session_state.authenticate_user
        data_input = st.text_area("📝 Enter data to encrypt and store")
        password = st.text_input("🔒 Password", type="password")

        if st.button("💾 Store Data"):
            if data_input and password:
                encrypted_data = encrypt_data(data_input, password)
                data = load_data()
                if user not in data:
                    st.error("❌ User not found.")
                else:
                    data[user].setdefault("data", []).append(encrypted_data)
                    save_data(data)
                    st.success("✅ Data stored successfully!")
            else:
                st.error("⚠️ Please enter both data and password.")
    else:
        st.warning("⚠️ Please login to store data.")

# Retrieve Data Page
elif choice == "📤 Retrieve Data":
    st.subheader("📤 Retrieve Data")
    if not st.session_state.authenticate_user:
        st.error("❌ Please login to retrieve data.")
    else:
        user = st.session_state.authenticate_user
        data = load_data()
        user_data = data.get(user, {}).get("data", [])

        if not user_data:
            st.warning("⚠️ No data found for this user.")
        else:
            st.write("🔐 Encrypted Data Entries")
            for i, item in enumerate(user_data):
                st.code(item, language="plaintext")

            encrypted_input = st.text_area("🔒 Paste encrypted data to decrypt")
            password_input = st.text_input("🔑 Password to decrypt", type="password")

            if st.button("🔓 Decrypt Data"):
                if encrypted_input and password_input:
                    decrypted_data = decrypt_data(encrypted_input, password_input)
                    if decrypted_data:
                        st.success(f"✅ Decrypted Data: {decrypted_data}")
                else:
                    st.error("⚠️ Please enter both encrypted data and password.")
