import os
import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import sha256
from hashlib import pbkdf2_hmac

# Contants 
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_here"  # Use a secure random salt in production
LOCKOUT_DURATION = 60  # seconds

# Session state initialization
if 'authenticate_user' not in st.session_state:
    st.session_state.authenticate_user= False
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

def hash_password_pbkdf2(password: str) -> str:
    """Hash the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_key(password: str) -> bytes:
    """Generate a key for encryption using the password."""
    key = sha256(password.encode()).digest()
    return urlsafe_b64encode(key)

def encrypt_data(data: str, password: str) -> str:
    """Encrypt the data using the password."""
    cipher = Fernet(generate_key(password))
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:
    """Decrypt the data using the password."""
    try:
        cipher = Fernet(generate_key(password))
        return cipher.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        st.error("Decryption failed. Please check your password.")
        return None
    
# load store date from json file
def load_store_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

# Navigate to the login page
st.title("🔒 Secure Multi User Data System")
menu = ["🏠 Home", "🔑 Login", "📝 Register", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("Select an option", menu) 

# Home page
if choice == "🏠 Home":
    st.subheader("Welcome to the Secure Multi User Data System")
    st.write("This application allows you to securely store and retrieve data using encryption. Each user has their own protected data")
    st.write("Please login or register to continue.")

# Login page
elif choice == "🔑 Login":
    st.subheader("🔑 Login")

    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")

    login_clicked = st.button("🔓 Login")

    if login_clicked:
        # Lockout check
        if st.session_state.failed_login >= 3:
            time_since_lockout = time.time() - st.session_state.lockout_time
            if time_since_lockout < LOCKOUT_DURATION:
                remaining = int(LOCKOUT_DURATION - time_since_lockout)
                st.error(f"🚫 Too many failed attempts. Try again in {remaining} seconds.")
                st.stop()
            else:
                st.session_state.failed_login = 0  # Reset on timeout

        if username and password:
            data = load_data()
            hashed_input = hash_password_pbkdf2(password)

            if username in data:
                stored_password = data[username].get("password")
                if hashed_input == stored_password:
                    st.success("✅ Login successful!")
                    st.session_state.authenticate_user = username
                    st.session_state.failed_login = 0  # Reset attempts
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

# Register page
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
                data[username] = hashed_password
                save_data(data)
                st.success("🎉 User registered successfully! You can now login.")
        else:
            st.error("⚠️ Please enter both username and password.")

# Store Data page
elif choice == "📥 Store Data":
    st.subheader("📥 Store Data")
    if st.session_state.authenticate_user:
        data = st.text_area("📝 Enter data to encrypt and store")
        password = st.text_input("🔒 Password", type="password")

        if st.button("💾 Store Data"):
            if data and password:
                encrypted_data = encrypt_data(data, password)
                store_data = load_store_data()
                store_data[st.session_state.authenticate_user] = {"data": [encrypted_data]}
                save_data(store_data)
                st.success("✅ Data stored successfully!")
            else:
                st.error("⚠️ Please enter both data and password.")
    else:
        st.warning("⚠️ Please login to store data.")

# Retrieve Data page
elif choice == "📤 Retrieve Data":
    st.subheader("📤 Retrieve Data")
    if not st.session_state.authenticate_user:
        st.error("❌ Please login to retrieve data.")
    else:
        st.subheader("📤 Retrieve Data")
        stored_data = load_store_data()
        user_data = stored_data.get(st.session_state.authenticate_user, {}).get("data", [])
        
        if not user_data:
            st.warning("⚠️ No data found for this user.")
        else:
            st.write("🔐 Encrypted Data Entries")
            for i, item in enumerate(user_data):
                st.code(item, language="plaintext")

                encrypted_input = st.text_area("🔒 Enter the encrypted data to decrypt")
                password_input = st.text_input("🔑 Enter the password to decrypt", type="password")

                if st.button("🔓 Decrypt Data", key=f"decrypt_{i}"):
                    if encrypted_input and password_input:
                        decrypted_data = decrypt_data(encrypted_input, password_input)
                        if decrypted_data:
                            st.success(f"✅ Decrypted Data: {decrypted_data}")
                        else:
                            st.error("❌ Decryption failed. Please check your password.")
                    else:
                        st.error("⚠️ Please enter both encrypted data and password.")
