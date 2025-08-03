import streamlit as st
import socket
import threading
import time
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import queue
from datetime import datetime

# Main chat client class
class StreamlitChatClient:
    def __init__(self, passphrase):
        self.AES_KEY = self.generate_key_from_passphrase(passphrase)
        self.client = None
        self.connected = False
        self.nickname = ""
        self.message_queue = queue.Queue()
        self.receive_thread = None
        
    def generate_key_from_passphrase(self, passphrase):
        """Generate a 32-byte AES key from a passphrase using PBKDF2"""
        try:
            # Use the same fixed salt as the server for consistency
            salt = b'chatapp_salt_2024'  # 18 bytes
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 32 bytes = 256 bits for AES-256
                salt=salt,
                iterations=100000,  # Same number of iterations as server
            )
            key = kdf.derive(passphrase.encode('utf-8'))
            return key
        except Exception as e:
            st.error(f"Key generation error: {e}")
            return b'default_key_1234567890123456789012'  # Fallback key
        
    def encrypt_message(self, message):
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.AES_KEY), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted
        except Exception as e:
            st.error(f"Encryption error: {e}")
            return message.encode('utf-8')
    
    def decrypt_message(self, ciphertext):
        try:
            if len(ciphertext) < 16:
                return ciphertext.decode('utf-8', errors='ignore')
            iv = ciphertext[:16]
            encrypted = ciphertext[16:]
            cipher = Cipher(algorithms.AES(self.AES_KEY), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(encrypted) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(padded) + unpadder.finalize()
            return decrypted.decode('utf-8')
        except Exception:
            try:
                return ciphertext.decode('utf-8', errors='ignore')
            except:
                return "[Decryption Failed]"
    
    def receive_messages(self):
        while self.connected:
            try:
                data = self.client.recv(1024)
                if not data:
                    break
                try:
                    message = self.decrypt_message(data)
                except:
                    message = data.decode('utf-8', errors='ignore')
                if message == 'NICK':
                    self.client.send(self.nickname.encode('utf-8'))
                elif message.startswith('Connected to the server'):
                    self.message_queue.put(f"✅ {message}")
                elif message.startswith('Nickname already taken'):
                    self.message_queue.put(f"❌ {message}")
                    self.disconnect()
                    return
                else:
                    if message.strip():
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        self.message_queue.put(f"[{timestamp}] {message}")
            except Exception as e:
                if self.connected:
                    self.message_queue.put(f"❌ Connection error: {e}")
                break
        self.connected = False
    
    def connect(self, host, port, nickname):
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect((host, port))
            self.connected = True
            self.nickname = nickname
            self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            self.receive_thread.start()
            return True
        except Exception as e:
            st.error(f"Failed to connect: {e}")
            return False
    
    def send_message(self, message):
        if not self.connected:
            return False
        try:
            full_message = f'{self.nickname}: {message}'
            encrypted_msg = self.encrypt_message(full_message)
            self.client.send(encrypted_msg)
            return True
        except Exception as e:
            st.error(f"Failed to send message: {e}")
            return False
    
    def disconnect(self):
        self.connected = False
        if self.client:
            try:
                self.client.close()
            except:
                pass
    
    def get_messages(self):
        messages = []
        while not self.message_queue.empty():
            try:
                messages.append(self.message_queue.get_nowait())
            except queue.Empty:
                break
        return messages

# Session state
if 'chat_client' not in st.session_state:
    st.session_state.chat_client = None
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'connected' not in st.session_state:
    st.session_state.connected = False

# UI configuration
st.set_page_config(page_title="🔐 Encrypted Chat", page_icon="💬", layout="wide")
st.title("🔐 Encrypted Chat Application")
st.markdown("Secure real-time chat with AES-256 encryption from passphrase")

# Sidebar input
with st.sidebar:
    st.header("🔗 Connection Settings")
    host = st.text_input("Server Host", value="127.0.0.1")
    port = st.number_input("Port", min_value=1, max_value=65535, value=65432)
    nickname = st.text_input("Nickname", max_chars=20)
    passphrase_input = st.text_input("🔐 Secret Passphrase/Word", type="password", help="Enter any word/phrase - will be converted to AES key")

    if not st.session_state.connected:
        if st.button("Connect", type="primary"):
            if not all([host, port, nickname, passphrase_input]):
                st.error("Please fill in all fields including the passphrase.")
            else:
                passphrase = passphrase_input.strip()
                with st.spinner("🔐 Generating AES key from passphrase..."):
                    st.session_state.chat_client = StreamlitChatClient(passphrase)
                if st.session_state.chat_client.connect(host, port, nickname):
                    st.session_state.connected = True
                    st.success("Connected successfully!")
                    st.rerun()
                else:
                    st.error("Failed to connect to server")
    else:
        st.success(f"Connected as: {nickname}")
        if st.button("Disconnect", type="secondary"):
            st.session_state.chat_client.disconnect()
            st.session_state.connected = False
            st.session_state.messages.clear()
            st.rerun()

    st.markdown("---")
    st.markdown("### 📊 Connection Status")
    st.success("🟢 Connected" if st.session_state.connected else "🔴 Disconnected")

    st.markdown("---")
    st.markdown("### 🔐 Security Info")
    st.info("🔑 AES-256 key is automatically generated from your passphrase using PBKDF2 with 100,000 iterations")
    st.warning("⚠️ Only users with the same passphrase can decrypt messages")

# Main chat interface
col1, col2 = st.columns([3, 1])

with col1:
    st.header("💬 Chat Messages")
    if st.session_state.connected:
        new_messages = st.session_state.chat_client.get_messages()
        st.session_state.messages.extend(new_messages)

    with st.container():
        if st.session_state.messages:
            for message in st.session_state.messages[-50:]:
                if message.startswith("✅"):
                    st.success(message)
                elif message.startswith("❌"):
                    st.error(message)
                elif f"{nickname}:" in message:
                    st.markdown(f"**{message}**")
                else:
                    st.markdown(message)
        else:
            st.info("No messages yet. Start chatting!")

    if st.session_state.connected:
        message_input = st.text_input("Type your message:", key="message_input")
        col_send, col_clear = st.columns([1, 1])
        with col_send:
            if st.button("Send Message", type="primary"):
                if message_input.strip():
                    if st.session_state.chat_client.send_message(message_input):
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        own_message = f"[{timestamp}] {nickname}: {message_input}"
                        st.session_state.messages.append(own_message)
                        st.rerun()
                else:
                    st.warning("Please enter a message.")
        with col_clear:
            if st.button("Clear Chat"):
                st.session_state.messages.clear()
                st.rerun()
    else:
        st.warning("Please connect to start chatting.")

with col2:
    st.header("🛠️ Chat Controls")
    auto_refresh = st.checkbox("Auto-refresh (5s)", value=True)
    if auto_refresh and st.session_state.connected:
        time.sleep(5)
        st.rerun()

    if st.button("🔄 Refresh Messages"):
        st.rerun()

    st.markdown("---")
    st.markdown("### 📈 Statistics")
    st.metric("Total Messages", len(st.session_state.messages))

    st.markdown("---")
    st.markdown("### ⚡ Quick Actions")
    if st.session_state.connected:
        quick_messages = [
            "👋 Hello everyone!",
            "👍 Agreed!",
            "😄 That's funny!",
            "🤔 Interesting...",
            "👋 Goodbye!"
        ]
        selected_quick = st.selectbox("Quick Messages", ["Select..."] + quick_messages)
        if selected_quick != "Select..." and st.button("Send Quick Message"):
            if st.session_state.chat_client.send_message(selected_quick):
                timestamp = datetime.now().strftime("%H:%M:%S")
                own_message = f"[{timestamp}] {nickname}: {selected_quick}"
                st.session_state.messages.append(own_message)
                st.rerun()

st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🔐 Encrypted Chat App | AES-256-CBC with PBKDF2 Key Derivation"
    "</div>",
    unsafe_allow_html=True
)
