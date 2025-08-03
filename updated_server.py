import socket
import threading
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chat_server.log'),
        logging.StreamHandler()
    ]
)

class StreamlitChatServer:
    def __init__(self, host='0.0.0.0', port=65432, passphrase=''):
        self.HOST = host
        self.PORT = port
        self.AES_KEY = self.generate_key_from_passphrase(passphrase)
        self.clients = []
        self.nicknames = []
        self.server = None
        self.running = False
        
    def generate_key_from_passphrase(self, passphrase):
        """Generate a 32-byte AES key from a passphrase using PBKDF2"""
        try:
            # Use a fixed salt for consistency across server/client
            # In production, you might want to use a configurable salt
            salt = b'chatapp_salt_2024'  # 18 bytes
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 32 bytes = 256 bits for AES-256
                salt=salt,
                iterations=100000,  # Standard number of iterations
            )
            key = kdf.derive(passphrase.encode('utf-8'))
            logging.info(f"Generated AES key from passphrase (length: {len(key)} bytes)")
            return key
        except Exception as e:
            logging.error(f"Key generation error: {e}")
            return b'default_key_1234567890123456789012'  # Fallback key
        
    def encrypt_message(self, message):
        try:
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            padded_data = padder.update(message_bytes) + padder.finalize()
            cipher = Cipher(algorithms.AES(self.AES_KEY), modes.CBC(iv))
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return iv + encrypted
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            return message.encode('utf-8') if isinstance(message, str) else message
    
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
        except Exception as e:
            logging.warning(f"Decryption failed: {e}")
            try:
                return ciphertext.decode('utf-8', errors='ignore')
            except:
                return "[Encrypted message - decryption failed]"
    
    def broadcast(self, message, sender_client=None, encrypt=True):
        disconnected_clients = []
        message_data = (
            self.encrypt_message(message)
            if encrypt and isinstance(message, str)
            else (message.encode('utf-8') if isinstance(message, str) else message)
        )
        for client in self.clients:
            if client != sender_client:
                try:
                    client.send(message_data)
                except Exception as e:
                    logging.warning(f"Failed to send to client: {e}")
                    disconnected_clients.append(client)
        for client in disconnected_clients:
            self.remove_client(client)
    
    def remove_client(self, client):
        try:
            if client in self.clients:
                index = self.clients.index(client)
                self.clients.remove(client)
                if index < len(self.nicknames):
                    nickname = self.nicknames[index]
                    self.nicknames.remove(nickname)
                    logging.info(f'{nickname} disconnected')
                    self.broadcast(f'📤 {nickname} left the chat.', encrypt=True)
                try:
                    client.close()
                except:
                    pass
                logging.info(f"Removed client. Active clients: {len(self.clients)}")
        except Exception as e:
            logging.error(f"Error removing client: {e}")
    
    def handle_client(self, client):
        while self.running:
            try:
                data = client.recv(1024)
                if not data:
                    logging.info("Client sent empty data, disconnecting")
                    break
                try:
                    message = self.decrypt_message(data)
                    if client in self.clients:
                        client_index = self.clients.index(client)
                        sender_nick = self.nicknames[client_index] if client_index < len(self.nicknames) else "Unknown"
                        logging.info(f"Message from {sender_nick}: {message[:100]}...")
                    self.broadcast(message, client, encrypt=True)
                except Exception as e:
                    logging.warning(f"Failed to decrypt message from client: {e}")
                    try:
                        plaintext = data.decode('utf-8', errors='ignore')
                        self.broadcast(plaintext, client, encrypt=True)
                    except:
                        logging.error("Failed to handle message as plaintext too")
            except Exception as e:
                logging.error(f"Client handling error: {e}")
                break
        self.remove_client(client)
    
    def start(self):
        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind((self.HOST, self.PORT))
            self.server.listen(10)
            self.running = True
            logging.info(f"🚀 Server running on {self.HOST}:{self.PORT}")
            while self.running:
                client, address = self.server.accept()
                logging.info(f"🔗 New connection from {str(address)}")
                if len(self.clients) >= 50:
                    client.send("Server is full. Please try again later.".encode('utf-8'))
                    client.close()
                    continue
                client.send('NICK'.encode('utf-8'))
                try:
                    nickname_data = client.recv(1024)
                    nickname = nickname_data.decode('utf-8').strip()
                    if not nickname or len(nickname) > 20:
                        client.send('Invalid nickname.'.encode('utf-8'))
                        client.close()
                        continue
                    if nickname in self.nicknames:
                        client.send('Nickname already taken.'.encode('utf-8'))
                        client.close()
                        continue
                    self.nicknames.append(nickname)
                    self.clients.append(client)
                    logging.info(f'✅ {nickname} joined the chat')
                    self.broadcast(f'📥 {nickname} joined the chat!', encrypt=True)
                    client.send('Connected to the server!'.encode('utf-8'))
                    thread = threading.Thread(target=self.handle_client, args=(client,))
                    thread.daemon = True
                    thread.start()
                except Exception as e:
                    logging.error(f"Client setup error: {e}")
                    client.close()
        except Exception as e:
            logging.error(f"Server start failed: {e}")
        finally:
            self.stop()
    
    def stop(self):
        logging.info("🛑 Shutting down server...")
        self.running = False
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        if self.server:
            try:
                self.server.close()
            except:
                pass
        self.clients.clear()
        self.nicknames.clear()
        logging.info("✅ Server stopped successfully")

def main():
    import signal
    import sys
    from getpass import getpass

    HOST = '26.227.104.15'
    PORT = 65432

    # Get passphrase instead of direct key
    passphrase = getpass("Enter passphrase/word for key generation: ").strip()
    if not passphrase:
        print("❌ Passphrase cannot be empty!")
        sys.exit(1)

    print(f"🔐 Generating AES key from passphrase...")
    server = StreamlitChatServer(HOST, PORT, passphrase)

    def signal_handler(sig, frame):
        logging.info("Received interrupt signal")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.start()
    except KeyboardInterrupt:
        logging.info("Server interrupted by user")
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        server.stop()

if __name__ == "__main__":
    main()