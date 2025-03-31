# 🧠 TgRAT - Telegram-Based Command and Control Server

**TgRAT** is a multi-client *Command & Control* (C2) framework that uses a **Telegram group with forum topics** as a communication channel between a central server and its agents. Each agent creates a dedicated thread for interaction, while the general channel allows global control of all bots.

> ⚠️ For educational purposes only.

## 🎞️ Images
![Server en consola](https://github.com/user-attachments/assets/7496d3be-5b43-46af-a615-d6ae458a5dfa)

![New Connection](https://github.com/user-attachments/assets/fccef3ae-44ea-480a-9ac6-994e8c036db0)

![Client tay whoami](https://github.com/user-attachments/assets/ea8555b0-3adc-423e-ac28-5e0c99ac6ba8)

![Uploaded Succesfully](https://github.com/user-attachments/assets/e2428b57-0bc7-45c9-8f24-dfd98e43528b)

![Downloaded Succesfully](https://github.com/user-attachments/assets/9467a452-e44d-4817-b0f3-278505d802f6)

![Screenshot](https://github.com/user-attachments/assets/e91c1df5-0202-4470-9919-4a12f8337f99)

![Sendall whoami](https://github.com/user-attachments/assets/d6383c40-6cd5-4563-899f-9fe370b01a9f)

![statusall](https://github.com/user-attachments/assets/43c85222-452d-4b45-a3d3-18ec549e4806)

---

## 🚀 Features

### ✅ Communication
- Encrypted end-to-end using **AES-256-CBC**
- Socket-based communication (TCP)
- Commands and responses are structured and encoded

### 🧠 Logging System
- Optional logging system (`/logs`) with dedicated forum topic
- Logs include timestamp and command information
- Can be enabled/disabled at runtime

### 🫀 Heartbeat System
- Agents send heartbeat messages every 30 seconds
- Server updates `last_seen` field in the database for each agent
- Used in `/listclients` and cleanup logic to detect inactive bots

### 📦 Server
- Built in Python using `pyTelegramBotAPI`
- Creates a forum topic per agent
- Stores client data in SQLite
- Handles multiple bots in parallel
- Global control commands from the main thread

### 🧠 Agent
- Sends system info on connect (hostname + OS)
- Captures screenshots (`screenshot`)
- Executes arbitrary shell commands (`shell`)
- Sends encrypted responses back to server
- Sends periodic heartbeats to indicate it's alive

### 🔐 Security
- AES-256 with random IV for each message
- Base64 encoding for safe transmission
- Handles broken pipes, socket errors, reconnections

---

## 📖 Available Commands

### Inside a client thread
- `/status` – Check if the client is online
- `/shell <command>` – Execute a command on the client
- `/screenshot` – Take a screenshot and send it back
- `/delete` – Delete the client thread
- `/kill` – Delete the client thread
- `/download <file path>` – Download a file from the agent
- `/upload <file path>` – Upload a file to the agent
- `/listwebcams` – Return the index of available cameras
- `/photo <camera index>` – Take Photo from the webcam
- `/stream <camera index> <time> <fps>` – Takes a video from the webcam

### In the main thread (global)
- `/sendall <command>` – Execute command on all clients
- `/logs` -  Start/Stop the logging system in a channel named Logs
- `/listclients` - List all registered clients
- `/clean` -  Deletes duplicate or inactive (48h+) clients and their topics
- `/statusall` – Check connection status for all clients
- `/shutdown` – Gracefully shut down the C2 server
- `/photoall` – Takes a photo from default webcam  of all the clients

---

## 🛠 Requirements

- Python 3.8+
- Python packages:
  - `pyTelegramBotAPI`
  - `pycryptodome`
  - `mss`
  - `Pillow`
  - `sqlite3` (built-in)
  - `pillow`
  - `termcolor`
  - `opencv-python`
- A Telegram bot token
- A Telegram group with **forum topics** enabled

---

## ⚙️ Setup

An spanish Set-Up guide is on [My Blog](https://17tay.pages.dev/posts/post-c2-sobre-telegram/#set-up)

---

## 📋 TODO / Roadmap

- [x] Improve bot disconnection detection (ping-pong, heartbeat, etc.)
- [ ] Agent persistence (registry, scheduled tasks)
- [ ] Auto-update feature for agents
- [ ] Authentication system for agents (pre-shared key or signature)
- [x] Command logging system (file or DB)
- [ ] Tagging/grouping system for bots (e.g. by OS, location)
- [ ] Basic anti-debug & evasion in agent (sandbox, VM detection)
- [ ] Cross-platform agent (Windows, Linux, MacOS)
- [x] Webcam control
- [x] File exfiltration (`/upload`, `/download`)
- [ ] Keylogging and ransomware included on the agent
- [ ] Alternate C2 channels (Discord, HTTP over CDN, direct Telegram API)
- [ ] Optional web dashboard (clients list, commands, status, etc.)

---

## ⚠️ Disclaimer

This tool is strictly for **educational** and **research** purposes. Unauthorized use against systems you don’t own is **illegal**. Use responsibly in controlled environments.

