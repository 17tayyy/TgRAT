# 🧠 C2OverTG - Telegram-Based Command and Control Server

**C2OverTG** is a multi-client *Command & Control* (C2) framework that uses a **Telegram group with forum topics** as a communication channel between a central server and its agents. Each agent creates a dedicated thread for interaction, while the general channel allows global control of all bots.

> ⚠️ For educational purposes only.

---

## 🚀 Features

### ✅ Communication
- Encrypted end-to-end using **AES-256-CBC**
- Socket-based communication (TCP)
- Commands and responses are structured and encoded

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

### In the main thread (global)
- `/sendall <command>` – Execute command on all clients
- `/statusall` – Check connection status for all clients
- `/shutdown` – Gracefully shut down the C2 server

---

## 🛠 Requirements

- Python 3.8+
- Python packages:
  - `pyTelegramBotAPI`
  - `pycryptodome`
  - `mss`
  - `Pillow`
  - `sqlite3` (built-in)
- A Telegram bot token
- A Telegram group with **forum topics** enabled

---

## 📋 TODO / Roadmap

- [ ] Improve bot disconnection detection (ping-pong, heartbeat, etc.)
- [ ] Agent persistence (registry, scheduled tasks)
- [ ] Auto-update feature for agents
- [ ] Authentication system for agents (pre-shared key or signature)
- [ ] Command logging system (file or DB)
- [ ] Tagging/grouping system for bots (e.g. by OS, location)
- [ ] Basic anti-debug & evasion in agent (sandbox, VM detection)
- [ ] Cross-platform agent (Windows, Linux, MacOS)
- [ ] Webcam control
- [x] File exfiltration (`/upload`, `/download`)
- [ ] Keylogging and ransomware included on the agent
- [ ] Alternate C2 channels (Discord, HTTP over CDN, direct Telegram API)
- [ ] Optional web dashboard (clients list, commands, status, etc.)
- [ ] Runtime plugin loading (dynamic agent modules)

---

## ⚠️ Disclaimer

This tool is strictly for **educational** and **research** purposes. Unauthorized use against systems you don’t own is **illegal**. Use responsibly in controlled environments.

