# RL Name Spoofer (`backup.py`)

A Windows-only GUI tool that uses a local HTTP proxy (mitmproxy) to spoof your Rocket League display name by intercepting Epic Games / Psyonix account API traffic. The app is built with Tkinter + CustomTkinter and is designed to be packaged as a standalone executable.

> Use at your own risk. Intercepting and modifying network traffic may violate game or platform Terms of Service. This project is for educational and personal use only.

---

## Features

- Spoofs the Epic/Rocket League `displayName` field in account API responses
- Simple GUI to enter and update your spoofed name
- Auto-detects when `RocketLeague.exe` is running and auto-attaches/detaches the proxy
- Optional “Run automatically on Startup” via Windows Task Scheduler
- First‑time setup flow that helps install the mitmproxy root certificate
- System tray support (minimize to tray) when `pystray` + `Pillow` are installed
- Persistent configuration and logs stored under `%APPDATA%\RLNameSpoofer`

---

## Requirements

- **OS:** Windows 10/11 (required for WinRegistry, Task Scheduler, and process checks)
- **Python:** 3.8+ (recommended)
- **Dependencies:** managed via `requirements.txt`:
  - `customtkinter`
  - `mitmproxy`
  - `opencv-python`
  - `pystray`
  - `cryptography`
  - `Pillow`

You also need the mitmproxy CA bundle file used by the script (by default: `mitmproxy-ca-cert.p12`) in the same directory as `backup.py` or bundled when packaging.

---

## Installation

1. **Clone or download this repository**

   ```bash
   git clone <your-repo-url>
   cd mod-key-system-checkip
   ```

2. **Create and activate a virtual environment (optional but recommended)**

   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure the mitmproxy certificate bundle is present**

   - Place `mitmproxy-ca-cert.p12` next to `backup.py`, or
   - Adjust `PFX_FILENAME` in `install_cer()` inside `backup.py` if you use a different file name or password.

---

## Usage

From the project directory:

```bash
python backup.py
```

On startup, the app:

1. Runs `install_cer()` to ensure the mitmproxy certificate is imported into the **Current User → Trusted Root** store.
2. Starts the CustomTkinter GUI (`SpooferGUI`).

### Typical flow

1. **First-time setup**
   - Follow the in-app “BEGIN SETUP” flow.
   - The app will start the proxy and open `http://mitm.it` in your browser so you can install the mitmproxy certificate.
   - Once done, finish the setup from the GUI.

2. **Spoofing your name**
   - Enter your desired display name in the main window.
   - Click **ACTIVATE** to start the proxy.
   - Launch Rocket League; the tool will intercept account responses and rewrite your `displayName`.

3. **Auto-manage mode (optional)**
   - Enable the **auto-scan / auto-manage** option to let the tool:
     - Watch for `RocketLeague.exe` starting/stopping.
     - Automatically start/stop the proxy accordingly.
   - Use **“Run automatically on Startup”** to create a Windows Task Scheduler entry so the app runs in the background at login (may require elevated permissions).

4. **System tray**
   - Minimizing / closing to tray uses `pystray` to provide:
     - A tray icon
     - “Show” and “Quit” menu items
   - If `pystray` or `Pillow` are missing, the app falls back to normal minimize behavior.

---

## Configuration & Logs

On Windows, user data is stored under:

- Config directory: `%APPDATA%\RLNameSpoofer`
- Files:
  - `config.json` – last spoofed name, auto-scan preference, etc.
  - `mitmproxy_app_log.txt` – debug log (stdout/stderr redirected)
  - `first_run_flag.txt` – tracks whether first-time setup is completed

You can safely delete these files to reset settings; they will be recreated as needed.

---

## Building a Standalone EXE (Optional)

This project is designed to be bundled with PyInstaller. A typical command might look like:

```bash
pyinstaller --onefile --noconsole backup.py
```

You may want to:

- Include `mitmproxy-ca-cert.p12` as bundled data (`--add-data`).
- Use or adapt the existing `.spec` files in the repo for more refined packaging.

Refer to PyInstaller’s documentation for full packaging options.

---

## Troubleshooting

- **Mitmproxy import errors**
  - Ensure `mitmproxy` is installed: `pip install mitmproxy`
- **Certificate not detected**
  - Re-run the in-app setup or click the “Re-run Setup” button in the menu.
  - Confirm the mitmproxy CA appears in the Windows Trusted Root store (Current User).
- **Port already in use**
  - The app listens on `127.0.0.1:6969` by default. Close other proxies or change the port in `backup.py` (`MITMPROXY_LISTEN_PORT`).
- **No tray icon**
  - Install `pystray` and `Pillow`: `pip install pystray Pillow`

---

## Disclaimer

This tool modifies network traffic for Rocket League / Epic services on your local machine. It is not affiliated with or endorsed by Psyonix, Epic Games, or any other company. You are responsible for understanding and complying with all applicable Terms of Service and local laws when using this software.

