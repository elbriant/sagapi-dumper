import frida
import sys
import os

# Git Bash / MSYS2 pipes stdout, making Python block-buffer prints so the log
# appears in late bursts instead of in real time. Force line buffering so the
# user sees each agent message the moment it arrives (matches real-time order).
reconfigure = getattr(sys.stdout, "reconfigure", None)
if callable(reconfigure):
    reconfigure(line_buffering=True)
import subprocess
import threading
import urllib.request
import zipfile
import io
import json
import shutil
from datetime import datetime, timezone

# ======== CONFIGURATION ========
DUMPER_DIR = "il2cppdumper"
IL2CPPDUMPER_PATH = os.path.join(DUMPER_DIR, "Il2CppDumper.exe")
# Puerto en el que frida-server escucha en el dispositivo.
# - 27042 = valor por defecto (sin argumento -l al lanzar frida-server).
# - Si lanzas frida-server con `-l 0.0.0.0:<port>`, pon aquí ESE puerto.
FRIDA_PORT = 37042
# ===============================

# Global variables populated dynamically
dumps_dir = ""
output_dir = ""
base_address_final = ""
app_id = ""
done_event = threading.Event()

# --- AUTO-DOWNLOAD SYSTEM (v6.7.46 - .NET 8) ---
def ensure_require_any_key_false():
    """El config.json que viene del zip tiene RequireAnyKey: true, lo que
    hace que Il2CppDumper llame a Console.ReadKey() al final y falle cuando
    stdin está redirigido por subprocess.run(input=). Lo ponemos en false."""
    cfg_path = os.path.join(DUMPER_DIR, "config.json")
    if not os.path.exists(cfg_path):
        return
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        if cfg.get("RequireAnyKey") != False:
            cfg["RequireAnyKey"] = False
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print("[*] PC: Patched config.json RequireAnyKey=false.")
    except Exception as e:
        print(f"[-] Warning: could not patch config.json: {e}")


def setup_il2cppdumper():
    if os.path.exists(IL2CPPDUMPER_PATH):
        ensure_require_any_key_false()
        return

    print("[*] PC: Il2CppDumper not found. Downloading version v6.7.46 (NET 8)...")
    download_url = "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-win-v6.7.46.zip"
    
    try:
        print(f"[*] PC: Downloading from {download_url} ...")
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            zip_data = response.read()
            
        print("[*] PC: Extracting files directly to memory...")
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            z.extractall(DUMPER_DIR)
        
        ensure_require_any_key_false()
        
        print("[+] PC: Il2CppDumper (NET 8) installed successfully.\n")
    except Exception as e:
        print(f"[-] Error downloading Il2CppDumper: {e}")
        sys.exit(1)

setup_il2cppdumper()

def ensure_adb():
    """Inicia el demonio de ADB si no está corriendo y verifica que haya un dispositivo."""
    try:
        subprocess.run(["adb", "start-server"], check=True, capture_output=True)
    except FileNotFoundError:
        print("[-] ADB not found in PATH. Install platform-tools and retry.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[-] Could not start ADB daemon: {e}")
        sys.exit(1)

    out = subprocess.run(["adb", "devices"], check=True, capture_output=True, text=True)
    devices = [line for line in out.stdout.splitlines()[1:] if line.strip() and "unauthorized" not in line]
    if not devices:
        print("[-] No devices available over ADB. Plug in the phone and enable USB debugging.")
        sys.exit(1)
    print(f"[*] ADB daemon ready. Device found: {devices[0]}")

def get_app_version(app_id):
    """Consulta la versión del APK directamente usando ADB"""
    try:
        # Pide a Android que nos de la información del paquete
        out = subprocess.check_output(f"adb shell dumpsys package {app_id}", shell=True, text=True)
        for line in out.split('\n'):
            if "versionName=" in line:
                return line.split('=')[1].strip()
    except Exception:
        pass
    return "Unknown"

# --- FRIDA RECEIVER SYSTEM ---

# --- MAIN PROCESS ---
import time

MAX_ATTEMPTS = 5
WAIT_TIMEOUT_S = 300

def get_frida_device():
    """Conecta respetando FRIDA_PORT.
    - 27042: `frida.get_usb_device()` normal (adb lo reenvía por defecto).
    - Otro puerto: hace `adb forward tcp:<port> tcp:<port>` y se conecta a localhost.
    """
    if FRIDA_PORT == 27042:
        return frida.get_usb_device()
    try:
        subprocess.run(
            ["adb", "forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}"],
            check=True, capture_output=True, timeout=30
        )
    except Exception as e:
        print(f"[-] Could not set up adb forward for FRIDA_PORT {FRIDA_PORT}: {e}")
        sys.exit(1)
    return frida.get_device_manager().add_remote_device(f"127.0.0.1:{FRIDA_PORT}")

def relaunch_app(app_id):
    print(f"[*] Relaunching {app_id} via adb...")
    try:
        subprocess.run(
            ["adb", "shell", "monkey", "-p", app_id, "-c", "android.intent.category.LAUNCHER", "1"],
            check=False, capture_output=True, timeout=60
        )
    except Exception as e:
        print(f"[-] Warning: could not relaunch app: {e}")
    print("[*] Waiting for the game to come to the foreground...")
    time.sleep(10)

def attach_and_dump(device):
    """Intenta un dump completo; devuelve True si llegó la señal 'done' y el metadato es válido."""
    global base_address_final, dumps_dir, output_dir, app_id
    done_event.clear()
    metadata_ok = [False]

    def on_message(message, data):
        nonlocal metadata_ok
        global base_address_final
        if message['type'] == 'send':
            payload = message['payload']

            if payload['type'] == 'log':
                print(payload['msg'])

            elif payload['type'] == 'init_file':
                filename = os.path.join(dumps_dir, payload['name'])
                print(f"[*] PC: Creating file {payload['name']} ({payload['size'] / 1024 / 1024:.2f} MB)")
                with open(filename, "wb") as f:
                    f.truncate(payload['size'])

            elif payload['type'] == 'write_chunk':
                filename = os.path.join(dumps_dir, payload['name'])
                with open(filename, "r+b") as f:
                    size = os.path.getsize(filename)
                    offset = payload['offset']
                    if 0 <= offset <= size:
                        f.seek(offset)
                        f.write(data)
                    else:
                        print(f"[!] PC: ignoring write_chunk with invalid offset {offset} for {payload['name']}")

            elif payload['type'] == 'finish_file':
                print(f"[+] PC: File {payload['name']} assembled successfully!")

            elif payload['type'] == 'done':
                base_address_final = payload['base_addr']
                metadata_ok[0] = payload.get('metadata_ok', False)

                # --- Manifest.json ---
                app_version = get_app_version(app_id)
                meta_version = payload.get('metadata_version', 'Unknown')

                manifest_data = {
                    "package_name": app_id,
                    "app_version": app_version,
                    "metadata_version": meta_version,
                    "libil2cpp_base": base_address_final,
                    "dump_date": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                }

                manifest_path = os.path.join(output_dir, "manifest.json")
                with open(manifest_path, "w", encoding="utf-8") as m:
                    json.dump(manifest_data, m, indent=4)

                print(f"[*] PC: manifest.json generated (App: v{app_version} | Meta: v{meta_version}).")
                # -----------------------------------------

                done_event.set()

    try:
        front_app = device.get_frontmost_application()
        if not front_app:
            print("[-] No app on screen. Open the game first.")
            return False

        app_id = front_app.identifier
        print(f"[*] Infiltrating: {front_app.name} [{app_id}] (PID: {front_app.pid})...")

        dumps_dir = os.path.join("dumps", app_id)
        output_dir = os.path.join("DummyDlls", app_id)
        os.makedirs(dumps_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        session = device.attach(front_app.pid)

        explicitly_detached = [False]

        def on_detached(reason, crash):
            if explicitly_detached[0]:
                pass  # our own detach, ignore
            elif base_address_final == "":
                print(f"[-] Session detached ({reason}) — the app died before finishing. Will retry.")
            else:
                print(f"[-] Session detached ({reason}) — app died after dump started. Will retry.")
            done_event.set()

        session.on('detached', on_detached)

        with open("agent.js", "r", encoding="utf-8") as f:
            script_code = f.read()

        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        print("[*] Link established. Mining memory...\n")

        # Wait for either the 'done' signal or the session being killed
        done_event.wait(timeout=WAIT_TIMEOUT_S)
        try:
            explicitly_detached[0] = True
            session.detach()
        except Exception:
            pass
        return base_address_final != "" and metadata_ok[0]
    except Exception as e:
        print(f"[-] Error during dump attempt: {e}")
        return False

try:
    ensure_adb()
    print("[*] Connecting to USB device...")

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"\n[*] ===== ATTEMPT {attempt}/{MAX_ATTEMPTS} =====")
        device = get_frida_device()  # fresh handle each try (frida-server may have died)
        if attach_and_dump(device):
            print(f"[+] Dump completed on attempt {attempt}.")
            break
        if attempt < MAX_ATTEMPTS:
            print(f"[-] Dump failed on attempt {attempt}. Relaunching the game...")
            if app_id:
                relaunch_app(app_id)
    else:
        print("[-] All attempts failed. Check the device, game state, and frida-server.")
        sys.exit(1)
except Exception as e:
    print(f"[-] Connection error: {e}")
    sys.exit(1)

# ==========================================
# 3. IL2CPPDUMPER AUTO-DUMP
# ==========================================
print(f"\n==================================================")
print(f"[*] STARTING IL2CPPDUMPER FOR: {app_id}")
print(f"[*] Injecting Base Address: {base_address_final}")
print(f"==================================================\n")

# dll folder cleanup (i dont know why sometimes dont work without this)
dll_subfolder = os.path.join(output_dir, "DummyDll")
if os.path.exists(dll_subfolder):
    try:
        shutil.rmtree(dll_subfolder)
        print("[*] PC: Old folder cleaned. Clean slate ready.")
    except Exception as e:
        print(f"[-] Warning: Could not clean the old folder: {e}")

# Validate that the dumped files are structurally sound before
# invoking Il2CppDumper. A stale/empty file from a failed prior
# attempt would otherwise produce bogus schemas.
lib_path = os.path.join(dumps_dir, "libil2cpp.so")
meta_path = os.path.join(dumps_dir, "global-metadata.dat")

if not os.path.exists(lib_path) or os.path.getsize(lib_path) < 10 * 1024 * 1024:
    print("[-] Aborting Il2CppDumper: libil2cpp.so is missing or too small.")
    sys.exit(1)

if not os.path.exists(meta_path):
    print("[-] Aborting Il2CppDumper: global-metadata.dat is missing.")
    sys.exit(1)

with open(meta_path, "rb") as f:
    magic = f.read(8)
if magic != b'\xaf\x1b\xb1\xfa\x1d\x00\x00\x00':
    print("[-] Aborting Il2CppDumper: global-metadata.dat has an invalid header "
          f"(got {magic.hex()}, expected af1bb1fa1d00000000). Stale data.")
    sys.exit(1)

print(f"[*] Running Il2CppDumper ({IL2CPPDUMPER_PATH})...")
try:
    proc = subprocess.run(
        [IL2CPPDUMPER_PATH, lib_path, meta_path, output_dir],
        input=f"{base_address_final}\n\n",
        text=True,
        capture_output=True,
    )
    if proc.stdout:
        print(proc.stdout, end='')
    if proc.returncode != 0:
        print(f"\n[-] Il2CppDumper exited with code {proc.returncode}.")
        if proc.stderr:
            print(f"[-] stderr: {proc.stderr}")
        sys.exit(1)
except Exception as e:
    print(f"\n[-] Critical error running Il2CppDumper: {e}")
    sys.exit(1)

print(f"\n[+] AUTOMATION 100% COMPLETED!")
print(f"[+] Raw dumps are located in: /dumps/{app_id}/")
print(f"[+] Perfect DummyDlls are located in: /DummyDlls/{app_id}/")