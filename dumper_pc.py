import frida
import sys
import os
import subprocess
import threading
import urllib.request
import zipfile
import io

# ======== CONFIGURATION ========
DUMPER_DIR = "il2cppdumper"
IL2CPPDUMPER_PATH = os.path.join(DUMPER_DIR, "Il2CppDumper.exe")
# ===============================

# Global variables populated dynamically
dumps_dir = ""
output_dir = ""
base_address_final = ""
done_event = threading.Event()

# --- AUTO-DOWNLOAD SYSTEM (v6.7.46 - .NET 8) ---
def setup_il2cppdumper():
    if os.path.exists(IL2CPPDUMPER_PATH):
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
            
        print("[+] PC: Il2CppDumper (NET 8) installed successfully.\n")
    except Exception as e:
        print(f"[-] Error downloading Il2CppDumper: {e}")
        sys.exit(1)

setup_il2cppdumper()

# --- FRIDA RECEIVER SYSTEM ---
def on_message(message, data):
    global base_address_final, dumps_dir
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
                f.seek(payload['offset'])
                f.write(data)
                
        elif payload['type'] == 'finish_file':
            print(f"[+] PC: File {payload['name']} assembled successfully!")
            
        elif payload['type'] == 'done':
            base_address_final = payload['base_addr']
            done_event.set()

# --- MAIN PROCESS ---
try:
    print("[*] Connecting to USB device...")
    device = frida.get_usb_device()
    front_app = device.get_frontmost_application()
    
    if not front_app:
        print("[-] Error: Please open the game on your device screen.")
        sys.exit(1)
        
    app_id = front_app.identifier # Magically captures the package name (e.g., com.YoStarJP.Arknights)
    print(f"[*] Infiltrating: {front_app.name} [{app_id}] (PID: {front_app.pid})...")
    
    # Create dynamic folders using the application ID
    dumps_dir = os.path.join("dumps", app_id)
    output_dir = os.path.join("DummyDlls", app_id)
    os.makedirs(dumps_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    session = device.attach(front_app.pid)
except Exception as e:
    print(f"[-] Connection error: {e}")
    sys.exit(1)

with open("agent.js", "r", encoding="utf-8") as f:
    script_code = f.read()

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print("[*] Link established. Mining memory...\n")

# Wait until the device sends the 'done' signal
done_event.wait()
session.detach()

# ==========================================
# 3. IL2CPPDUMPER AUTO-DUMP
# ==========================================
print(f"\n==================================================")
print(f"[*] STARTING IL2CPPDUMPER FOR: {app_id}")
print(f"[*] Injecting Base Address: {base_address_final}")
print(f"==================================================\n")

try:
    # Dynamic paths for the dumper
    lib_path = os.path.join(dumps_dir, "libil2cpp.so")
    meta_path = os.path.join(dumps_dir, "global-metadata.dat")
    
    subprocess.run(
        [IL2CPPDUMPER_PATH, lib_path, meta_path, output_dir],
        # Double \n feeds the address and skips the "Press any key to exit" prompt
        input=f"{base_address_final}\n\n", 
        text=True,
        stderr=subprocess.DEVNULL # Mutes cosmetic exceptions at the end
    )
    print(f"\n[+] AUTOMATION 100% COMPLETED!")
    print(f"[+] Raw dumps are located in: /dumps/{app_id}/")
    print(f"[+] Perfect DummyDlls are located in: /DummyDlls/{app_id}/")
except Exception as e:
    print(f"\n[-] Critical error running Il2CppDumper: {e}")