# sagapi-dumps

Automated tool for the extraction and processing of Unity binaries (`libil2cpp.so` and `global-metadata.dat`) directly from the RAM of any Arknights client, utilizing Frida and Il2CppDumper.

## System Requirements

To ensure the script functions correctly, the following requirements must be met in both environments:

**On the Computer (PC):**

* **Python 3.x**
* **.NET 8 Runtime/SDK:** Strictly required to run the automated version of Il2CppDumper (v6.7.46).
* USB drivers installed and USB Debugging (ADB) enabled for device connection.

**On the Android Device:**

* **Root Access:** Mandatory to bypass system memory protections.
* **Termux** (or any equivalent terminal emulator).
* **frida-server:** Must be installed on the device, running with root privileges, and compatible with the Frida version installed on the PC.
* The desired Arknights client (Global, CN, TW, etc.).

## Important Notes on Operation

* **Frontmost Injection:** The script is designed to automatically detect and inject into the application currently active on the device's screen. The game must remain open and visible during the connection process.
* **Storage Savings (No OBB Required):** If your sole objective is to extract the binaries for analysis, you do not need to download the complete game data. Installing the base APK is sufficient. Upon launching, the game will display a connection or resource download error, but by that point, the `libil2cpp.so` and `global-metadata.dat` libraries will already have been loaded and decrypted in the RAM, ready for extraction.

## Usage Instructions

Follow these steps carefully to perform the memory dump:

### Step 1: Android Device Preparation

1. Open Termux and request superuser privileges by executing `su`.
2. Execute the `frida-server` binary and leave it running in the background.
3. Open the desired Arknights client and keep it on the main screen.
4. Connect the device to your PC via a USB cable.

#### Note: works with [magisk-frida](https://github.com/ViRb3/magisk-frida) too!

### Step 2: PC Preparation

1. Clone or download this repository to your local machine.
2. Open a terminal in the root of the project and run the following command to install the Python dependencies:
```bash
pip install -r requirements.txt

```

### Step 3: Running the Tool

1. With the game open on your phone's screen, execute the main script on your PC:
```bash
python dumper_pc.py

```

2. The script will perform the following process completely automatically:
* Check for and download the correct version of Il2CppDumper if it is not found on the system.
* Connect to the Arknights process via Frida.
* Extract the clean memory blocks from the RAM and transfer them to the PC.
* Execute Il2CppDumper, passing it the exact memory base address.

## Output Structure

The script is built with multi-region support. Upon successful completion, it will generate a folder ecosystem dynamically organized according to the extracted client's package name (e.g., `com.YoStarJP.Arknights`):

* `./dumps/[Package_Name]/`: Directory containing the raw and assembled dumps extracted directly from RAM (`libil2cpp.so` and `global-metadata.dat`).
* `./DummyDlls/[Package_Name]/`: Final directory containing the restored DLL files, schemas, and code structures ready for reverse engineering or data-mining.

#### Thanks to [Perfare's iL2CppDumper](https://github.com/Perfare/Il2CppDumper/releases)