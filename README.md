# sagapi-dumper

Automated tool for the extraction and processing of Unity binaries (`libil2cpp.so` and `global-metadata.dat`) directly from the RAM of any Arknights client, utilizing Frida and Il2CppDumper. Designed to be version-agnostic and server-agnostic. Feeds `sagapi-flatbuffers`.

## System Requirements

**On the Computer (PC):**

* **Python 3.x**
* **.NET 8 Runtime/SDK:** Required to run the automated version of Il2CppDumper (v6.7.46).
* USB drivers installed and USB Debugging (ADB) enabled.

**On the Android Device:**

* **Root Access:** Mandatory to bypass system memory protections.
* **Termux** (or any equivalent terminal emulator).
* **frida-server:** Must be installed and running with root privileges, compatible with the Frida version on the PC (frida==17.7.3 pinned).
* The desired Arknights client (Global, CN, TW, etc.).

## Important Notes on Operation

* **Frontmost Injection:** The script automatically detects and injects into the application currently on the device's screen. The game must remain open and visible during the connection process.
* **No OBB Required:** If your sole objective is to extract the binaries, you do not need the complete game data. Installing the base APK is sufficient — the `libil2cpp.so` and `global-metadata.dat` libraries are already loaded and decrypted in RAM at launch.
* **Anti-Detection:** A best-effort anti-detection layer (`ANTI_DETECT = true` in `agent.js`) hides Frida's presence from the game's own checks. It is fail-open (never crashes the dump if a symbol is missing).

## Important Gotchas

### Frida 17 API change
The static `Module.findExportByName(null, ...)` form **no longer exists** in Frida 17 — calling it throws `TypeError: not a function`, silently disabling the entire anti-detect layer. The script uses `Process.findModuleByName("libc.so").findExportByName(name)` instead.

### Frida server port
`FRIDA_PORT` in `dumper_pc.py` controls how the PC connects to `frida-server`. The default in this repo is `37042`; set it to the port frida-server actually listens on (`27042` for a stock frida-server, or the port passed with `-l 0.0.0.0:<port>`).

### Il2CppDumper console keypress
**`RequireAnyKey: false` must be set in `il2cppdumper/config.json`.** When `true`, Il2CppDumper calls `Console.ReadKey()` at the end, which throws `InvalidOperationException` when stdin is redirected by `subprocess.run(input=...)`. `setup_il2cppdumper()` patches this automatically after downloading the tool.

### Metadata handling
`global-metadata.dat` is dumped exactly as it is in RAM. Before running Il2CppDumper, `normalize_metadata()` fixes the magic/version and converts non-standard layouts (e.g. the protected TW builds with 92-byte `typeDefinition` records) to the v29 layout the bundled dumper understands; when needed, it patches the dumper with `dnfile`. If the in-RAM scan fails, the PC recovers the metadata over ADB from `DUMP_APK`, the file extracted by the game, or the installed APK.

## Usage Instructions

### Step 1: Android Device Preparation

1. Open Termux and request superuser privileges by executing `su`.
2. Execute `frida-server` and leave it running in the background:
   ```bash
   frida-server -l 0.0.0.0:<custom-port>
   ```
   (Use stock port `27042` if you do not need to change it.)
3. Open the desired Arknights client and keep it on the main screen.
4. Connect the device to your PC via USB cable.

#### Note: works with [magisk-frida](https://github.com/ViRb3/magisk-frida) too!

### Step 2: PC Preparation

1. Clone or download this repository to your local machine.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Step 3: Running the Tool

1. With the game open on your phone's screen, execute:
   ```bash
   python dumper_pc.py
   ```
2. The script performs the entire process automatically:
   * Checks/downloads Il2CppDumper v6.7.46 (auto-patches `config.json`).
   * Connects to the Arknights process via Frida.
   * Extracts memory blocks from RAM and transfers them to the PC.
   * Recovers the metadata over ADB if the in-RAM scan fails.
   * Executes Il2CppDumper with the correct memory base address.

## Configuration

Edit `dumper_pc.py` (CONFIGURATION section) to adjust:

| Variable         | Default | Description                                                          |
| ---------------- | ------- | -------------------------------------------------------------------- |
| `FRIDA_PORT`     | `37042` | Port frida-server listens on. Set to `27042` for stock frida-server. |
| `MAX_ATTEMPTS`   | `5`     | Number of retry attempts if the dump fails.                          |
| `WAIT_TIMEOUT_S` | `300`   | Seconds to wait for the `done` signal per attempt.                   |

`DUMP_APK` (environment variable) can point to an APK already on the PC; it is used as the first metadata-recovery source when the in-RAM scan fails.

## Output Structure

The script is built with multi-region support. Upon successful completion:

* `./dumps/[Package_Name]/`: Raw and assembled dumps extracted from RAM (`libil2cpp.so`, `global-metadata.dat`).
* `./DummyDlls/[Package_Name]/`: Final directory containing the restored DLL files, schemas, and code structures ready for reverse engineering or data-mining.
  * `DummyDll/*.dll`, `manifest.json` — generated output.
  * `dump.cs`, `il2cpp.h`, `script.json`, `stringliteral.json` — gitignored.

#### Thanks to [Perfare's Il2CppDumper](https://github.com/Perfare/Il2CppDumper/releases)
