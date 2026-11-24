import platform
import frida
import sys
import os

# Git Bash / MSYS2 pipes stdout, making Python block-buffer prints so the log
# appears in late bursts instead of in real time. Force line buffering so the
# user sees each agent message the moment it arrives (matches real-time order).
# errors="replace" además garantiza que un nombre de app no-ASCII (アークナイツ,
# nombres chinos de otros servers, ...) NUNCA lance UnicodeEncodeError y mate
# el intento entero cuando la consola Windows usa una codepage como cp1252.
reconfigure = getattr(sys.stdout, "reconfigure", None)
if callable(reconfigure):
    try:
        sys.stdout.reconfigure(line_buffering=True, errors="replace") # type: ignore
        sys.stderr.reconfigure(errors="replace") # type: ignore
    except (ValueError, OSError):
        sys.stdout.reconfigure(line_buffering=True) # type: ignore
import subprocess
import struct
import threading
import tempfile
import urllib.request
import zipfile
import io
import json
import shutil
from datetime import datetime, timezone

# ======== CONFIGURATION ========
DUMPER_DIR = "il2cppdumper"
FRIDA_PORT = 37042
IS_LINUX = platform.system() == "Linux"
IL2CPPDUMPER_PATH = os.path.join(DUMPER_DIR, "Il2CppDumper.dll" if IS_LINUX else "Il2CppDumper.exe")
# Puerto en el que frida-server escucha en el dispositivo.
# - 27042 = valor por defecto (sin argumento -l al lanzar frida-server).
# - Si lanzas frida-server con `-l 0.0.0.0:<port>`, pon aquí ESE puerto.
# ===============================

# Global variables populated dynamically
dumps_dir = ""
output_dir = ""
base_address_final = ""
app_id = ""
done_event = threading.Event()
# Versión de il2cpp que se le fuerza a Il2CppDumper (None = la que deduce del
# propio metadata). La fija normalize_metadata() cuando el binario y el
# metadata tienen formatos distintos.
force_il2cpp_version = None

# --- AUTO-DOWNLOAD SYSTEM (v6.7.46 - .NET 8) ---
def ensure_il2cppdumper_config(force_version=None):
    """Parchea il2cppdumper/config.json.

    1) RequireAnyKey=true hace que Il2CppDumper llame a Console.ReadKey() al
       final y falle cuando stdin está redirigido por subprocess.run(input=).
    2) ForceIl2CppVersion/ForceVersion permiten interpretar el binario con
       una versión distinta de la del metadata. Hace falta cuando el metadata
       hay que presentarlo como v24.x para conservar el stride real del
       typeDefinition (ver normalize_metadata())."""
    cfg_path = os.path.join(DUMPER_DIR, "config.json")
    if not os.path.exists(cfg_path):
        return
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        changed = False
        if cfg.get("RequireAnyKey") != False:
            cfg["RequireAnyKey"] = False
            changed = True
        want_force = force_version is not None
        if cfg.get("ForceIl2CppVersion") != want_force:
            cfg["ForceIl2CppVersion"] = want_force
            changed = True
        if want_force and cfg.get("ForceVersion") != force_version:
            cfg["ForceVersion"] = force_version
            changed = True
        if changed:
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print("[*] PC: Patched config.json (RequireAnyKey=false"
                  + (f", ForceIl2CppVersion={force_version}" if want_force else "")
                  + ").")
    except Exception as e:
        print(f"[-] Warning: could not patch config.json: {e}")


def setup_il2cppdumper():
    if os.path.exists(IL2CPPDUMPER_PATH):
        ensure_il2cppdumper_config()
        return

    if IS_LINUX:
        download_url = "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net7-v6.7.46.zip"
    else:
        download_url = "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-win-v6.7.46.zip"

    try:
        print(f"[*] PC: Downloading from {download_url} ...")
        req = urllib.request.Request(download_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            zip_data = response.read()

        print("[*] PC: Extracting files directly to memory...")
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            z.extractall(DUMPER_DIR)

        ensure_il2cppdumper_config()

        print("[+] PC: Il2CppDumper installed successfully.\n")
    except Exception as e:
        print(f"[-] Error downloading Il2CppDumper: {e}")
        sys.exit(1)

setup_il2cppdumper()

# --- PARCHE DEL STRIDE DEL typeDefinitions (builds con layout propio) ---
# Il2CppDumper lee Il2CppTypeDefinition con el tamano que deduce de la version
# del metadata (88 bytes en v29 / 92 bytes en v24.2-24.5, por byrefTypeIndex).
# El build TW 37.x usa un typeDefinition de 92 bytes con el binario en v29: si
# se presenta el metadata como v24.x se pierden los CustomAttributes (el
# DummyAssemblyGenerator usa la ruta de atributos de il2cpp v29, que necesita
# attributeData/attributeDataRange, y el constructor de Metadata solo los lee
# si el metadata es >= v29). Presentandolo como v29 con 92 bytes se conserva
# TODO el comportamiento v29 (atributos, vtable, ...), pero para eso hay que
# hacer que SizeOf(Il2CppTypeDefinition) devuelva 92 en v29, es decir, que el
# campo byrefTypeIndex se lea en v29 aunque su [Version(Max = 24.5)] no lo
# incluya.
#
# OJO: el blob de ese atributo esta COMPARTIDO (deduplicacion del heap #Blob)
# con Il2CppCodeRegistration.customAttributeCount/customAttributeGenerators y
# con Il2CppGenericClass.typeDefinitionIndex. Reescribirlo (p.ej. a Max = 40)
# hace que esos campos tambien se lean en v29 y desplaza Il2CppCodeRegistration:
# Il2Cpp.Init muere con "Sequence contains no matching element". Por eso NO se
# toca el blob: VersionAttribute es AllowMultiple y basta con repuntar SOLO la
# fila CustomAttribute de byrefTypeIndex a otro blob VersionAttribute ya
# existente cuyo rango incluya v29 (se reutiliza uno de los [Version(Min = 29)]).
# El parche vive solo en la copia descargada; se guarda un .orig y se restaura
# cuando no hace falta.
DUMPER_ORIG_SUFFIX = ".orig"
VERSION_ATTR_NAME = "VersionAttribute"


def _version_attr_range(blob):
    """Decodifica un blob de VersionAttribute: (min, max) o None si no es un
    blob valido (prolog 01 00, solo named args Min/Max R8, sin bytes de sobra)."""
    if len(blob) < 4 or blob[0:2] != b"\x01\x00":
        return None
    count = int.from_bytes(blob[2:4], "little")
    i = 4
    mn, mx = 0.0, 99.0
    try:
        for _ in range(count):
            i += 1                      # 0x53/0x54: atributo de campo o propiedad
            etype = blob[i]
            i += 1
            nlen = blob[i]
            i += 1
            name = blob[i:i + nlen].decode("ascii")
            i += nlen
            if name not in ("Min", "Max"):
                return None
            if etype == 0x0D:           # R8 (double)
                val = struct.unpack_from("<d", blob, i)[0]
                i += 8
            elif etype == 0x0C:         # R4 (float)
                val = struct.unpack_from("<f", blob, i)[0]
                i += 4
            else:
                return None
            if name == "Min":
                mn = val
            else:
                mx = val
    except (IndexError, struct.error, UnicodeDecodeError):
        return None
    if i != len(blob):
        return None
    return mn, mx


def _managed_assembly_span(data):
    """(base, size) del ensamblado .NET que define Il2CppTypeDefinition.

    En Linux el objetivo ya es Il2CppDumper.dll; en Windows es el .exe
    single-file, que lleva Il2CppDumper.dll EMBEBIDO como un PE completo. Se
    localiza por la cadena de la tabla #Strings y se recorta con la tabla de
    secciones del PE, sin depender del manifiesto del bundle."""
    pos = data.find(b"byrefTypeIndex\x00")
    if pos < 0:
        return None
    m = data.rfind(b"MZ", 0, pos)
    while m >= 0:
        try:
            e_lfanew = struct.unpack_from("<I", data, m + 0x3C)[0]
            if 0 < e_lfanew < 0x1000 and data[m + e_lfanew:m + e_lfanew + 4] == b"PE\0\0":
                coff = m + e_lfanew + 4
                nsec = struct.unpack_from("<H", data, coff + 2)[0]
                opt_size = struct.unpack_from("<H", data, coff + 16)[0]
                sh = coff + 20 + opt_size
                end = 0
                for i in range(nsec):
                    raw_size = struct.unpack_from("<I", data, sh + i * 40 + 16)[0]
                    raw_ptr = struct.unpack_from("<I", data, sh + i * 40 + 20)[0]
                    end = max(end, raw_ptr + raw_size)
                if 0 < end <= len(data) - m and m < pos < m + end:
                    return m, end
        except struct.error:
            pass
        m = data.rfind(b"MZ", 0, m)
    return None


def _patch_stride_attribute(data):
    """Hace que byrefTypeIndex se lea en v29 repuntando su CustomAttribute a un
    VersionAttribute existente con rango >= 29. Devuelve True si parcheo (False
    si ya estaba parcheado). `data` es un bytearray modificado in situ."""
    import dnfile

    span = _managed_assembly_span(data)
    if span is None:
        raise RuntimeError("no se encontro el PE embebido de Il2CppDumper")
    base, size = span
    asm = bytearray(data[base:base + size])
    pe = dnfile.dnPE(data=asm)
    net = pe.net
    mdtables = net.mdtables if net is not None else None
    if mdtables is None:
        raise RuntimeError("el PE embebido de Il2CppDumper no tiene metadata .NET")
    md = mdtables
    typedefs = md.TypeDef
    if typedefs is None:
        raise RuntimeError("el ensamblado de Il2CppDumper no tiene tabla TypeDef")

    # dnfile anota los valores de los heaps como str/bytes, pero en tiempo de
    # ejecucion devuelve objetos con .value; getattr cubre ambas formas.
    def _heap_value(obj):
        return getattr(obj, "value", obj)

    fields = {}
    method_type = {}
    for td in typedefs:
        tname = _heap_value(td.TypeName) if td.TypeName else ""
        for fi in td.FieldList:
            frow = fi.row
            fname = _heap_value(frow.Name) if frow is not None and frow.Name else ""
            fields[fi.row_index] = (tname, fname)
        for mi in td.MethodList:
            method_type[mi.row_index] = tname
    byref_field = next((r for r, v in fields.items()
                        if v == ("Il2CppTypeDefinition", "byrefTypeIndex")), None)
    if byref_field is None:
        raise RuntimeError("Il2CppTypeDefinition.byrefTypeIndex no encontrado")

    ca = md.CustomAttribute
    if ca is None:
        raise RuntimeError("el ensamblado de Il2CppDumper no tiene tabla CustomAttribute")
    byref_row = None
    donors = []
    for r in range(1, ca.num_rows + 1):
        row = ca.get_with_row_index(r)
        picked = _version_attr_range(_heap_value(row.Value))
        if picked is None:
            continue
        ca_type = row.Type
        if ca_type.table is None or method_type.get(ca_type.row_index) != VERSION_ATTR_NAME:
            continue
        parent = row.Parent
        if (parent.table is not None and parent.table.name == "Field"
                and parent.row_index == byref_field):
            byref_row = (row, getattr(row.struct, "Value_BlobIndex"), picked)
        if picked[0] <= 29.0 <= picked[1]:
            donors.append(getattr(row.struct, "Value_BlobIndex"))

    if byref_row is None:
        raise RuntimeError("CustomAttribute de byrefTypeIndex no encontrado")
    row, _orig_index, picked = byref_row
    if picked[0] <= 29.0 <= picked[1]:
        return False                    # ya parcheado en una ejecucion anterior
    if not donors:
        raise RuntimeError("no hay ningun VersionAttribute que incluya v29")

    rel = row.struct.get_field_relative_offset("Value_BlobIndex")
    abs_off = row.struct.get_field_absolute_offset("Value_BlobIndex")
    width = ca.row_size - rel
    data[base + abs_off:base + abs_off + width] = donors[0].to_bytes(width, "little")
    return True


def set_dumper_stride(stride):
    """Parchea (stride=92) o restaura (stride=None) el binario de Il2CppDumper.

    Siempre se parte del .orig para que el parche sea idempotente y para que un
    dump interrumpido no deje el dumper parcheado en la siguiente ejecucion."""
    path = IL2CPPDUMPER_PATH
    bak = path + DUMPER_ORIG_SUFFIX
    if not os.path.exists(path):
        return
    if stride == 92:
        if not os.path.exists(bak):
            shutil.copy2(path, bak)
        with open(path, "rb") as f:
            data = bytearray(f.read())
        try:
            changed = _patch_stride_attribute(data)
        except Exception as e:
            print(f"[-] PC: no se pudo parchear il2cppdumper para stride 92: {e}")
            print("[-] PC: el dump de un layout propio fallara "
                  "(falta dnfile? `pip install -r requirements.txt`)")
            return
        if not changed:
            print("[*] PC: il2cppdumper ya estaba parcheado (typeDefinition de 92 bytes en v29).")
            return
        with open(path, "wb") as f:
            f.write(data)
        print("[*] PC: il2cppdumper parcheado (typeDefinition de 92 bytes en v29).")
    elif os.path.exists(bak):
        shutil.copy2(bak, path)
        print("[*] PC: il2cppdumper restaurado (sin parche de stride).")

# Un parche de una ejecucion anterior interrumpida no debe filtrarse a este dump.
set_dumper_stride(None)

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

# --- METADATA RECOVERY OVER ADB (fallback when agent.js cannot find it in RAM) ---

# ============================================================================
# NORMALIZACION DEL global-metadata.dat
# ============================================================================
# Il2CppDumper 6.7.46 solo entiende los layouts de metadata estandar de
# Unity. Hay builds que usan un layout PROPIO (servidor TW 37.x):
#   * header con el orden de campos de v29 pero pares extra al final (2 en
#     37.7.41), el byte de version a 24 y el magic a 0,
#   * typeDefinition de 92 bytes (v29 con un campo extra en +64) mientras el
#     binario es v29 (88 bytes).
# Ese archivo se presenta como v29 (ver convert_custom_metadata): el stride del
# typeDefinition tiene que coincidir con el que usa el juego en RAM, porque
# Il2CppDumper calcula el indice de cada tipo a partir de la direccion de su
# typeDefinition (typeHandle) en vez de leerlo del metadata. Como v29 lee 88
# bytes por defecto, ademas hay que parchear el dumper (set_dumper_stride).
META_MAGIC = b"\xaf\x1b\xb1\xfa"

# Layout del header v29 (31 pares, 256 bytes) segun Il2CppDumper 6.7.46.
# El layout propio de estos builds ya usa el ORDEN de campos de v29 (mas pares
# extra al final), asi que la conversion no reordena secciones: solo fija el
# header y transforma los registros de typeDefinition (in situ). Ni las
# secciones de atributos ni la de vtableMethods se tocan: el metadata sigue
# siendo v29 de verdad.
V29_HEADER = [
    "stringLiteral", "stringLiteralData", "string", "events", "properties", "methods",
    "parameterDefaultValues", "fieldDefaultValues", "fieldAndParameterDefaultValueData",
    "fieldMarshaledSizes", "parameters", "fields", "genericParameters",
    "genericParameterConstraints", "genericContainers", "nestedTypes", "interfaces",
    "vtableMethods", "interfaceOffsets", "typeDefinitions", "images", "assemblies",
    "fieldRefs", "referencedAssemblies", "attributeData", "attributeDataRange",
    "unresolvedVirtualCallParameterTypes", "unresolvedVirtualCallParameterRanges",
    "windowsRuntimeTypeNames", "windowsRuntimeStrings", "exportedTypeDefinitions",
]

def metadata_pairs(blob):
    """Lee los pares (offset, size) del header del global-metadata.dat."""
    if len(blob) < 0x100:
        return []
    first_off = int.from_bytes(blob[8:12], "little")
    if first_off < 16 or (first_off - 8) % 8:
        return []
    n = (first_off - 8) // 8
    pairs = []
    for i in range(n):
        off = int.from_bytes(blob[8 + i * 8: 12 + i * 8], "little")
        size = int.from_bytes(blob[12 + i * 8: 16 + i * 8], "little")
        pairs.append((off, size))
    return pairs

def metadata_stride(blob, pairs):
    """Stride real del typeDefinition: el que hace que los nameIndex apunten a
    cadenas validas de la tabla de strings. None si no se puede determinar."""
    if len(pairs) < 20:
        return None
    str_off, str_size = pairs[2]
    td_off, td_size = pairs[19]
    if td_size < 88 or str_size == 0:
        return None
    for stride in (88, 92, 96, 104):
        if td_size % stride:
            continue
        ok = True
        for i in range(min(td_size // stride, 400)):
            base = td_off + i * stride
            nm = int.from_bytes(blob[base:base + 4], "little")
            if nm >= str_size:
                ok = False
                break
            end = blob.find(b"\x00", str_off + nm)
            if end < 0 or end - (str_off + nm) > 256:
                ok = False
                break
            if not all(32 <= c < 127 for c in blob[str_off + nm:end]):
                ok = False
                break
        if ok:
            return stride
    return None

def convert_custom_metadata(blob, pairs):
    """Reescribe in situ el layout propio del build al v29 que Il2CppDumper
    entiende con el parche de stride (ver set_dumper_stride).

    El header del juego ya usa el ORDEN de campos de v29 (los pares extra van
    al final), asi que basta fijar magic/version y transformar cada
    typeDefinition para que tenga el orden de v29 CON byrefTypeIndex (que es
    el que lee el dumper parcheado):
        juego: name, ns, byval, declaring, ..., [4 bytes extra en +64], ...
        v29:   name, ns, byval, byref(-1), declaring, ...
    Se conserva el tamano del archivo y no se mueve NINGUNA seccion, asi que
    attributeData/attributeDataRange y sus offsets internos quedan intactos
    (los 2 pares extra del header quedan como relleno: el dumper lee 31)."""
    td_off, td_size = pairs[19]
    stride = 92
    if td_size < stride or td_size % stride:
        raise ValueError(f"typeDefinitions invalido ({td_size} bytes)")
    out = bytearray(blob)
    out[0:4] = META_MAGIC
    out[4:8] = (29).to_bytes(4, "little")
    for i in range(td_size // stride):
        b = td_off + i * stride
        rec = blob[b:b + stride]
        out[b:b + stride] = rec[0:12] + b"\xff\xff\xff\xff" + rec[12:64] + rec[68:92]
    return bytes(out)

def normalize_metadata(blob):
    """Normaliza el global-metadata.dat al layout que Il2CppDumper 6.7.46
    entiende. Devuelve (blob, version, force_il2cpp_version, patch_stride, nota).
    patch_stride = 92 indica que hay que parchear el dumper (ver
    set_dumper_stride); None = binario estandar."""
    version = int.from_bytes(blob[4:8], "little") if len(blob) >= 8 else 0
    pairs = metadata_pairs(blob)
    if not pairs:
        out = bytearray(blob)
        out[0:4] = META_MAGIC
        return bytes(out), version, None, None, "header no reconocido (solo se corrigio el magic)"
    stride = metadata_stride(blob, pairs)

    if stride == 92 and len(pairs) > 31 and blob[:4] != META_MAGIC:
        # Layout propio del build: el buffer descifrado en RAM lleva el magic a
        # cero y 2 pares extra tras los 31 de v29. Se presenta como v29 con
        # typeDefinition de 92 bytes (ver convert_custom_metadata) y se parchea
        # el dumper para que lea 92 bytes tambien en v29.
        out = convert_custom_metadata(blob, pairs)
        return out, 29, None, 92, ("layout propio del build (typeDefinition de "
                                   "92 bytes) reescrito in situ a v29; "
                                   "il2cppdumper parcheado para stride 92")

    if stride == 92 and len(pairs) > 31 and version >= 29:
        # Ya convertido in situ en una ejecucion anterior (idempotente).
        return bytes(blob), 29, None, 92, ("layout propio ya normalizado in situ "
                                           "(v29, typeDefinition de 92 bytes)")

    if len(pairs) == 31 and stride == 88:
        # Layout v29 estandar (magic spoofeado o no): se fija v29.
        out = bytearray(blob)
        out[0:8] = META_MAGIC + (29).to_bytes(4, "little")
        return bytes(out), 29, None, None, "v29 estandar"

    if len(pairs) == 31 and stride == 92:
        # Compactado por una version anterior de la herramienta, o un build
        # v29 con registros de 92 bytes: solo hace falta el parche del dumper.
        out = bytearray(blob)
        out[0:8] = META_MAGIC + (29).to_bytes(4, "little")
        return bytes(out), 29, None, 92, ("v29 con typeDefinition de 92 bytes "
                                          "(layout propio ya normalizado)")

    out = bytearray(blob)
    out[0:4] = META_MAGIC
    return bytes(out), version, None, None, (f"v{version} sin cambios "
                                             f"({len(pairs)} pares, stride {stride})")

def normalize_metadata_file(directory):
    """Normaliza dumps/<pkg>/global-metadata.dat en sitio. Devuelve
    (version, force_il2cpp_version, patch_stride, nota) o None si no hay
    archivo. Antes de convertir se guarda el volcado original en
    global-metadata.raw.dat (gitignored) para no perder informacion."""
    path = os.path.join(directory, "global-metadata.dat")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        blob = f.read()
    new_blob, version, force_ver, patch_stride, note = normalize_metadata(blob)
    if new_blob != blob:
        if patch_stride == 92:
            raw_path = os.path.join(directory, "global-metadata.raw.dat")
            with open(raw_path, "wb") as f:
                f.write(blob)
            print(f"[*] PC: volcado original guardado en {raw_path}")
        with open(path, "wb") as f:
            f.write(new_blob)
    print(f"[*] PC: global-metadata.dat normalizado ({note}) -> v{version}"
          + (f", il2cpp forzado a v{force_ver}" if force_ver else "")
          + (", dumper con stride 92" if patch_stride else ""))
    return version, force_ver, patch_stride, note

META_ANCHOR = b"UnityEngine.CoreModule.dll"
APK_META_ENTRY = "assets/bin/Data/Managed/Metadata/global-metadata.dat"

def validate_metadata_blob(blob, label):
    """Devuelve (version, None) si el global-metadata.dat es utilizable, o (None, motivo)."""
    if not blob:
        return None, f"{label}: no data"
    if len(blob) < 4 * 1024 * 1024:
        return None, f"{label}: only {len(blob)} bytes"
    if blob[:4] != META_MAGIC:
        return None, f"{label}: bad magic {blob[:4].hex()}"
    version = int.from_bytes(blob[4:8], "little", signed=True)
    if not 24 <= version <= 40:
        return None, f"{label}: implausible metadata version {version}"
    if META_ANCHOR not in blob:
        print(f"[!] PC: {label}: anchor string missing (unusual build), using it anyway")
    return version, None

def adb_exec_out(cmd, timeout=300):
    """Ejecuta `cmd` en el dispositivo y devuelve stdout en binario (sin CRLF)."""
    try:
        res = subprocess.run(["adb", "exec-out", cmd], capture_output=True, timeout=timeout)
    except Exception:
        return None
    if res.returncode != 0 or not res.stdout:
        return None
    return res.stdout

def recover_metadata_over_adb(dest_dir, pkg):
    """Cuando agent.js no resuelve el global-metadata.dat en RAM, leerlo del
    dispositivo. Fuentes en orden:
      1. DUMP_APK (env): APK ya local en el PC, sin depender del dispositivo.
      2. El .dat que el propio juego extrajo a Android/data/<pkg>/files/...
      3. La copia en claro dentro del APK instalado (pm path + unzip -p).
      4. APK descargado a un temporal y leido con zipfile (si no hay unzip).
    Escribe dest_dir/global-metadata.dat SOBRESCRIBIENDO cualquier resto de
    otra version y devuelve (version, etiqueta_fuente) o (None, None).
    """
    dest = os.path.join(dest_dir, "global-metadata.dat")

    def store(blob, version, label):
        with open(dest, "wb") as f:
            f.write(blob)
        print(f"[+] PC: metadata recovered from {label} ({len(blob):,} bytes, v{version})")
        return version, label

    # 1) APK local indicado por el entorno (lo usa CI tras descargarlo)
    local_apk = os.environ.get("DUMP_APK")
    if local_apk and os.path.isfile(local_apk):
        print(f"[*] PC: reading metadata from local APK {local_apk} ...")
        try:
            with zipfile.ZipFile(local_apk) as z:
                names = [n for n in z.namelist() if n.endswith("global-metadata.dat")]
                blob = z.read(names[0]) if names else None
            version, err = validate_metadata_blob(blob, "DUMP_APK")
            if version is not None:
                return store(blob, version, os.path.basename(local_apk))
            print(f"[-] PC: {err}")
        except Exception as e:
            print(f"[-] PC: DUMP_APK failed: {e}")

    # 2) el archivo que el propio juego extrajo (es el que mapea con mmap)
    for path in (
        f"/storage/emulated/0/Android/data/{pkg}/files/il2cpp/Metadata/global-metadata.dat",
        f"/data/data/{pkg}/files/il2cpp/Metadata/global-metadata.dat",
        f"/data/user_de/0/{pkg}/files/il2cpp/Metadata/global-metadata.dat",
    ):
        print(f"[*] PC: trying metadata on device: {path}")
        for cmd in (f"su -c 'cat {path}'", f"cat {path}"):
            blob = adb_exec_out(cmd)
            version, err = validate_metadata_blob(blob, "device file")
            if version is not None:
                return store(blob, version, path)
            last_err = err
        print(f"[-] PC: {last_err}")

    # 3) el APK instalado: su global-metadata.dat esta en claro y es identico
    base_apk = None
    try:
        out = subprocess.run(["adb", "shell", "pm", "path", pkg],
                             capture_output=True, text=True, timeout=60, check=False)
        for line in out.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:") and line.endswith("base.apk"):
                base_apk = line[len("package:"):]
                break
    except Exception as e:
        print(f"[-] PC: `pm path {pkg}` failed: {e}")

    if not base_apk:
        print(f"[-] PC: could not locate base.apk for {pkg}")
        return None, None

    print(f"[*] PC: extracting {APK_META_ENTRY} from {base_apk} ...")
    blob = adb_exec_out(f"unzip -p '{base_apk}' '{APK_META_ENTRY}'")
    version, err = validate_metadata_blob(blob, "installed apk (unzip)")
    if version is not None:
        return store(blob, version, "installed apk")
    print(f"[-] PC: {err} - pulling the APK to read it locally instead")

    # 4) ultimo recurso: descargar el APK y leer el zip en el PC
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        res = subprocess.run(["adb", "pull", base_apk, tmp], capture_output=True, timeout=900, check=False)
        if res.returncode != 0:
            raise RuntimeError(res.stderr.decode(errors="replace").strip()[:200])
        with zipfile.ZipFile(tmp) as z:
            names = [n for n in z.namelist() if n.endswith("global-metadata.dat")]
            if not names:
                raise RuntimeError("no global-metadata.dat entry inside the APK")
            blob = z.read(names[0])
        version, err = validate_metadata_blob(blob, "pulled apk")
        if version is not None:
            return store(blob, version, "pulled apk")
        print(f"[-] PC: {err}")
    except Exception as e:
        print(f"[-] PC: could not read the APK: {e}")
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass

    return None, None

def write_manifest(app_version, meta_version, meta_source, meta_format=""):
    manifest_data = {
        "package_name": app_id,
        "app_version": app_version,
        "metadata_version": meta_version if meta_version is not None else "Unknown",
        "metadata_source": meta_source,
        "metadata_format": meta_format,
        "libil2cpp_base": base_address_final,
        "dump_date": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    }
    manifest_path = os.path.join(output_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as m:
        json.dump(manifest_data, m, indent=4)
    print(f"[*] PC: manifest.json generated (App: v{app_version} | Meta: v{manifest_data['metadata_version']} | source: {meta_source}).")


def attach_and_dump(device):
    """Intenta un dump completo; devuelve True si llegó la señal 'done' y el metadato es válido."""
    global base_address_final, dumps_dir, output_dir, app_id, force_il2cpp_version
    done_event.clear()
    # Cada intento parte de un dumper sin parchear; normalize_metadata_file lo
    # parcheara de nuevo si el layout de ESTE build lo necesita. Asi un intento
    # que muera antes de normalizar no hereda el parche del anterior.
    set_dumper_stride(None)
    metadata_ok = [False]
    meta_version: list = [None]  # int cuando se conoce, "Unknown" si no
    meta_source: list = ["ram"]
    meta_format: list = [""]
    done_payload = [None]

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
                version = payload.get('metadata_version', 'Unknown')
                meta_version[0] = version if isinstance(version, int) else None
                # manifest.json se escribe AL FINAL de attach_and_dump, cuando
                # se sepa si el fallback por ADB tuvo que rescatar el metadata.
                done_payload[0] = payload
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

        if done_payload[0] is not None:
            if not metadata_ok[0]:
                # Nunca dejes sobrevivir el global-metadata.dat de OTRA version
                # junto al .so de esta: Il2CppDumper los emparejaria en silencio.
                stale = os.path.join(dumps_dir, "global-metadata.dat")
                if os.path.exists(stale):
                    try:
                        os.remove(stale)
                        print("[*] PC: removed stale global-metadata.dat (belongs to another build)")
                    except OSError as e:
                        print(f"[-] PC: could not remove stale metadata: {e}")
                version, source = recover_metadata_over_adb(dumps_dir, app_id)
                if version is not None:
                    metadata_ok[0] = True
                    meta_version[0] = version
                    meta_source[0] = source

            # Normaliza el global-metadata.dat al layout que Il2CppDumper
            # 6.7.46 entiende (el build puede falsear el header o usar un
            # layout propio; ver normalize_metadata).
            normalized = normalize_metadata_file(dumps_dir)
            if normalized is not None:
                meta_version[0], force_il2cpp_version, patch_stride, meta_format[0] = normalized
                set_dumper_stride(patch_stride)
            write_manifest(get_app_version(app_id), meta_version[0], meta_source[0], meta_format[0])

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
if magic[:4] != b'\xaf\x1b\xb1\xfa':
    print("[-] Aborting Il2CppDumper: global-metadata.dat has an invalid magic "
          f"(got {magic[:4].hex()}, expected af1bb1fa). Stale data.")
    sys.exit(1)

# Version de il2cpp forzada (el build puede tener el binario en v29 y el
# metadata en un layout v24.x; ver normalize_metadata).
ensure_il2cppdumper_config(force_il2cpp_version)

print(f"[*] Running Il2CppDumper ({IL2CPPDUMPER_PATH})...")
try:
    if IS_LINUX:
        proc = subprocess.run(
            ["dotnet", IL2CPPDUMPER_PATH, lib_path, meta_path, output_dir],
            input=f"{base_address_final}\n\n",
            text=True,
            capture_output=True,
        )
    else:
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
    # Il2CppDumper devuelve 0 incluso cuando aborta por dentro (p.ej. cuando
    # no encuentra el MetadataRegistration y pide las direcciones a mano: stdin
    # ya se ha agotado y revienta con una excepcion). Hay que mirar la salida
    # y comprobar que se han generado los DummyDlls.
    if "ERROR" in proc.stdout or "Exception" in proc.stdout:
        print("\n[-] Il2CppDumper reported errors (see the output above).")
        sys.exit(1)
except Exception as e:
    print(f"\n[-] Critical error running Il2CppDumper: {e}")
    sys.exit(1)

dummy_dir = os.path.join(output_dir, "DummyDll")
if not os.path.isdir(dummy_dir) or not [f for f in os.listdir(dummy_dir) if f.endswith(".dll")]:
    print("[-] Il2CppDumper did not generate any DummyDll.")
    sys.exit(1)

print(f"\n[+] AUTOMATION 100% COMPLETED!")
print(f"[+] Raw dumps are located in: /dumps/{app_id}/")
print(f"[+] Perfect DummyDlls are located in: /DummyDlls/{app_id}/")