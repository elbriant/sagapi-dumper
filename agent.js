function log(msg) {
    send({ type: 'log', msg: msg });
}

// ==========================================
// 0. ANTI-DETECTION LAYER (best-effort, hides Frida's presence)
//    Set ANTI_DETECT = false to disable.
// ==========================================
var ANTI_DETECT = true;

function antiDetect() {
    var MARKERS = ["frida", "gum-js-loop", "gum-graft", "frida-server", "linjector"];

    function isMarker(s) {
        if (!s) return false;
        var l = s.toLowerCase();
        for (var i = 0; i < MARKERS.length; i++) {
            if (l.indexOf(MARKERS[i]) !== -1) return true;
        }
        return false;
    }

    // Frida 17 removed the static Module.findExportByName(...) form; resolve
    // exports via the libc module's instance method instead.
    function findExport(name) {
        var mods = ["libc.so", "libc.bionic.so"];
        for (var i = 0; i < mods.length; i++) {
            var m = Process.findModuleByName(mods[i]);
            if (m) {
                var e = m.findExportByName(name);
                if (e) return e;
            }
        }
        try { return Module.findGlobalExportByName(name); } catch (e) { return null; }
    }

    // Each hook is isolated: one failure must never kill the others.
    function hook(exp, onEnter, onLeave) {
        try {
            var p = findExport(exp);
            if (!p) return;
            Interceptor.attach(p, {
                onEnter: function (args) {
                    try { if (onEnter) onEnter.call(this, args); } catch (e) { }
                },
                onLeave: function (retval) {
                    try { if (onLeave) onLeave.call(this, retval); } catch (e) { }
                }
            });
            log("[+] anti-detect hook installed: " + exp);
        } catch (e) {
            log("[-] anti-detect hook failed: " + exp + ": " + e);
        }
    }

    try {
        // 1) String compare/search functions: fake "not found" when a Frida marker
        //    string is involved, so the game's string-based checks never match.
        hook("strcmp", function (args) {
            try {
                this.a = args[0].readCString(128);
                this.b = args[1].readCString(128);
            } catch (e) { this.a = null; this.b = null; }
        }, function (retval) {
            if (isMarker(this.a) || isMarker(this.b)) retval.replace(1);
        });
        hook("strncmp", function (args) {
            try {
                this.a = args[0].readCString(128);
                this.b = args[1].readCString(128);
            } catch (e) { this.a = null; this.b = null; }
        }, function (retval) {
            if (isMarker(this.a) || isMarker(this.b)) retval.replace(1);
        });
        hook("strcasestr", function (args) {
            try { this.needle = args[1].readCString(128); } catch (e) { this.needle = null; }
        }, function (retval) {
            if (isMarker(this.needle)) retval.replace(ptr(0));
        });
        hook("strstr", function (args) {
            try { this.needle = args[1].readCString(128); } catch (e) { this.needle = null; }
        }, function (retval) {
            if (isMarker(this.needle)) retval.replace(ptr(0));
        });
    } catch (e) { log("[-] anti-detect str hooks failed: " + e); }

    try {
        // 2) Blank any /proc/self/{maps,task,status,comm} line that reveals Frida.
        //    NOTE: covers caller's fgets(); direct read(2) on these files is NOT hidden.
        var procFiles = {};
        hook("fopen", function (args) {
            try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
        }, function (retval) {
            if (this.path && this.path.indexOf("/proc/") !== -1 && !retval.isNull()) {
                procFiles[retval.toInt32()] = this.path;
            }
        });
        hook("fgets", function (args) {
            this.buf = args[0];
            this.fp = args[2].toInt32();
        }, function (retval) {
            if (retval.isNull()) return;
            var path = procFiles[this.fp];
            if (!path) return;
            if (path.indexOf("maps") !== -1 || path.indexOf("/task/") !== -1 ||
                path.indexOf("status") !== -1 || path.indexOf("comm") !== -1) {
                try {
                    var line = this.buf.readCString(256);
                    if (isMarker(line)) this.buf.writeUtf8String("\n");
                } catch (e) { }
            }
        });
    } catch (e) { log("[-] anti-detect /proc hooks failed: " + e); }
}

if (ANTI_DETECT) {
    try { antiDetect(); } catch (e) { log("[-] anti-detect failed: " + e); }
}

setTimeout(function () {
    log("\n[+] Initializing Arknights Memory Scanner (Dynamic Heuristic V3.2)...");

    var MAX_CHUNK = 64 * 1024 * 1024; // Fewest round-trips = least exposure time; anti-cheat kills frida-server if dump is slow
    var foundVersion = "Unknown";

    // ==========================================
    // 1. DUMP LIBIL2CPP
    // ==========================================
    var lib = Process.getModuleByName("libil2cpp.so");
    log("[+] libil2cpp.so base: " + lib.base + " | Size: " + (lib.size / 1024 / 1024).toFixed(2) + " MB");

    send({ type: 'init_file', name: 'libil2cpp.so', size: lib.size });

    log("[*] Transferring readable memory blocks to PC...");
    // Do NOT trust lib.enumerateRanges(): the anti-cheat can make Frida's
    // module parser hallucinate a ghost range ~full-module-size located
    // outside [base, base+size). Use the kernel's own process memory map
    // and clip every readable range to the module span instead.
    var libEnd = lib.base.add(lib.size);
    var procRanges = Process.enumerateRanges('r--');
    var sentTotal = 0;

    procRanges.forEach(function (r) {
        var rEnd = r.base.add(r.size);
        var s = r.base.compare(lib.base) < 0 ? lib.base : r.base;
        var e = rEnd.compare(libEnd) > 0 ? libEnd : rEnd;
        if (e.compare(s) <= 0) return;

        var rOffset = s.sub(lib.base).toUInt32();
        var rSize = e.sub(s).toUInt32();

        for (var i = 0; i < rSize; i += MAX_CHUNK) {
            var remain = rSize - i;
            var readSize = remain < MAX_CHUNK ? remain : MAX_CHUNK;
            try {
                var buf = s.add(i).readByteArray(readSize);
                send({ type: 'write_chunk', name: 'libil2cpp.so', offset: rOffset + i }, buf);
                sentTotal += readSize;
            } catch (err) {
                // Ignore memory pages protected by the kernel
            }
        }
    });

    if (sentTotal < lib.size * 0.1) {
        log("[-] WARNING: only " + (sentTotal / 1024 / 1024).toFixed(2) +
            " MB readable inside module span; the real code may be remapped elsewhere.");
    }
    log("[*] Transferred " + (sentTotal / 1024 / 1024).toFixed(2) + " MB of libil2cpp.so");
    send({ type: 'finish_file', name: 'libil2cpp.so' });

    // ==========================================
    // 2. DUMP GLOBAL-METADATA (DYNAMIC HEURISTIC ALGORITHM)
    // ==========================================
    log("\n[*] Scanning RAM for global-metadata...");
    var pattern = "55 6e 69 74 79 45 6e 67 69 6e 65 2e 43 6f 72 65 4d 6f 64 75 6c 65 2e 64 6c 6c";

    // The metadata block is ~37MB, so skip tiny ranges and scan the biggest
    // candidates first: the anchor is found in the very first scanSync instead
    // of after sweeping dozens of ranges (shorter exposure = fewer kills).
    // NOTE: the spoofed-version heuristic relies on version being 24..31; do not
    // weaken the filter below or the anchor search may scan unrelated regions.
    var memRanges = Process.enumerateRanges('rw-')
        .filter(function (r) { return r.size >= 2 * 1024 * 1024; })
        .sort(function (a, b) { return b.size - a.size; });
    var found = false;

    for (var j = 0; j < memRanges.length; j++) {
        var rMeta = memRanges[j];
        if (rMeta.size > 50 * 1024 * 1024) continue;

        var matches = Memory.scanSync(rMeta.base, rMeta.size, pattern);
        if (matches.length > 0) {
            var anchorAddr = matches[0].address;
            var metaBase = null;
            var realSize = 0;

            var possibleBases = [rMeta.base];
            var pageAligned = anchorAddr.sub(anchorAddr.toInt32() % 4096);
            while (pageAligned.compare(rMeta.base) >= 0) {
                if (!pageAligned.equals(rMeta.base)) {
                    possibleBases.push(pageAligned);
                }
                pageAligned = pageAligned.sub(4096);
            }

            for (var k = 0; k < possibleBases.length; k++) {
                var testBase = possibleBases[k];
                try {
                    // The game spoofs the version to 24, we allow finding it to locate the header
                    var version = testBase.add(4).readInt();
                    if (version >= 24 && version <= 31) {
                        var strOffset = testBase.add(8).readInt();
                        if (strOffset > 0 && strOffset < 100 * 1024 * 1024) {

                            var maxSize = 0;
                            var minOffset = 0xFFFFFFF;
                            var p = 0;

                            while (true) {
                                var fieldOffset = 8 + p * 8;
                                if (fieldOffset >= minOffset) break;

                                var offset = testBase.add(fieldOffset).readInt();
                                var size = testBase.add(fieldOffset + 4).readInt();

                                if (offset > 0 && offset < minOffset) minOffset = offset;
                                if (offset + size > maxSize) maxSize = offset + size;

                                p++;
                                if (p > 50) break;
                            }

                            if (maxSize > 0) {
                                metaBase = testBase;
                                realSize = maxSize;
                                foundVersion = version;
                                break;
                            }
                        }
                    }
                } catch (e) { }
            }

            // Reject anchors whose calculated size is absurdly large —
            // a valid global-metadata.dat is never > 80 MB. A wrong anchor
            // makes the heuristic over-estimate and readByteArray then walks
            // past the real data into guard pages, producing the
            // "access violation" seen on the PC side.
            if (metaBase !== null && realSize > 80 * 1024 * 1024) {
                log("[-] Skipping anchor: calculated size " + realSize + " bytes is unrealistic.");
                metaBase = null;
                realSize = 0;
            }

            if (metaBase !== null && realSize > 0) {
                log("[+] Anchor found at: " + anchorAddr);
                log("[+] Metadata header dynamically detected at: " + metaBase);
                log("[+] Calculated actual size: " + realSize + " bytes");

                send({ type: 'init_file', name: 'global-metadata.dat', size: realSize });
                log("[*] Transferring metadata to PC and restoring Version 29 header...");

                try {
                    for (var offset = 0; offset < realSize; offset += MAX_CHUNK) {
                        var remainMeta = realSize - offset;
                        var readSizeMeta = remainMeta < MAX_CHUNK ? remainMeta : MAX_CHUNK;
                        var bufMeta = metaBase.add(offset).readByteArray(readSizeMeta);

                        if (offset === 0) {
                            // Force Magic Bytes + Version 29 (0x1D) to bypass memory spoofing
                            var magic8 = [0xAF, 0x1B, 0xB1, 0xFA, 0x1D, 0x00, 0x00, 0x00];

                            var tempMem = Memory.alloc(readSizeMeta);
                            tempMem.writeByteArray(bufMeta);
                            tempMem.writeByteArray(magic8); // Overwrite the first 8 bytes
                            bufMeta = tempMem.readByteArray(readSizeMeta);
                        }

                        send({ type: 'write_chunk', name: 'global-metadata.dat', offset: offset }, bufMeta);
                    }
                    send({ type: 'finish_file', name: 'global-metadata.dat' });
                    found = true;
                    break;
                } catch (e) {
                    log("[-] Error transferring metadata: " + e);
                }
            }
        }
        if (found) break;
    }

    if (!found) {
        log("[-] Could not dynamically resolve metadata in RAM.");
    }

    log("\n[+] RAM extraction completed. Handing control over to PC...");
    send({
        type: 'done',
        base_addr: lib.base.toString(),
        metadata_version: foundVersion,
        metadata_ok: found
    });

}, 5000);