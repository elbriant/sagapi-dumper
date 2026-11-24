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
    log("\n[+] Initializing Arknights Memory Scanner (Dynamic Heuristic V3.3)...");

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
    var anchorPat = "55 6e 69 74 79 45 6e 67 69 6e 65 2e 43 6f 72 65 4d 6f 64 75 6c 65 2e 64 6c 6c"; // UnityEngine.CoreModule.dll
    var magicPat = "af 1b b1 fa";

    // HOW THE METADATA RESIDES IN RAM DIFFERS PER BUILD, so scan ALL readable
    // ranges instead of only 'rw-':
    //   - older clients malloc() the buffer    -> rw- anonymous range
    //   - 37.x clients mmap() the extracted file READ-ONLY
    //     (.../Android/data/<pkg>/files/il2cpp/Metadata/global-metadata.dat,
    //      r-- file-backed). Scanning only 'rw-' (pre-V3.3) never sees it and
    //     reports "Could not dynamically resolve metadata" although it IS in RAM.
    // NOTE: in Frida, enumerateRanges('r--') is a MASK match: it returns every
    // readable range (r--, rw- and r-x alike) - verified 3097 == all readable.
    var SCAN_BUDGET = 1024 * 1024 * 1024; // max bytes per pass: bounds anti-cheat exposure
    // OJO: NO se puede filtrar "/dev/" en bloque. El build 37.x del server TW
    // NO mapea el global-metadata.dat: lo lee cifrado del disco y lo
    // descifra en un buffer anonimo sobre /dev/zero (r-- / rw- "(deleted)"),
    // que es justo donde vive el metadata. Ese path cae en "/dev/" y el
    // filtro lo descartaba -> "Could not dynamically resolve metadata".
    var SKIP_PATH = [".so", "/lib/arm64/", ".jar", ".ttf", "/apex/", "/system/",
        "/dev/kgsl", "/dev/ashmem", "/dev/__properties__", "/dev/binder",
        "/dev/dmabuf", "/dev/socket", "kgsl", "dmabuf", "binder", "ashmem",
        "jit-", "icudt", "dalvik"];

    var mods = Process.enumerateModules();
    function insideModule(r) {
        for (var mi = 0; mi < mods.length; mi++) {
            var mm = mods[mi];
            if (r.base.compare(mm.base) >= 0 && r.base.compare(mm.base.add(mm.size)) < 0) return true;
        }
        return false;
    }

    var candidates = [], seenBase = {};
    Process.enumerateRanges('r--').forEach(function (r) {
        var key = r.base.toString();
        if (seenBase[key]) return;
        seenBase[key] = 1;
        if (r.size < 256 * 1024 || r.size > 512 * 1024 * 1024) return;
        if (insideModule(r)) return; // module .rodata holds a copy of the anchor: pure false-positive bait
        var p = r.file ? r.file.path : "";
        for (var si = 0; si < SKIP_PATH.length; si++) {
            if (p.indexOf(SKIP_PATH[si]) !== -1) return; // code/GPU/jit/system mappings never hold metadata
        }
        candidates.push({ r: r, path: p });
    });
    // Prioridad de busqueda del metadata:
    //  0) rango cuyo path contiene "global-metadata" -> el archivo mapeado
    //     con mmap() (clientes que no cifran el metadata).
    //  1) rango cuyo path contiene "/dev/zero" -> buffer desencriptado en
    //     memoria por el protector (builds que cifran el metadata en disco).
    //  2) el resto, del rango mas grande al mas pequeno (buffer malloc()).
    function pathPriority(p) {
        if (p.indexOf("global-metadata") !== -1) return 0;
        if (p.indexOf("/dev/zero") !== -1) return 1;
        return 2;
    }
    candidates.sort(function (a, b) {
        var pa = pathPriority(a.path), pb = pathPriority(b.path);
        if (pa !== pb) return pa - pb;
        if (pa === 2) return b.r.size - a.r.size;
        return 0;
    });
    log("[*] " + candidates.length + " candidate readable ranges (non-module, 256KB..512MB)");

    // scanSync aborts the whole range on a hole; retry in 1MB blocks instead.
    function scanSafe(base, size, pat) {
        try {
            return Memory.scanSync(base, size, pat);
        } catch (e) {
            var out = [];
            for (var off = 0; off < size; off += 0x100000) {
                var n = Math.min(0x100000, size - off);
                try { out = out.concat(Memory.scanSync(base.add(off), n, pat)); } catch (e2) { }
            }
            return out;
        }
    }

    var rejectNotes = [];
    // Same validation the original walk-back used: spoofed builds report
    // version 24, honest builds report their true version (29/31/...), and
    // both must yield a plausible section table. `where` labels the caller
    // so a rejection says WHICH pass rejected it.
    function readHeader(addr, where) {
        try {
            var version = addr.add(4).readInt();
            if (version < 24 || version > 40) {
                if (rejectNotes.length < 8) rejectNotes.push("      " + where + " " + addr + ": version " + version + " outside 24..40");
                return null;
            }
            var strOffset = addr.add(8).readInt();
            if (strOffset <= 0 || strOffset >= 100 * 1024 * 1024) {
                if (rejectNotes.length < 8) rejectNotes.push("      " + where + " " + addr + ": v" + version + " but strOffset " + strOffset + " is implausible");
                return null;
            }

            var maxSize = 0, minOffset = 0xFFFFFFF, pi = 0;
            while (true) {
                var fieldOffset = 8 + pi * 8;
                if (fieldOffset >= minOffset) break;

                var off = addr.add(fieldOffset).readInt();
                var sz = addr.add(fieldOffset + 4).readInt();

                if (off > 0 && off < minOffset) minOffset = off;
                if (off + sz > maxSize) maxSize = off + sz;

                pi++;
                if (pi > 50) break;
            }

            if (maxSize <= 0) {
                if (rejectNotes.length < 8) rejectNotes.push("      " + where + " " + addr + ": v" + version + " but empty section table");
                return null;
            }
            // A valid global-metadata.dat is never > 80 MB. A wrong candidate
            // over-estimates size and readByteArray then walks past the real
            // data into guard pages -> "access violation" on the PC side.
            if (maxSize > 80 * 1024 * 1024) {
                log("[-] Skipping " + where + " candidate " + addr + ": calculated size " + maxSize + " bytes is unrealistic.");
                return null;
            }
            return { version: version, size: maxSize };
        } catch (e) { return null; }
    }

    var metaBase = null, realSize = 0;
    var magicHits = 0, anchorHits = 0, budgetHit = false;
    var found = false;

    // ---- PASS 1: the real AF1BB1FA magic (37.x does NOT spoof it in RAM) ----
    var scanned1 = 0;
    for (var ci = 0; ci < candidates.length && !metaBase; ci++) {
        var cand1 = candidates[ci];
        if (scanned1 >= SCAN_BUDGET) { budgetHit = true; break; }
        var mHits = scanSafe(cand1.r.base, cand1.r.size, magicPat);
        scanned1 += cand1.r.size;
        magicHits += mHits.length;
        for (var mgi = 0; mgi < mHits.length; mgi++) {
            var hdr1 = readHeader(mHits[mgi].address, "magic");
            if (!hdr1) continue;
            metaBase = mHits[mgi].address;
            realSize = hdr1.size;
            foundVersion = hdr1.version;
            log("[+] Real metadata header (AF1BB1FA v" + hdr1.version + ") found at: " + metaBase +
                (cand1.path ? " [" + cand1.path + "]" : ""));
            break;
        }
    }
    log("[*] Pass 1 (magic): " + (scanned1 / 1048576).toFixed(0) + " MB scanned, " + magicHits + " raw hit(s), header " + (metaBase ? "FOUND" : "not found"));

    // ---- PASS 2: anchor walk-back (covers builds that spoof the header bytes) ----
    if (!metaBase) {
        log("[*] Pass 2: UnityEngine.CoreModule.dll anchor walk-back...");
        var scanned2 = 0;
        for (var cj = 0; cj < candidates.length && !metaBase; cj++) {
            var cand2 = candidates[cj];
            if (scanned2 >= SCAN_BUDGET) { budgetHit = true; break; }
            var aHits = scanSafe(cand2.r.base, cand2.r.size, anchorPat);
            scanned2 += cand2.r.size;
            anchorHits += aHits.length;
            if (aHits.length === 0) continue;
            log("[*] Anchor x" + aHits.length + " in " + cand2.r.base + " (" +
                (cand2.r.size / 1048576).toFixed(1) + "MB " + cand2.r.protection +
                (cand2.path ? " " + cand2.path : "") + ")");

            // The old code only tested matches[0]; test EVERY hit, otherwise a
            // stray copy of the anchor elsewhere in the range masks the real one.
            for (var ai = 0; ai < aHits.length && !metaBase; ai++) {
                var anchorAddr = aHits[ai].address;
                var pageAligned = anchorAddr.and(ptr("0xfffffffffffff000"));
                var steps = 0;
                while (pageAligned.compare(cand2.r.base) >= 0 && steps++ < 262144) {
                    // +0 for mmap'd buffers, +8..56 for allocator chunk headers
                    // (scudo stores one right after the page start, so a large
                    // malloc()'d buffer is NOT page-aligned).
                    for (var aoff = 0; aoff < 64 && !metaBase; aoff += 8) {
                        var testBase = pageAligned.add(aoff);
                        if (testBase.compare(cand2.r.base) < 0) continue;
                        var hdr2 = readHeader(testBase, "anchor");
                        if (!hdr2) continue;
                        metaBase = testBase;
                        realSize = hdr2.size;
                        foundVersion = hdr2.version;
                        log("[+] Anchor found at: " + anchorAddr);
                        log("[+] Metadata header dynamically detected at: " + metaBase);
                        log("[+] Calculated actual size: " + realSize + " bytes");
                    }
                    pageAligned = pageAligned.sub(4096);
                }
            }
        }
        log("[*] Pass 2 (anchor): " + (scanned2 / 1048576).toFixed(0) + " MB scanned, " + anchorHits + " anchor hit(s), header " + (metaBase ? "FOUND" : "not found"));
    }

    if (metaBase !== null && realSize > 0) {
        // Sanity signal only: a real metadata always embeds the anchor literal.
        try {
            if (Memory.scanSync(metaBase, Math.min(realSize, 80 * 1024 * 1024), anchorPat).length === 0) {
                log("[!] Warning: anchor string is not inside the candidate - unusual build, dumping anyway.");
            }
        } catch (e) { }

        send({ type: 'init_file', name: 'global-metadata.dat', size: realSize });
        log("[*] Transferring metadata to PC (raw header, normalized on the PC)...");

        try {
            for (var woff = 0; woff < realSize; woff += MAX_CHUNK) {
                var remainMeta = realSize - woff;
                var readSizeMeta = remainMeta < MAX_CHUNK ? remainMeta : MAX_CHUNK;
                var bufMeta = metaBase.add(woff).readByteArray(readSizeMeta);

                // El header se copia TAL CUAL está en RAM: algunos builds lo
                // falsean (magic a 0, version a 24) y otros usan un layout
                // propio (typeDefinition de 92 bytes). dumper_pc.py es quien
                // normaliza el archivo segun el layout real detectado.
                send({ type: 'write_chunk', name: 'global-metadata.dat', offset: woff }, bufMeta);
            }
            send({ type: 'finish_file', name: 'global-metadata.dat' });
            found = true;
        } catch (e) {
            log("[-] Error transferring metadata: " + e);
        }
    }

    if (!found) {
        log("[-] Could not dynamically resolve metadata in RAM.");
        log("[-] Diagnostics: candidates=" + candidates.length +
            " scanned=" + (((scanned1 + (scanned2 || 0)) / 1048576).toFixed(0)) + "MB" +
            (budgetHit ? " (SCAN BUDGET EXHAUSTED - raise SCAN_BUDGET)" : "") +
            " magicHits=" + magicHits + " anchorHits=" + anchorHits);
        rejectNotes.forEach(function (n) { log(n); });
    }

    log("\n[+] RAM extraction completed. Handing control over to PC...");
    send({
        type: 'done',
        base_addr: lib.base.toString(),
        metadata_version: foundVersion,
        metadata_ok: found
    });

}, 5000);