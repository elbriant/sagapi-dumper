function log(msg) {
    send({ type: 'log', msg: msg });
}

setTimeout(function () {
    log("\n[+] Initializing Arknights Memory Scanner (Dynamic Heuristic V3.2)...");

    var MAX_CHUNK = 4 * 1024 * 1024; // Transmit in 4MB chunks to prevent Frida from crashing

    // ==========================================
    // 1. DUMP LIBIL2CPP
    // ==========================================
    var lib = Process.getModuleByName("libil2cpp.so");
    log("[+] libil2cpp.so base: " + lib.base + " | Size: " + (lib.size / 1024 / 1024).toFixed(2) + " MB");

    // Notify PC to prepare the file
    send({ type: 'init_file', name: 'libil2cpp.so', size: lib.size });

    log("[*] Transferring readable memory blocks to PC...");
    var ranges = lib.enumerateRanges('r--'); // Filter for readable memory

    ranges.forEach(function (r) {
        var rOffset = r.base.sub(lib.base).toInt32();
        var rSize = r.size;

        // Split into 4MB chunks for large memory blocks
        for (var i = 0; i < rSize; i += MAX_CHUNK) {
            var remain = rSize - i;
            var readSize = remain < MAX_CHUNK ? remain : MAX_CHUNK;
            try {
                var buf = r.base.add(i).readByteArray(readSize);
                send({ type: 'write_chunk', name: 'libil2cpp.so', offset: rOffset + i }, buf);
            } catch (e) {
                // Ignore memory pages protected by the kernel
            }
        }
    });
    send({ type: 'finish_file', name: 'libil2cpp.so' });

    // ==========================================
    // 2. DUMP GLOBAL-METADATA (DYNAMIC HEURISTIC ALGORITHM)
    // ==========================================
    log("\n[*] Scanning RAM for global-metadata...");
    var pattern = "55 6e 69 74 79 45 6e 67 69 6e 65 2e 43 6f 72 65 4d 6f 64 75 6c 65 2e 64 6c 6c";

    var memRanges = Process.enumerateRanges('rw-');
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
                                break;
                            }
                        }
                    }
                } catch (e) { }
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

    // Signal Python script to terminate and send the real Base Address
    send({
        type: 'done',
        base_addr: lib.base.toString()
    });

}, 5000);