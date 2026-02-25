function log(msg) {
    send({ type: 'log', msg: msg });
}

setTimeout(function () {
    log("\n[+] Initializing Arknights Memory Scanner...");

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
    // 2. DUMP GLOBAL-METADATA
    // ==========================================
    log("\n[*] Scanning RAM for global-metadata...");
    var pattern = "55 6e 69 74 79 45 6e 67 69 6e 65 2e 43 6f 72 65 4d 6f 64 75 6c 65 2e 64 6c 6c";
    var offsetOriginal = 0x6D82A5;
    var tamanoReal = 35770528;

    var memRanges = Process.enumerateRanges('rw-');
    var found = false;

    for (var j = 0; j < memRanges.length; j++) {
        var rMeta = memRanges[j];
        if (rMeta.size > 50 * 1024 * 1024) continue;

        var matches = Memory.scanSync(rMeta.base, rMeta.size, pattern);
        if (matches.length > 0) {
            var anchorAddr = matches[0].address;
            var metaBase = anchorAddr.sub(offsetOriginal);

            log("[+] Anchor found at: " + anchorAddr);
            log("[+] Calculated actual start offset at: " + metaBase);

            send({ type: 'init_file', name: 'global-metadata.dat', size: tamanoReal });
            log("[*] Transferring metadata to PC and restoring header...");

            try {
                for (var offset = 0; offset < tamanoReal; offset += MAX_CHUNK) {
                    var remainMeta = tamanoReal - offset;
                    var readSizeMeta = remainMeta < MAX_CHUNK ? remainMeta : MAX_CHUNK;
                    var bufMeta = metaBase.add(offset).readByteArray(readSizeMeta);

                    // Restore Magic Bytes in the first chunk before sending it to the PC
                    if (offset === 0) {
                        var magic = [0xAF, 0x1B, 0xB1, 0xFA, 0x1D, 0x00, 0x00, 0x00];
                        var tempMem = Memory.alloc(readSizeMeta);
                        tempMem.writeByteArray(bufMeta);
                        tempMem.writeByteArray(magic);
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

    if (!found) {
        log("[-] Anchor not found in RAM.");
    }

    log("\n[+] RAM extraction completed. Handing control over to PC...");

    // Signal Python script to terminate and send the real Base Address
    send({
        type: 'done',
        base_addr: lib.base.toString()
    });

}, 5000);