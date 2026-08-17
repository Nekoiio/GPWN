# gd_lib Reference

Full function-by-function documentation for `gd_lib.py`. For install instructions,
a quick-start, and the general pitch, see the [main README](../README.md) — this
page is the deep-dive you come back to once you're mid-exploit.

---

## Template Walkthrough

`template.py` is a thin scaffold, not a full solve script:

| Section | Purpose |
|---|---|
| `context.update(...)` / `context.log_level` / `context.aslr` | Standard pwntools context. ASLR is off by default for local iteration. |
| Commented **Func examples** block | Copy/paste starting points for the most common calls (`gfs_off`, `hit_matcher`, `ghex_toAscii`, `gs_lookup`). |
| `proc`, `elf`, `libc`, `rop` | Target binary / libc / ROP object slots — uncomment `libc`/`rop` as needed. |
| `start_line`, `recv_line` | The two prompts `gd_lib` needs to know when to send input and where to start reading the response. |
| `loc_pie_base` | Reference PIE base (`0x555555554000`) matching the default `VMMAP` entry, handy for offset math against a local, no-ASLR run. |
| `r = process(proc)` / `r = remote()` | Swap between local and remote once your exploit is ready. |
| Trailing comment block | An inline cheat-sheet of `gfs_off`, `gs_lookup`, and `hit_matcher` parameters, so you don't have to leave the file while writing an exploit. |

---

## Library Reference

### Printing / Color

```python
class C          # ANSI color constants + C.color256(n) / C.bg256(n) for 256-color codes
cprint(text, color)   # e.g. cprint("leak ok", "green")
```
`color` is case-insensitive and matches any attribute on `C` (`red`, `green`,
`blue`, plus semantic aliases like `error`, `success`, `warning`, `info`, `debug`).

### Address Classification

```python
classify_addr(addr: int, maps=VMMAP) -> str
```
Given a pointer, returns a human-readable label + range, e.g.
`"heap (0x555555559000 - 0x55555557a000)"`. Falls back to
`"unknown (None - None)"` if the address isn't inside any known range.

`VMMAP` is a **static table** of typical 32-bit and 64-bit memory layouts (PIE,
non-PIE, and standard libc/ld/stack ranges) assuming ASLR is disabled. It exists
purely so leaks print with a readable label — it is *not* introspected from the
live process. **Replace or extend it with the real ranges** (from pwndbg's
`vmmap` or `/proc/<pid>/maps`) if your environment's layout differs, or
`classify_addr` will mislabel — or miss — your leaks.

### Format-String Recon

```python
gfs_off(p_name="./vuln", architecture=64, start_line=b": \n", recv_line=b": ", lim=50) -> int
```
Brute-forces `%N$p` (or `%N$x` for 32-bit) until the sent test pattern
(`AAAAAAAA` / `AAAA`) is echoed back, returning that offset (`-1` if not found
within `lim`).

```python
gs_lookup(
    p_name="./vuln", architecture=64,
    start_line=b": \n", recv_line=b": ",
    lim=50, start=1, spec="",
    lookup=b'', iter=6,
    multi_line=False, multild=b"=", avectors=2
) -> None
```
Sends `%i$p` (or `spec`) for `i` in `range(start, lim)`, one fresh process per
position, and prints each leak alongside its `classify_addr` label. If
`lookup` is non-empty, it's forwarded to `hit_matcher`. **Always ends by
calling `process_leaks` automatically**, so a `base_offset.txt` is written as
a side effect of every scan. `multi_line`/`avectors` are placeholders for
binaries that leak multiple values per send — **not implemented yet**.

```python
process_leaks(results, maps=VMMAP, outfile="base_offset.txt") -> list[tuple]
```
Classifies every leak in `results`, keeps one entry per memory *range* (dedup),
computes `offset = pointer - region_start`, sorts by offset, and writes:
```
<offset>  <pointer>  <section>  %<i>$p  <range>
```
to `outfile`. Called automatically by `gs_lookup`; call it yourself if you
build your own `results` list.

```python
hit_matcher(look=b"", results=[], direct=False, direct_ls=[], iter=6) -> None
```
Two modes:
- **Indirect** (default): scans `results` (as produced by `gs_lookup`) for
  `look`, matching both byte orders. On a hit, pulls in the next `iter` leaks
  and reconstructs them as ASCII in both endian orders.
- **Direct** (`direct=True`): skip scanning — pass your own `direct_ls` list of
  already-collected hex leaks and get the same little/big-endian ASCII
  reconstruction.

```python
gfmts(count: int, specifier: str = "p", delim: str = "") -> str
```
Builds a specifier chain, e.g. `gfmts(4, delim=".")` →
`"%1$p.%2$p.%3$p.%4$p"`. Useful for quickly building `%n`-write payload
skeletons once you know your offsets.

### Hex / ASCII Utilities

```python
gd_ascii(lek: bytes | str) -> str
```
Takes a **`0x`-prefixed hex string**, strips the prefix, pads an odd nibble
count, and decodes to ASCII (`errors='replace'`).
⚠️ Passing raw `bytes` doesn't currently work correctly — the decode result is
discarded, so pass a `str` like `"0x41414141"`.

```python
ghex_stream(hexstream: str, delim: str, end: str = 'LITTLE') -> str
```
Splits a long hex dump on `delim`, runs each chunk through `gd_ascii`, and
joins the result — meant for reassembling a wall of `%p` output into text.
⚠️ Marked broken for 32-bit in the source, and it strips `0x` **before**
calling `gd_ascii` (which also expects a `0x` prefix), so double-check output
before trusting it.

```python
ghex_toAscii(conv: int | str, end: str = "BIG") -> str
```
Converts an int or hex string to ASCII; pass `end="little"` to get the
reversed string for little-endian reconstruction.

### Shellcode

```python
gshellc(hexs: str) -> None
```
Writes `bytes.fromhex(hexs)` to a file named `tl`. Expects pre-encoded hex
shellcode — does not assemble raw assembly (see Roadmap).

---

## Roadmap / Known Issues

Pulled directly from `# TODO` markers in the source — flagging these so you
don't lose time debugging something that's a known gap:

- [ ] **`gs_lookup`**: `multi_line` / `avectors` (multiple leaks per send) is
      stubbed out, not implemented.
- [ ] **`ghex_stream`**: doesn't correctly handle 32-bit leaks; also double-
      strips the `0x` prefix before calling `gd_ascii`.
- [ ] **`gd_ascii`**: `bytes` input path discards the decoded value instead of
      using it.
- [ ] **`gshellc`**: only accepts pre-hex-encoded shellcode; should eventually
      take raw assembly and call pwntools' `asm()`.
- [ ] **`gfilter`**: unfinished — intended to strip non-ASCII leaks out of a
      results list before further processing.
- [ ] **`gfms_pay`**: not started — planned helper to build a full `%n`
      write-primitive payload from `{address: value}` writes and a known
      offset.
- [ ] **Heap support**: no heap helpers yet (`guaf_s`, a UAF allocation-size
      helper, is a placeholder for a future release).

---

## Tips

- `gs_lookup` spawns a **fresh process per position** it tests, so large `lim`
  values on slow-starting binaries can take a while — narrow the range once
  you have a rough idea where your leak lives.
- `context.aslr = False` in the template is for local iteration; remove it (or
  set per-run) once you're leaking real addresses to defeat.
- Check `base_offset.txt` after any `gs_lookup` run — it's sorted by offset
  from each region's base, which makes it fast to eyeball "this is libc + 0x..."
  or "this is the heap base."