<div align="center">

# Gpwn

**One command to go from "new CTF pwn challenge" to a working recon workspace.**

![python](https://img.shields.io/badge/python-3.10%2B-blue)
![built on](https://img.shields.io/badge/built%20on-pwntools-black)
![status](https://img.shields.io/badge/status-WIP-yellow)

</div>

---

`Gpwn` preps a fresh CTF pwn directory in one shot: it drops in a local test
flag, copies over your format-string recon library and exploit template, and
makes the challenge binary executable — so you can spend your time on the
exploit instead of on setup chores.

```bash
cd ~/ctf/pico2026/baby-fmt
Gpwn
```

That's it — `gd_lib.py` and `template.py` are now sitting in your challenge
folder, wired up and ready to go, and the binary you downloaded is already
runnable.

## Why

- **No more manual `/proc/pid/maps` cross-referencing.** Every `%p` leak gets
  auto-labeled as stack / heap / libc / binary / ld on the way to your terminal.
- **No more rewriting the offset-finder.** `gfs_off()` brute-forces your
  format-string offset in one call.
- **No more losing track of what you leaked.** Every scan writes a sorted,
  deduplicated `base_offset.txt` — a running log of every pointer and where it
  came from.
- **No more manual endian juggling.** `hit_matcher()` reconstructs a leak as
  ASCII in both byte orders so you don't have to guess.
- **No more "permission denied" on a freshly downloaded binary.** `Gpwn`
  chmods it for you on the way in.
- **No more missing a local flag.** A throwaway `flag.txt` is dropped in so
  you can confirm your exploit actually works before pointing it at the
  remote.

## How `Gpwn` works

It's a small, boring bash script — no magic, easy to read in ten seconds:

```bash
#!/bin/bash
echo "picoCTF{local_flag}" > flag.txt
echo "Created: flag.txt"
cp ~/Templates/pwn/* .
for f in *; do
    # skip directories
    [ -d "$f" ] && continue
    # check if filename has no dot
    if [[ "$f" != *.* ]]; then
        chmod +x "$f"
        echo "Made $f executable"
    fi
done
```

1. Writes a placeholder `flag.txt` so any local run of the challenge has
   something to `cat`.
2. Copies everything out of `~/Templates/pwn/` into the current directory —
   that's where `gd_lib.py` and `template.py` live, so keep that folder as
   the source of truth if you add more helpers later.
3. Walks every file (not directories) in the current directory and
   `chmod +x`'s anything **without a dot in its name** — which catches the
   challenge binary itself (`vuln`, no extension) without touching `.py`
   files that don't need the execute bit.

## Example session

```
$ ls
vuln

$ Gpwn
Created: flag.txt
Made vuln executable

$ ls
flag.txt  gd_lib.py  template.py  vuln
```

`Gpwn` doesn't print anything for the template copy itself — only the flag
creation and each `chmod` get echoed, so a quiet run after that first line
just means the copy succeeded silently.

From there, running your exploit script prints classified leaks as it scans:

```
$ python3 template.py
position 6: 0x7ffff7dc4d40 -> lib (0x7ffff7dc2000 - 0x7ffff7f9a000)
position 7: 0x5555555592a0 -> heap (0x555555559000 - 0x55555557a000)
position 8: 0x7fffffffe110 -> stack (0x7ffffffde000 - 0x7ffffffff000)
position 9: 0x555555555179 -> .text (0x555555555000 - 0x555555556000)
...
[i] wrote base_offset.txt (9 leaks, deduped by region)
```

## Install

`Gpwn` expects two things to already be in place:

1. **A template source directory** — `gd_lib.py` and `template.py` need to
   live in `~/Templates/pwn/`, since that's what gets copied into every new
   challenge folder:
   ```bash
   mkdir -p ~/Templates/pwn
   cp gd_lib.py template.py ~/Templates/pwn/
   ```
2. **The `Gpwn` script itself on your `PATH`:**
   ```bash
   chmod +x Gpwn
   mv Gpwn ~/.local/bin/   # or anywhere already on your $PATH
   which Gpwn              # sanity check it resolves
   ```

**Requirements:** Python 3.10+ and [`pwntools`](https://docs.pwntools.com/)
(`pip install pwntools`).

## Quick start

```python
# template.py, after Gpwn has dropped it in
offset = gfs_off(start_line=start_line, recv_line=recv_line)
gs_lookup(start_line=start_line, recv_line=recv_line, lim=100)
```

Run it, then open `base_offset.txt` for a sorted map of every stack, heap, and
libc pointer the binary handed you — that's usually enough to start planning
your write primitive.

## What's in the box

| | |
|---|---|
| `gfs_off` | Find your format-string offset automatically |
| `gs_lookup` | Scan the stack via `%N$p`, print + classify every leak |
| `process_leaks` | Dedup leaks by region, compute offsets, write `base_offset.txt` |
| `hit_matcher` | Find a known value among your leaks, both endian directions |
| `gfmts` | Build `%N$p` / `%N$n` specifier chains for payloads |
| `gd_ascii` / `ghex_toAscii` / `ghex_stream` | Hex ⇄ ASCII helpers |
| `classify_addr` / `VMMAP` | Label a raw pointer by memory region |
| `gshellc` | Write hex-encoded shellcode to a file |

## Documentation

The table above is the highlight reel — for full parameter-by-parameter docs,
a walkthrough of `template.py`, and the current known-issues / roadmap list,
see **[docs/REFERENCE.md](docs/REFERENCE.md)**.

## Status

This is a personal toolkit that grows as I hit new CTF challenges — it's
solid for format-string recon today, with heap helpers, a `%n`-write payload
builder, and raw-assembly shellcode support planned next. Rough edges are
called out honestly in the [reference docs](docs/REFERENCE.md#roadmap--known-issues)
rather than hidden.
