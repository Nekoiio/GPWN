# Format String Exploit Helper Suite

A full set of helper utilities for scanning format string vulnerabilities, 
retrieving stack leaks, detecting patterns, classifying memory regions, and 
automating leak offset calculations.

Designed for CTFs, exploit dev, and reverse engineering.

---

# Features

- Automated format-string offset discovery (`gfs_off`)
- Full stack enumeration (`gs_lookup`)
- Byte-sequence leak searching (`hit_matcher`)
- Hex → ASCII conversion (`ghex_toAscii`)
- Colored terminal printing (`cprint`)
- Memory region classification from vmmap (`classify_addr`)
- Automated base-offset calculations for leaked pointers (`process_leaks`)

---

# Function Reference

---

## `gfs_off`

**Description**  
Finds the format-string offset where attacker-controlled input appears on the stack.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `p_name` | `str` | Path to binary |
| `architecture` | `int` | 32/64 bit |
| `start_line` | `bytes` | Prompt before sending |
| `recv_line` | `bytes` | Prompt after sending |
| `lim` | `int` | Max positions to test |

**Returns**: `int` — stack offset or `-1`.

---

## `gs_lookup`

**Description**  
Enumerates stack positions using `%N$p` and returns all leaked values.

**Parameters**

Same as `gfs_off`, plus:

| Name | Type | Description |
|------|------|-------------|
| `spec` | `str` | Override formatting (`$p`, `$x`) |
| `lookup` | `bytes` | Auto-triggers hit_matcher |

**Returns**: `list[(index, leak)]`

---

## `hit_matcher`

**Description**  
Searches stack leaks for a target byte sequence or reversed byte sequence.

**Parameters**

- `look` — byte sequence  
- `results` — leak list  
- `direct` — direct mode  
- `direct_ls` — raw leaks  

**Returns**: None — prints matches.

---

## `ghex_toAscii`

**Description**  
Converts hex (int/string) to ASCII. Handles endian reversal.

| Parameter | Description |
|----------|-------------|
| `conv` | int or hex string |
| `end` | `"BIG"` or `"LITTLE"` |

**Returns**: ASCII string.

---

## `cprint`

Color print wrapper with ANSI escape codes.

---

# Memory Mapping & Region Classification

---

## `classify_addr`

**Description**  
Classifies an address into:

- stack  
- heap  
- lib  
- ld  
- vdso / vvar  
- .text  
- .data  
- anonymous executable regions  

**Returns**:  
`(classification: str, (start, end): tuple)`  
or  
`("unknown", None)`

---

## `process_leaks`

**Description**  
Takes all leaks from `gs_lookup`, determines their region with `classify_addr`,  
deduplicates by region, computes offsets, and writes everything to a file.

**Output file format**

```
0xOFFSET 0xLEAK SECTION %index$p 0xSTART-0xEND
```
