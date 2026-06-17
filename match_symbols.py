#!/usr/bin/env python3
"""
match_symbols.py — Extract function signatures from a reference ELF (with symbols)
and locate them in a stripped binary (same toolchain, different addresses).

Emits a Ghidra Jython script that applies all matched labels + function names
when run inside Ghidra on the stripped binary.

Usage:
    pip install pyelftools
    python3 match_symbols.py <reference.elf> <stripped.elf> [output_ghidra.py]

The reference ELF must have a symbol table (.symtab or .dynsym).
The stripped ELF is the one you have open in Ghidra.
"""

import sys
import argparse
from dataclasses import dataclass
from typing import Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit("pyelftools not found. Run: pip install pyelftools")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Bytes sampled from the start of each function for matching.
# Longer = fewer false positives but more sensitivity to minor code changes.
SIG_LENGTH = 32

# Minimum bytes required to attempt a match at all.
MIN_SIG_BYTES = 12

# Wildcarded opcodes for Xtensa (ESP32): call0/call4/call8/call12 and l32r.
# These embed relative offsets that differ between binaries even for identical code.
# Format: (first_byte_mask, first_byte_value, instruction_length, wildcard_from_byte)
#   We match on the low nibble of byte 0 to identify the opcode family.
XTENSA_WILDCARD_OPCODES = [
    # CALL0 / CALL4 / CALL8 / CALL12: 3-byte, low nibble = 0x5
    (0x0F, 0x05, 3, 1),
    # L32R: 3-byte, low nibble = 0x1 (RI16 format, byte 0 bits[3:0] == 0x1)
    (0x0F, 0x01, 3, 1),
    # J (jump): 3-byte, low nibble = 0x6
    (0x0F, 0x06, 3, 1),
]

# If True, skip symbols with auto-generated-looking names.
SKIP_AUTO_NAMES = True

import re
AUTO_NAME_RE = re.compile(r'^(FUN_|SUB_|sub_|loc_|DAT_|off_|LAB_|thunk_|\$)', re.I)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FuncSig:
    name: str
    pattern: bytes   # raw bytes (0x00 where wildcarded)
    mask: bytes      # 0xFF = fixed, 0x00 = wildcard
    ref_addr: int    # address in reference binary (for logging)
    size: int        # original function size


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

def load_elf_segments(elf: ELFFile) -> list[tuple[int, bytes]]:
    """Return list of (vaddr, data) for all LOAD segments."""
    segments = []
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD" and seg.header.p_filesz > 0:
            segments.append((seg.header.p_vaddr, seg.data()))
    return segments


def vaddr_to_bytes(segments: list[tuple[int, bytes]], addr: int, length: int) -> Optional[bytes]:
    """Read `length` bytes at virtual address `addr` from loaded segments."""
    for base, data in segments:
        offset = addr - base
        if 0 <= offset < len(data):
            end = min(offset + length, len(data))
            chunk = data[offset:end]
            return chunk if len(chunk) >= MIN_SIG_BYTES else None
    return None


def iter_functions(elf: ELFFile):
    """Yield (name, addr, size) for all STT_FUNC symbols with known size."""
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for sym in section.iter_symbols():
            if sym.entry.st_info.type != "STT_FUNC":
                continue
            name = sym.name
            addr = sym.entry.st_value
            size = sym.entry.st_size
            if not name or addr == 0:
                continue
            yield name, addr, size


# ---------------------------------------------------------------------------
# Signature building
# ---------------------------------------------------------------------------

def make_signature(raw: bytes, arch: str) -> Optional["FuncSig"]:
    """Build a masked signature, wildcarding call/jump targets for Xtensa."""
    pat = bytearray(raw)
    msk = bytearray(b'\xff' * len(raw))

    if arch in ("EM_XTENSA",):
        i = 0
        while i < len(pat):
            b = pat[i]
            for first_mask, first_val, ilen, wc_from in XTENSA_WILDCARD_OPCODES:
                if (b & first_mask) == first_val and i + ilen <= len(pat):
                    for j in range(wc_from, ilen):
                        msk[i + j] = 0x00
                        pat[i + j] = 0x00
                    i += ilen
                    break
            else:
                i += 1  # no opcode matched, advance one byte

    fixed = sum(1 for m in msk if m == 0xFF)
    if fixed < MIN_SIG_BYTES:
        return None

    return FuncSig(
        name="",
        pattern=bytes(pat),
        mask=bytes(msk),
        ref_addr=0,
        size=0,
    )


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def compile_pattern(pattern: bytes, mask: bytes):
    """
    Compile a masked byte pattern into a regex. Wildcarded bytes (mask byte == 0x00)
    become '.', fixed bytes are escaped literals. Wrapped in a zero-width lookahead
    so the regex engine still reports overlapping matches, same as a manual
    byte-by-byte sliding window would -- but at C speed instead of Python speed.
    """
    parts = []
    for p, m in zip(pattern, mask):
        if m == 0xFF:
            parts.append(re.escape(bytes([p])))
        else:
            parts.append(b'.')
    return re.compile(b'(?=' + b''.join(parts) + b')', re.DOTALL)


def search_pattern(haystack: bytes, compiled) -> list[int]:
    """
    Search for a pre-compiled masked pattern (see compile_pattern) in haystack.
    Returns up to 2 matching byte offsets (we only care about unique vs ambiguous).
    """
    hits = []
    for mo in compiled.finditer(haystack):
        hits.append(mo.start())
        if len(hits) > 1:
            break
    return hits


def match_signatures(
    sigs: list[FuncSig],
    target_segments: list[tuple[int, bytes]],
) -> list[tuple[FuncSig, int]]:
    """
    For each signature, search all LOAD segments of the target binary.
    Returns list of (sig, matched_vaddr) for unique matches only.
    """
    # Flatten target into one searchable buffer per segment to preserve vaddrs
    results = []
    for sig in sigs:
        compiled = compile_pattern(sig.pattern, sig.mask)
        all_hits = []
        for base, data in target_segments:
            offsets = search_pattern(data, compiled)
            for off in offsets:
                all_hits.append(base + off)
                if len(all_hits) > 1:
                    break
            if len(all_hits) > 1:
                break

        if len(all_hits) == 1:
            results.append((sig, all_hits[0]))

    return results


# ---------------------------------------------------------------------------
# Ghidra script emission
# ---------------------------------------------------------------------------

GHIDRA_SCRIPT_HEADER = '''\
# Auto-generated by match_symbols.py — run inside Ghidra on the stripped binary.
# Script applies {n_matches} matched function names from the reference binary.
#
# @category Analysis

from ghidra.program.model.symbol import SourceType

fm  = currentProgram.getFunctionManager()
st  = currentProgram.getSymbolTable()
af  = currentProgram.getAddressFactory()

def apply_name(addr_int, name):
    addr = af.getDefaultAddressSpace().getAddress(addr_int)
    func = fm.getFunctionAt(addr)
    if func is None:
        func = fm.createFunction(name, addr, None, SourceType.IMPORTED)
    else:
        func.setName(name, SourceType.IMPORTED)

'''

def emit_ghidra_script(matches: list[tuple[FuncSig, int]], out_path: str):
    lines = [GHIDRA_SCRIPT_HEADER.format(n_matches=len(matches))]
    for sig, vaddr in sorted(matches, key=lambda x: x[1]):
        name = sig.name.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'apply_name(0x{vaddr:08x}, "{name}")')
    lines.append('\nprint("Done. Applied %d names." % ' + str(len(matches)) + ')\n')
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"[+] Ghidra script written to: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global SIG_LENGTH, MIN_SIG_BYTES
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("reference", help="ELF with symbols (upstream/reference build)")
    parser.add_argument("stripped",  help="Stripped ELF (your fork)")
    parser.add_argument("output",    nargs="?", default="apply_symbols.py",
                        help="Output Ghidra script path (default: apply_symbols.py)")
    parser.add_argument("--sig-length", type=int, default=SIG_LENGTH,
                        help=f"Signature length in bytes (default: {SIG_LENGTH})")
    parser.add_argument("--min-fixed",  type=int, default=MIN_SIG_BYTES,
                        help=f"Minimum non-wildcarded bytes (default: {MIN_SIG_BYTES})")
    args = parser.parse_args()

    SIG_LENGTH   = args.sig_length
    MIN_SIG_BYTES = args.min_fixed

    # --- Load reference ELF --------------------------------------------------
    print(f"[*] Loading reference ELF: {args.reference}")
    with open(args.reference, "rb") as f:
        ref_elf = ELFFile(f)
        arch = ref_elf["e_machine"]
        print(f"    Architecture: {arch}")
        ref_segs = load_elf_segments(ref_elf)

        sigs: list[FuncSig] = []
        skipped = no_bytes = no_sig = 0

        for name, addr, size in iter_functions(ref_elf):
            if SKIP_AUTO_NAMES and AUTO_NAME_RE.match(name):
                skipped += 1
                continue

            sample_len = min(SIG_LENGTH, size) if size > 0 else SIG_LENGTH
            raw = vaddr_to_bytes(ref_segs, addr, sample_len)
            if raw is None:
                no_bytes += 1
                continue

            sig = make_signature(raw, arch)
            if sig is None:
                no_sig += 1
                continue

            sig.name     = name
            sig.ref_addr = addr
            sig.size     = size
            sigs.append(sig)

    print(f"    Functions found  : {len(sigs) + skipped + no_bytes + no_sig}")
    print(f"    Skipped (auto)   : {skipped}")
    print(f"    No bytes         : {no_bytes}")
    print(f"    Too few fixed B  : {no_sig}")
    print(f"    Signatures built : {len(sigs)}")

    # --- Load target (stripped) ELF -----------------------------------------
    print(f"\n[*] Loading stripped ELF: {args.stripped}")
    with open(args.stripped, "rb") as f:
        tgt_elf  = ELFFile(f)
        tgt_segs = load_elf_segments(tgt_elf)
    total_target_bytes = sum(len(d) for _, d in tgt_segs)
    print(f"    LOAD segments    : {len(tgt_segs)}  ({total_target_bytes:,} bytes)")

    # --- Match ---------------------------------------------------------------
    print(f"\n[*] Matching {len(sigs)} signatures against target...")
    matches = match_signatures(sigs, tgt_segs)

    print(f"    Unique matches   : {len(matches)}")
    print(f"    Not matched      : {len(sigs) - len(matches)}  (ambiguous or absent)")

    if not matches:
        print("\n[!] No matches found. Tips:")
        print("    - Check that both ELFs target the same architecture")
        print("    - Try --sig-length 16 --min-fixed 8 for more permissive matching")
        print("    - Verify the reference ELF has a .symtab section (nm -n reference.elf)")
        return 1

    # --- Emit Ghidra script --------------------------------------------------
    emit_ghidra_script(matches, args.output)
    print(f"\n[*] To use: open the stripped binary in Ghidra, then run the generated script")
    print(f"    via Script Manager (Window → Script Manager → Run Script).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
