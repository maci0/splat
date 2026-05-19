"""Reassemble a splat-split win32 PE back into a single PE/EXE/DLL.

Pipeline (no ld needed — GAS + objcopy is enough since each split .s
file is positioned at the right file-offset by the YAML's segment
ordering):

  1. Parse the YAML to discover segment order + rom_start offsets.
  2. For each .s segment: `as` to ELF, `objcopy -O binary -j <linker_section>`
     to extract the raw bytes that the section would occupy in the PE.
  3. For each `.bin` asset: read the raw bytes directly.
  4. Concatenate in rom_start order, padding to each segment's declared
     start offset.
  5. Write the resulting blob — it IS the reassembled PE.

Each `.s` produced by splat uses `.section <name>, "<flags>"` so `as`
emits the bytes verbatim into that named section. The PE header
segment (header.s) carries the full DOS+COFF+optional-header layout,
and every other segment is the matching section payload.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from ..util import log


def _which(cmd: str) -> str:
    found = shutil.which(cmd)
    if not found:
        log.error(
            f"win32_reassemble: required tool '{cmd}' not on PATH — "
            "install binutils (provides as / objcopy)"
        )
    return found


def _read_yaml(yaml_path: Path) -> dict:
    return yaml.safe_load(yaml_path.read_text(encoding="utf-8"))


def _detect_bitness(yaml_path: Path, conf: dict) -> bool:
    """Return True if the source PE is PE32+ (x86_64). Inspect the
    `target_path` binary's optional-header magic."""
    target = conf["options"].get("target_path")
    if not target:
        log.error("win32_reassemble: YAML missing options.target_path")
    opts = conf["options"]
    base_path = (yaml_path.parent / opts.get("base_path", ".")).resolve()
    target_path = (base_path / target).resolve()
    if not target_path.exists():
        log.error(f"win32_reassemble: target binary not found at {target_path}")
    data = target_path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        log.error(f"win32_reassemble: {target_path} is not a PE")
    pe_off = int.from_bytes(data[0x3C:0x40], "little")
    magic = int.from_bytes(data[pe_off + 0x18 : pe_off + 0x1A], "little")
    return magic == 0x20B


# Map a segment's `type:` token to (linker_section, expected_filename_suffix).
# The linker section is what `objcopy -O binary -j` will extract from the
# `as` output.
_SECTION_FOR_TYPE: Dict[str, str] = {
    "header": ".header",
    "text": ".text",
    "code": ".text",  # parent type — payload is in child subsegments
    "data": ".data",
    "rodata": ".rodata",
    "pdata": ".pdata",
    "bss": "__BSS__",  # zero-filled, no .s file
    "bin": "__BIN__",  # raw binary, no .s file
    "asm": ".text",
}


def _walk_segments(conf: dict) -> List[dict]:
    """Flatten the YAML's segment list to a list of leaf segments
    each carrying (name, start, type, linker_section)."""
    out: List[dict] = []
    for seg in conf.get("segments", []):
        if isinstance(seg, list):
            # Position marker — no segment.
            continue
        if not isinstance(seg, dict):
            continue
        s_type = seg.get("type")
        # Code parent → expand to its subsegments.
        if s_type == "code" and "subsegments" in seg:
            for sub in seg["subsegments"]:
                if isinstance(sub, list) and len(sub) >= 3:
                    sub_start, sub_type, sub_name = sub[0], sub[1], sub[2]
                    out.append({
                        "name": sub_name,
                        "start": sub_start,
                        "type": sub_type,
                    })
                elif isinstance(sub, dict):
                    # Inline-dict subsegment form: { start: ..., type: ..., name: ... }
                    out.append({
                        "name": sub.get("name", ""),
                        "start": sub.get("start"),
                        "type": sub.get("type"),
                    })
            continue
        out.append({
            "name": seg.get("name", ""),
            "start": seg.get("start"),
            "type": s_type,
            "vram": seg.get("vram"),
            "bss_size": seg.get("bss_size", 0),
        })
    return out


def _segment_source(
    base_path: Path,
    asm_path: Path,
    data_path: Path,
    asset_path: Path,
    seg: dict,
) -> Optional[Path]:
    """Find the .s or .bin file for a flattened segment, by name."""
    s_type = seg["type"]
    name = seg["name"]
    if s_type == "bss":
        return None
    if s_type == "bin":
        # Splat writes `.bin` under asset_path with the segment name.
        candidate = asset_path / f"{name}.bin"
        if candidate.exists():
            return candidate
        for p in asset_path.rglob(f"{name}.bin"):
            return p
        return None
    # .s files live under asm_path (text/code) or data_path (data/rodata/pdata).
    roots = [asm_path, data_path]
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob(f"{name}.s"):
            return p
    return None


def _extract_section_bytes(
    asm: str,
    objcopy: str,
    s_path: Path,
    section: str,
    mode_flag: str,
    tmpdir: Path,
    verbose: bool,
) -> bytes:
    """Assemble `s_path` and dump the named section's raw bytes."""
    o_path = tmpdir / (s_path.stem + ".o")
    bin_path = tmpdir / (s_path.stem + ".bin")
    _run([asm, mode_flag, str(s_path), "-o", str(o_path)], verbose)
    # Force alloc+load on the target section so `-O binary` doesn't
    # silently emit zero bytes — splat's custom sections (e.g. .header,
    # .pdata without exec) get tagged READONLY-only by GAS and would
    # otherwise be filtered out of the binary dump.
    _run(
        [
            objcopy,
            "--set-section-flags", f"{section}=alloc,load,data",
            "-O", "binary", "-j", section,
            str(o_path), str(bin_path),
        ],
        verbose,
    )
    if not bin_path.exists():
        return b""
    return bin_path.read_bytes()


def _run(
    cmd: List[str], verbose: bool, cwd: Optional[Path] = None
) -> None:
    if verbose:
        prefix = f"(cd {cwd}) " if cwd else ""
        print(f"$ {prefix}" + " ".join(str(c) for c in cmd))
    r = subprocess.run(cmd, capture_output=True, cwd=str(cwd) if cwd else None)
    if r.returncode != 0:
        sys.stderr.write(r.stderr.decode(errors="replace"))
        log.error(f"win32_reassemble: command failed: {cmd[0]}")


def reassemble(yaml_path: Path, out_path: Path, verbose: bool = False) -> Path:
    """Drive the full assemble + objcopy pipeline for a splat-generated
    win32 config. Returns the path to the produced PE."""
    conf = _read_yaml(yaml_path)
    opts = conf["options"]
    base_path = (yaml_path.parent / opts.get("base_path", ".")).resolve()
    asm_path = (base_path / opts.get("asm_path", "asm")).resolve()
    data_path = (base_path / opts.get("data_path", "data")).resolve()
    asset_path = (base_path / opts.get("asset_path", "assets")).resolve()

    is_pe32_plus = _detect_bitness(yaml_path, conf)
    mode_flag = "--64" if is_pe32_plus else "--32"

    asm_tool = _which("as")
    objcopy = _which("objcopy")

    segments = _walk_segments(conf)
    # Sort by start (defensive — YAML order should already be monotonic).
    segments.sort(key=lambda s: (s.get("start") or 0))

    with tempfile.TemporaryDirectory(prefix="splat-reasm-") as td:
        tmpdir = Path(td)
        blob = bytearray()
        prev_end = 0
        for seg in segments:
            start = seg.get("start") or 0
            # Pad with zero up to this segment's rom_start.
            if start > prev_end:
                blob.extend(b"\x00" * (start - prev_end))
                prev_end = start
            elif start < prev_end:
                # BSS segments overlap virtually but have no file presence.
                pass
            s_type = seg["type"]
            section = _SECTION_FOR_TYPE.get(s_type, ".data")
            if section == "__BSS__":
                # Zero-filled, no file bytes.
                continue
            src = _segment_source(base_path, asm_path, data_path, asset_path, seg)
            if src is None:
                if verbose:
                    print(f"  ({seg['name']}: no source — skipping)")
                continue
            if section == "__BIN__":
                payload = src.read_bytes()
            else:
                payload = _extract_section_bytes(
                    asm_tool, objcopy, src, section, mode_flag, tmpdir, verbose
                )
            blob.extend(payload)
            prev_end = start + len(payload)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes(blob))

    if verbose:
        sha = hashlib.sha1(out_path.read_bytes()).hexdigest()
        print(f"Produced {out_path} ({len(out_path.read_bytes())} bytes, sha1 {sha})")

    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Reassemble a splat-split Win32 PE back into a single .exe/.dll"
    )
    parser.add_argument("yaml", type=Path, help="splat YAML config")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output PE path (defaults to <target>.reasm)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    conf = _read_yaml(args.yaml)
    target = conf["options"].get("target_path")
    out_path = args.out
    if out_path is None:
        if not target:
            log.error("win32_reassemble: YAML has no target_path; pass --out")
        base_path = (
            args.yaml.parent / conf["options"].get("base_path", ".")
        ).resolve()
        out_path = Path(str((base_path / target).resolve()) + ".reasm")

    reassemble(args.yaml, out_path, verbose=args.verbose)


if __name__ == "__main__":
    main()
