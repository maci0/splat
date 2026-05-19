#! /usr/bin/env python3

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
from typing import List, Optional

from ..util.n64 import find_code_length, rominfo
from ..util.psx import psxexeinfo
from ..util.ps2 import ps2elfinfo
from ..util import log, file_presets, conf


def main(file_path: Path, objcopy: Optional[str]):
    if not file_path.exists():
        sys.exit(f"File {file_path} does not exist ({file_path.absolute()})")
    if file_path.is_dir():
        sys.exit(f"Path {file_path} is a directory ({file_path.absolute()})")

    # Check for N64 ROM
    if file_path.suffix.lower() == ".n64" or file_path.suffix.lower() == ".z64":
        create_n64_config(file_path)
        return

    file_bytes = file_path.read_bytes()

    # Check for PSX executable
    if file_bytes[0:8] == b"PS-X EXE":
        create_psx_config(file_path, file_bytes)
        return

    # Check for ELFs
    if file_bytes[0:4] == b"\x7fELF":
        do_elf(file_path, file_bytes, objcopy)
        return

    # Check for Win32 PE
    if file_bytes[0:2] == b"MZ" and len(file_bytes) >= 0x40:
        pe_off = int.from_bytes(file_bytes[0x3C:0x40], "little")
        if pe_off + 4 <= len(file_bytes) and file_bytes[pe_off : pe_off + 4] == b"PE\x00\x00":
            create_win32_config(file_path, file_bytes)
            return

    log.error(f"create_config does not support the file format of '{file_path}'")


def remove_invalid_path_characters(p: str) -> str:
    invalid_characters = ["<", ">", ":", '"', "/", "\\", "|", "?", "*"]
    for invalid in invalid_characters:
        p = p.replace(invalid, "_")
    return p


def create_n64_config(rom_path: Path):
    rom_bytes = rominfo.read_rom(rom_path)

    rom = rominfo.get_info(rom_path, rom_bytes)
    basename = rom.name.replace(" ", "").lower()
    cleaned_basename = remove_invalid_path_characters(basename)

    header = f"""\
name: {rom.name.title()} ({rom.get_country_name()})
sha1: {rom.sha1}
options:
  basename: {basename}
  target_path: {rom_path.with_suffix(".z64")}
  elf_path: build/{cleaned_basename}.elf
  base_path: .
  platform: n64
  compiler: {rom.compiler}

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True

  find_file_boundaries: True
  header_encoding: {rom.header_encoding}

  o_as_suffix: True
  use_legacy_include_asm: False
  mips_abi_float_regs: o32

  # section_order: [".text", ".data", ".rodata", ".bss"]
  # auto_link_sections: [".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  # string_encoding: ASCII
  # data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2
  # libultra_symbols: True
  # hardware_regs: True
  # gfx_ucode: # one of [f3d, f3db, f3dex, f3dexb, f3dex2]
"""

    # Start analysing after the entrypoint segment.
    first_section_end = find_code_length.run(
        rom_bytes, 0x1000 + rom.entrypoint_info.segment_size(), rom.entry_point
    )

    extra_message = ""
    if not rom.entrypoint_info.traditional_entrypoint:
        extra_message = " # This game uses a non-traditional entrypoint, meaning splat's analysis may be wrong"

    segments = f"""\
segments:
  - name: header
    type: header
    start: 0x0

  - name: ipl3
    type: bin
    start: 0x40

  - name: entry{extra_message}
    type: code
    start: 0x1000
    vram: 0x{rom.entry_point:X}
    subsegments:
      - [0x1000, hasm]
"""
    if rom.entrypoint_info.data_size is not None:
        segments += f"""\
      - [0x{0x1000 + rom.entrypoint_info.entry_size:X}, data]
"""

    main_rom_start = 0x1000 + rom.entrypoint_info.segment_size()
    segments += f"""\

  - name: main
    type: code
    start: 0x{main_rom_start:X}
    vram: 0x{rom.entry_point + rom.entrypoint_info.segment_size():X}
    follows_vram: entry
"""

    if rom.entrypoint_info.bss_size is not None:
        segments += f"""\
    bss_size: 0x{rom.entrypoint_info.bss_size.value:X}
"""

    segments += f"""\
    subsegments:
      - [0x{main_rom_start:X}, asm]
"""

    if (
        rom.entrypoint_info.bss_size is not None
        and rom.entrypoint_info.bss_start_address is not None
        and first_section_end > main_rom_start
    ):
        bss_start = (
            rom.entrypoint_info.bss_start_address.value - rom.entry_point + 0x1000
        )
        # first_section_end points to the start of data
        segments += f"""\
      - [0x{first_section_end:X}, data]
      - {{ type: bss, vram: 0x{rom.entrypoint_info.bss_start_address.value:08X} }}
"""
        # Point next segment to the detected end of the main one
        first_section_end = bss_start

    if first_section_end > main_rom_start:
        segments += f"""\

  - type: bin
    start: 0x{first_section_end:X}
    follows_vram: main
"""

    segments += f"""\

  - [0x{rom.size:X}]
"""

    out_file = Path(f"{cleaned_basename}.yaml")
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)

    # `file_presets` requires an initialized `opts`.
    # A simple way to do that is to simply load the yaml we just generated.
    conf.load([out_file])
    file_presets.write_all_files()

    # Write reloc_addrs.txt file
    reloc_addrs: list[str] = []

    addresses_info: list[tuple[Optional[rominfo.EntryAddressInfo], str]] = [
        (rom.entrypoint_info.main_address, "main"),
        (rom.entrypoint_info.bss_start_address, "main_BSS_START"),
        (rom.entrypoint_info.bss_size, "main_BSS_SIZE"),
        (rom.entrypoint_info.bss_end_address, "main_BSS_END"),
    ]

    for addr_info, sym_name in addresses_info:
        if addr_info is None:
            continue
        if addr_info.ori:
            # Avoid emitting relocations for `ori`s since `%lo` doesn't support it.
            continue
        if addr_info.rom_hi == addr_info.rom_lo:
            # hi and lo may be the same for the "main" address, i.e. a direct jal.
            continue

        reloc_addrs.append(
            f"rom:0x{addr_info.rom_hi:06X} reloc:MIPS_HI16 symbol:{sym_name}"
        )
        reloc_addrs.append(
            f"rom:0x{addr_info.rom_lo:06X} reloc:MIPS_LO16 symbol:{sym_name}"
        )
        reloc_addrs.append("")

    if (
        rom.entrypoint_info.stack_top is not None
        and not rom.entrypoint_info.stack_top.ori
    ):
        reloc_addrs.append(
            '// This entry corresponds to the "stack top", which is the end of the array used as the stack for the main segment.'
        )
        reloc_addrs.append(
            "// It is commented out because it was not possible to infer what the start of the stack symbol is, so you'll have to figure it out by yourself."
        )
        reloc_addrs.append(
            "// Once you have found it you can properly name it and specify the length of this stack as the addend value here."
        )
        reloc_addrs.append(
            f"// The address of the end of the stack is 0x{rom.entrypoint_info.stack_top.value:08X}."
        )
        reloc_addrs.append(
            f"// A common size for this stack is 0x2000, so try checking for the address 0x{rom.entrypoint_info.stack_top.value - 0x2000:08X}. Note the stack may have a different size."
        )
        reloc_addrs.append(
            f"// rom:0x{rom.entrypoint_info.stack_top.rom_hi:06X} reloc:MIPS_HI16 symbol:main_stack addend:0xXXXX"
        )
        reloc_addrs.append(
            f"// rom:0x{rom.entrypoint_info.stack_top.rom_lo:06X} reloc:MIPS_LO16 symbol:main_stack addend:0xXXXX"
        )
        reloc_addrs.append("")
    if reloc_addrs:
        with Path("reloc_addrs.txt").open("w", encoding="utf-8", newline="\n") as f:
            print("Writing reloc_addrs.txt")
            f.write(
                "// Visit https://github.com/ethteck/splat/wiki/Advanced-Reloc for documentation about this file\n"
            )
            f.write("// entrypoint relocs\n")
            contents = "\n".join(reloc_addrs)
            f.write(contents)

    # Write symbol_addrs.txt file
    symbol_addrs = []
    symbol_addrs.append(f"entrypoint = 0x{rom.entry_point:08X}; // type:func")
    if rom.entrypoint_info.main_address is not None:
        symbol_addrs.append(
            f"main = 0x{rom.entrypoint_info.main_address.value:08X}; // type:func"
        )
    if symbol_addrs:
        symbol_addrs.append("")
        with Path("symbol_addrs.txt").open("w", encoding="utf-8", newline="\n") as f:
            print("Writing symbol_addrs.txt")
            f.write(
                "// Visit https://github.com/ethteck/splat/wiki/Adding-Symbols for documentation about this file\n"
            )
            contents = "\n".join(symbol_addrs)
            f.write(contents)


def create_psx_config(exe_path: Path, exe_bytes: bytes):
    exe = psxexeinfo.PsxExe.get_info(exe_path, exe_bytes)
    basename = exe_path.name.replace(" ", "").lower()
    cleaned_basename = remove_invalid_path_characters(basename)

    header = f"""\
name: {exe_path.name}
sha1: {exe.sha1}
options:
  basename: {basename}
  target_path: {exe_path}
  elf_path: build/{cleaned_basename}.elf
  base_path: .
  platform: psx
  compiler: PSYQ

  # asm_path: asm
  # src_path: src
  # build_path: build
  # create_asm_dependencies: True

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True

  find_file_boundaries: False
  gp_value: 0x{exe.initial_gp:08X}
  # ld_gp_expression: main_SCOMMON_START + 0x7FF0

  o_as_suffix: True
  use_legacy_include_asm: False

  section_order: [".rodata", ".text", ".data", ".bss"]
  # auto_link_sections: [".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  subalign: 2

  string_encoding: ASCII
  data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2

  # Uncomment this line if you need to use the maspsx reorder workaround hack
  # https://github.com/mkst/maspsx?tab=readme-ov-file#include_asm-reordering-workaround-hack
  # include_asm_macro_style: maspsx_hack
"""

    segments = f"""\
segments:
  - name: header
    type: header
    start: 0x0

  - name: main
    type: code
    start: 0x800
    vram: 0x{exe.destination_vram:X}
    # bss_size: Please fill out this value when you figure out the bss size
    subsegments:
"""
    text_offset = exe.text_offset
    if text_offset != 0x800:
        segments += """\
      - [0x800, rodata, 800]
"""
    segments += f"""\
      - [0x{text_offset:X}, asm, {text_offset:X}] # estimated
"""

    if exe.data_offset != 0:
        data_offset = exe.data_offset
        segments += f"""\
      - [0x{data_offset:X}, data, {data_offset:X}] # estimated
"""

    segments += f"""\
  - [0x{exe.size:X}]
"""

    out_file = Path(f"{cleaned_basename}.yaml")
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)

    # `file_presets` requires an initialized `opts`.
    # A simple way to do that is to simply load the yaml we just generated.
    conf.load([out_file])
    file_presets.write_all_files()


def create_win32_config(exe_path: Path, exe_bytes: bytes):
    from ..platforms.win32 import parse_pe, SCN_CNT_CODE, SCN_CNT_UNINITIALIZED_DATA, SCN_MEM_EXECUTE, SCN_MEM_WRITE

    pe = parse_pe(exe_bytes)
    basename = exe_path.name.replace(" ", "").lower()
    cleaned_basename = remove_invalid_path_characters(basename)

    sha1 = hashlib.sha1(exe_bytes).hexdigest()

    # Quote paths to survive YAML special characters (spaces, ':', '#'
    # are all syntactically meaningful when unquoted).
    def _yaml_quote(s: object) -> str:
        text = str(s)
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    header = f"""\
# name: {exe_path.name}
sha1: {sha1}
options:
  basename: {basename}
  target_path: {_yaml_quote(exe_path)}
  base_path: .
  platform: win32
  compiler: MSVC6

  # asm_path: asm
  # src_path: src
  # build_path: build

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True

  o_as_suffix: True

  section_order: [".text", ".rdata", ".data", ".rodata", ".bss"]

  symbol_addrs_path:
    - symbol_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  string_encoding: ASCII
  data_string_encoding: ASCII
"""

    # First raw byte of the first non-NOLOAD section delimits the header.
    first_raw = min(
        (s.raw_pointer for s in pe.sections if s.raw_size > 0),
        default=pe.size_of_headers,
    )

    segments = "\nsegments:\n"
    segments += f"""\
  - name: header
    type: header
    start: 0x0

"""

    # Order sections by file position so segments stay monotonically
    # increasing in rom_start (splat requires this).
    file_sections = sorted(
        (s for s in pe.sections if s.raw_size > 0),
        key=lambda s: s.raw_pointer,
    )
    bss_sections = [
        s
        for s in pe.sections
        if s.raw_size == 0
        and (s.characteristics & SCN_CNT_UNINITIALIZED_DATA)
    ]

    # Disambiguate duplicate section names (PE spec doesn't require
    # uniqueness; some packers and hand-crafted images have repeats).
    seen_names: dict = {}

    def _unique_name(raw: str) -> str:
        n = remove_invalid_path_characters(raw.lstrip(".") or "section")
        count = seen_names.get(n, 0)
        seen_names[n] = count + 1
        return n if count == 0 else f"{n}_{count}"

    for s in file_sections:
        # Derive a sensible subsegment type from the section flags.
        if s.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE):
            sub_type = "text"
        elif s.characteristics & SCN_MEM_WRITE:
            sub_type = "data"
        else:
            sub_type = "rodata"

        safe_name = _unique_name(s.name)
        vram = pe.image_base + s.virtual_address
        segments += f"""\
  - name: {safe_name}
    type: code
    start: 0x{s.raw_pointer:X}
    vram: 0x{vram:08X}
    subsegments:
      - [0x{s.raw_pointer:X}, {sub_type}, {safe_name}_main]

"""

        # Virtual-only tail: file-backed section that extends in memory
        # past its raw bytes (MSVC zero-init globals). Model as a BSS
        # segment so the linker layout matches the runtime image.
        if s.virtual_size > s.raw_size and s.characteristics & SCN_MEM_WRITE:
            tail_vram = pe.image_base + s.virtual_address + s.raw_size
            tail_size = s.virtual_size - s.raw_size
            segments += f"""\
  - {{ name: {safe_name}_bss, type: bss, vram: 0x{tail_vram:08X}, bss_size: 0x{tail_size:X} }}

"""

    for s in bss_sections:
        # Sections claiming "uninitialized data" with VirtualSize 0 carry
        # no runtime footprint — skip rather than emit `bss_size: 0x0`
        # which splat treats as a malformed segment.
        if s.virtual_size == 0:
            continue
        safe_name = _unique_name(s.name or "bss")
        vram = pe.image_base + s.virtual_address
        segments += f"""\
  - {{ name: {safe_name}, type: bss, vram: 0x{vram:08X}, bss_size: 0x{s.virtual_size:X} }}

"""

    segments += f"  - [0x{len(exe_bytes):X}]\n"

    out_file = Path(f"{cleaned_basename}.yaml")
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)

    conf.load([out_file])
    file_presets.write_all_files()

    # Stash the entry point and any exported function as known symbols so
    # the disassembly labels them. Some DLLs are built without DllMain and
    # leave AddressOfEntryPoint = 0 — skip the entrypoint symbol in that
    # case so we don't emit a label pointing at the PE header.
    from ..platforms import win32 as _w32
    _sanitize_id = _w32.sanitize_label

    symbol_addrs: List[str] = []
    if pe.entry_point_rva:
        symbol_addrs.append(
            f"entrypoint = 0x{pe.entry_point_va:08X}; // type:func"
        )
    export_labels = _w32.compute_export_labels(
        pe, reserved={"entrypoint"} if pe.entry_point_rva else set()
    )
    # Build a {ordinal: label} lookup so we can emit them in iteration
    # order while still using the centralised dedup-aware map.
    va_to_label = export_labels
    if pe.exports:
        symbol_addrs.append("")
        symbol_addrs.append(f"// Exports from {pe.export_dll_name or exe_path.name}")
        for exp in pe.exports:
            if exp.forwarder is not None:
                continue
            va = pe.image_base + exp.rva
            safe = va_to_label.get(va)
            if safe is None:
                continue
            trailing = f"// type:func -- ordinal {exp.ordinal}"
            if exp.name and safe != exp.name:
                trailing += f" (original {exp.name})"
            symbol_addrs.append(f"{safe} = 0x{va:08X}; {trailing}")
        forwarders = [e for e in pe.exports if e.forwarder is not None]
        if forwarders:
            symbol_addrs.append("")
            symbol_addrs.append("// Forwarded exports (live outside this DLL)")
            for exp in forwarders:
                name = exp.name or f"export_{exp.ordinal}"
                safe = _sanitize_id(name)
                # No real VA — record as a comment so users see the mapping.
                symbol_addrs.append(
                    f"// {safe}  ->  {exp.forwarder}  (ordinal {exp.ordinal})"
                )

    iat_labels = _w32.compute_iat_labels(pe)
    if pe.imports:
        symbol_addrs.append("")
        symbol_addrs.append("// IAT slots (each `call dword ptr [<va>]` reaches one of these)")
        for imp in pe.imports:
            slot_va = pe.image_base + imp.iat_rva
            full = iat_labels.get(slot_va)
            if full is None or not full.startswith("imp_"):
                continue
            trailing = f"// type:u32 -- import from {imp.dll}"
            if imp.ordinal is not None:
                trailing += f" ordinal {imp.ordinal}"
            symbol_addrs.append(f"{full} = 0x{slot_va:08X}; {trailing}")

    if pe.delay_imports:
        symbol_addrs.append("")
        symbol_addrs.append("// Delay-load IAT slots (resolved on first call via __delayLoadHelper2)")
        for imp in pe.delay_imports:
            slot_va = pe.image_base + imp.iat_rva
            full = iat_labels.get(slot_va)
            if full is None or not full.startswith("dimp_"):
                continue
            trailing = f"// type:u32 -- delay-loaded import from {imp.dll}"
            if imp.ordinal is not None:
                trailing += f" ordinal {imp.ordinal}"
            symbol_addrs.append(f"{full} = 0x{slot_va:08X}; {trailing}")
    symbol_addrs.append("")
    with Path("symbol_addrs.txt").open("w", encoding="utf-8", newline="\n") as f:
        print("Writing symbol_addrs.txt")
        f.write(
            "// Visit https://github.com/ethteck/splat/wiki/Adding-Symbols for documentation about this file\n"
        )
        f.write("\n".join(symbol_addrs))


def do_elf(elf_path: Path, elf_bytes: bytes, objcopy: Optional[str]):
    elf = ps2elfinfo.Ps2Elf.get_info(elf_path, elf_bytes)
    if elf is None:
        log.error(f"Unsupported elf file '{elf_path}'")

    basename = elf_path.name.replace(" ", "")
    cleaned_basename = remove_invalid_path_characters(basename)

    rom_name = Path(f"{cleaned_basename}.rom")
    # Prefer the user objcopy
    if objcopy is None:
        objcopy = find_objcopy()
    objcopy_cmd = run_objcopy(objcopy, str(elf_path), str(rom_name))

    sha1 = hashlib.sha1(rom_name.read_bytes()).hexdigest()

    header = f"""\
# name: Your game name here!
sha1: {sha1}
options:
  basename: {basename}
  target_path: {rom_name}
  elf_path: build/{cleaned_basename}.elf
  base_path: .
  platform: ps2
  compiler: {elf.compiler}
"""

    if elf.gp is not None:
        header += f"""
  gp_value: 0x{elf.gp:08X}
"""
        if elf.ld_gp_expression is not None:
            header += f"  ld_gp_expression: {elf.ld_gp_expression}\n"
        else:
            header += "  # ld_gp_expression:\n"

    header += f"""
  # asm_path: asm
  # src_path: src
  # build_path: build

  ld_script_path: {cleaned_basename}.ld
  ld_dependencies: True
  ld_wildcard_sections: True
  ld_bss_contains_common: True

  create_asm_dependencies: True

  find_file_boundaries: False

  o_as_suffix: True

  symbol_addrs_path:
    - symbol_addrs.txt
  reloc_addrs_path:
    - reloc_addrs.txt

  # undefined_funcs_auto_path: undefined_funcs_auto.txt
  # undefined_syms_auto_path: undefined_syms_auto.txt

  extensions_path: tools/splat_ext

  string_encoding: ASCII
  data_string_encoding: ASCII
  rodata_string_guesser_level: 2
  data_string_guesser_level: 2

  named_regs_for_c_funcs: False
"""

    header += "\n  section_order:\n"
    for sect, is_valid in elf.elf_section_names:
        comment = "" if is_valid else "# "
        header += f"    {comment}- {sect}\n"

    header += "\n  auto_link_sections:\n"
    for sect, is_valid in elf.elf_section_names:
        comment = "" if is_valid else "# "
        if sect != ".text" and sect != ".vutext":
            header += f"    {comment}- {sect}\n"

    segments = "\nsegments:"
    for seg in elf.segs:
        segments += f"""
  - name: {seg.name}
    type: code
    start: 0x{seg.start:06X}
    vram: 0x{seg.vram:08X}
    bss_size: 0x{seg.bss_size:X}
    subalign: null
    subsegments:
"""
        for section in seg.sections:
            if section.is_nobits:
                segments += f"      - {{ type: {section.splat_segment_type}, vram: 0x{section.vram:08X}, name: {seg.name}/{section.vram:08X} }} # {section.name}\n"
            else:
                segments += f"      - [0x{section.start:06X}, {section.splat_segment_type}, {seg.name}/{section.start:06X}] # {section.name}\n"

    segments += f"""\
  - [0x{elf.size:X}]
"""

    out_file = Path(f"{cleaned_basename}.yaml")
    with out_file.open("w", encoding="utf-8", newline="\n") as f:
        print(f"Writing config to {out_file}")
        f.write(header)
        f.write(segments)

    # `file_presets` requires an initialized `opts`.
    # A simple way to do that is to simply load the yaml we just generated.
    conf.load([out_file])
    file_presets.write_all_files()

    # Write symbol_addrs.txt file
    symbol_addrs = []
    symbol_addrs.append(f"_start = 0x{elf.entrypoint:08X}; // type:func")
    if symbol_addrs:
        symbol_addrs.append("")
        with Path("symbol_addrs.txt").open("w", encoding="utf-8", newline="\n") as f:
            print("Writing symbol_addrs.txt")
            f.write(
                "// Visit https://github.com/ethteck/splat/wiki/Adding-Symbols for documentation about this file\n"
            )
            contents = "\n".join(symbol_addrs)
            f.write(contents)

    # Write other linker script
    linker_script = []
    linker_script.append("ENTRY(_start);")
    if linker_script:
        linker_script.append("")
        with Path("linker_script_extra.ld").open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as f:
            print("Writing linker_script_extra.ld")
            f.write(
                "/* Pass this file to the linker with the `-T linker_script_extra.ld` flag */\n"
            )
            contents = "\n".join(linker_script)
            f.write(contents)

    print()
    print(
        "The generated yaml does not use the actual ELF file as input, but instead it"
    )
    print(
        'uses a "rom" generated from said ELF, which contains the game code without any'
    )
    print("of the elf metadata.")
    print(
        'Use the following command to generate this "rom". It is recommended to include'
    )
    print("this command into your setup/configure script.")
    print("```")
    print(" ".join(objcopy_cmd))
    print("```")


def find_objcopy() -> str:
    # First we try to figure out if the user has objcopy on their pc, and under
    # which name.
    # We just try a bunch and hope for the best
    options = [
        "mips-linux-gnu-objcopy",
        "mipsel-linux-gnu-objcopy",
    ]

    for name in options:
        sub = subprocess.run([name, "--version"], capture_output=True)
        if sub.returncode == 0:
            return name

    msg = "Unable to find objcopy.\nI tried the following list of names:\n"
    for name in options:
        msg += f"  - {name}\n"
    msg += "\nTry to install one of those or use the `--objcopy` flag to pass the name to your own objcopy to me."
    log.error(msg)


def run_objcopy(objcopy_name: str, elf_path: str, rom: str) -> list[str]:
    cmd = [objcopy_name, "-O", "binary", "--gap-fill=0x00", elf_path, rom]
    print("Running:", " ".join(cmd))
    sub = subprocess.run(cmd)
    if sub.returncode != 0:
        log.error("Failed to run objcopy")
    return cmd


def add_arguments_to_parser(parser: argparse.ArgumentParser):
    parser.add_argument(
        "file",
        help="Path to a .z64/.n64 ROM, PSX executable, PS2 ELF, or Win32 PE",
        type=Path,
    )
    parser.add_argument(
        "--objcopy",
        help="Path to an user-provided objcopy program. Only used when processing ELF files",
        type=str,
    )


def process_arguments(args: argparse.Namespace):
    main(args.file, args.objcopy)


script_description = (
    "Create a splat config from an N64 ROM, PSX executable, PS2 ELF, or Win32 PE."
)


def add_subparser(subparser: argparse._SubParsersAction):
    parser = subparser.add_parser(
        "create_config", help=script_description, description=script_description
    )
    add_arguments_to_parser(parser)
    parser.set_defaults(func=process_arguments)


parser = argparse.ArgumentParser(description=script_description)
add_arguments_to_parser(parser)

if __name__ == "__main__":
    args = parser.parse_args()
    process_arguments(args)
