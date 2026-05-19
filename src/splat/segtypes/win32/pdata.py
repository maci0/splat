"""Win32 .pdata segment — PE32+ Exception Directory.

The `.pdata` section is an array of `RUNTIME_FUNCTION` records, each
12 bytes: `(BeginAddress, EndAddress, UnwindInfoAddress)` as RVAs. Splat
emits one row per entry with function-target labels resolved so the
table reads as a function map rather than an opaque byte blob.
"""

from pathlib import Path
import struct
from typing import Optional

from ..common.segment import CommonSegment
from ...util import options


class Win32SegPdata(CommonSegment):
    @staticmethod
    def is_rodata() -> bool:
        return True

    @property
    def exact_encoding(self) -> bool:
        """Mirror Win32SegText / Win32SegData semantics: per-subsegment
        YAML wins; falls back to parent code-group YAML. When on, the
        emitted .long uses raw hex RVA values rather than symbolic
        `func_<va> - ImageBase` expressions — necessary for the
        win32_reassemble byte-identical round-trip since cross-segment
        symbols would otherwise resolve to 0 without ld."""
        if isinstance(self.yaml, dict):
            v = self.yaml.get("exact_encoding")
            if v is not None:
                return bool(v)
        if self.parent is not None and isinstance(self.parent.yaml, dict):
            v = self.parent.yaml.get("exact_encoding")
            if v is not None:
                return bool(v)
        return False

    def get_linker_section(self) -> str:
        return ".pdata"

    def get_section_flags(self) -> Optional[str]:
        return "a"

    def out_path(self) -> Path:
        return options.opts.data_path / self.dir / f"{self.name}.s"

    def should_split(self) -> bool:
        return (
            self.extract
            and options.opts.is_mode_active("code")
            and self.rom_start is not None
            and self.rom_end is not None
        )

    def split(self, rom_bytes: bytes):
        if self.rom_start is None or self.rom_end is None:
            return
        if self.rom_start == self.rom_end:
            return

        from ...platforms import win32 as win32_platform
        from ...util import symbols as symbols_mod

        pe = win32_platform.info
        data = rom_bytes[self.rom_start : self.rom_end]
        exact = self.exact_encoding

        def resolve_func_rva(rva: int) -> str:
            """Map a RUNTIME_FUNCTION RVA (a function start, end, or
            interior cold-block address) to the matching splat label.
            Prefers a user-declared symbol_addrs entry; falls back to
            the `func_<va>` convention text segments emit at every
            direct call target so cross-segment links resolve."""
            va = pe.image_base + rva
            entries = symbols_mod.all_symbols_dict.get(va)
            if entries:
                return entries[0].name
            # Pdata entries reference function bodies; cross-segment refs
            # use the same `func_<va>` convention as text segments.
            return f"func_{va:08X}"

        path = self.out_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as f:
            preamble = options.opts.generated_s_preamble
            if preamble:
                f.write(preamble + "\n\n")
            f.write(self.get_section_asm_line() + "\n\n")
            f.write(f".global {self.name}\n")
            f.write(f"{self.name}:\n")

            i = 0
            n = len(data)
            entry_index = 0
            while i + 12 <= n:
                begin, end, unwind = struct.unpack_from("<III", data, i)
                if begin == 0 and end == 0 and unwind == 0:
                    # Null terminator — emit it and switch to a .space
                    # block for any remaining padding so the output isn't
                    # dominated by hundreds of zero rows.
                    f.write(
                        "    .long 0, 0, 0  /* RUNTIME_FUNCTION terminator */\n"
                    )
                    i += 12
                    entry_index += 1
                    pad = n - i
                    if pad > 0:
                        f.write(
                            f"    .space 0x{pad:X}  /* zero padding to section end */\n"
                        )
                    i = n
                    break
                # Unwind RVA emitted as `unwind_<va> - ImageBase` when a
                # matching symbol is registered in symbol_addrs.txt — let
                # the analyst rename it; falls back to raw hex when no
                # such symbol exists (degenerate inputs or chained
                # records masked off in create_config).
                base_uw = unwind & 0x7FFFFFFF
                unwind_label = None
                if base_uw:
                    candidate = symbols_mod.all_symbols_dict.get(
                        pe.image_base + base_uw
                    )
                    if candidate:
                        unwind_label = candidate[0].name
                if unwind_label is not None:
                    # Preserve the chained-record bit by ORing it in
                    # after the symbolic subtraction.
                    uw_expr = (
                        f"({unwind_label} - 0x{pe.image_base:X})"
                        + (f" | 0x80000000" if unwind & 0x80000000 else "")
                    )
                else:
                    uw_expr = f"0x{unwind:X}"
                # Optional prologue annotation: every UNWIND_INFO blob
                # carries an opcode list (push reg, alloc N, set FP, ...)
                # — surface it in the row's trailing comment when
                # parse_unwind_info decoded one.
                unwind_decoded = pe.unwind_info.get(base_uw)
                unwind_comment = ""
                if unwind_decoded is not None and unwind_decoded.codes:
                    prolog_ops = ", ".join(
                        f"{op}({info})" for _ofs, op, info in unwind_decoded.codes
                    )
                    unwind_comment = (
                        f" prolog=0x{unwind_decoded.prolog_size:X} [{prolog_ops}]"
                    )
                if exact:
                    # Byte-identical mode: emit raw RVAs so the
                    # assembled output matches the original bytes
                    # without needing cross-segment symbol resolution.
                    f.write(
                        f"    .long 0x{begin:X}, 0x{end:X}, 0x{unwind:X}"
                        f"  /* [{entry_index}] RUNTIME_FUNCTION{unwind_comment} */\n"
                    )
                else:
                    f.write(
                        f"    .long {resolve_func_rva(begin)} - 0x{pe.image_base:X}"
                        f", {resolve_func_rva(end)} - 0x{pe.image_base:X}"
                        f", {uw_expr}"
                        f"  /* [{entry_index}] RUNTIME_FUNCTION{unwind_comment} */\n"
                    )
                i += 12
                entry_index += 1

            # Trailing bytes that don't form a complete 12-byte record
            # (shouldn't happen with valid .pdata, but be defensive).
            if i < n:
                tail = data[i:]
                hexed = ", ".join(f"0x{b:02X}" for b in tail)
                f.write(f"    .byte {hexed}  /* trailing bytes */\n")

        self.log(f"Wrote {self.name} ({entry_index} runtime functions) to {path}")
