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
from ...util import log, options


class Win32SegPdata(CommonSegment):
    @staticmethod
    def is_rodata() -> bool:
        return True

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
                # Unwind RVA emitted as a raw 32-bit value: the high
                # bit set means "chained record" (UNWIND_INFO is itself
                # a UNWIND_HISTORY pointing at the next handler in the
                # chain) — round-trips byte-for-byte either way.
                f.write(
                    f"    .long {resolve_func_rva(begin)} - 0x{pe.image_base:X}"
                    f", {resolve_func_rva(end)} - 0x{pe.image_base:X}"
                    f", 0x{unwind:X}"
                    f"  /* [{entry_index}] RUNTIME_FUNCTION */\n"
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
